// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Re-export and barrel-chain resolution, exercised through `scan::prepare`:
//! what an import binds to when the symbol arrives through a barrel, a
//! namespace or a package.

use super::reexport::*;

mod tests {
    use rustc_hash::{FxHashMap, FxHashSet};

    use super::*;

    fn files(entries: &[(&str, &str, &str)]) -> Vec<(String, String, String)> {
        entries
            .iter()
            .map(|(p, s, e)| ((*p).to_string(), (*s).to_string(), (*e).to_string()))
            .collect()
    }

    /// A barrel chain past the budget is a reported truncation, not a silent
    /// miss: the unresolved import becomes an unknown origin downstream, so
    /// every package-scoped fact for that call goes inert.
    #[test]
    fn barrel_chain_past_the_budget_reports_the_resolve_depth_cap() {
        let _ = crate::telemetry::drain_caps();

        let hops = MAX_REEXPORT_RESOLVE_DEPTH + 2;
        let mut export_map: FileExportMap = FxHashMap::default();
        let mut barrel_map: FileBarrelMap = FxHashMap::default();
        export_map
            .entry("src/barrel0.ts".to_string())
            .or_default()
            .insert(
                "handler".to_string(),
                ExportTarget::Local("handler".to_string()),
            );
        for n in 1..=hops {
            barrel_map.insert(
                format!("src/barrel{n}.ts"),
                vec![Specifier::File(format!("src/barrel{}.ts", n - 1))],
            );
        }
        let mut ir_names: FxHashSet<String> = FxHashSet::default();
        ir_names.insert("src/barrel0.ts::handler".to_string());
        let fn_file = FxHashMap::default();

        let resolved = resolve_symbol(
            &format!("src/barrel{hops}.ts"),
            "handler",
            &export_map,
            &barrel_map,
            &ir_names,
            &fn_file,
            0,
        );

        assert_eq!(resolved, None, "past the budget nothing may resolve");
        let hits = crate::telemetry::drain_caps();
        let hit = hits
            .iter()
            .find(|hit| hit.cap == "reexport_resolve_depth")
            .unwrap_or_else(|| panic!("expected a resolve-depth cap hit: {hits:?}"));
        assert_eq!(hit.hits, 1, "one truncation, one recorded hit: {hits:?}");
    }

    /// `import { X } from "./barrel"` where the barrel re-exports `X` from a
    /// package: the importing file's import table must name the package, or
    /// every package-scoped fact for `X` is unreachable from that call site.
    #[test]
    fn barrel_import_carries_the_package_origin() {
        let program = files(&[
            (
                "src/barrel.ts",
                "export { $queryRawUnsafe } from \"@prisma/client\";\n",
                "ts",
            ),
            (
                "src/app.ts",
                "import { $queryRawUnsafe } from \"./barrel\";\nconst q = $queryRawUnsafe;\n",
                "ts",
            ),
        ]);
        let prepared = crate::scan::prepare(&program).expect("prepare");
        let import = prepared
            .file_package_imports
            .get("src/app.ts")
            .and_then(|m| m.get("$queryRawUnsafe"))
            .unwrap_or_else(|| panic!("{:?}", prepared.file_package_imports));
        assert_eq!(import.package, "@prisma/client");
        assert_eq!(import.symbol.as_deref(), Some("$queryRawUnsafe"));
    }

    /// The exported alias is not the package's symbol: the import must record
    /// the name the package declares, which is what sink facts are keyed on.
    #[test]
    fn aliased_reexport_reports_the_package_symbol() {
        let program = files(&[
            (
                "src/barrel.ts",
                "export { $queryRawUnsafe as raw } from \"@prisma/client\";\n",
                "ts",
            ),
            (
                "src/app.ts",
                "import { raw } from \"./barrel\";\nconst q = raw;\n",
                "ts",
            ),
        ]);
        let prepared = crate::scan::prepare(&program).expect("prepare");
        let import = prepared
            .file_package_imports
            .get("src/app.ts")
            .and_then(|m| m.get("raw"))
            .unwrap_or_else(|| panic!("{:?}", prepared.file_package_imports));
        assert_eq!(import.package, "@prisma/client");
        assert_eq!(import.symbol.as_deref(), Some("$queryRawUnsafe"));
    }

    /// `import * as util from "./util"` binds the module, so the import table
    /// records where the binding points and the call graph resolves
    /// `util.parse()` inside that file.
    #[test]
    fn namespace_import_of_a_program_module_binds_the_module() {
        let program = files(&[
            (
                "src/util.ts",
                "export function parse(x: string) { return x; }\n",
                "ts",
            ),
            (
                "src/app.ts",
                "import * as util from \"./util\";\nutil.parse(q);\n",
                "ts",
            ),
        ]);
        let prepared = crate::scan::prepare(&program).expect("prepare");
        let module = prepared
            .file_namespace_aliases
            .get("src/app.ts")
            .and_then(|m| m.get("util"))
            .unwrap_or_else(|| panic!("{:?}", prepared.file_namespace_aliases));
        assert_eq!(module, "src/util.ts");
    }

    /// The same binding reached through a re-export: the barrel publishes the
    /// module under a name, so the importer's binding still points at the file.
    #[test]
    fn namespace_reexport_of_a_program_module_binds_the_module() {
        let program = files(&[
            (
                "src/util.ts",
                "export function parse(x: string) { return x; }\n",
                "ts",
            ),
            ("src/barrel.ts", "export * as util from \"./util\";\n", "ts"),
            (
                "src/app.ts",
                "import { util } from \"./barrel\";\nutil.parse(q);\n",
                "ts",
            ),
        ]);
        let prepared = crate::scan::prepare(&program).expect("prepare");
        let module = prepared
            .file_namespace_aliases
            .get("src/app.ts")
            .and_then(|m| m.get("util"))
            .unwrap_or_else(|| panic!("{:?}", prepared.file_namespace_aliases));
        assert_eq!(module, "src/util.ts");
    }

    /// `export * as ns from "<pkg>"` binds the package itself. Reading it as a
    /// re-export of a member named `ns` records the namespace as the package's
    /// symbol, and every fact keyed on the real member goes unreachable.
    #[test]
    fn namespace_reexport_binds_the_package_without_a_member() {
        let program = files(&[
            (
                "src/barrel.ts",
                "export * as prisma from \"@prisma/client\";\n",
                "ts",
            ),
            (
                "src/app.ts",
                "import { prisma } from \"./barrel\";\nprisma.$queryRawUnsafe(q);\n",
                "ts",
            ),
        ]);
        let prepared = crate::scan::prepare(&program).expect("prepare");
        let import = prepared
            .file_package_imports
            .get("src/app.ts")
            .and_then(|m| m.get("prisma"))
            .unwrap_or_else(|| panic!("{:?}", prepared.file_package_imports));
        assert_eq!(import.package, "@prisma/client");
        assert_eq!(import.symbol, None, "a namespace binding names no member");
    }

    /// A file that only re-exports everything from a package still gives its
    /// importers that package's origin.
    #[test]
    fn wildcard_package_barrel_carries_the_package_origin() {
        let program = files(&[
            (
                "src/barrel.ts",
                "export * from \"node:child_process\";\n",
                "ts",
            ),
            (
                "src/app.ts",
                "import { execSync } from \"./barrel\";\nexecSync(cmd);\n",
                "ts",
            ),
        ]);
        let prepared = crate::scan::prepare(&program).expect("prepare");
        let import = prepared
            .file_package_imports
            .get("src/app.ts")
            .and_then(|m| m.get("execSync"))
            .unwrap_or_else(|| panic!("{:?}", prepared.file_package_imports));
        assert_eq!(import.package, "child_process");
        assert_eq!(import.symbol.as_deref(), Some("execSync"));
    }
}
