// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Re-export and barrel-chain resolution for imported symbols.
//!
//! Split out of `graph::module` so the re-export walk, its depth budget
//! and the telemetry that reports truncation live in one place.
//!
//! Resolution returns an origin, not just a name. A chain may end at a
//! declaration in the program (`./util` -> `util.ts::parse`), or at an
//! external package (`export * from "@prisma/client"`). The second case used
//! to be dropped, which made the importing file look like it imported nothing:
//! every package-scoped sink, source and sanitizer fact went inert for a call
//! made through a barrel. Carrying the package along the hop keeps the fact
//! matchable.

use rustc_hash::{FxHashMap, FxHashSet};

use frensense_lang::spec::{Export, ItemKind};

use super::{concat3, resolve_module_path};

/// Maximum recursion depth when resolving re-exports and barrel exports.
///
/// Deep barrel chains (e.g. `entry -> barrel1 -> barrel2 -> ... -> target`)
/// resolve transitively across multiple hops up to this limit. The depth
/// bound prevents infinite recursion on cyclic re-export topologies.
///
/// Exceeding it is a truncation, not a miss: the import stays unresolved, the
/// fact layer reads that as an unknown origin, and every package-scoped fact
/// for the call goes inert. The `Cap::ReexportResolveDepth` counter records it
/// so the budget can be justified from measurements instead of guessed.
pub(super) const MAX_REEXPORT_RESOLVE_DEPTH: usize = 12;

/// Where a module specifier points: a file in the program, or an external
/// package that the program does not contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Specifier {
    /// A file of this program, already resolved.
    File(String),
    /// A package the program does not contain (`@prisma/client`).
    Package(String),
}

/// What one export declaration in a file means.
#[derive(Debug, Clone)]
pub(super) enum ExportTarget {
    /// `export function foo()` / `export { foo }`: a declaration in this file.
    Local(String),
    /// `export { a as b } from "<specifier>"`.
    ReExport { target: Specifier, symbol: String },
    /// `export * as ns from "<specifier>"`: the exported name is the module
    /// itself, not a member of it (`Export::kind` is `ItemKind::Module`).
    Namespace(Specifier),
}

/// A symbol resolved through the re-export graph.
///
/// `package` is `Some` exactly when the chain ends outside the program; the
/// caller records that as the import's package origin so package-scoped facts
/// still match the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedExport {
    /// Program symbol (`file::name`) or the imported name when external.
    pub(super) symbol: String,
    /// External package the chain ended at, if any.
    pub(super) package: Option<String>,
    /// The imported name is the module itself (`export * as ns from ...`), so
    /// it names no member and the caller must not record one.
    pub(super) namespace: bool,
}

pub(super) type FileExportMap = FxHashMap<String, FxHashMap<String, ExportTarget>>;
pub(super) type FileBarrelMap = FxHashMap<String, Vec<Specifier>>;

/// Normalized external package name for a specifier that is not a program
/// file: quotes trimmed, `node:` prefix dropped.
pub(super) fn package_name(specifier: &str) -> String {
    let spec = specifier.trim_matches(['"', '\'']);
    spec.strip_prefix("node:").unwrap_or(spec).to_string()
}

pub(super) fn build_export_maps(
    file_exports: &FxHashMap<String, Vec<Export>>,
    known_files: &[String],
    fn_file: &FxHashMap<String, String>,
) -> (FileExportMap, FileBarrelMap) {
    let mut export_map: FileExportMap = FxHashMap::default();
    let mut barrel_map: FileBarrelMap = FxHashMap::default();

    for (path, exps) in file_exports {
        let m = export_map.entry(path.clone()).or_default();
        for exp in exps {
            if let Some(from_mod) = &exp.from_module {
                // A specifier that is not a program file is a package: the
                // hop keeps it so import provenance survives the chain.
                let target = match resolve_module_path(path, from_mod, known_files) {
                    Some(file) => Specifier::File(file),
                    None => Specifier::Package(package_name(from_mod)),
                };
                if exp.exported_name == "*" {
                    let list = barrel_map.entry(path.clone()).or_default();
                    if !list.contains(&target) {
                        list.push(target);
                    }
                } else if exp.kind == ItemKind::Module {
                    // The declaration kind is what separates the two ways a
                    // `from` re-export names a target: `export { x } from`
                    // names a member, `export * as ns from` names the module.
                    // Reading them alike looks up a symbol the module does
                    // not declare, and files an external package under the
                    // namespace's own name as if that were its member.
                    m.insert(exp.exported_name.clone(), ExportTarget::Namespace(target));
                } else {
                    m.insert(
                        exp.exported_name.clone(),
                        ExportTarget::ReExport {
                            target,
                            symbol: exp.local_name.clone(),
                        },
                    );
                }
            } else {
                m.insert(
                    exp.exported_name.clone(),
                    ExportTarget::Local(exp.local_name.clone()),
                );
            }
        }
    }

    for (func_name, file_path) in fn_file {
        let bare = func_name.rsplit("::").next().unwrap_or(func_name);
        export_map
            .entry(file_path.clone())
            .or_default()
            .entry(bare.to_string())
            .or_insert_with(|| ExportTarget::Local(bare.to_string()));
    }

    (export_map, barrel_map)
}

/// Recursively resolve an imported `symbol` from `file` across re-exports and barrel files.
///
/// Resolution order:
/// 1. Directly declared local export in `file` (`export function foo()`)
/// 2. Explicit named re-export (`export { foo } from "./other"` or a package)
/// 3. Wildcard barrel exports (`export * from "./submodule"`), searching all barrels declared in `file`
/// 4. Direct match in `ir_names` qualified or bare for the file
///
/// The search recurses across multi-hop re-export chains up to [`MAX_REEXPORT_RESOLVE_DEPTH`].
pub(super) fn resolve_symbol(
    file: &str,
    symbol: &str,
    export_map: &FileExportMap,
    barrel_map: &FileBarrelMap,
    ir_names: &FxHashSet<String>,
    fn_file: &FxHashMap<String, String>,
    depth: usize,
) -> Option<ResolvedExport> {
    if depth > MAX_REEXPORT_RESOLVE_DEPTH {
        crate::telemetry::Cap::ReexportResolveDepth.record();
        return None;
    }

    if let Some(target) = export_map.get(file).and_then(|m| m.get(symbol)) {
        match target {
            ExportTarget::Local(local_sym) => {
                let local = if ir_names.contains(&concat3(file, "::", local_sym)) {
                    concat3(file, "::", local_sym)
                } else {
                    local_sym.clone()
                };
                return Some(ResolvedExport {
                    symbol: local,
                    package: None,
                    namespace: false,
                });
            }
            ExportTarget::ReExport { target, symbol } => {
                return match target {
                    Specifier::File(from_file) => resolve_symbol(
                        from_file,
                        symbol,
                        export_map,
                        barrel_map,
                        ir_names,
                        fn_file,
                        depth + 1,
                    ),
                    // The chain leaves the program: this is the package the
                    // importing file really depends on, under the name the
                    // package exports.
                    Specifier::Package(package) => Some(ResolvedExport {
                        symbol: symbol.clone(),
                        package: Some(package.clone()),
                        namespace: false,
                    }),
                };
            }
            ExportTarget::Namespace(target) => {
                return match target {
                    // The namespace is the package: the binding keeps the
                    // package, and the member (if any) comes from the call.
                    Specifier::Package(package) => Some(ResolvedExport {
                        symbol: symbol.to_string(),
                        package: Some(package.clone()),
                        namespace: true,
                    }),
                    // A namespace over a program file needs its member
                    // resolved inside that file, which the alias table cannot
                    // express; it stays unresolved rather than being recorded
                    // as a member that does not exist.
                    Specifier::File(_) => None,
                };
            }
        }
    }

    // Check all wildcard barrel exports for this file (multi-barrel support)
    if let Some(barrels) = barrel_map.get(file) {
        for barrel in barrels {
            match barrel {
                Specifier::File(barrel_file) => {
                    if let Some(resolved) = resolve_symbol(
                        barrel_file,
                        symbol,
                        export_map,
                        barrel_map,
                        ir_names,
                        fn_file,
                        depth + 1,
                    ) {
                        return Some(resolved);
                    }
                }
                Specifier::Package(package) => {
                    return Some(ResolvedExport {
                        symbol: symbol.to_string(),
                        package: Some(package.clone()),
                        namespace: false,
                    });
                }
            }
        }
    }

    // Check if directly in ir_names
    let qual = concat3(file, "::", symbol);
    if ir_names.contains(&qual) {
        return Some(ResolvedExport {
            symbol: qual,
            package: None,
            namespace: false,
        });
    }
    if ir_names.contains(symbol) && fn_file.get(symbol).map(|f| f == file).unwrap_or(false) {
        return Some(ResolvedExport {
            symbol: symbol.to_string(),
            package: None,
            namespace: false,
        });
    }

    None
}

#[cfg(test)]
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
