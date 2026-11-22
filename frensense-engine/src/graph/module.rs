// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Cross-file module import & export alias resolution (§8.10).
//!
//! Provides language-agnostic module path resolution and alias chaining:
//! tracks import aliases (`import { a as b }`), local export aliases (`export { a as b }`),
//! and re-export chains (`export { a as b } from "./mod"`) across multi-file project graphs.

use rustc_hash::{FxHashMap, FxHashSet};

use frensense_lang::spec::{Export, Import, ModuleItem};

fn concat2(a: &str, b: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len());
    s.push_str(a);
    s.push_str(b);
    s
}

fn concat3(a: &str, b: &str, c: &str) -> String {
    let mut s = String::with_capacity(a.len() + b.len() + c.len());
    s.push_str(a);
    s.push_str(b);
    s.push_str(c);
    s
}

/// Resolves a module specifier (e.g. `"./sink_raw"`, `".utils"`) relative to `from_file`
/// against the known file paths in the program.
pub(crate) fn resolve_module_path(
    from_file: &str,
    specifier: &str,
    known_files: &[String],
) -> Option<String> {
    let from_norm = from_file.replace('\\', "/");
    let parent = std::path::Path::new(&from_norm)
        .parent()
        .unwrap_or(std::path::Path::new(""));

    let spec_clean = specifier.trim_matches(['"', '\'']);
    let mut parts: Vec<&str> = parent
        .iter()
        .filter_map(|s| s.to_str())
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    if spec_clean.starts_with('.') {
        // Python-style leading dots or standard relative path
        if spec_clean.starts_with("./") || spec_clean.starts_with("../") {
            for segment in spec_clean.split('/') {
                if segment.is_empty() || segment == "." {
                    continue;
                } else if segment == ".." {
                    parts.pop();
                } else {
                    parts.push(segment);
                }
            }
        } else {
            // Python relative import: e.g. `.utils` or `..views`
            let dot_count = spec_clean.chars().take_while(|c| *c == '.').count();
            let rest = &spec_clean[dot_count..];
            for _ in 1..dot_count {
                parts.pop();
            }
            if !rest.is_empty() {
                for seg in rest.split('.') {
                    if !seg.is_empty() {
                        parts.push(seg);
                    }
                }
            }
        }
    } else {
        // Package / module name: e.g. `sink_module` or `crate::sink`
        let clean = spec_clean
            .trim_start_matches("crate::")
            .trim_start_matches("super::");
        for seg in clean.split('/') {
            for sub in seg.split("::") {
                if !sub.is_empty() {
                    parts.push(sub);
                }
            }
        }
    }

    let candidate_base = parts.join("/");
    let candidate_stem = candidate_base.rsplit('/').next().unwrap_or(&candidate_base);

    // 1. Direct path matches
    for kf in known_files {
        let kf_norm = kf.replace('\\', "/");
        if kf_norm == candidate_base {
            return Some(kf.clone());
        }
        for ext in &[
            ".ts", ".js", ".tsx", ".jsx", ".mts", ".cts", ".vue", ".py", ".rs", ".go", ".c",
            ".mjs", ".cjs",
        ] {
            if kf_norm == concat2(&candidate_base, ext) {
                return Some(kf.clone());
            }
        }
        for index in &[
            "/index.ts",
            "/index.js",
            "/index.tsx",
            "/index.jsx",
            "/mod.rs",
            "/__init__.py",
        ] {
            if kf_norm == concat2(&candidate_base, index) {
                return Some(kf.clone());
            }
        }
    }

    // 2. Stem match fallback (single match across known files)
    let mut stem_matches = Vec::new();
    for kf in known_files {
        let kf_norm = kf.replace('\\', "/");
        let kf_stem = std::path::Path::new(&kf_norm)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if kf_stem == candidate_stem {
            stem_matches.push(kf.clone());
        }
    }
    if stem_matches.len() == 1 {
        return Some(stem_matches.remove(0));
    }

    None
}

/// Maximum recursion depth when resolving re-exports and barrel exports.
///
/// Deep barrel chains (e.g. `entry -> barrel1 -> barrel2 -> ... -> target`)
/// resolve transitively across multiple hops up to this limit. The depth
/// bound prevents infinite recursion on cyclic re-export topologies.
pub const MAX_REEXPORT_RESOLVE_DEPTH: usize = 12;

#[derive(Debug, Clone)]
enum ExportTarget {
    Local(String),
    ReExport { from_file: String, symbol: String },
    Barrel(String),
}

type FileExportMap = FxHashMap<String, FxHashMap<String, ExportTarget>>;
type FileBarrelMap = FxHashMap<String, Vec<String>>;

/// The package-import table that applies to `fn_name`: its own file's, or, when
/// the function's file is untracked and the program has exactly one file's
/// imports, that single table. `None` otherwise (unknown origin stays inert).
///
/// This is the one definition of the single-file fallback; the taint engine,
/// its guard map and the policy scope all resolve imports through it.
pub(crate) fn imports_for_function<'m>(
    fn_file: &FxHashMap<String, String>,
    file_package_imports: &'m FxHashMap<String, FxHashMap<String, PackageImport>>,
    fn_name: &str,
) -> Option<&'m FxHashMap<String, PackageImport>> {
    fn_file
        .get(fn_name)
        .and_then(|file| file_package_imports.get(file))
        .or_else(|| {
            if file_package_imports.len() == 1 {
                file_package_imports.values().next()
            } else {
                None
            }
        })
}

/// An imported package symbol: package name and optional imported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageImport {
    /// Name of the imported package.
    pub package: String,
    /// The imported symbol, or `None` for a whole-package import.
    pub symbol: Option<String>,
}

/// Result of whole-program module resolution.
///
/// Alias resolution is what taint needs; the other three maps are the
/// surface it had to parse to get there, kept because every module-level
/// question (what does this file declare, what does it export, who imports
/// it) reads them, and re-parsing would make each consumer a second source
/// of truth about the same source text.
#[derive(Debug, Clone, Default)]
pub(crate) struct ModuleResolution {
    /// Per file, the local names that an import binds to a program function.
    pub file_aliases: FxHashMap<String, FxHashMap<String, String>>,
    /// Per file, the local names that an import binds to an external package.
    pub file_package_imports: FxHashMap<String, FxHashMap<String, PackageImport>>,
    /// Import declarations per file, aliases included.
    pub file_imports: FxHashMap<String, Vec<Import>>,
    /// Export and re-export declarations per file, with visibility and
    /// declaration kind.
    pub file_exports: FxHashMap<String, Vec<Export>>,
    /// Every top-level declaration per file, exported or not.
    pub file_module_items: FxHashMap<String, Vec<ModuleItem>>,
}

/// Computes module aliases and external package imports per file.
#[derive(Debug)]
pub(crate) struct ModuleAliasResolver;

impl ModuleAliasResolver {
    /// Resolves the imports and exports of `files` (`(path, source, extension)`
    /// rows) against the program's functions `ir_names`, using `fn_file` to
    /// place each function in its file. Borrows the caller's strings instead
    /// of copying the corpus, so a per-file frontend never duplicates every
    /// source file's text.
    fn build_export_maps(
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
                    if let Some(target_file) = resolve_module_path(path, from_mod, known_files) {
                        if exp.exported_name == "*" {
                            m.insert("*".to_string(), ExportTarget::Barrel(target_file.clone()));
                            let list = barrel_map.entry(path.clone()).or_default();
                            if !list.contains(&target_file) {
                                list.push(target_file);
                            }
                        } else {
                            m.insert(
                                exp.exported_name.clone(),
                                ExportTarget::ReExport {
                                    from_file: target_file,
                                    symbol: exp.local_name.clone(),
                                },
                            );
                        }
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

    pub(crate) fn build_from_refs(
        files: &[(&str, &str, &str)], // (path, source, ext)
        ir_names: &FxHashSet<String>,
        fn_file: &FxHashMap<String, String>,
    ) -> ModuleResolution {
        let known_files: Vec<String> = files.iter().map(|(p, _, _)| (*p).to_owned()).collect();
        let mut file_imports: FxHashMap<String, Vec<Import>> = FxHashMap::default();
        let mut file_exports: FxHashMap<String, Vec<Export>> = FxHashMap::default();
        let mut file_module_items: FxHashMap<String, Vec<ModuleItem>> = FxHashMap::default();

        for &(path, source, ext) in files {
            let Some(spec) = frensense_lang::spec_for_ext(ext) else {
                continue;
            };
            let mut parser = tree_sitter::Parser::new();
            if parser.set_language(&spec.tree_sitter_language()).is_err() {
                continue;
            }
            let Some(tree) = parser.parse(source, None) else {
                continue;
            };

            let imps = spec.extract_imports(tree.root_node(), source);
            let exps = spec.extract_exports(tree.root_node(), source);
            let items = spec.extract_module_items(tree.root_node(), source);
            file_imports.insert(path.to_owned(), imps);
            file_exports.insert(path.to_owned(), exps);
            file_module_items.insert(path.to_owned(), items);
        }

        let (export_map, barrel_map) =
            Self::build_export_maps(&file_exports, &known_files, fn_file);

        // Resolve imports for each file
        let mut file_aliases: FxHashMap<String, FxHashMap<String, String>> = FxHashMap::default();
        let mut file_package_imports: FxHashMap<String, FxHashMap<String, PackageImport>> =
            FxHashMap::default();

        for (importer_path, imps) in &file_imports {
            for imp in imps {
                let local_name = &imp.local_name;
                let package = &imp.package;
                let symbol = imp.symbol.as_deref().unwrap_or(local_name.as_str());

                let Some(target_file) = resolve_module_path(importer_path, package, &known_files)
                else {
                    let normalized_pkg = package
                        .strip_prefix("node:")
                        .unwrap_or(package.as_str())
                        .to_string();
                    file_package_imports
                        .entry(importer_path.clone())
                        .or_default()
                        .insert(
                            local_name.clone(),
                            PackageImport {
                                package: normalized_pkg,
                                symbol: imp.symbol.clone(),
                            },
                        );
                    continue;
                };

                if let Some(canonical) = Self::resolve_symbol(
                    &target_file,
                    symbol,
                    &export_map,
                    &barrel_map,
                    ir_names,
                    fn_file,
                    0,
                ) {
                    file_aliases
                        .entry(importer_path.clone())
                        .or_default()
                        .insert(local_name.clone(), canonical);
                }
            }
        }

        ModuleResolution {
            file_aliases,
            file_package_imports,
            file_imports,
            file_exports,
            file_module_items,
        }
    }

    /// Recursively resolve an imported `symbol` from `file` across re-exports and barrel files.
    ///
    /// Resolution order:
    /// 1. Directly declared local export in `file` (`export function foo()`)
    /// 2. Explicit named re-export (`export { foo } from "./other"`)
    /// 3. Wildcard barrel exports (`export * from "./submodule"`), searching all barrels declared in `file`
    /// 4. Direct match in `ir_names` qualified or bare for the file
    ///
    /// The search recurses across multi-hop re-export chains up to [`MAX_REEXPORT_RESOLVE_DEPTH`].
    fn resolve_symbol(
        file: &str,
        symbol: &str,
        export_map: &FileExportMap,
        barrel_map: &FileBarrelMap,
        ir_names: &FxHashSet<String>,
        fn_file: &FxHashMap<String, String>,
        depth: usize,
    ) -> Option<String> {
        if depth > MAX_REEXPORT_RESOLVE_DEPTH {
            return None;
        }

        if let Some(target) = export_map.get(file).and_then(|m| m.get(symbol)) {
            match target {
                ExportTarget::Local(local_sym) => {
                    let qual = concat3(file, "::", local_sym);
                    if ir_names.contains(&qual) {
                        return Some(qual);
                    }
                    if ir_names.contains(local_sym) {
                        return Some(local_sym.clone());
                    }
                    return Some(local_sym.clone());
                }
                ExportTarget::ReExport {
                    from_file,
                    symbol: target_sym,
                } => {
                    return Self::resolve_symbol(
                        from_file,
                        target_sym,
                        export_map,
                        barrel_map,
                        ir_names,
                        fn_file,
                        depth + 1,
                    );
                }
                ExportTarget::Barrel(from_file) => {
                    return Self::resolve_symbol(
                        from_file,
                        symbol,
                        export_map,
                        barrel_map,
                        ir_names,
                        fn_file,
                        depth + 1,
                    );
                }
            }
        }

        // Check all wildcard barrel exports for this file (multi-barrel support)
        if let Some(barrels) = barrel_map.get(file) {
            for barrel_file in barrels {
                if let Some(resolved) = Self::resolve_symbol(
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
        }

        // Check if directly in ir_names
        let qual = concat3(file, "::", symbol);
        if ir_names.contains(&qual) {
            return Some(qual);
        }
        if ir_names.contains(symbol) && fn_file.get(symbol).map(|f| f == file).unwrap_or(false) {
            return Some(symbol.to_string());
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::scan;
    use frensense_lang::spec::Visibility;

    fn files(entries: &[(&str, &str, &str)]) -> Vec<(String, String, String)> {
        entries
            .iter()
            .map(|(p, s, e)| ((*p).to_string(), (*s).to_string(), (*e).to_string()))
            .collect()
    }

    /// The surface the resolver parses must survive into the prepared
    /// program: alias resolution is only one of its four readers.
    #[test]
    fn prepared_program_keeps_the_module_surface() {
        let program = files(&[
            (
                "src/server.ts",
                "export function handler() {}\nexport const LIMIT = 1;\nfunction local() {}\n",
                "ts",
            ),
            (
                "src/other.ts",
                "import { handler } from \"./server\";\nhandler();\n",
                "ts",
            ),
        ]);
        let prepared = scan::prepare(&program).expect("prepare");

        let exports = prepared.exports_of("src/server.ts");
        assert_eq!(exports.len(), 2, "{exports:?}");
        assert!(exports.iter().any(|e| e.exported_name == "handler"));
        assert!(exports.iter().any(|e| e.exported_name == "LIMIT"));

        let items = prepared.module_items_of("src/server.ts");
        let local = items.iter().find(|i| i.name == "local").expect("local");
        assert_eq!(local.visibility, Visibility::Private);

        let imports = prepared.imports_of("src/other.ts");
        assert!(imports.iter().any(|i| i.local_name == "handler"));

        // Alias resolution still works off the same parse.
        assert!(
            prepared
                .file_aliases
                .get("src/other.ts")
                .and_then(|m| m.get("handler"))
                .is_some(),
            "{:?}",
            prepared.file_aliases
        );

        assert_eq!(prepared.files(), vec!["src/other.ts", "src/server.ts"]);
    }

    #[test]
    fn rust_surface_keeps_private_items_for_visibility_checks() {
        let program = files(&[(
            "src/lib.rs",
            "pub fn serve() {}\nfn helper() {}\npub(crate) fn internal() {}\n",
            "rs",
        )]);
        let prepared = scan::prepare(&program).expect("prepare");

        let exported: Vec<&str> = prepared
            .exports_of("src/lib.rs")
            .iter()
            .map(|e| e.exported_name.as_str())
            .collect();
        assert_eq!(exported, vec!["serve"]);

        let items = prepared.module_items_of("src/lib.rs");
        assert_eq!(
            items
                .iter()
                .find(|i| i.name == "helper")
                .map(|i| i.visibility),
            Some(Visibility::Private)
        );
        assert_eq!(
            items
                .iter()
                .find(|i| i.name == "internal")
                .map(|i| i.visibility),
            Some(Visibility::Internal)
        );
    }

    #[test]
    fn multi_hop_reexport_and_multiple_barrel_exports() {
        let program = files(&[
            (
                "src/target.ts",
                "export function coreHandler() { return 42; }\n",
                "ts",
            ),
            (
                "src/other.ts",
                "export function otherHandler() { return 99; }\n",
                "ts",
            ),
            (
                // Barrel 1: wildcard re-exports target and other
                "src/barrel1.ts",
                "export * from \"./target\";\nexport * from \"./other\";\n",
                "ts",
            ),
            (
                // Barrel 2: intermediate barrel re-exporting barrel 1
                "src/barrel2.ts",
                "export * from \"./barrel1\";\n",
                "ts",
            ),
            (
                // Barrel 3: 3rd hop named re-export
                "src/barrel3.ts",
                "export { coreHandler, otherHandler } from \"./barrel2\";\n",
                "ts",
            ),
            (
                // Importer at 4th hop
                "src/app.ts",
                "import { coreHandler, otherHandler } from \"./barrel3\";\ncoreHandler();\notherHandler();\n",
                "ts",
            ),
        ]);
        let prepared = scan::prepare(&program).expect("prepare");

        let aliases = prepared
            .file_aliases
            .get("src/app.ts")
            .expect("aliases for src/app.ts");
        assert!(
            aliases.get("coreHandler").is_some(),
            "coreHandler must resolve across 4 hops and multiple barrels: {aliases:?}"
        );
        assert!(
            aliases.get("otherHandler").is_some(),
            "otherHandler from 2nd export * must not be overwritten: {aliases:?}"
        );
    }
}

#[cfg(test)]
/// Assertions lifted from the doc examples of items that are now
/// crate-private; a doctest cannot see them.
mod doc_examples {
    #[test]
    fn doc_example_resolve_module_path() {
        use crate::graph::module::resolve_module_path;

        let known = vec![
            "src/a.ts".to_string(),
            "src/lib/util.ts".to_string(),
            "src/lib/index.ts".to_string(),
            "pkg/mod.py".to_string(),
        ];
        // Relative specifier, extension filled in.
        assert_eq!(
            resolve_module_path("src/a.ts", "./lib/util", &known).as_deref(),
            Some("src/lib/util.ts")
        );
        // `..` climbs one directory.
        assert_eq!(
            resolve_module_path("src/lib/util.ts", "../a", &known).as_deref(),
            Some("src/a.ts")
        );
        // A directory resolves to its index file.
        assert_eq!(
            resolve_module_path("src/a.ts", "./lib", &known).as_deref(),
            Some("src/lib/index.ts")
        );
        // Python-style leading dot.
        assert_eq!(
            resolve_module_path("pkg/x.py", ".mod", &known).as_deref(),
            Some("pkg/mod.py")
        );
        // Unknown files and bare package names do not resolve.
        assert_eq!(resolve_module_path("src/a.ts", "./missing", &known), None);
        assert_eq!(resolve_module_path("src/a.ts", "react", &known), None);
    }
}
