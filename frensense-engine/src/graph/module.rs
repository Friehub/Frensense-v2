// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Cross-file module import & export alias resolution (§8.10).
//!
//! Provides language-agnostic module path resolution and alias chaining:
//! tracks import aliases (`import { a as b }`), local export aliases (`export { a as b }`),
//! and re-export chains (`export { a as b } from "./mod"`) across multi-file project graphs.

use rustc_hash::{FxHashMap, FxHashSet};

use frensense_lang::spec::{Export, Import};

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
pub fn resolve_module_path(
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
            ".ts", ".js", ".tsx", ".jsx", ".py", ".rs", ".go", ".c", ".mjs", ".cjs",
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

#[derive(Debug, Clone)]
enum ExportTarget {
    Local(String),
    ReExport { from_file: String, symbol: String },
    Barrel(String),
}

/// Computes module aliases per file: `file_path -> (local_name -> canonical_function_key)`.
pub struct ModuleAliasResolver;

impl ModuleAliasResolver {
    pub fn build(
        files: &[(String, String, String)], // (path, source, ext)
        ir_names: &FxHashSet<String>,
        fn_file: &FxHashMap<String, String>,
    ) -> FxHashMap<String, FxHashMap<String, String>> {
        let known_files: Vec<String> = files.iter().map(|(p, _, _)| p.clone()).collect();
        let mut file_imports: FxHashMap<String, Vec<Import>> = FxHashMap::default();
        let mut file_exports: FxHashMap<String, Vec<Export>> = FxHashMap::default();

        for (path, source, ext) in files {
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
            file_imports.insert(path.clone(), imps);
            file_exports.insert(path.clone(), exps);
        }

        // Build per-file export map
        let mut export_map: FxHashMap<String, FxHashMap<String, ExportTarget>> =
            FxHashMap::default();

        for (path, exps) in &file_exports {
            let m = export_map.entry(path.clone()).or_default();
            for exp in exps {
                if let Some(from_mod) = &exp.from_module {
                    if let Some(target_file) = resolve_module_path(path, from_mod, &known_files) {
                        if exp.exported_name == "*" {
                            m.insert("*".to_string(), ExportTarget::Barrel(target_file));
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

        // Add declared IR functions to export map as local exports
        for (func_name, file_path) in fn_file {
            let bare = func_name.rsplit("::").next().unwrap_or(func_name);
            export_map
                .entry(file_path.clone())
                .or_default()
                .entry(bare.to_string())
                .or_insert_with(|| ExportTarget::Local(bare.to_string()));
        }

        // Resolve imports for each file
        let mut file_aliases: FxHashMap<String, FxHashMap<String, String>> = FxHashMap::default();

        for (importer_path, imps) in &file_imports {
            for imp in imps {
                let local_name = &imp.local_name;
                let package = &imp.package;
                let symbol = imp.symbol.as_deref().unwrap_or(local_name.as_str());

                let Some(target_file) = resolve_module_path(importer_path, package, &known_files)
                else {
                    continue;
                };

                if let Some(canonical) =
                    Self::resolve_symbol(&target_file, symbol, &export_map, ir_names, fn_file, 0)
                {
                    file_aliases
                        .entry(importer_path.clone())
                        .or_default()
                        .insert(local_name.clone(), canonical);
                }
            }
        }

        file_aliases
    }

    fn resolve_symbol(
        file: &str,
        symbol: &str,
        export_map: &FxHashMap<String, FxHashMap<String, ExportTarget>>,
        ir_names: &FxHashSet<String>,
        fn_file: &FxHashMap<String, String>,
        depth: usize,
    ) -> Option<String> {
        if depth > 6 {
            return None;
        }

        if let Some(m) = export_map.get(file) {
            if let Some(target) = m.get(symbol) {
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
                            ir_names,
                            fn_file,
                            depth + 1,
                        );
                    }
                }
            }

            // Check barrel export fallback
            if let Some(ExportTarget::Barrel(barrel_file)) = m.get("*")
                && let Some(resolved) = Self::resolve_symbol(
                    barrel_file,
                    symbol,
                    export_map,
                    ir_names,
                    fn_file,
                    depth + 1,
                )
            {
                return Some(resolved);
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
