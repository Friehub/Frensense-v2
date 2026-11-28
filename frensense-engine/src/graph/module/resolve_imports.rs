// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! What each imported name binds to: a program function, an external package
//! member, or a whole module.
//!
//! Split out of `graph::module`: path resolution answers "which file is this",
//! the re-export walk answers "which symbol in it", and this module turns those
//! answers into the three per-file tables every consumer reads.

use rustc_hash::{FxHashMap, FxHashSet};

use frensense_lang::spec::Import;

use super::reexport::{
    FileAliases, FileBarrelMap, FileExportMap, NamespaceBindings, package_name, resolve_symbol,
};
use super::{PackageImport, PackageImportTable, resolve_module_path};

/// The three per-file import tables.
pub(super) struct ImportResolution {
    pub(super) file_aliases: FileAliases,
    pub(super) file_package_imports: PackageImportTable,
    pub(super) file_namespace_aliases: NamespaceBindings,
}

/// Resolve every import of every file against the program's exports.
pub(super) fn resolve_imports(
    file_imports: &FxHashMap<String, Vec<Import>>,
    known_files: &[String],
    export_map: &FileExportMap,
    barrel_map: &FileBarrelMap,
    ir_names: &FxHashSet<String>,
    fn_file: &FxHashMap<String, String>,
) -> ImportResolution {
    let mut file_aliases: FxHashMap<String, FxHashMap<String, String>> = FxHashMap::default();
    let mut file_package_imports: PackageImportTable = FxHashMap::default();

    let mut file_namespace_aliases: FxHashMap<String, FxHashMap<String, String>> =
        FxHashMap::default();

    for (importer_path, imps) in file_imports {
        for imp in imps {
            let local_name = &imp.local_name;
            let package = &imp.package;
            let target_file = resolve_module_path(importer_path, package, known_files);

            // A namespace import (`import * as ns from "./m"`) binds the
            // module, not one of its members, so there is no symbol to
            // look up: over a program file it becomes a namespace alias
            // the call graph resolves members through, and over a package
            // it is a package import with no member - the shape a
            // namespace re-export resolves to.
            let Some(symbol) = imp.symbol.as_deref() else {
                match target_file {
                    Some(file) => {
                        file_namespace_aliases
                            .entry(importer_path.clone())
                            .or_default()
                            .insert(local_name.clone(), file);
                    }
                    None => {
                        file_package_imports
                            .entry(importer_path.clone())
                            .or_default()
                            .insert(
                                local_name.clone(),
                                PackageImport {
                                    package: package_name(package),
                                    symbol: None,
                                },
                            );
                    }
                }
                continue;
            };

            let Some(target_file) = target_file else {
                file_package_imports
                    .entry(importer_path.clone())
                    .or_default()
                    .insert(
                        local_name.clone(),
                        PackageImport {
                            package: package_name(package),
                            symbol: Some(symbol.to_string()),
                        },
                    );
                continue;
            };

            let Some(resolved) = resolve_symbol(
                &target_file,
                symbol,
                export_map,
                barrel_map,
                ir_names,
                fn_file,
                0,
            ) else {
                continue;
            };
            // `export * as ns from "./m"` reached through this import: the
            // binding denotes the module, so record where it points.
            if let Some(module) = resolved.module {
                file_namespace_aliases
                    .entry(importer_path.clone())
                    .or_default()
                    .insert(local_name.clone(), module);
                continue;
            }
            match resolved.package {
                // The chain left the program: record the package so
                // package-scoped facts still match the call site.
                Some(pkg) => {
                    file_package_imports
                        .entry(importer_path.clone())
                        .or_default()
                        .insert(
                            local_name.clone(),
                            PackageImport {
                                package: pkg,
                                // A namespace binding names the module,
                                // so the member is whatever the call site
                                // selects; naming the namespace would make
                                // the package's facts unmatchable.
                                symbol: (!resolved.namespace).then_some(resolved.symbol),
                            },
                        );
                }
                None => {
                    file_aliases
                        .entry(importer_path.clone())
                        .or_default()
                        .insert(local_name.clone(), resolved.symbol);
                }
            }
        }
    }

    ImportResolution {
        file_aliases,
        file_package_imports,
        file_namespace_aliases,
    }
}
