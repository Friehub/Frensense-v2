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
    /// The program file a namespace binding denotes. `Some` only when the
    /// namespace is a file of this program: a member call through the binding
    /// resolves inside it.
    pub(super) module: Option<String>,
}

pub(super) type FileExportMap = FxHashMap<String, FxHashMap<String, ExportTarget>>;
/// Per file, the local names bound to a whole module, and the file each one
/// denotes: `import * as ns from "./m"`, `export * as ns from "./m"` and the
/// barrel chains between them.
pub(crate) type NamespaceBindings = FxHashMap<String, FxHashMap<String, String>>;
/// Per file, the local names an import binds to a program function, and the
/// program-level symbol each one names.
pub(crate) type FileAliases = FxHashMap<String, FxHashMap<String, String>>;
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
                    module: None,
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
                        module: None,
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
                        module: None,
                    }),
                    // A namespace over a program file: the binding denotes
                    // that file, so a member call through it resolves to a
                    // function declared there.
                    Specifier::File(file) => Some(ResolvedExport {
                        symbol: symbol.to_string(),
                        package: None,
                        namespace: true,
                        module: Some(file.clone()),
                    }),
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
                        module: None,
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
            module: None,
        });
    }
    if ir_names.contains(symbol) && fn_file.get(symbol).map(|f| f == file).unwrap_or(false) {
        return Some(ResolvedExport {
            symbol: symbol.to_string(),
            package: None,
            namespace: false,
            module: None,
        });
    }

    None
}
