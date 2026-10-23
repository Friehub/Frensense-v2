// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! ESM/CommonJS import extraction shared by the JS and TS specs.

use tree_sitter::Node;

use crate::spec::{node_text, Export, Import, ItemKind, ModuleItem, Visibility};

pub(super) fn extract_js_imports<'tree>(root: Node<'tree>, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();

        if node.kind() == "import_statement" {
            // `import defaultExport from "module"`
            // `import { named, other as alias } from "module"`
            // `import * as ns from "module"`
            let package = find_string_child(node, source)
                .unwrap_or_default()
                .trim_matches(['"', '\''])
                .to_owned();

            for i in 0..node.named_child_count() {
                let child = node.named_child(i).unwrap();
                match child.kind() {
                    "identifier" => {
                        // default import
                        imports.push(Import {
                            local_name: node_text(child, source).to_owned(),
                            package: package.clone(),
                            symbol: None,
                        });
                    }
                    "import_clause" => {
                        extract_import_clause(child, source, &package, &mut imports);
                    }
                    _ => {}
                }
            }
        }

        if node.kind() == "call_expression" {
            // `require("module")` and `require("module").something`
            if let Some(callee) = node.child_by_field_name("function") {
                if node_text(callee, source) == "require" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if let Some(str_node) = args.named_child(0) {
                            let pkg = node_text(str_node, source)
                                .trim_matches(['"', '\''])
                                .to_owned();
                            extract_require_imports(node, source, pkg, &mut imports);
                        }
                    }
                }
            }
        }

        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                break 'outer;
            }
        }
    }

    imports
}

fn extract_import_clause(node: Node<'_>, source: &str, package: &str, out: &mut Vec<Import>) {
    for i in 0..node.named_child_count() {
        let child = node.named_child(i).unwrap();
        match child.kind() {
            "identifier" => {
                // `import { Foo }` - no alias
                out.push(Import {
                    local_name: node_text(child, source).to_owned(),
                    package: package.to_owned(),
                    symbol: Some(node_text(child, source).to_owned()),
                });
            }
            "named_imports" => {
                for j in 0..child.named_child_count() {
                    let spec = child.named_child(j).unwrap();
                    if spec.kind() == "import_specifier" {
                        extract_import_specifier(spec, source, package, out);
                    }
                }
            }
            "import_specifier" => {
                extract_import_specifier(child, source, package, out);
            }
            "namespace_import" => {
                // `import * as ns`
                if let Some(id) = child.named_child(0) {
                    out.push(Import {
                        local_name: node_text(id, source).to_owned(),
                        package: package.to_owned(),
                        symbol: None,
                    });
                }
            }
            _ => {}
        }
    }
}

fn extract_import_specifier(child: Node<'_>, source: &str, package: &str, out: &mut Vec<Import>) {
    // `import { Foo as Bar }` → local=Bar, symbol=Foo
    let name = child
        .child_by_field_name("name")
        .map(|n| node_text(n, source))
        .unwrap_or("");
    let alias = child
        .child_by_field_name("alias")
        .map(|n| node_text(n, source))
        .unwrap_or(name);
    out.push(Import {
        local_name: alias.to_owned(),
        package: package.to_owned(),
        symbol: Some(name.to_owned()),
    });
}

pub(super) fn extract_js_exports<'tree>(root: Node<'tree>, source: &str) -> Vec<Export> {
    let mut exports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();

        if node.kind() == "export_statement" {
            extract_export_statement(node, source, &mut exports);
        }

        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                break 'outer;
            }
        }
    }

    exports
}

/// One `export …` statement.
///
/// ESM has four shapes and they export different names, so they are matched
/// in that order:
///
/// 1. `export default <decl|expr>` - the importer sees `default`, never the
///    declaration's own name;
/// 2. `export { a as b } [from "m"]` - one export per specifier;
/// 3. `export [async] function …` / `export class …` / `export const …` /
///    `export enum …` / `export type …` / `export interface …` /
///    `export namespace …` - the declaration's own name;
/// 4. `export * [as ns] from "m"` - a barrel.
fn extract_export_statement(node: Node<'_>, source: &str, out: &mut Vec<Export>) {
    let from_module =
        find_string_child(node, source).map(|s| s.trim_matches(['"', '\'']).to_owned());

    if has_default_token(node) {
        let declared = node.named_child(0);
        let local = declared
            .and_then(|d| d.child_by_field_name("name"))
            .map(|n| node_text(n, source).to_owned())
            .unwrap_or_else(|| "default".to_owned());
        out.push(Export {
            exported_name: "default".to_owned(),
            local_name: local,
            from_module: None,
            visibility: Visibility::Public,
            kind: declared.map(declaration_kind).unwrap_or(ItemKind::Other),
        });
        return;
    }

    let mut produced = false;
    for i in 0..node.named_child_count() {
        let child = node.named_child(i).unwrap();
        match child.kind() {
            "export_clause" => {
                produced = true;
                for j in 0..child.named_child_count() {
                    let spec = child.named_child(j).unwrap();
                    if spec.kind() != "export_specifier" {
                        continue;
                    }
                    let name = spec
                        .child_by_field_name("name")
                        .map(|n| node_text(n, source))
                        .unwrap_or("");
                    let alias = spec
                        .child_by_field_name("alias")
                        .map(|n| node_text(n, source))
                        .unwrap_or(name);
                    out.push(Export {
                        exported_name: alias.to_owned(),
                        local_name: name.to_owned(),
                        from_module: from_module.clone(),
                        visibility: Visibility::Public,
                        kind: ItemKind::Other,
                    });
                }
            }
            // `export * as ns from "./m"`
            "namespace_export" => {
                produced = true;
                let name = child
                    .named_child(0)
                    .map(|n| node_text(n, source))
                    .unwrap_or("*")
                    .to_owned();
                out.push(Export {
                    exported_name: name.clone(),
                    local_name: name,
                    from_module: from_module.clone(),
                    visibility: Visibility::Public,
                    kind: ItemKind::Module,
                });
            }
            _ => {
                let names = declaration_names(child, source);
                if !names.is_empty() {
                    produced = true;
                    for (name, kind) in names {
                        out.push(Export {
                            exported_name: name.clone(),
                            local_name: name,
                            from_module: None,
                            visibility: Visibility::Public,
                            kind,
                        });
                    }
                }
            }
        }
    }

    // A bare `export * from "./m"`: no clause, no declaration, one barrel.
    if !produced && from_module.is_some() && node_text(node, source).contains('*') {
        out.push(Export {
            exported_name: "*".to_owned(),
            local_name: "*".to_owned(),
            from_module,
            visibility: Visibility::Public,
            kind: ItemKind::Module,
        });
    }
}

/// Every top-level declaration, exported or not.
///
/// A declaration is public when an `export` statement publishes it - either
/// by wrapping the declaration, or by naming it in a local `export { … }`
/// clause. Everything else at module scope is private to the file.
/// Re-exports and barrels declare nothing here.
pub(super) fn extract_js_module_items<'tree>(root: Node<'tree>, source: &str) -> Vec<ModuleItem> {
    let exported_locally = locally_exported_names(root, source);
    let mut items = Vec::new();

    for i in 0..root.named_child_count() {
        let Some(child) = root.named_child(i) else {
            continue;
        };
        if child.kind() == "export_statement" {
            if has_default_token(child) {
                // `export default class Foo {}` declares Foo, publicly.
                if let Some(decl) = child.named_child(0) {
                    if let Some(name) = decl.child_by_field_name("name") {
                        items.push(ModuleItem {
                            name: node_text(name, source).to_owned(),
                            kind: declaration_kind(decl),
                            visibility: Visibility::Public,
                        });
                    }
                }
                continue;
            }
            for j in 0..child.named_child_count() {
                let Some(decl) = child.named_child(j) else {
                    continue;
                };
                for (name, kind) in declaration_names(decl, source) {
                    items.push(ModuleItem {
                        name,
                        kind,
                        visibility: Visibility::Public,
                    });
                }
            }
            continue;
        }
        for (name, kind) in declaration_names(child, source) {
            let visibility = if exported_locally.contains(&name) {
                Visibility::Public
            } else {
                Visibility::Private
            };
            items.push(ModuleItem {
                name,
                kind,
                visibility,
            });
        }
    }

    items
}

/// Names published by a local `export { a, b as c }` clause.
fn locally_exported_names(root: Node<'_>, source: &str) -> rustc_hash::FxHashSet<String> {
    let mut names = rustc_hash::FxHashSet::default();
    for i in 0..root.named_child_count() {
        let Some(child) = root.named_child(i) else {
            continue;
        };
        if child.kind() != "export_statement" || find_string_child(child, source).is_some() {
            continue;
        }
        for j in 0..child.named_child_count() {
            let Some(clause) = child.named_child(j) else {
                continue;
            };
            if clause.kind() != "export_clause" {
                continue;
            }
            for k in 0..clause.named_child_count() {
                let Some(spec) = clause.named_child(k) else {
                    continue;
                };
                if spec.kind() != "export_specifier" {
                    continue;
                }
                if let Some(name) = spec.child_by_field_name("name") {
                    names.insert(node_text(name, source).to_owned());
                }
            }
        }
    }
    names
}

/// The `default` keyword of `export default …` is an anonymous token, so it
/// has to be looked up by kind rather than by field name.
fn has_default_token(node: Node<'_>) -> bool {
    (0..node.child_count()).any(|i| {
        node.child(i)
            .is_some_and(|c| !c.is_named() && c.kind() == "default")
    })
}

fn declaration_kind(node: Node<'_>) -> ItemKind {
    match node.kind() {
        "function_declaration"
        | "generator_function_declaration"
        | "function_expression"
        | "arrow_function" => ItemKind::Function,
        "class_declaration" | "abstract_class_declaration" | "class" => ItemKind::Class,
        "enum_declaration" => ItemKind::Enum,
        "interface_declaration" => ItemKind::Interface,
        "type_alias_declaration" => ItemKind::Type,
        "internal_module" | "module" => ItemKind::Module,
        _ => ItemKind::Other,
    }
}

/// Names an `export <declaration>` publishes, with their item kinds.
///
/// Declaration forms that bind several names (`export const a = 1, b = 2`)
/// produce one export each; patterns that bind none we can name (destructuring
/// into computed keys) produce nothing.
fn declaration_names(node: Node<'_>, source: &str) -> Vec<(String, ItemKind)> {
    match node.kind() {
        "lexical_declaration" | "variable_declaration" => {
            let keyword = (0..node.child_count())
                .filter_map(|i| node.child(i))
                .find(|c| !c.is_named())
                .map(|c| c.kind())
                .unwrap_or("let");
            let kind = if keyword == "const" {
                ItemKind::Constant
            } else {
                ItemKind::Variable
            };
            let mut out = Vec::new();
            for i in 0..node.named_child_count() {
                let decl = node.named_child(i).unwrap();
                if decl.kind() != "variable_declarator" {
                    continue;
                }
                let Some(name_node) = decl.child_by_field_name("name") else {
                    continue;
                };
                if name_node.kind() == "identifier" {
                    out.push((node_text(name_node, source).to_owned(), kind));
                }
            }
            out
        }
        _ => {
            let kind = declaration_kind(node);
            if kind == ItemKind::Other {
                return Vec::new();
            }
            node.child_by_field_name("name")
                .map(|n| vec![(node_text(n, source).to_owned(), kind)])
                .unwrap_or_default()
        }
    }
}

fn find_string_child<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    for i in 0..node.named_child_count() {
        let child = node.named_child(i)?;
        if matches!(child.kind(), "string" | "template_string") {
            return Some(node_text(child, source));
        }
    }
    None
}

fn extract_require_imports(call_node: Node<'_>, source: &str, pkg: String, out: &mut Vec<Import>) {
    if let Some(parent) = call_node.parent() {
        if parent.kind() == "variable_declarator" {
            if let Some(name_node) = parent.child_by_field_name("name") {
                match name_node.kind() {
                    "identifier" => {
                        out.push(Import {
                            local_name: node_text(name_node, source).to_owned(),
                            package: pkg,
                            symbol: None,
                        });
                        return;
                    }
                    "object_pattern" => {
                        let mut extracted = false;
                        for i in 0..name_node.named_child_count() {
                            if let Some(child) = name_node.named_child(i) {
                                match child.kind() {
                                    "shorthand_property_identifier_pattern" => {
                                        let sym = node_text(child, source).to_owned();
                                        out.push(Import {
                                            local_name: sym.clone(),
                                            package: pkg.clone(),
                                            symbol: Some(sym),
                                        });
                                        extracted = true;
                                    }
                                    "pair_pattern" => {
                                        let key = child
                                            .child_by_field_name("key")
                                            .map(|k| node_text(k, source));
                                        let val = child
                                            .child_by_field_name("value")
                                            .map(|v| node_text(v, source));
                                        if let (Some(k), Some(v)) = (key, val) {
                                            out.push(Import {
                                                local_name: v.to_owned(),
                                                package: pkg.clone(),
                                                symbol: Some(k.to_owned()),
                                            });
                                            extracted = true;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        if extracted {
                            return;
                        }
                    }
                    _ => {}
                }
            }
        } else if parent.kind() == "member_expression" {
            let prop = parent
                .child_by_field_name("property")
                .map(|p| node_text(p, source));
            if let Some(p_name) = prop {
                if let Some(grandparent) = parent.parent() {
                    if grandparent.kind() == "variable_declarator" {
                        if let Some(name_node) = grandparent.child_by_field_name("name") {
                            if name_node.kind() == "identifier" {
                                out.push(Import {
                                    local_name: node_text(name_node, source).to_owned(),
                                    package: pkg,
                                    symbol: Some(p_name.to_owned()),
                                });
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    // Fallback: push placeholder using package stem
    out.push(Import {
        local_name: pkg.rsplit('/').next().unwrap_or(&pkg).to_owned(),
        package: pkg,
        symbol: None,
    });
}
