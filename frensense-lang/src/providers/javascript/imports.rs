// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! ESM/CommonJS import extraction shared by the JS and TS specs.

use tree_sitter::Node;

use crate::spec::{node_text, Export, Import};

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
                            // The binding name comes from the outer variable_declarator
                            // We push a placeholder; the fingerprinter resolves it
                            // from the parent `variable_declarator.name` field.
                            imports.push(Import {
                                local_name: pkg.rsplit('/').next().unwrap_or(&pkg).to_owned(),
                                package: pkg,
                                symbol: None,
                            });
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
            let from_module =
                find_string_child(node, source).map(|s| s.trim_matches(['"', '\'']).to_owned());

            let mut has_clause = false;
            for i in 0..node.named_child_count() {
                let child = node.named_child(i).unwrap();
                match child.kind() {
                    "export_clause" => {
                        has_clause = true;
                        for j in 0..child.named_child_count() {
                            let spec = child.named_child(j).unwrap();
                            if spec.kind() == "export_specifier" {
                                let name = spec
                                    .child_by_field_name("name")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or("");
                                let alias = spec
                                    .child_by_field_name("alias")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or(name);
                                exports.push(Export {
                                    exported_name: alias.to_owned(),
                                    local_name: name.to_owned(),
                                    from_module: from_module.clone(),
                                });
                            }
                        }
                    }
                    "function_declaration" => {
                        has_clause = true;
                        if let Some(name_node) = child.child_by_field_name("name") {
                            let name = node_text(name_node, source);
                            exports.push(Export {
                                exported_name: name.to_owned(),
                                local_name: name.to_owned(),
                                from_module: None,
                            });
                        }
                    }
                    _ => {}
                }
            }

            if !has_clause && from_module.is_some() && node_text(node, source).contains('*') {
                exports.push(Export {
                    exported_name: "*".to_owned(),
                    local_name: "*".to_owned(),
                    from_module: from_module.clone(),
                });
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

    exports
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
