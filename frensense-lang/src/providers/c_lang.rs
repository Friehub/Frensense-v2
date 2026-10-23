// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//! C [`LanguageSpec`] implementation.
//!
//! Covers C99/C11 tree-sitter grammar node kinds.

use tree_sitter::Node;

use crate::spec::{
    node_text, Export, Import, ItemKind, LanguageSpec, ModuleItem, NodeRole, PackageCategory,
    TaintOrigin, Visibility,
};

// ── AST classification ────────────────────────────────────────────────────────

fn classify_c(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        "function_definition" => NodeRole::Function {
            is_method: false,
            name_field: Some("declarator".into()),
            params_field: "declarator".into(), // walked from the declarator
            body_field: "body".into(),
        },

        // ── Declarations / assignments ───────────────────────────────────
        "declaration" | "init_declarator" => NodeRole::Declaration {
            name_field: "declarator".into(),
            value_field: "value".into(),
        },
        "assignment_expression" => NodeRole::Assignment {
            lhs_field: "left".into(),
            rhs_field: "right".into(),
        },

        // ── Calls ────────────────────────────────────────────────────────
        "call_expression" => NodeRole::Call {
            callee_field: "function".into(),
            args_field: "arguments".into(),
        },
        "field_expression" => NodeRole::MemberAccess {
            object_field: "argument".into(),
            property_field: "field".into(),
        },
        "subscript_expression" => NodeRole::MemberAccess {
            object_field: "argument".into(),
            property_field: "index".into(),
        },

        // ── Control flow ─────────────────────────────────────────────────
        "if_statement" | "switch_statement" => NodeRole::Branch,
        "conditional_expression" => NodeRole::Conditional,
        "for_statement" | "while_statement" | "do_statement" => NodeRole::Loop,
        "return_statement" => NodeRole::Return,

        // ── Structural ───────────────────────────────────────────────────
        "compound_statement" => NodeRole::Block,
        "identifier" => NodeRole::Identifier,
        "string_literal" | "char_literal" | "number_literal" | "true" | "false" | "null" => {
            NodeRole::Literal
        }

        // ── Supplementary structural roles ───────────────────────────────
        "parameter_list" | "parameter_declaration" | "parameter_type_list" => NodeRole::Parameters,
        "argument_list" => NodeRole::Arguments,
        "struct_specifier" | "enum_specifier" | "type_definition" | "composite_type" => {
            NodeRole::ClassDef
        }
        "binary_expression" => NodeRole::BinaryOp,
        "unary_expression" | "pointer_expression" | "sizeof_expression" => NodeRole::UnaryOp,
        // `x++` / `--x`: lowered as read-modify-write by visit_unary_op.
        "update_expression" => NodeRole::UnaryOp,

        _ => NodeRole::Other,
    }
}

// ── Import extraction (C #include) ────────────────────────────────────────────

fn extract_c_includes(root: Node<'_>, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();
        if node.kind() == "preproc_include" {
            let pkg = node
                .named_child(0)
                .map(|n| {
                    let raw = node_text(n, source);
                    // Strip <stdio.h> or "myheader.h"
                    raw.trim_matches(['<', '>', '"', '\'']).to_owned()
                })
                .unwrap_or_default();
            if !pkg.is_empty() {
                let local = pkg
                    .rsplit('/')
                    .next()
                    .unwrap_or(&pkg)
                    .trim_end_matches(".h")
                    .to_owned();
                imports.push(Import {
                    local_name: local,
                    package: pkg,
                    symbol: None,
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

    imports
}

// ── Package knowledge ─────────────────────────────────────────────────────────

fn c_package_category(pkg: &str) -> Option<PackageCategory> {
    let base = pkg.trim_end_matches(".h");
    match base {
        "sqlite3" | "mysql" | "libpq" | "pgsql" => Some(PackageCategory::SqlDatabase),
        "curl" | "libcurl" => Some(PackageCategory::HttpClient),
        "openssl/md5" | "openssl/sha" => Some(PackageCategory::Crypto),
        _ => None,
    }
}

// ── CSpec ─────────────────────────────────────────────────────────────────────

pub struct CSpec;

impl LanguageSpec for CSpec {
    fn name(&self) -> &'static str {
        "c"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["c", "h"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "c-grammar")]
        return tree_sitter_c::LANGUAGE.into();
        #[cfg(not(feature = "c-grammar"))]
        panic!("frensense-lang: 'c-grammar' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_c(kind)
    }

    fn is_cast(&self, kind: &str) -> bool {
        kind == "cast_expression"
    }

    fn wrap_region(&self, code: &str) -> String {
        format!("void _region() {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["preproc_include"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_c_includes(root, source)
    }

    fn extract_exports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Export> {
        // C's export rule is linkage: a file-scope definition without
        // `static` is visible to the linker, with `static` it is not.
        c_module_items(root, source)
            .into_iter()
            .filter(|item| item.visibility == Visibility::Public)
            .map(|item| Export {
                exported_name: item.name.clone(),
                local_name: item.name,
                from_module: None,
                visibility: item.visibility,
                kind: item.kind,
            })
            .collect()
    }

    fn extract_module_items<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<ModuleItem> {
        c_module_items(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(
            r"
            (function_definition
                declarator: (function_declarator
                    declarator: (identifier) @name))
            (declaration
                declarator: (function_declarator
                    declarator: (identifier) @name))
        ",
        )
    }

    fn call_query(&self) -> Option<&'static str> {
        Some(
            r"
            (function_definition
                declarator: (function_declarator declarator: (identifier) @caller)
                body: (_
                    (expression_statement
                        (call_expression function: (identifier) @call))))
        ",
        )
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        c_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        _type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        match name? {
            "argc" | "argv" => Some(TaintOrigin::UserInput),
            _ => None,
        }
    }

    /// C owns the memory-safety rule domain: temporal (free-then-use,
    /// double-free) and spatial (buffer overflow / out-of-bounds) rules rank
    /// Critical with memory-safety advisory templates.
    fn known_rule_registry(&self) -> &'static [crate::severity::RuleEntry] {
        use crate::rules;
        use crate::severity::{RuleAdvisory, RuleEntry, Severity};

        static REGISTRY: &[RuleEntry] = &[
            RuleEntry {
                rule: rules::USE_AFTER_FREE,
                advisory: RuleAdvisory {
                    level: Severity::Critical,
                    title: "Memory safety violation: {rule} ({function})",
                    impact: "{rule} at {file}:{line}, dangerous temporal memory safety defect leading to memory corruption or arbitrary code execution.",
                    improvement: "Ensure memory is not used after free or freed multiple times in `{function}`. Zero or null pointer variables after free.",
                    tag: "memory-safety",
                },
            },
            RuleEntry {
                rule: rules::DOUBLE_FREE,
                advisory: RuleAdvisory {
                    level: Severity::Critical,
                    title: "Memory safety violation: {rule} ({function})",
                    impact: "{rule} at {file}:{line}, dangerous temporal memory safety defect leading to memory corruption or arbitrary code execution.",
                    improvement: "Ensure memory is not used after free or freed multiple times in `{function}`. Zero or null pointer variables after free.",
                    tag: "memory-safety",
                },
            },
            RuleEntry {
                rule: rules::UNINITIALIZED_FREE,
                advisory: RuleAdvisory {
                    level: Severity::Critical,
                    title: "Memory safety violation: {rule} ({function})",
                    impact: "{rule} at {file}:{line}, dangerous temporal memory safety defect leading to memory corruption or arbitrary code execution.",
                    improvement: "Initialize pointer variables before freeing them in `{function}`. Assign a valid allocation (or null) before every free.",
                    tag: "memory-safety",
                },
            },
            RuleEntry {
                rule: rules::BUFFER_OVERFLOW,
                advisory: RuleAdvisory {
                    level: Severity::Critical,
                    title: "Memory safety violation: {rule} ({function})",
                    impact: "{rule} at {file}:{line}, dangerous spatial memory safety defect leading to memory corruption, out-of-bounds access, or arbitrary code execution.",
                    improvement: "Ensure buffer bounds and subscript indices are strictly validated before access in `{function}`. Guard index against buffer capacity.",
                    tag: "memory-safety",
                },
            },
            RuleEntry {
                rule: rules::OUT_OF_BOUNDS_READ,
                advisory: RuleAdvisory {
                    level: Severity::Critical,
                    title: "Memory safety violation: {rule} ({function})",
                    impact: "{rule} at {file}:{line}, dangerous spatial memory safety defect leading to memory corruption, out-of-bounds access, or arbitrary code execution.",
                    improvement: "Ensure buffer bounds and subscript indices are strictly validated before access in `{function}`. Guard index against buffer capacity.",
                    tag: "memory-safety",
                },
            },
            RuleEntry {
                rule: rules::OUT_OF_BOUNDS_ACCESS,
                advisory: RuleAdvisory {
                    level: Severity::Critical,
                    title: "Memory safety violation: {rule} ({function})",
                    impact: "{rule} at {file}:{line}, dangerous spatial memory safety defect leading to memory corruption, out-of-bounds access, or arbitrary code execution.",
                    improvement: "Ensure buffer bounds and subscript indices are strictly validated before access in `{function}`. Guard index against buffer capacity.",
                    tag: "memory-safety",
                },
            },
            RuleEntry {
                rule: rules::INTEGER_OVERFLOW_ALLOC,
                advisory: RuleAdvisory {
                    level: Severity::Critical,
                    title: "Memory safety violation: {rule} ({function})",
                    impact: "{rule} at {file}:{line}, integer wrap in the allocation size produces an undersized buffer and a subsequent heap buffer overflow.",
                    improvement: "Validate the count against SIZE_MAX / element size before multiplying in `{function}` (pre-divide guard), or use an overflow-checked allocation (calloc / checked mul).",
                    tag: "memory-safety",
                },
            },
            RuleEntry {
                rule: rules::MEMORY_LEAK,
                advisory: RuleAdvisory {
                    level: Severity::Warning,
                    title: "Resource lifetime violation: {rule} ({function})",
                    impact: "{rule} at {file}:{line}, an allocation is still owned by the frame when the function returns - it is never released, returned, or stored where it outlives the call, so the memory can never be reclaimed.",
                    improvement: "Release the allocation on every path out of `{function}`, hand ownership back by returning or storing it, or make the callee that receives the pointer responsible for it.",
                    tag: "resource-lifetime",
                },
            },
        ];
        REGISTRY
    }
}

// ── Module surface ────────────────────────────────────────────────────────────

/// Every file-scope declaration, with its linkage.
///
/// C has no `export`: a definition at file scope is visible to the linker
/// unless it is `static`, and `static` is the only way a translation unit
/// keeps a symbol to itself. Namespace and linkage-spec bodies (C++) and
/// template declarations are descended into; class members are not, since
/// their access is a per-member question this layer does not model.
fn c_module_items(root: Node<'_>, source: &str) -> Vec<ModuleItem> {
    let mut items = Vec::new();
    collect_c_items(root, source, &mut items);
    items
}

fn collect_c_items(node: Node<'_>, source: &str, out: &mut Vec<ModuleItem>) {
    for i in 0..node.named_child_count() {
        let Some(child) = node.named_child(i) else {
            continue;
        };
        match child.kind() {
            "function_definition" => {
                let visibility = c_visibility(child, source);
                if let Some(name) =
                    c_declarator_name(child.child_by_field_name("declarator"), source)
                {
                    out.push(ModuleItem {
                        name,
                        kind: ItemKind::Function,
                        visibility,
                    });
                }
            }
            "declaration" => {
                let visibility = c_visibility(child, source);
                for j in 0..child.named_child_count() {
                    let Some(decl) = child.named_child(j) else {
                        continue;
                    };
                    let Some(name) = c_declarator_name(Some(decl), source) else {
                        continue;
                    };
                    let kind = if c_is_function_declarator(decl) {
                        ItemKind::Function
                    } else if decl.kind() == "type_identifier" {
                        continue;
                    } else {
                        ItemKind::Variable
                    };
                    out.push(ModuleItem {
                        name,
                        kind,
                        visibility,
                    });
                }
            }
            "type_definition" => {
                for j in 0..child.named_child_count() {
                    let Some(decl) = child.named_child(j) else {
                        continue;
                    };
                    if let Some(name) = c_declarator_name(Some(decl), source) {
                        out.push(ModuleItem {
                            name,
                            kind: ItemKind::Type,
                            visibility: c_visibility(child, source),
                        });
                    }
                }
            }
            "struct_specifier" | "union_specifier" | "class_specifier" => {
                if child.child_by_field_name("body").is_none() {
                    continue;
                }
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                out.push(ModuleItem {
                    name: node_text(name, source).to_owned(),
                    kind: ItemKind::Struct,
                    visibility: c_visibility(child, source),
                });
            }
            "enum_specifier" => {
                if child.child_by_field_name("body").is_none() {
                    continue;
                }
                let Some(name) = child.child_by_field_name("name") else {
                    continue;
                };
                out.push(ModuleItem {
                    name: node_text(name, source).to_owned(),
                    kind: ItemKind::Enum,
                    visibility: c_visibility(child, source),
                });
            }
            "namespace_definition" | "linkage_specification" => {
                if let Some(body) = child.child_by_field_name("body") {
                    collect_c_items(body, source, out);
                }
            }
            "template_declaration" => {
                for j in 0..child.named_child_count() {
                    if let Some(inner) = child.named_child(j) {
                        collect_c_items(inner, source, out);
                    }
                }
            }
            _ => {}
        }
    }
}

/// `static` at file scope is the only non-exporting storage class.
fn c_visibility(node: Node<'_>, source: &str) -> Visibility {
    if c_contains_static(node, source) {
        Visibility::Private
    } else {
        Visibility::Public
    }
}

fn c_contains_static(node: Node<'_>, source: &str) -> bool {
    if node.kind() == "storage_class_specifier" && node_text(node, source) == "static" {
        return true;
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            if c_contains_static(child, source) {
                return true;
            }
        }
    }
    false
}

/// The declared name behind C's nesting declarators
/// (`*p`, `f(int)`, `a[10]`, `x = 1`, `Ns::name`).
fn c_declarator_name(node: Option<Node<'_>>, source: &str) -> Option<String> {
    let node = node?;
    match node.kind() {
        "identifier" | "field_identifier" | "type_identifier" => {
            Some(node_text(node, source).to_owned())
        }
        "qualified_identifier" => node
            .child_by_field_name("name")
            .map(|n| node_text(n, source).to_owned()),
        "function_declarator"
        | "pointer_declarator"
        | "array_declarator"
        | "init_declarator"
        | "parenthesized_declarator" => {
            c_declarator_name(node.child_by_field_name("declarator"), source)
        }
        _ => None,
    }
}

fn c_is_function_declarator(node: Node<'_>) -> bool {
    match node.kind() {
        "function_declarator" => true,
        "pointer_declarator" | "init_declarator" | "parenthesized_declarator" => node
            .child_by_field_name("declarator")
            .is_some_and(c_is_function_declarator),
        _ => false,
    }
}
