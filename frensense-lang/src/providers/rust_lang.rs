// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//! Rust [`LanguageSpec`] implementation.

use tree_sitter::Node;

use crate::spec::{Import, LanguageSpec, NodeRole, PackageCategory, TaintOrigin};

// ── AST classification ────────────────────────────────────────────────────────

fn classify_rust(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        // All function kinds in Rust use `function_item` regardless of whether
        // they appear at top level or inside an `impl` block.
        "function_item" => NodeRole::Function {
            is_method: false, // impl context determined by parent
            name_field: Some("name".into()),
            params_field: "parameters".into(),
            body_field: "body".into(),
        },
        "closure_expression" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters".into(),
            body_field: "body".into(),
        },

        // ── Declarations / assignments ───────────────────────────────────
        "let_declaration" => NodeRole::Declaration {
            name_field: "pattern".into(),
            value_field: "value".into(),
        },
        "assignment_expression" => NodeRole::Assignment {
            lhs_field: "left".into(),
            rhs_field: "right".into(),
        },
        "compound_assignment_expr" => NodeRole::Assignment {
            lhs_field: "left".into(),
            rhs_field: "right".into(),
        },

        // ── Calls ────────────────────────────────────────────────────────
        "call_expression" => NodeRole::Call {
            callee_field: "function".into(),
            args_field: "arguments".into(),
        },
        "method_call_expression" => NodeRole::Call {
            callee_field: "method".into(),
            args_field: "arguments".into(),
        },
        "macro_invocation" => NodeRole::Call {
            callee_field: "macro".into(),
            args_field: "token_tree".into(),
        },
        "field_expression" => NodeRole::MemberAccess {
            object_field: "value".into(),
            property_field: "field".into(),
        },

        // ── Control flow ─────────────────────────────────────────────────
        "if_expression" | "if_let_expression" | "match_expression" => NodeRole::Branch,
        "for_expression" | "while_expression" | "while_let_expression" | "loop_expression" => {
            NodeRole::Loop
        }
        "return_expression" => NodeRole::Return,
        "try_expression" => NodeRole::ErrorPropagation, // the `?` operator
        "await_expression" => NodeRole::Await,

        // ── Structural ───────────────────────────────────────────────────
        "block" => NodeRole::Block,
        "use_declaration" => NodeRole::Import,
        "identifier" | "scoped_identifier" | "type_identifier" | "field_identifier"
        | "primitive_type" => NodeRole::Identifier,
        "string_literal" | "raw_string_literal" | "integer_literal" | "float_literal"
        | "boolean_literal" => NodeRole::Literal,

        // ── Supplementary structural roles ───────────────────────────────
        "parameters"
        | "parameter"
        | "tuple_pattern"
        | "tuple_struct_pattern"
        | "struct_pattern"
        | "slice_pattern"
        | "identifier_pattern" => NodeRole::Parameters,
        "token_tree" | "token_tree_delimited" => NodeRole::Arguments,
        "struct_item" | "enum_item" | "trait_item" | "impl_item" | "type_item" | "union_item"
        | "trait_alias" | "type_alias" => NodeRole::ClassDef,
        "binary_expression" => NodeRole::BinaryOp,
        "unary_expression" | "reference_expression" => NodeRole::UnaryOp,
        "match_expression" => NodeRole::Match,
        "unsafe_block" => NodeRole::Unsafe,
        "async_block" => NodeRole::AsyncBlock,

        _ => NodeRole::Other,
    }
}

// ── Import extraction ─────────────────────────────────────────────────────────

fn extract_rust_imports(root: Node<'_>, source: &str) -> Vec<Import> {
    use crate::spec::node_text;

    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();

        if node.kind() == "use_declaration" {
            // `use axum::Router;`
            // `use axum::{Router, extract::Json};`
            // `use sqlx::PgPool as Pool;`
            let text = node_text(node, source)
                .trim_start_matches("use ")
                .trim_end_matches(';')
                .trim();
            flatten_rust_use(text, &mut imports);
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

/// Recursively expand `axum::{Router, extract::Json}` into flat imports.
fn flatten_rust_use(path: &str, out: &mut Vec<Import>) {
    let path = path.trim();
    if let Some(brace_start) = path.find('{') {
        let prefix = &path[..brace_start];
        let inner = path[brace_start + 1..].trim_end_matches('}');
        for segment in split_rust_use_list(inner) {
            let full = format!("{}{}", prefix, segment.trim());
            flatten_rust_use(&full, out);
        }
    } else if let Some((pkg, local)) = path.rsplit_once(" as ") {
        let pkg_base = pkg.split("::").next().unwrap_or(pkg);
        out.push(Import {
            local_name: local.trim().to_owned(),
            package: pkg_base.to_owned(),
            symbol: Some(pkg.trim().to_owned()),
        });
    } else {
        let pkg_base = path.split("::").next().unwrap_or(path);
        let local = path.rsplit("::").next().unwrap_or(path);
        out.push(Import {
            local_name: local.to_owned(),
            package: pkg_base.to_owned(),
            symbol: Some(path.to_owned()),
        });
    }
}

fn split_rust_use_list(inner: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (i, c) in inner.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            ',' if depth == 0 => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts
}

// ── Package catalogue ─────────────────────────────────────────────────────────

fn rust_package_category(pkg: &str) -> Option<PackageCategory> {
    match pkg {
        "axum" | "actix-web" | "actix_web" | "rocket" | "warp" | "tide" | "poem" | "salvo"
        | "ntex" | "viz" | "gotham" => Some(PackageCategory::HttpFramework),

        "sqlx" | "diesel" | "sea-orm" | "sea_orm" | "tokio-postgres" | "rusqlite" | "mysql"
        | "mysql_async" | "tiberius" | "quaint" => Some(PackageCategory::SqlDatabase),

        "mongodb" | "redis" | "elasticsearch" | "cassandra-cpp" => {
            Some(PackageCategory::NoSqlDatabase)
        }

        "tokio" => None, // runtime - tokio::process is a sink but tokio itself is not
        "std" => None,   // std::process::Command is generator vocabulary, not a package

        "reqwest" | "hyper" | "ureq" | "surf" | "isahc" | "attohttpc" => {
            Some(PackageCategory::HttpClient)
        }

        "tera" | "handlebars" | "askama" | "minijinja" | "liquid" => {
            Some(PackageCategory::TemplateEngine)
        }

        "serde_pickle" | "bincode" | "rmp-serde" | "ciborium" | "postcard" => {
            Some(PackageCategory::Deserialization)
        }

        "ring" | "rustls" | "openssl" | "aes" | "sha2" | "hmac" | "rand" => {
            Some(PackageCategory::Crypto)
        }

        "tokio-test" | "mockall" | "proptest" | "rstest" => Some(PackageCategory::Testing),

        _ => None,
    }
}

// ── Param taint ───────────────────────────────────────────────────────────────

fn rust_classify_param(_name: Option<&str>, ann: Option<&str>) -> Option<TaintOrigin> {
    let a = ann?.split('<').next().unwrap_or(ann?).trim();
    // Strip leading reference / mut
    let a = a.trim_start_matches('&').trim_start_matches("mut").trim();
    match a {
        // Axum extractors
        "Json" | "Form" | "Query" | "Path" | "Bytes" | "Multipart" | "TypedHeader"
        | "Extension" | "RawBody" | "RawQuery" | "RawPath" => Some(TaintOrigin::UserInput),
        // Actix-web extractors
        "web::Json" | "web::Form" | "web::Query" | "web::Path" | "web::Bytes" | "web::Payload"
        | "HttpRequest" => Some(TaintOrigin::UserInput),
        // Rocket
        "&RocketRequest" | "Form" | "Json" | "Data" => Some(TaintOrigin::UserInput),
        _ => None,
    }
}

const RUST_SYMBOL_QUERY: &str = r#"
    (function_item name: (identifier) @name)
    (struct_item   name: (type_identifier) @name)
    (enum_item     name: (type_identifier) @name)
    (trait_item    name: (type_identifier) @name)
    (impl_item     type: (type_identifier) @name)
"#;

const RUST_CALL_QUERY: &str = r#"
    (function_item name: (identifier) @caller
        body: (block
            (expression_statement
                (call_expression function: (identifier) @call))))
    (function_item name: (identifier) @caller
        body: (block
            (expression_statement
                (method_call_expression method: (field_identifier) @call))))
    (function_item name: (identifier) @caller
        body: (block
            (expression_statement
                (macro_invocation macro: (identifier) @call))))
"#;

// ── RustSpec ──────────────────────────────────────────────────────────────────

pub struct RustSpec;

impl LanguageSpec for RustSpec {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["rs"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "rust-grammar")]
        return tree_sitter_rust::LANGUAGE.into();
        #[cfg(not(feature = "rust-grammar"))]
        panic!("frensense-lang: 'rust-grammar' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_rust(kind)
    }

    fn is_cast(&self, kind: &str) -> bool {
        kind == "type_cast_expression"
    }

    // tree-sitter-rust: `field_expression` property children are
    // `field_identifier`, a named field, not a computed index.
    fn is_property_kind(&self, kind: &str) -> bool {
        kind == "field_identifier"
    }

    fn wrap_region(&self, code: &str) -> String {
        format!("fn _region() {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["use_declaration"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_rust_imports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(RUST_SYMBOL_QUERY)
    }
    fn call_query(&self) -> Option<&'static str> {
        Some(RUST_CALL_QUERY)
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        rust_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        rust_classify_param(name, type_annotation)
    }

    fn is_http_route_decorator(&self, name: &str) -> bool {
        // Rocket proc-macro attributes: `#[get("/")]`, `#[post("/")]`, etc.
        matches!(
            name,
            "get" | "post" | "put" | "delete" | "patch" | "options" | "head" | "route"
        )
    }
}
