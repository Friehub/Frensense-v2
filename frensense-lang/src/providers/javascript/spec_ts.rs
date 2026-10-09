// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! TypeScript [`LanguageSpec`](crate::spec::LanguageSpec) implementation.

use tree_sitter::Node;

use crate::spec::{Export, Import, LanguageSpec, NodeRole, PackageCategory, TaintOrigin};

use super::{
    ast::{
        classify_js, is_js_cast, is_js_destructuring_pattern, is_js_pair_entry, is_js_pair_pattern,
        is_js_template_literal_fragment, is_js_template_string, is_js_ternary_straight_line,
    },
    imports::{extract_js_exports, extract_js_imports},
    packages::js_package_category,
    params::classify_js_param,
};

// ── TypeScript spec ───────────────────────────────────────────────────────────

pub struct TypeScriptSpec;

impl LanguageSpec for TypeScriptSpec {
    fn name(&self) -> &'static str {
        "typescript"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["ts", "tsx", "mts", "cts"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "typescript")]
        return tree_sitter_typescript::LANGUAGE_TSX.into();
        #[cfg(not(feature = "typescript"))]
        panic!("frensense-lang: 'typescript' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_js(kind)
    }

    fn is_cast(&self, kind: &str) -> bool {
        is_js_cast(kind)
    }

    fn is_template_string(&self, kind: &str) -> bool {
        is_js_template_string(kind)
    }

    fn is_template_literal_fragment(&self, kind: &str) -> bool {
        is_js_template_literal_fragment(kind)
    }

    fn is_destructuring_pattern(&self, kind: &str) -> bool {
        is_js_destructuring_pattern(kind)
    }

    fn is_pair_pattern(&self, kind: &str) -> bool {
        is_js_pair_pattern(kind)
    }

    fn is_pair_entry(&self, kind: &str) -> bool {
        is_js_pair_entry(kind)
    }

    fn is_ternary_straight_line(&self, kind: &str) -> bool {
        is_js_ternary_straight_line(kind)
    }

    fn implicit_return_node<'a>(&self, fn_node: Node<'a>, body: Node<'a>) -> Option<Node<'a>> {
        if fn_node.kind() == "arrow_function" && body.kind() != "statement_block" {
            Some(body)
        } else {
            None
        }
    }

    fn wrap_region(&self, code: &str) -> String {
        format!("function _region(): void {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["import_statement"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_js_imports(root, source)
    }

    fn extract_exports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Export> {
        extract_js_exports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(
            r#"
            (function_declaration name: (identifier) @name)
            (method_definition name: (property_identifier) @name)
            (class_declaration name: (type_identifier) @name)
            (interface_declaration name: (type_identifier) @name)
            (variable_declarator name: (identifier) @name)
            (call_expression arguments: (arguments (arrow_function) @name))
            (call_expression arguments: (arguments (function_expression) @name))
        "#,
        )
    }

    fn call_query(&self) -> Option<&'static str> {
        Some(
            r#"
            (function_declaration name: (identifier) @caller
                body: (statement_block
                    (expression_statement
                        (call_expression function: (identifier) @call))))
            (function_declaration name: (identifier) @caller
                body: (statement_block
                    (expression_statement
                        (call_expression
                            function: (member_expression
                                property: (property_identifier) @call)))))
            (method_definition name: (property_identifier) @caller
                body: (statement_block
                    (expression_statement
                        (call_expression function: (identifier) @call))))
        "#,
        )
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        js_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        classify_js_param(name, type_annotation)
    }

    fn is_http_route_decorator(&self, decorator_name: &str) -> bool {
        matches!(
            decorator_name,
            "Get"
                | "Post"
                | "Put"
                | "Delete"
                | "Patch"
                | "All"
                | "Controller"
                | "Route"
                | "HttpGet"
                | "HttpPost"
                | "UseGuards"
                | "UseInterceptors"
        )
    }
}
