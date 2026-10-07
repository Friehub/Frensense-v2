// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! JavaScript [`LanguageSpec`](crate::spec::LanguageSpec) implementation.

use tree_sitter::Node;

use crate::spec::{Import, LanguageSpec, NodeRole, PackageCategory, TaintOrigin};

use super::{
    ast::{
        classify_js, is_js_cast, is_js_destructuring_pattern, is_js_pair_entry, is_js_pair_pattern,
        is_js_template_literal_fragment, is_js_template_string, is_js_ternary_straight_line,
    },
    imports::extract_js_imports,
    packages::js_package_category,
    params::classify_js_param,
    spec_ts::TypeScriptSpec,
};

// ── JavaScript spec ────────────────────────────────────────────────────────────

pub struct JavaScriptSpec;

impl LanguageSpec for JavaScriptSpec {
    fn name(&self) -> &'static str {
        "javascript"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["js", "jsx", "mjs", "cjs"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "javascript")]
        return tree_sitter_javascript::LANGUAGE.into();
        #[cfg(not(feature = "javascript"))]
        panic!("frensense-lang: 'javascript' feature not enabled");
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

    fn wrap_region(&self, code: &str) -> String {
        format!("function _region() {{\n{}\n}}", code)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["import_statement"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_js_imports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(
            r#"
            (function_declaration name: (identifier) @name)
            (method_definition name: (property_identifier) @name)
            (class_declaration name: (identifier) @name)
            (variable_declarator name: (identifier) @name)
            (call_expression arguments: (arguments (arrow_function) @name))
            (call_expression arguments: (arguments (function_expression) @name))
        "#,
        )
    }
    fn call_query(&self) -> Option<&'static str> {
        TypeScriptSpec.call_query()
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
}
