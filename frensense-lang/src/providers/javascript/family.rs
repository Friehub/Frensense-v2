// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! One [`LanguageSpec`] implementation for the whole JavaScript family.
//!
//! JavaScript, TypeScript and a Vue SFC's script blocks are the *same*
//! language to this crate: one tree-sitter grammar (TS is a superset, and a
//! `.vue` script block is parsed with the TSX grammar after
//! [`VueSpec`](super::VueSpec)'s `preprocess` blanks the markup), the same
//! node classification, the same import/export extraction, the same package
//! and parameter knowledge.
//!
//! So the family is written **once**, here, and each member states only what
//! makes it itself — its [`JsDialect`]:
//!
//! ```ignore
//! impl JsFamily for JavaScriptSpec {
//!     const DIALECT: JsDialect = JsDialect::JavaScript;
//! }
//! ```
//!
//! [`JsFamily`] has a blanket [`LanguageSpec`] implementation, so a new
//! single-file container (Svelte, Astro) needs a [`JsDialect`] arm and a
//! `preprocess` override — not a fourth copy of the delegate ladder.
//!
//! Security vocabulary (sinks, sources, sanitizers) lives in
//! `frensense-packgen`; this file is mechanism only.

use std::borrow::Cow;

use tree_sitter::Node;

use crate::spec::{
    Export, Import, JsxPart, LanguageSpec, ModuleItem, NodeRole, PackageCategory, TaintOrigin,
};

use super::{
    ast::{
        classify_js, is_js_cast, is_js_destructuring_pattern, is_js_pair_entry, is_js_pair_pattern,
        is_js_template_literal_fragment, is_js_template_string, is_js_ternary_straight_line,
    },
    imports::{extract_js_exports, extract_js_imports, extract_js_module_items},
    packages::js_package_category,
    params::classify_js_param,
};

// ── Tree-sitter queries ───────────────────────────────────────────────────────

/// Definitions JavaScript's grammar spells with `identifier` names.
const JS_SYMBOL_QUERY: &str = r#"
            (function_declaration name: (identifier) @name)
            (method_definition name: (property_identifier) @name)
            (class_declaration name: (identifier) @name)
            (variable_declarator name: (identifier) @name)
            (call_expression arguments: (arguments (arrow_function) @name))
            (call_expression arguments: (arguments (function_expression) @name))
        "#;

/// As [`JS_SYMBOL_QUERY`], plus TypeScript's `type_identifier` names and
/// `interface_declaration`.
const TS_SYMBOL_QUERY: &str = r#"
            (function_declaration name: (identifier) @name)
            (method_definition name: (property_identifier) @name)
            (class_declaration name: (type_identifier) @name)
            (interface_declaration name: (type_identifier) @name)
            (variable_declarator name: (identifier) @name)
            (call_expression arguments: (arguments (arrow_function) @name))
            (call_expression arguments: (arguments (function_expression) @name))
        "#;

/// Call sites inside function bodies. Shared by every family member: the
/// capture names (`@caller`, `@call`) and their node kinds are identical in
/// the JavaScript and TypeScript grammars.
const CALL_QUERY: &str = r#"
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
        "#;

// ── Dialect: the only thing that differs ─────────────────────────────────────

/// Which member of the JavaScript family a spec is.
///
/// Every value here is a difference the grammar actually forces: the
/// extensions a file lands on, which tree-sitter grammar parses it, how the
/// language's names are spelled in its symbol query, and how a bare snippet
/// must be wrapped to re-parse as a function body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsDialect {
    /// Plain JavaScript, parsed by tree-sitter-javascript.
    JavaScript,
    /// TypeScript, parsed by the TSX grammar.
    TypeScript,
    /// A Vue SFC. Its script blocks are TypeScript, parsed by the TSX grammar
    /// after [`super::VueSpec`] blanks the markup in place.
    Vue,
}

impl JsDialect {
    /// Canonical short name used in fingerprints and the FRC bundle.
    fn name(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Vue => "vue",
        }
    }

    /// File extensions, lowercase and without the dot.
    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::JavaScript => &["js", "jsx", "mjs", "cjs"],
            Self::TypeScript => &["ts", "tsx", "mts", "cts"],
            Self::Vue => &["vue"],
        }
    }

    /// The grammar this dialect parses with.
    fn language(self) -> tree_sitter::Language {
        match self {
            Self::JavaScript => javascript_grammar(),
            Self::TypeScript | Self::Vue => typescript_grammar(),
        }
    }

    /// The `FactTable` / bundle section this dialect's knowledge lives in.
    ///
    /// A Vue script block *is* TypeScript, so its facts belong in the
    /// `typescript` section; a `vue` section is filled by nothing.
    fn fact_language(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Vue => "typescript",
        }
    }

    /// Symbol-definition query for this dialect's grammar.
    fn symbol_query(self) -> &'static str {
        match self {
            Self::JavaScript => JS_SYMBOL_QUERY,
            Self::TypeScript | Self::Vue => TS_SYMBOL_QUERY,
        }
    }

    /// Wrap a snippet so it re-parses as a function body in this dialect.
    fn wrap_region(self, code: &str) -> String {
        match self {
            Self::JavaScript => format!("function _region() {{\n{code}\n}}"),
            Self::TypeScript | Self::Vue => format!("function _region(): void {{\n{code}\n}}"),
        }
    }

    /// Is this decorator name an HTTP route decorator?
    ///
    /// NestJS's `@Get`-family decorators are TypeScript-only; plain
    /// JavaScript has no decorator route vocabulary here.
    fn http_route_decorator(self, decorator_name: &str) -> bool {
        match self {
            Self::JavaScript => false,
            Self::TypeScript | Self::Vue => matches!(
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
            ),
        }
    }
}

// ── The family contract ──────────────────────────────────────────────────────

/// A member of the JavaScript family.
///
/// Implement this instead of [`LanguageSpec`]: the whole grammar-facing
/// contract is provided by the blanket implementation below, and a member
/// only names its [`JsDialect`]. Override
/// [`preprocess_source`](Self::preprocess_source) when the file is a
/// container around script code (as Vue SFCs are).
pub trait JsFamily: Send + Sync + 'static {
    /// Which member of the family this spec is.
    const DIALECT: JsDialect;

    /// Rewrite the source before parsing. Defaults to the identity.
    ///
    /// Same contract as [`LanguageSpec::preprocess`]: the rewrite must
    /// preserve every byte offset so findings keep pointing at the original
    /// file.
    fn preprocess_source<'a>(&self, source: &'a str) -> Cow<'a, str> {
        Cow::Borrowed(source)
    }
}

// ── One implementation, every family member ──────────────────────────────────

impl<T: JsFamily> LanguageSpec for T {
    fn name(&self) -> &'static str {
        T::DIALECT.name()
    }

    fn extensions(&self) -> &'static [&'static str] {
        T::DIALECT.extensions()
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        T::DIALECT.language()
    }

    fn preprocess<'a>(&self, source: &'a str) -> Cow<'a, str> {
        self.preprocess_source(source)
    }

    fn fact_language(&self) -> &'static str {
        T::DIALECT.fact_language()
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

    fn is_variable_declaration_statement(&self, kind: &str) -> bool {
        matches!(kind, "lexical_declaration" | "variable_declaration")
    }

    fn is_variable_declarator(&self, kind: &str) -> bool {
        kind == "variable_declarator"
    }

    // The two anonymous function spellings the extraction walk binds to a
    // name. `function_declaration` / `method_definition` are excluded on
    // purpose: they carry their own name.
    fn is_function_value(&self, kind: &str) -> bool {
        matches!(kind, "arrow_function" | "function_expression")
    }

    fn is_array_composite(&self, kind: &str) -> bool {
        kind == "array"
    }

    fn is_object_composite(&self, kind: &str) -> bool {
        kind == "object"
    }

    fn is_array_pattern(&self, kind: &str) -> bool {
        kind == "array_pattern"
    }

    fn is_switch_statement(&self, kind: &str) -> bool {
        kind == "switch_statement"
    }

    fn is_case_clause(&self, kind: &str) -> bool {
        matches!(kind, "switch_case" | "switch_default")
    }

    fn jsx_part(&self, kind: &str) -> Option<JsxPart> {
        match kind {
            "jsx_element" => Some(JsxPart::Element),
            "jsx_self_closing_element" => Some(JsxPart::SelfClosingElement),
            "jsx_fragment" => Some(JsxPart::Fragment),
            "jsx_opening_element" => Some(JsxPart::OpeningElement),
            "jsx_children" => Some(JsxPart::Children),
            "jsx_attribute" => Some(JsxPart::Attribute),
            _ => None,
        }
    }

    fn is_jsx_attribute_value(&self, kind: &str) -> bool {
        matches!(
            kind,
            "jsx_expression"
                | "string"
                | "jsx_element"
                | "jsx_self_closing_element"
                | "jsx_fragment"
        )
    }

    fn implicit_return_node<'a>(&self, fn_node: Node<'a>, body: Node<'a>) -> Option<Node<'a>> {
        if fn_node.kind() == "arrow_function" && body.kind() != "statement_block" {
            Some(body)
        } else {
            None
        }
    }

    fn wrap_region(&self, code: &str) -> String {
        T::DIALECT.wrap_region(code)
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

    fn extract_module_items<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<ModuleItem> {
        extract_js_module_items(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(T::DIALECT.symbol_query())
    }

    fn call_query(&self) -> Option<&'static str> {
        Some(CALL_QUERY)
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
        T::DIALECT.http_route_decorator(decorator_name)
    }
}

// ── Feature-gated grammars ───────────────────────────────────────────────────

#[cfg(feature = "javascript")]
fn javascript_grammar() -> tree_sitter::Language {
    tree_sitter_javascript::LANGUAGE.into()
}

#[cfg(not(feature = "javascript"))]
fn javascript_grammar() -> tree_sitter::Language {
    panic!("frensense-lang: 'javascript' feature not enabled")
}

#[cfg(feature = "typescript")]
fn typescript_grammar() -> tree_sitter::Language {
    tree_sitter_typescript::LANGUAGE_TSX.into()
}

#[cfg(not(feature = "typescript"))]
fn typescript_grammar() -> tree_sitter::Language {
    panic!("frensense-lang: 'typescript' feature not enabled")
}
