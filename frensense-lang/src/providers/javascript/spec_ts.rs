// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! TypeScript [`LanguageSpec`](crate::spec::LanguageSpec) implementation.

use tree_sitter::Node;

use crate::spec::{
    Import, LanguageSpec, NodeRole, PackageCategory, PropagatorRule, SanitizerKind, TaintOrigin,
};

use super::{
    ast::{
        classify_js, is_js_cast, is_js_destructuring_pattern, is_js_pair_entry, is_js_pair_pattern,
        is_js_template_literal_fragment, is_js_template_string, is_js_ternary_straight_line,
    },
    imports::extract_js_imports,
    packages::js_package_category,
    params::classify_js_param,
    propagators::JS_PROPAGATORS,
    sanitizers::{js_classify_sanitizer, JS_SANITIZER_NAMES},
    tables::{JS_IDOR_SINKS, JS_SINK_NAMES, JS_SINK_SIGNATURES, JS_SOURCE_PATTERNS},
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

    fn wrap_region(&self, code: &str) -> String {
        format!("function _region(): void {{\n{}\n}}", code)
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

    fn request_param_names(&self) -> &'static [&'static str] {
        // NOTE: deliberately excludes framework app objects (`app`, `server`,
        // `io`) and function handles (`handler`, `fn`), these are never user
        // input, and treating them as sources made every Express route
        // registration (`app.post(path, mw...)`) a phantom source→sink flow.
        &[
            "req", "request", "ctx", "context", "event", "c", "e", "r", "input", "args", "parent",
            "info",
        ]
    }

    fn known_sink_names(&self) -> &'static [(&'static str, crate::spec::SinkLabel)] {
        JS_SINK_NAMES
    }

    fn known_sink_signatures(&self) -> &'static [(&'static str, &'static [usize], bool)] {
        JS_SINK_SIGNATURES
    }

    fn known_idor_sinks(&self) -> &'static [(&'static str, &'static [&'static str])] {
        JS_IDOR_SINKS
    }

    fn known_source_patterns(&self) -> &'static [&'static str] {
        JS_SOURCE_PATTERNS
    }

    fn propagator_rules(&self) -> &'static [PropagatorRule] {
        JS_PROPAGATORS
    }

    fn classify_sanitizer(&self, call: &str) -> Option<SanitizerKind> {
        js_classify_sanitizer(call)
    }

    fn known_sanitizer_names(&self) -> &'static [&'static str] {
        JS_SANITIZER_NAMES
    }

    fn route_context_hints(&self) -> &'static [&'static str] {
        &[
            "(req, res)",
            "app.get(",
            "router.get(",
            "app.post(",
            "router.post(",
            "res.send",
            "res.json",
            "res.status",
            "c.req",
            "c.json",
            "ctx.body",
            "ctx.response",
            "fastify.get(",
            "fastify.post(",
            "export async function GET(",
            "export async function POST(",
            "export async function PUT(",
            "export async function DELETE(",
            "export async function PATCH(",
            "export default function handler(",
            "publicProcedure.input(",
            "protectedProcedure.input(",
            "t.procedure",
            "Query: {",
            "Mutation: {",
            "Subscription: {",
            "resolve(",
            "export async function loader(",
            "export async function action(",
            "export async function load(",
            "export const GET = ",
            "export const POST = ",
            "io.on('connection'",
            "socket.on(",
            "Bun.serve(",
            "Deno.serve(",
            "Deno.serve({ handler",
        ]
    }

    fn test_context_hints(&self) -> &'static [&'static str] {
        &[
            "describe(",
            " it(",
            "test(",
            "expect(",
            "jest.",
            "vitest.",
            "chai.",
            "assert.",
        ]
    }

    fn response_method_names(&self) -> &'static [&'static str] {
        &[
            "json",
            "send",
            "redirect",
            "status",
            "render",
            "end",
            "write",
            "setHeader",
            "cookie",
            "clearCookie",
            "type",
            "format",
            "attachment",
        ]
    }

    fn db_api_method_names(&self) -> &'static [&'static str] {
        &[
            "query",
            "execute",
            "prepare",
            "raw",
            "find",
            "findOne",
            "findMany",
            "insert",
            "update",
            "delete",
            "create",
            "save",
            "select",
            "from",
            "where",
            "join",
            "aggregate",
            "count",
            "transaction",
            "commit",
            "rollback",
            "upsert",
        ]
    }

    fn shell_api_method_names(&self) -> &'static [&'static str] {
        &[
            "exec",
            "spawn",
            "execFile",
            "execSync",
            "spawnSync",
            "system",
        ]
    }

    fn route_registration_patterns(&self) -> &'static [&'static str] {
        &[
            "app.get(",
            "app.post(",
            "app.put(",
            "app.delete(",
            "app.patch(",
            "router.get(",
            "router.post(",
            "fastify.get(",
            "hono.get(",
        ]
    }
}
