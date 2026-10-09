// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Shared AST classification for JS/TS (single tree-sitter grammar).

use crate::spec::NodeRole;

// ── Shared AST logic ──────────────────────────────────────────────────────────

pub(super) fn classify_js(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        "function_declaration"
        | "function"
        | "async_function_declaration"
        | "generator_function_declaration" => NodeRole::Function {
            is_method: false,
            name_field: Some("name".into()),
            params_field: "parameters".into(),
            body_field: "body".into(),
        },
        "function_expression" | "async_function_expression" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters".into(),
            body_field: "body".into(),
        },
        "arrow_function" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters".into(),
            body_field: "body".into(),
        },
        "method_definition" => NodeRole::Function {
            is_method: true,
            name_field: Some("name".into()),
            params_field: "parameters".into(),
            body_field: "body".into(),
        },

        // ── Declarations / assignments ───────────────────────────────────
        "variable_declarator" | "lexical_declarator" => NodeRole::Declaration {
            name_field: "name".into(),
            value_field: "value".into(),
        },
        "assignment_expression" => NodeRole::Assignment {
            lhs_field: "left".into(),
            rhs_field: "right".into(),
        },
        // `x += 1`, `x **= 2`, ... - JS uses a distinct node kind with the
        // compound operator; unmapped it was dropped (x never changed).
        "augmented_assignment_expression" => NodeRole::Assignment {
            lhs_field: "left".into(),
            rhs_field: "right".into(),
        },

        // ── Calls ────────────────────────────────────────────────────────
        "call_expression" => NodeRole::Call {
            callee_field: "function".into(),
            args_field: "arguments".into(),
        },
        // tree-sitter-javascript names the callee of `new X(...)` field
        // "constructor", not "function", sharing the call_expression arm
        // made every `new X(...)` expression lower to nothing.
        "new_expression" => NodeRole::Call {
            callee_field: "constructor".into(),
            args_field: "arguments".into(),
        },
        "member_expression" => NodeRole::MemberAccess {
            object_field: "object".into(),
            property_field: "property".into(),
        },
        "subscript_expression" => NodeRole::MemberAccess {
            object_field: "object".into(),
            property_field: "index".into(),
        },

        // ── Control flow ─────────────────────────────────────────────────
        "if_statement" | "switch_statement" => NodeRole::Branch,
        "ternary_expression" => NodeRole::Conditional,
        "for_statement" | "for_in_statement" | "for_of_statement" | "while_statement"
        | "do_statement" => NodeRole::Loop,
        "return_statement" => NodeRole::Return,
        "try_statement" => NodeRole::Try,
        "catch_clause" => NodeRole::Catch,
        "finally_clause" => NodeRole::Finally,
        "throw_statement" => NodeRole::Throw,
        "await_expression" => NodeRole::Await,

        // ── Structural ───────────────────────────────────────────────────
        "statement_block" => NodeRole::Block,
        // Value-context object/array literals: `{ key: val }`, `[a, b]`, and
        // spread payloads. NOT statement blocks, all children are
        // value-producers, and taint in any child taints the whole composite.
        "object" | "array" | "parenthesized_expression" => NodeRole::Composite,
        "import_statement" => NodeRole::Import,
        "export_statement" => NodeRole::Export,
        "identifier" | "property_identifier" | "shorthand_property_identifier" => {
            NodeRole::Identifier
        }
        "string" | "template_string" | "number" | "true" | "false" | "null" | "undefined"
        | "regex" => NodeRole::Literal,

        // ── Supplementary structural roles ───────────────────────────────
        "formal_parameters" | "parameters" => NodeRole::Parameters,
        "arguments" => NodeRole::Arguments,
        "class_declaration" | "interface_declaration" | "enum_declaration" => NodeRole::ClassDef,
        "binary_expression" => NodeRole::BinaryOp,
        "unary_expression" | "update_expression" => NodeRole::UnaryOp,
        "switch_expression" => NodeRole::Match,

        _ => NodeRole::Other,
    }
}

pub(super) fn is_js_cast(kind: &str) -> bool {
    matches!(kind, "as_expression" | "cast_expression" | "type_assertion")
}

pub(super) fn is_js_template_string(kind: &str) -> bool {
    matches!(kind, "template_string" | "string" | "binary_expression")
}

pub(super) fn is_js_template_literal_fragment(kind: &str) -> bool {
    kind == "string_fragment"
}

pub(super) fn is_js_destructuring_pattern(kind: &str) -> bool {
    matches!(kind, "object_pattern" | "array_pattern")
}

pub(super) fn is_js_pair_pattern(kind: &str) -> bool {
    kind == "pair_pattern"
}

pub(super) fn is_js_pair_entry(kind: &str) -> bool {
    kind == "pair"
}

pub(super) fn is_js_ternary_straight_line(kind: &str) -> bool {
    matches!(
        kind,
        "ternary_expression" | "conditional_expression" | "conditional_type"
    )
}
