// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! The node-kind vocabulary the lowering asks about.
//!
//! Each test pins one grammar's answers to exactly the spellings the engine
//! compares today, so the engine can drop its own copy without a behaviour
//! change: a predicate that answered `true` for a kind the engine never
//! matched would move findings, and one that answered `false` for a kind it
//! did match would lose them.
//!
//! A grammar must also not answer another grammar's question - the engine
//! reads `false`/`None` as "this language has no such node", so a leaked
//! answer makes a language-specific decision look language-independent.

use crate::registry::spec_for_ext;
use crate::spec::{JsxPart, JumpKind, LanguageSpec, LiteralShape};

fn spec(ext: &str) -> &'static dyn LanguageSpec {
    spec_for_ext(ext).expect("spec for extension")
}

#[test]
fn every_grammar_calls_a_comment_a_comment() {
    for ext in ["ts", "js", "vue", "py", "rs", "go", "c"] {
        let s = spec(ext);
        assert!(s.is_comment("comment"), "{ext}: comment");
        assert!(
            !s.is_comment("identifier"),
            "{ext}: an identifier is not a comment"
        );
    }
}

#[test]
fn javascript_family_answers_its_placement_questions() {
    let ts = spec("ts");

    assert!(ts.is_variable_declaration_statement("lexical_declaration"));
    assert!(ts.is_variable_declaration_statement("variable_declaration"));
    assert!(!ts.is_variable_declaration_statement("declaration"));
    assert!(ts.is_variable_declarator("variable_declarator"));
    assert!(!ts.is_variable_declarator("lexical_declaration"));

    // Only the anonymous spellings; a declaration carries its own name.
    assert!(ts.is_function_value("arrow_function"));
    assert!(ts.is_function_value("function_expression"));
    assert!(!ts.is_function_value("function_declaration"));
    assert!(!ts.is_function_value("method_definition"));

    assert!(ts.is_array_composite("array"));
    assert!(!ts.is_array_composite("object"));
    assert!(ts.is_array_pattern("array_pattern"));
    assert!(!ts.is_array_pattern("object_pattern"));

    // The statement form is the one the condition-chain lowering owns.
    assert!(ts.is_switch_statement("switch_statement"));
    assert!(!ts.is_switch_statement("switch_expression"));
    assert!(ts.is_case_clause("switch_case"));
    assert!(ts.is_case_clause("switch_default"));
    assert!(!ts.is_case_clause("case_statement"));

    assert_eq!(ts.jsx_part("jsx_element"), Some(JsxPart::Element));
    assert_eq!(
        ts.jsx_part("jsx_self_closing_element"),
        Some(JsxPart::SelfClosingElement)
    );
    assert_eq!(ts.jsx_part("jsx_fragment"), Some(JsxPart::Fragment));
    assert_eq!(
        ts.jsx_part("jsx_opening_element"),
        Some(JsxPart::OpeningElement)
    );
    assert_eq!(ts.jsx_part("jsx_children"), Some(JsxPart::Children));
    assert_eq!(ts.jsx_part("jsx_attribute"), Some(JsxPart::Attribute));
    assert_eq!(ts.jsx_part("jsx_text"), None);

    for value in [
        "jsx_expression",
        "string",
        "jsx_element",
        "jsx_self_closing_element",
        "jsx_fragment",
    ] {
        assert!(ts.is_jsx_attribute_value(value), "{value}");
    }
    assert!(!ts.is_jsx_attribute_value("jsx_text"));

    // The default jump table is the C-family vocabulary the CFG lowering has
    // always applied to every grammar, so the JavaScript family inherits all
    // four spellings rather than narrowing them (a narrow table here would
    // drop `break`/`continue` lowering for the grammars that share them).
    assert_eq!(ts.jump_kind("break_statement"), Some(JumpKind::Break));
    assert_eq!(ts.jump_kind("continue_statement"), Some(JumpKind::Continue));
    assert_eq!(ts.jump_kind("labeled_statement"), Some(JumpKind::Label));
    assert_eq!(ts.jump_kind("goto_statement"), Some(JumpKind::Goto));
    assert_eq!(ts.jump_kind("expression_statement"), None);
}

#[test]
fn c_answers_storage_preprocessor_switch_and_jumps() {
    let c = spec("c");

    assert!(c.is_storage_class_specifier("storage_class_specifier"));
    assert!(!c.is_storage_class_specifier("type_qualifier"));
    assert!(c.is_pointer_expression("pointer_expression"));
    assert!(!c.is_pointer_expression("unary_expression"));

    for kind in [
        "preproc_if",
        "preproc_ifdef",
        "preproc_elif",
        "preproc_elifdef",
        "preproc_else",
    ] {
        assert!(c.is_preproc_conditional(kind), "{kind}");
    }
    assert!(!c.is_preproc_conditional("preproc_include"));
    assert!(c.is_preproc_else("preproc_else"));
    assert!(!c.is_preproc_else("preproc_if"));

    assert!(c.is_switch_statement("switch_statement"));
    assert!(c.is_case_clause("case_statement"));
    assert!(!c.is_case_clause("switch_case"));

    assert_eq!(c.jump_kind("goto_statement"), Some(JumpKind::Goto));
    assert_eq!(c.jump_kind("labeled_statement"), Some(JumpKind::Label));
    assert_eq!(c.jump_kind("break_statement"), Some(JumpKind::Break));
    assert_eq!(c.jump_kind("continue_statement"), Some(JumpKind::Continue));
}

#[test]
fn python_answers_lambda_and_match() {
    let py = spec("py");

    assert!(py.is_function_value("lambda"));
    assert!(!py.is_function_value("function_definition"));
    assert!(py.is_match_statement("match_statement"));
    assert!(!py.is_match_statement("switch_statement"));
    assert!(py.is_match_guard("if_clause"));
    assert!(!py.is_match_guard("match_guard"));
    assert_eq!(py.jsx_part("jsx_element"), None);
}

#[test]
fn rust_answers_closure_and_guard() {
    let rs = spec("rs");

    assert!(rs.is_function_value("closure_expression"));
    assert!(!rs.is_function_value("function_item"));
    assert!(rs.is_match_guard("match_guard"));
    assert!(!rs.is_match_guard("if_clause"));
    assert!(!rs.is_switch_statement("switch_statement"));
}

#[test]
fn go_answers_func_literal() {
    let go = spec("go");

    assert!(go.is_function_value("func_literal"));
    assert!(!go.is_function_value("function_declaration"));
    assert!(!go.is_array_composite("array"));
    assert_eq!(go.jsx_part("jsx_element"), None);
}

/// The engine reads `false`/`None` as "this language has no such node", so a
/// grammar must not answer another grammar's question.
#[test]
fn vocabulary_does_not_leak_across_grammars() {
    assert!(!spec("py").is_preproc_conditional("preproc_if"));
    assert!(!spec("c").is_function_value("arrow_function"));
    assert!(!spec("go").is_match_statement("match_statement"));
    assert!(!spec("rs").is_storage_class_specifier("storage_class_specifier"));
    assert!(!spec("ts").is_storage_class_specifier("storage_class_specifier"));
}

/// The CFG builder discovers a loop/branch body by shape, because the grammars
/// disagree about which fields they expose. Each answer below is the one the
/// builder applies today, so moving the call sites cannot move a finding.
#[test]
fn shape_vocabulary_matches_the_lowering_heuristics() {
    for ext in ["ts", "py", "rs", "go", "c"] {
        let s = spec(ext);

        // A statement, a block or a `*_body` node can own a body.
        assert!(s.is_body_node("block"), "{ext}: block");
        assert!(s.is_body_node("statement_block"), "{ext}: statement_block");
        assert!(s.is_body_node("if_statement"), "{ext}: if_statement");
        assert!(s.is_body_node("function_body"), "{ext}: function_body");
        assert!(!s.is_body_node("identifier"), "{ext}: identifier");
        assert!(s.is_block_or_statement("compound_statement"), "{ext}");
        assert!(!s.is_block_or_statement("string"), "{ext}");

        // The condition is what is neither body nor declarator nor header clause.
        assert!(s.is_loop_condition_node("binary_expression"), "{ext}");
        assert!(!s.is_loop_condition_node("for_statement"), "{ext}");
        assert!(!s.is_loop_condition_node("variable_declarator"), "{ext}");
        assert!(!s.is_loop_condition_node("update_expression"), "{ext}");
        assert!(!s.is_branch_condition_node("variable_declaration"), "{ext}");
        assert!(
            !s.is_branch_condition_node("assignment_expression"),
            "{ext}"
        );
        assert!(s.is_branch_condition_node("call_expression"), "{ext}");

        // Go labels its jump targets `statement_identifier`; others do not.
        assert!(s.is_jump_target_name("statement_identifier"), "{ext}");
        assert!(s.is_jump_target_name("identifier"), "{ext}");
        assert!(!s.is_jump_target_name("field_identifier"), "{ext}");

        // Match-arm patterns: an alternative, Python's wrapper, the discard.
        assert!(s.is_match_pattern_node("case_pattern"), "{ext}");
        assert!(s.is_alternative_pattern("union_pattern"), "{ext}");
        assert!(s.is_pattern_wrapper("case_pattern"), "{ext}");
        assert!(s.is_discard_pattern("_"), "{ext}");
        assert!(!s.is_discard_pattern("wildcard_pattern"), "{ext}");
    }
}

#[test]
fn literal_shape_names_only_the_foldable_literals() {
    for ext in ["ts", "py", "rs", "go", "c"] {
        let s = spec(ext);
        assert_eq!(
            s.literal_shape("string"),
            Some(LiteralShape::String),
            "{ext}"
        );
        assert_eq!(
            s.literal_shape("concatenated_string"),
            Some(LiteralShape::String)
        );
        assert_eq!(s.literal_shape("integer"), Some(LiteralShape::Integer));
        assert_eq!(s.literal_shape("float"), Some(LiteralShape::Float));
        assert_eq!(s.literal_shape("true"), Some(LiteralShape::Boolean(true)));
        assert_eq!(s.literal_shape("false"), Some(LiteralShape::Boolean(false)));
        assert_eq!(s.literal_shape("none"), Some(LiteralShape::Null));
        assert_eq!(s.literal_shape("null"), Some(LiteralShape::Null));
        assert_eq!(s.literal_shape("identifier"), None);
        assert_eq!(s.literal_shape("call_expression"), None);
    }
}

#[test]
fn string_expression_covers_the_folding_union() {
    for ext in ["ts", "py", "rs", "go", "c"] {
        let s = spec(ext);
        for kind in ["string", "concatenated_string", "binary_expression"] {
            assert!(s.is_string_expression(kind), "{ext}: {kind}");
        }
        assert!(!s.is_string_expression("identifier"), "{ext}");
    }

    // A template string is the JavaScript family's spelling; the other
    // grammars answer through `is_template_string`, which defaults to false.
    assert!(spec("ts").is_string_expression("template_string"));
    assert!(!spec("c").is_string_expression("template_string"));
}
