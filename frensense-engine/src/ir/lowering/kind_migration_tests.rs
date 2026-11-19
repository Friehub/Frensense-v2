// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Differential tests for the node-kind vocabulary `frensense-lang` owns.
//!
//! Each `LanguageSpec` query below replaced a `node.kind() == "..."` comparison
//! in this crate. The test walks real parse trees and asserts the query answers
//! exactly what the removed comparison answered, so a mistyped override in a
//! provider fails here rather than as a silently missing finding.
//!
//! Every test also asserts the fixture produced the shapes it compared: an
//! equality that only ever saw `identifier` would pass while proving nothing.

use frensense_lang::{JsxPart, LanguageSpec, NodeRole, spec_for_ext};
use tree_sitter::Node;

fn parse(ext: &str, source: &str) -> (&'static dyn LanguageSpec, tree_sitter::Tree) {
    let spec = spec_for_ext(ext).expect("a spec for the extension");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&spec.tree_sitter_language())
        .expect("the grammar for the extension");
    let tree = parser.parse(source, None).expect("a parse tree");
    (spec, tree)
}

/// Visit every named node once, pre-order.
fn walk<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>)) {
    visit(node);
    let mut cursor = node.walk();
    let children: Vec<Node<'t>> = node.named_children(&mut cursor).collect();
    for child in children {
        walk(child, visit);
    }
}

fn named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

const TS_FIXTURE: &str = r#"
// a comment
const run = (a: string, ...rest: any[]) => a;
const value = function () { return [1, 2]; };
const props = { inner: () => 1 };
const [head] = value;
const text = `x${head}`;
switch (head) { case 1: break; default: break; }
"#;

#[test]
fn placement_vocabulary_answers_what_the_removed_comparisons_answered() {
    let (spec, tree) = parse("ts", TS_FIXTURE);
    let mut seen: Vec<&str> = Vec::new();

    walk(tree.root_node(), &mut |node| {
        let kind = node.kind();
        seen.push(kind);

        assert_eq!(
            spec.is_comment(kind),
            kind == "comment",
            "is_comment({kind})"
        );
        assert_eq!(
            spec.is_variable_declaration_statement(kind),
            matches!(kind, "lexical_declaration" | "variable_declaration"),
            "is_variable_declaration_statement({kind})"
        );
        assert_eq!(
            spec.is_variable_declarator(kind),
            kind == "variable_declarator",
            "is_variable_declarator({kind})"
        );
        assert_eq!(
            spec.is_function_value(kind),
            matches!(kind, "arrow_function" | "function_expression"),
            "is_function_value({kind})"
        );
        assert_eq!(
            spec.is_array_composite(kind),
            kind == "array",
            "is_array_composite({kind})"
        );
        assert_eq!(
            spec.is_array_pattern(kind),
            kind == "array_pattern",
            "is_array_pattern({kind})"
        );
        assert_eq!(
            spec.is_string_expression(kind),
            spec.is_template_string(kind)
                || matches!(kind, "string" | "binary_expression" | "concatenated_string"),
            "is_string_expression({kind})"
        );
    });

    for required in [
        "comment",
        "lexical_declaration",
        "variable_declarator",
        "arrow_function",
        "function_expression",
        "array",
        "array_pattern",
        "switch_case",
        "switch_default",
    ] {
        assert!(
            seen.contains(&required),
            "fixture never produced `{required}`, so the equivalence is vacuous"
        );
    }
}

/// A switch clause the lowering cannot recognize is skipped silently, so every
/// named child of a switch body must answer `is_case_clause`.
#[test]
fn every_switch_clause_is_recognized() {
    let fixtures = [
        (
            "c",
            "void f(int x) { switch (x) { case 1: break; default: break; } }",
        ),
        (
            "ts",
            "function f(x: number) { switch (x) { case 1: break; default: break; } }",
        ),
    ];

    for (ext, source) in fixtures {
        let (spec, tree) = parse(ext, source);
        let mut switches = 0;

        walk(tree.root_node(), &mut |node| {
            if !spec.is_switch_statement(node.kind()) {
                return;
            }
            switches += 1;
            let body = node
                .child_by_field_name("body")
                .or_else(|| {
                    named_children(node)
                        .into_iter()
                        .find(|child| spec.is_body_node(child.kind()))
                })
                .expect("a switch body");

            let clauses = named_children(body);
            assert_eq!(clauses.len(), 2, "{ext}: one case and one default");
            for clause in clauses {
                assert!(
                    spec.is_case_clause(clause.kind()),
                    "{ext}: `{}` is a clause the lowering would skip",
                    clause.kind()
                );
            }
        });

        assert!(switches > 0, "{ext}: fixture produced no switch");
    }
}

/// The CFG builder finds a loop's body and condition by shape, not by field.
/// These are the exact heuristics the queries replaced; both must pick the
/// same child on real trees.
#[test]
fn loop_body_and_condition_selection_is_unchanged() {
    let fixtures = [
        (
            "ts",
            "function f(xs: any[], c: boolean) { for (const x of xs) { use(x); } while (c) { break; } }",
        ),
        (
            "py",
            "def f(xs, c):\n  for x in xs:\n    use(x)\n  while c:\n    break\n",
        ),
        (
            "go",
            "package main\nfunc f(xs []int, c bool) { for _, x := range xs { use(x) }; for c { break } }",
        ),
        (
            "rs",
            "fn f(xs: Vec<i32>, c: bool) { for x in xs { use(x); } while c { break; } }",
        ),
        (
            "c",
            "void f(int n, int c) { for (int i = 0; i < n; i++) { use(i); } while (c) { break; } }",
        ),
    ];

    for (ext, source) in fixtures {
        let (spec, tree) = parse(ext, source);
        let mut loops = 0;

        walk(tree.root_node(), &mut |node| {
            if !matches!(spec.classify(node.kind()), NodeRole::Loop) {
                return;
            }
            loops += 1;
            let mut cursor = node.walk();
            let children: Vec<Node> = node
                .children(&mut cursor)
                .filter(|c| c.is_named())
                .collect();

            let old_body = children.iter().rev().copied().find(|child| {
                let kind = child.kind();
                kind.contains("statement") || kind == "block" || kind.contains("block")
            });
            let new_body = children
                .iter()
                .rev()
                .copied()
                .find(|child| spec.is_body_node(child.kind()));
            assert_eq!(
                old_body.map(|n| n.id()),
                new_body.map(|n| n.id()),
                "{ext}: loop body moved"
            );

            let old_condition = children.iter().copied().find(|child| {
                let kind = child.kind();
                !kind.contains("statement")
                    && kind != "block"
                    && !kind.contains("block")
                    && !kind.contains("declarator")
                    && !kind.contains("update")
                    && !kind.contains("initializer")
            });
            let new_condition = children
                .iter()
                .copied()
                .find(|child| spec.is_loop_condition_node(child.kind()));
            assert_eq!(
                old_condition.map(|n| n.id()),
                new_condition.map(|n| n.id()),
                "{ext}: loop condition moved"
            );
        });

        assert!(loops > 0, "{ext}: fixture produced no loop");
    }
}

/// JSX props are lowered as field stores; a missed attribute is a missed
/// `dangerouslySetInnerHTML`, so every attribute's value must be recognized.
#[test]
fn jsx_attributes_and_their_values_are_recognized() {
    let (spec, tree) = parse(
        "tsx",
        r#"const el = <div className="x" onClick={() => 1}>hi</div>;"#,
    );
    let mut elements = 0;
    let mut attributes = 0;

    walk(tree.root_node(), &mut |node| {
        match spec.jsx_part(node.kind()) {
            Some(JsxPart::Element) => elements += 1,
            Some(JsxPart::Attribute) => {
                attributes += 1;
                for part in named_children(node) {
                    if spec.classify(part.kind()) == NodeRole::Identifier {
                        continue; // the attribute's name
                    }
                    assert!(
                        spec.is_jsx_attribute_value(part.kind()),
                        "attribute value `{}` not recognized",
                        part.kind()
                    );
                }
            }
            _ => {}
        }
    });

    assert_eq!(elements, 1, "one JSX element");
    assert_eq!(attributes, 2, "className and onClick");
}
