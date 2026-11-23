// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Per-grammar parameter shapes: which node of a parameter node is the binding.
//!
//! Called through [`LanguageSpec::param_bindings`](crate::spec::LanguageSpec::param_bindings);
//! grammars wrap a parameter in different shapes (`required_parameter`,
//! `typed_parameter`, `parameter_declaration`, splat patterns), and the name
//! the body resolves is nested inside that wrapper.

use tree_sitter::Node;

/// The binding identifiers of one parameter node, in declaration order.
pub(crate) fn param_bindings<'t>(p: Node<'t>) -> Vec<Node<'t>> {
    match p.kind() {
        "required_parameter" | "optional_parameter" | "parameter" | "variadic_parameter" => {
            param_binding(p).into_iter().collect()
        }
        "identifier" => vec![p],
        "parameter_declaration" | "variadic_parameter_declaration" => {
            if let Some(decl) = p.child_by_field_name("declarator") {
                return find_param_identifier(decl).into_iter().collect();
            }
            let mut cursor = p.walk();
            p.children_by_field_name("name", &mut cursor).collect()
        }
        "typed_parameter"
        | "default_parameter"
        | "typed_default_parameter"
        | "list_splat_pattern"
        | "dictionary_splat_pattern" => python_param_binding(p).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// The binding node of a parameter: a plain identifier, or the INNER
/// identifier of a wrapper-shaped pattern (`Query(p)`, `{ body }`, `&mut x`).
fn param_binding<'t>(p: Node<'t>) -> Option<Node<'t>> {
    let pattern = p.child_by_field_name("pattern").or_else(|| p.child(0))?;
    // `...parts` wraps the name: the rest marker is not part of it. Binding
    // the parameter under the text `...parts` leaves the body's `parts` an
    // undeclared name, so a rest parameter's value never reaches its uses.
    if pattern.kind() == "rest_pattern" {
        return pattern.named_child(0);
    }
    Some(extractor_binding(pattern).unwrap_or(pattern))
}

/// The binding identifier of a Python parameter node.
///
/// Python wraps annotated and defaulted parameters: `typed_parameter` has no
/// `name` field (its first child is the binding), while
/// `default_parameter`/`typed_default_parameter` expose `name`. A splat
/// parameter (`*args`, `**kwargs`, with or without an annotation) wraps the
/// identifier in `list_splat_pattern`/`dictionary_splat_pattern`. Only an
/// identifier is a binding: a tuple pattern (`def f((a, b))`) has no single
/// name, and naming the parameter after the pattern text would bind a name the
/// body never references.
fn python_param_binding<'t>(p: Node<'t>) -> Option<Node<'t>> {
    let binding = p.child_by_field_name("name").or_else(|| match p.kind() {
        "list_splat_pattern" | "dictionary_splat_pattern" => p.named_child(0),
        _ => p.child(0),
    })?;
    match binding.kind() {
        "identifier" => Some(binding),
        "list_splat_pattern" | "dictionary_splat_pattern" => {
            let mut cursor = binding.walk();
            let splat = binding
                .named_children(&mut cursor)
                .find(|c| c.kind() == "identifier");
            splat
        }
        _ => None,
    }
}

/// `Query(p)` (and `State(db)`, `Json(body)`) is a *named* pattern: it has a
/// `type` field naming the wrapper plus one binding inside. The binding - not
/// the wrapper - is what the body references, so the parameter is named after
/// it. Any other pattern (plain identifier, a destructuring pattern with no
/// `type` field, `&mut x`) is left alone.
fn extractor_binding<'t>(pattern: Node<'t>) -> Option<Node<'t>> {
    let wrapper = pattern.child_by_field_name("type")?;
    let mut cursor = pattern.walk();
    let mut inner = pattern
        .named_children(&mut cursor)
        .filter(|c| c.id() != wrapper.id());
    let first = inner.next()?;
    if first.kind() != "identifier" || inner.next().is_some() {
        return None;
    }
    Some(first)
}

/// Walk a C declarator chain to find the leaf `identifier`.
/// Handles `pointer_declarator`, `array_declarator`, etc.
fn find_param_identifier<'t>(node: Node<'t>) -> Option<Node<'t>> {
    match node.kind() {
        "identifier" => Some(node),
        _ => node
            .child_by_field_name("declarator")
            .and_then(find_param_identifier),
    }
}
