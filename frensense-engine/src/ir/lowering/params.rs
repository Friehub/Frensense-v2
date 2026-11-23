// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Binding a function's parameters into the lowered IR.
//!
//! The parameter list is the slot a call's arguments are passed into, so each
//! formal parameter becomes an IR variable of the function. A method's
//! receiver comes first: it is that same slot, filled by the call's receiver
//! rather than by a written argument.

use frensense_lang::spec::LanguageSpec;
use tree_sitter::Node;

use super::LoweringContext;
use crate::ir::function::{VarId, VarMetadata};

/// Bind the receiver a grammar leaves implicit (`this` in a JS/TS method).
///
/// The variable is entered into the function's scope under the keyword the
/// source writes, so `this.h` resolves to the same receiver the call site
/// passes.
pub(crate) fn bind_implicit_receiver(ctx: &mut LoweringContext, fn_node: Node, name: &'static str) {
    let span = fn_node
        .child_by_field_name("name")
        .map_or((fn_node.start_byte(), fn_node.start_byte()), |n| {
            (n.start_byte(), n.end_byte())
        });
    let v = ctx.ir.new_var(VarMetadata {
        source_name: Some(name.to_string()),
        type_name: None,
        byte_range: Some(span),
        is_memory_state: false,
        object_keys: Vec::new(),
        declared: true,
    });
    ctx.ir.parameters.push(v);
    bind_in_scope(ctx, name.to_string(), v);
}

/// Bind every parameter of `params`, in declaration order.
pub(crate) fn bind_params(
    ctx: &mut LoweringContext,
    spec: &dyn LanguageSpec,
    params: Node,
    source: &str,
) {
    let mut pc = params.walk();
    for p in params.children(&mut pc) {
        if spec.is_self_parameter(p.kind()) {
            let name = "self".to_string();
            let v = ctx.ir.new_var(VarMetadata {
                source_name: Some(name.clone()),
                type_name: None,
                byte_range: Some((p.start_byte(), p.end_byte())),
                is_memory_state: false,
                object_keys: Vec::new(),
                declared: true,
            });
            ctx.ir.parameters.push(v);
            bind_in_scope(ctx, name, v);
            continue;
        }
        // Parameter TYPE annotation (`Query<P>`, `web::Query<P>`,
        // `*http.Request`), normalized to its path. Source vocabulary that
        // names a type (the axum/actix extractor family, Go's `*gin.Context`)
        // matches this: the parameter's type - not the author's variable name -
        // decides whether the argument is attacker-controlled. One Go
        // declaration shares its type across every grouped name.
        let type_name = p
            .child_by_field_name("type")
            .map(|t| normalize_type_path(&source[t.start_byte()..t.end_byte()]))
            .filter(|t| !t.is_empty());
        for binding in spec.param_bindings(p) {
            let name = source[binding.start_byte()..binding.end_byte()].to_string();
            let v = ctx.ir.new_var(VarMetadata {
                source_name: Some(name.clone()),
                type_name: type_name.clone(),
                byte_range: Some((p.start_byte(), p.end_byte())),
                is_memory_state: false,
                object_keys: Vec::new(),
                declared: true,
            });
            ctx.ir.parameters.push(v);
            // A destructured parameter (`function run({ h }: Opts)`) names no
            // variable of its own: the pattern's names read the parts of the
            // parameter value, exactly like `const { h } = opts` inside the
            // body. The slot still occupies the parameter position (so the
            // call's argument maps to it), but the pattern text is not a name
            // the body can resolve, so it is not entered into the scope.
            if ctx.is_destructuring_pattern(binding.kind()) {
                ctx.bind_pattern(binding, v);
                continue;
            }
            bind_in_scope(ctx, name, v);
        }
    }
}

/// Enter `v` into the innermost scope under the name the source writes.
fn bind_in_scope(ctx: &mut LoweringContext, name: String, v: VarId) {
    if let Some(scope) = ctx.env.last_mut() {
        scope.insert(name, v);
    }
}

/// Normalize a parameter type annotation to its path: strip references and
/// mutability (`&mut Foo`), keep the path before the generic arguments
/// (`web::Query<P>` → `web::Query`), drop whitespace.
fn normalize_type_path(raw: &str) -> String {
    // The borrow marker is PRESERVED: framework request extractors are
    // consumed by value (`Path<P>`, `web::Query<Q>`, `Json<B>`), while a
    // borrowed type is the language's own value (`&Path` is `std::path::Path`).
    // Dropping `&` made them indistinguishable, so every helper taking
    // `&Path` was treated as an axum extractor and became a taint source.
    let borrowed = raw.trim_start().starts_with('&');
    let t = raw.trim();
    let t = t.trim_start_matches('&').trim();
    // Lifetime parameter: `&'a Path` -> `Path`.
    let t = t
        .strip_prefix('\'')
        .map_or(t, |rest| match rest.find(char::is_whitespace) {
            Some(i) => rest[i..].trim(),
            None => rest,
        });
    let t = t.trim_start_matches("mut").trim();
    let t = t.split('<').next().unwrap_or(t);
    let path: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    if borrowed {
        let mut owned = String::with_capacity(path.len() + 1);
        owned.push('&');
        owned.push_str(&path);
        owned
    } else {
        path
    }
}
