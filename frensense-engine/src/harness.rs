// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Shared analysis harness: the ONE implementation of "source text → lowered,
//! SSA'd, interprocedurally-linked program graph" used by the scanner, the
//! e2e drivers, and the bundler's fact extractor.
//!
//! The bundler MUST lower corpus pairs through this same harness (not its own
//! walker) so that facts are extracted from exactly the IR the engine scans.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::taint::facts::FactTable;
use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use crate::ir::ssa::SSABuilder;

/// Lower a single source file into a set of SSA'd `FunctionIR`s keyed by
/// function name.
///
/// Handles the module shapes that matter for app code:
/// * `function_declaration` / `method_definition` bodies,
/// * arrow/function-expression handlers registered via
///   `app.get|post|put|delete|use|all(path, handler)`, the dominant
///   Express-style shape,
/// * nested arrows inside those handlers.
///
/// Handler names are synthetic and file-position-stable
/// (`<path:handler@byte>`), so bundles derived from the same file hash to the
/// same keys.
pub fn lower_source(
    path: &str,
    source: &str,
    ext: &str,
) -> Result<FxHashMap<String, FunctionIR>, String> {
    lower_source_with_facts(path, source, ext, None)
}

/// Lower a single source file into SSA'd `FunctionIR`s with optional bundle facts
/// that supply dynamic grammar classifications and features.
pub fn lower_source_with_facts(
    path: &str,
    source: &str,
    ext: &str,
    facts: Option<&FactTable>,
) -> Result<FxHashMap<String, FunctionIR>, String> {
    let spec = frensense_lang::spec_for_ext(ext)
        .ok_or_else(|| format!("no language spec for extension '{ext}'"))?;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&spec.tree_sitter_language())
        .map_err(|e| format!("parser init failed: {e}"))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| format!("parse failed for {path}"))?;

    let mut irs: FxHashMap<String, FunctionIR> = FxHashMap::default();
    // Spans of function values already lowered under their binding name
    // (lexical const / route registration). The generic walker must not
    // lower the same node again under a positional `<fn@N>` name: the twin
    // duplicates every finding and policy segment of the bound function.
    let mut bound_fns: FxHashSet<usize> = FxHashSet::default();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        // Language-driven function detection: JS/TS `function_declaration` /
        // `method_definition`, Python `function_definition` (+ async),
        // Rust `function_item`, Go `function_declaration` / `method_declaration`.
        if spec.is_function_node(node.kind()) {
            let name = function_name_of(node, source);
            // Skip only bindings whose lexical declaration or route
            // registration already lowered this node under its binding
            // name. EVERY other function - including nameless nested ones
            // - is extracted: with inlining gone, extraction is its only
            // home, and call sites resolve to it by name or by cross edge.
            let is_twin = name.is_none() && bound_fns.contains(&node.start_byte());
            if !is_twin {
                let name = name.unwrap_or_else(|| format!("<fn@{}>", node.start_byte()));
                let mut ir = lower_one(&name, node, source, spec, facts);
                ir.enclosing_fn = enclosing_extracted_name(node, source, path, spec, facts);
                insert_ir(&mut irs, ir, node.start_byte());
            }
        }
        // Top-level arrow functions bound to consts/lets, the dominant
        // shape for utility libraries (`export const hash = (d) => ...`).
        if node.kind() == "lexical_declaration" || node.kind() == "variable_declaration" {
            let mut dc = node.walk();
            for decl in node.named_children(&mut dc) {
                if decl.kind() != "variable_declarator" {
                    continue;
                }
                crate::dbg_trace!(
                    crate::debug_flags::DebugFlags::get().static_trace,
                    "[static] decl kind={} value={:?}",
                    decl.kind(),
                    decl.child_by_field_name("value").map(|v| v.kind())
                );
                let Some(value) = decl.child_by_field_name("value") else {
                    continue;
                };
                let name = decl
                    .child_by_field_name("name")
                    .map(|n| source[n.start_byte()..n.end_byte()].to_string())
                    .unwrap_or_else(|| format!("<fn@{}>", decl.start_byte()));
                if value.kind() == "arrow_function" || value.kind() == "function_expression" {
                    bound_fns.insert(value.start_byte());
                    let mut ir = lower_one(&name, value, source, spec, facts);
                    ir.enclosing_fn = enclosing_extracted_name(value, source, path, spec, facts);
                    insert_ir(&mut irs, ir, value.start_byte());
                } else if !inside_function(node, spec) {
                    // Top-level non-function static initializer: allowlist
                    // Sets, config objects, schema builders. Lowered as
                    // pseudo-IR so the checker layer can assert policy over
                    // them. A NESTED declaration is skipped: its value is
                    // already lowered as part of the enclosing function's
                    // body, and extracting it again created a phantom
                    // top-level function attributed to no source construct
                    // (`const r = runTool(cmd)` inside a handler fired
                    // policy twice, once for `r`, once for the handler).
                    let ir = lower_static(&name, value, source, spec, facts);
                    insert_ir(&mut irs, ir, value.start_byte());
                }
            }
        }
        // Route-registration handlers: `app.get("/", (req, res) => ...)`.
        if node.kind() == "call_expression"
            && let (Some(callee), Some(args)) = (
                node.child_by_field_name("function"),
                node.child_by_field_name("arguments"),
            )
        {
            let callee_text = &source[callee.start_byte()..callee.end_byte()];
            if is_route_registration(callee_text, spec, facts) {
                let mut ac = args.walk();
                let arg_nodes: Vec<_> = args.named_children(&mut ac).collect();
                for a in &arg_nodes {
                    if a.kind() == "arrow_function" || a.kind() == "function_expression" {
                        let name = format!("<{}:handler@{}>", path, a.start_byte());
                        bound_fns.insert(a.start_byte());
                        let mut ir = lower_one(&name, *a, source, spec, facts);
                        ir.enclosing_fn = enclosing_extracted_name(*a, source, path, spec, facts);
                        insert_ir(&mut irs, ir, a.start_byte());
                    }
                }
            }
        }
        // Named children only: the anonymous `function` keyword token is
        // classified as a Function node by the JS spec, and visiting it
        // spawned an empty `<fn@N>` pseudo-function for every declaration.
        let mut c = node.walk();
        let kids: Vec<_> = node.named_children(&mut c).collect();
        for k in kids.into_iter().rev() {
            stack.push(k);
        }
    }
    Ok(irs)
}

/// Insert an IR keyed by its name, disambiguating on collision with the
/// function node's byte offset. One file legitimately contains several
/// same-named functions (four `set` object setters, several `handler`s):
/// the old `entry().or_insert()` kept the first and silently erased every
/// later twin's body from all analysis (the Juice Shop `weakPassword`
/// miss). The kept name is the first one in walk order, so keys stay
/// content-deterministic.
fn insert_ir(irs: &mut FxHashMap<String, FunctionIR>, mut ir: FunctionIR, start: usize) {
    if irs.contains_key(&ir.name) {
        let base = ir.name.clone();
        let mut key = format!("{base}@{start}");
        let mut n = 0usize;
        while irs.contains_key(&key) {
            n += 1;
            key = format!("{base}@{start}#{n}");
        }
        ir.name = key;
    }
    irs.insert(ir.name.clone(), ir);
}

/// True when `node` sits inside any function body (a named ancestor
/// classifies as Function). Only used to skip NESTED non-function static
/// initializers: their value is lowered as part of the enclosing function.
fn inside_function(node: tree_sitter::Node, spec: &dyn frensense_lang::spec::LanguageSpec) -> bool {
    let mut cur = node.parent();
    while let Some(ancestor) = cur {
        if spec.is_function_node(ancestor.kind()) {
            return true;
        }
        cur = ancestor.parent();
    }
    false
}

/// The declaration-level name of a function node: the `name` field, or the
/// C-style declarator chain (`function_definition → declarator → ...`).
fn function_name_of(node: tree_sitter::Node, source: &str) -> Option<String> {
    node.child_by_field_name("name")
        .or_else(|| {
            let mut decl = node.child_by_field_name("declarator");
            while let Some(d) = decl {
                if d.kind() == "identifier" {
                    return Some(d);
                }
                if let Some(inner) = d.child_by_field_name("declarator") {
                    decl = Some(inner);
                } else {
                    let mut c = d.walk();
                    return d.children(&mut c).find(|k| k.kind() == "identifier");
                }
            }
            None
        })
        .map(|n| source[n.start_byte()..n.end_byte()].to_string())
}

/// The program name under which `fn_node` was extracted, mirroring every
/// extraction branch in [`lower_source_with_facts`]. Always `Some` for a
/// function node - nameless, unbound ones get the positional `<fn@byte>`
/// name. Used to resolve an extracted function's lexical parent.
fn extracted_ancestor_name(
    fn_node: tree_sitter::Node,
    source: &str,
    path: &str,
    spec: &dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
) -> Option<String> {
    // Direct declaration name (function_declaration, method_definition,
    // named function expression) - same order as extraction.
    if let Some(name) = function_name_of(fn_node, source) {
        return Some(name);
    }
    // Bound to a const/let: the lexical branch extracts it under the
    // binding's name (`const helper = (x) => …`).
    if let Some(parent) = fn_node.parent()
        && parent.kind() == "variable_declarator"
        && parent.child_by_field_name("value") == Some(fn_node)
        && (fn_node.kind() == "arrow_function" || fn_node.kind() == "function_expression")
    {
        let name = parent
            .child_by_field_name("name")
            .map(|n| source[n.start_byte()..n.end_byte()].to_string())
            .unwrap_or_else(|| format!("<fn@{}>", parent.start_byte()));
        return Some(name);
    }
    // Route-registration handler: `app.get("/", handler)`.
    if let Some(args) = fn_node.parent()
        && args.kind() == "arguments"
        && let Some(call) = args.parent()
        && call.kind() == "call_expression"
        && let Some(callee) = call.child_by_field_name("function")
        && is_route_registration(&source[callee.start_byte()..callee.end_byte()], spec, facts)
    {
        return Some(format!("<{}:handler@{}>", path, fn_node.start_byte()));
    }
    // Nameless, unbound function: extracted positionally by byte offset.
    Some(format!("<fn@{}>", fn_node.start_byte()))
}

/// The program name of the innermost enclosing extracted function for a
/// function node at `node`'s position, or None at module scope.
fn enclosing_extracted_name(
    node: tree_sitter::Node,
    source: &str,
    path: &str,
    spec: &dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
) -> Option<String> {
    let mut cur = node.parent();
    while let Some(ancestor) = cur {
        if spec.is_function_node(ancestor.kind()) {
            return extracted_ancestor_name(ancestor, source, path, spec, facts);
        }
        cur = ancestor.parent();
    }
    None
}

fn is_route_registration(
    callee_text: &str,
    spec: &dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
) -> bool {
    if spec
        .known_route_verbs()
        .iter()
        .any(|s| callee_text.ends_with(s))
    {
        return true;
    }
    // Receiver-qualified patterns (`app.patch(`) match on their stem, so
    // they extend the verb list wherever the spec is narrower than the
    // source dialect. The patterns are pack vocabulary (Phase 6.4): the
    // default pack installs them into `FactTable::route_patterns` keyed by
    // language, so bare lowering without facts gets verbs only.
    facts
        .and_then(|f| f.route_patterns.get(spec.name()))
        .is_some_and(|pats| {
            pats.iter()
                .any(|p| callee_text.ends_with(p.trim_end_matches('(')))
        })
}

fn lower_one(
    name: &str,
    fn_node: tree_sitter::Node,
    source: &str,
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
) -> FunctionIR {
    let mut ctx = LoweringContext::new_with_facts(spec, source, name.to_string(), facts);

    // First try the direct `parameters` field (JS/TS/Python/Rust/Go).
    // For C, the function_definition has no direct `parameters` field; instead
    // the shape is: function_definition → declarator (function_declarator) →
    //   parameters (parameter_list).  Walk that chain as a fallback.
    let params = fn_node.child_by_field_name("parameters").or_else(|| {
        fn_node
            .child_by_field_name("declarator")
            .and_then(|decl| find_function_declarator(decl))
            .and_then(|fd| fd.child_by_field_name("parameters"))
    });
    if let Some(params) = params {
        bind_params(&mut ctx, params, source);
    }
    if let Some(body) = fn_node.child_by_field_name("body") {
        let has_implicit_ret = spec.implicit_return_node(fn_node, body).is_some();
        let ret_op = ctx.visit_node(body);
        if has_implicit_ret
            && let Some(ret) = ret_op
            && ctx
                .ir
                .blocks
                .get(&ctx.current_block)
                .is_none_or(|b| matches!(b.terminator, Terminator::None))
        {
            ctx.ir
                .set_terminator(ctx.current_block, Terminator::Return { src: Some(ret) });
        }
    }
    SSABuilder::new(ctx.ir).build()
}

/// Walk a declarator chain until we find a `function_declarator` node.
/// Handles C shapes like: pointer_declarator → function_declarator.
fn find_function_declarator(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    if node.kind() == "function_declarator" {
        return Some(node);
    }
    // pointer_declarator, abstract_declarator, etc. may wrap it
    node.child_by_field_name("declarator")
        .and_then(find_function_declarator)
}

/// Lower a top-level non-function initializer (`const x = new Set([...])`,
/// `const cfg = { ... }`, `const tools = { ... tool({...}) ... }`) into a
/// pseudo-function IR so non-dataflow checkers can assert policy over
/// static configuration, allowlist definitions, schema builders, feature
/// flags, that no function body contains.
fn lower_static(
    name: &str,
    value_node: tree_sitter::Node,
    source: &str,
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
) -> FunctionIR {
    let mut ctx = LoweringContext::new_with_facts(spec, source, name.to_string(), facts);
    ctx.visit_node(value_node);
    SSABuilder::new(ctx.ir).build()
}

fn bind_params(ctx: &mut LoweringContext, params: tree_sitter::Node, source: &str) {
    let mut pc = params.walk();
    for p in params.children(&mut pc) {
        // Language-dependent parameter shapes:
        // - JS/TS: `required_parameter`/`optional_parameter` with `pattern` field
        // - Python: plain `identifier` children of `parameters`
        // - Rust: `parameter` node wrapping the name identifier as first child
        // - Go: `parameter_declaration` with the name as first child
        if p.kind() == "self_parameter" {
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
            ctx.env.last_mut().unwrap().insert(name, v);
            continue;
        }
        let id = match p.kind() {
            "required_parameter" | "optional_parameter" => {
                p.child_by_field_name("pattern").or_else(|| p.child(0))
            }
            "identifier" => Some(p),
            // C `parameter_declaration`: shape is `type declarator`, where the
            // declarator may be pointer_declarator → identifier (e.g. `char *p`).
            // child(0) returns the type specifier, not the name - use the
            // `declarator` field and walk it to find the leaf identifier.
            "parameter_declaration" => p
                .child_by_field_name("declarator")
                .and_then(|d| find_param_identifier(d)),
            // Rust `parameter`, Go `parameter_declaration` (handled above),
            // variadic_parameter: first child is the identifier or pattern.
            "parameter" | "variadic_parameter" => p.child(0),
            _ => None,
        };
        if let Some(id) = id {
            let name = source[id.start_byte()..id.end_byte()].to_string();
            let v = ctx.ir.new_var(VarMetadata {
                source_name: Some(name.clone()),
                type_name: None,
                byte_range: Some((p.start_byte(), p.end_byte())),
                is_memory_state: false,
                object_keys: Vec::new(),
                declared: true,
            });
            ctx.ir.parameters.push(v);
            ctx.env.last_mut().unwrap().insert(name, v);
        }
    }
}

/// Walk a C declarator chain to find the leaf `identifier`.
/// Handles pointer_declarator, array_declarator, etc.
fn find_param_identifier(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    match node.kind() {
        "identifier" => Some(node),
        _ => node
            .child_by_field_name("declarator")
            .and_then(find_param_identifier),
    }
}

#[cfg(test)]
mod tests {
    use super::{lower_source, lower_source_with_facts};
    use crate::analysis::taint::facts::seeded_tables;

    fn keys(src: &str) -> Vec<String> {
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let mut ks: Vec<String> = fns.keys().cloned().collect();
        ks.sort();
        ks
    }

    /// The pack's route-registration patterns extend the verb suffix list:
    /// `.patch` is not in `known_route_verbs`, so an `app.patch(...)` arrow
    /// handler only extracts under the pattern stem (`app.patch(`). Since
    /// Phase 6.4 the patterns come from the seeded fact table (the pack),
    /// not the language spec.
    #[test]
    fn route_registration_pattern_extracts_handler() {
        let src = r#"
import express from "express";
const app = express();
app.patch("/item", (req, res) => {
  res.send("ok");
});
"#;
        let (_, facts) = seeded_tables(["ts"]);
        let fns = lower_source_with_facts("t.ts", src, "ts", Some(&facts)).unwrap();
        let handlers: Vec<&String> = fns.keys().filter(|k| k.contains("handler@")).collect();
        assert!(!handlers.is_empty(), "app.patch handler missing: {fns:?}");
    }

    /// Regression: `const r = runTool(cmd)` nested in a handler must NOT be
    /// extracted as a phantom top-level function - the call already belongs
    /// to the handler's IR, and the phantom fired policy checks twice under
    /// a function name that exists nowhere in the source.
    #[test]
    fn nested_non_function_const_not_extracted() {
        let src = r#"
export function handler (cmd: string) {
  const r = runTool(cmd)
  return r
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let mut ks: Vec<String> = fns.keys().cloned().collect();
        ks.sort();
        assert_eq!(ks, vec!["handler".to_string()], "phantom entries: {ks:?}");
        let handler = &fns["handler"];
        let has_run_tool =
            handler.blocks.values().any(|b| {
                b.instructions.iter().any(|i| matches!(
                i,
                crate::ir::function::Instruction::CallStatic { func, .. } if func == "runTool"
            ))
            });
        assert!(has_run_tool, "the nested call must stay in the handler IR");
    }

    /// The anonymous `function` keyword token classifies as a Function node;
    /// visiting it used to spawn an empty `<fn@N>` pseudo-function for every
    /// declaration in the file.
    #[test]
    fn function_keyword_token_not_extracted() {
        let ks = keys(
            r#"
export function handler (cmd: string) {
  return runTool(cmd)
}
"#,
        );
        assert_eq!(ks, vec!["handler".to_string()], "phantom entries: {ks:?}");
    }

    /// A nested arrow const is extracted ONCE under its binding name; the
    /// generic walker must not lower the same node again as `<fn@N>`.
    #[test]
    fn bound_arrow_lowered_exactly_once() {
        let ks = keys(
            r#"
export function handler (cmd: string) {
  const helper = (x) => db.execute(x)
  return helper(cmd)
}
"#,
        );
        assert_eq!(
            ks,
            vec!["handler".to_string(), "helper".to_string()],
            "expected exactly handler+helper, got: {ks:?}"
        );
    }

    /// Top-level arrow consts: one entry under the binding name, no twin.
    #[test]
    fn top_level_arrow_const_lowered_once() {
        let ks = keys(
            r#"
export const hash = (d: string) => db.execute(d)
"#,
        );
        assert_eq!(ks, vec!["hash".to_string()], "got: {ks:?}");
    }

    /// Route-registration handlers: lowered under the stable handler name
    /// only, not again as a positional `<fn@N>` twin.
    #[test]
    fn route_handler_lowered_once() {
        let ks = keys(
            r#"
const app = makeApp()
app.get("/", (req: any, res: any) => open(res))
"#,
        );
        assert!(
            ks.iter().all(|k| !k.starts_with("<fn@")),
            "positional twin leaked: {ks:?}"
        );
    }

    /// Top-level non-function statics keep their pseudo-IR: the checker
    /// layer asserts policy over allowlists/config objects defined here.
    #[test]
    fn top_level_static_still_extracted() {
        let ks = keys(
            r#"
const allowed = new Set(["http://a.example"])
export function handler () { return 1 }
"#,
        );
        assert!(ks.contains(&"allowed".to_string()), "got: {ks:?}");
        assert!(ks.contains(&"handler".to_string()), "got: {ks:?}");
    }

    /// A nameless module-scope function expression (IIFE) has no enclosing
    /// lowered IR - it must still be extracted, or its body is never scanned.
    #[test]
    fn module_scope_iife_still_extracted() {
        let ks = keys(
            r#"
(function () { runTool(cmd) })()
export function handler () { return 1 }
"#,
        );
        assert!(
            ks.iter().any(|k| k.starts_with("<fn@")),
            "IIFE coverage lost: {ks:?}"
        );
        assert!(ks.contains(&"handler".to_string()), "got: {ks:?}");
    }

    /// Nested NAMED function declarations are kept: call sites inside the
    /// enclosing function resolve to them via cross edges.
    #[test]
    fn nested_named_function_still_extracted() {
        let ks = keys(
            r#"
export function outer (cmd: string) {
  function inner (x: string) { return runTool(x) }
  return inner(cmd)
}
"#,
        );
        assert_eq!(
            ks,
            vec!["inner".to_string(), "outer".to_string()],
            "got: {ks:?}"
        );
    }
}
