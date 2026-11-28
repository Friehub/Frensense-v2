// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

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
use frensense_lang::NodeRole;

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
///
/// ```
/// use frensense_engine::harness::lower_source;
///
/// let src = "declare const app: any\n\
///            app.get('/x', (req: any, res: any) => { res.send(req.query.a) })\n\
///            function f() { return 1 }";
/// let fns = lower_source("t.ts", src, "ts").unwrap();
/// // Ordinary declarations are keyed by their name.
/// assert!(fns.contains_key("f"));
/// // The route handler gets a synthetic name built from the path and the byte
/// // offset of the handler, here the start of the arrow function's parameters.
/// let offset = src.find("(req").unwrap();
/// assert!(fns.contains_key(&format!("<t.ts:handler@{offset}>")));
/// ```
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
    Ok(lower_source_detailed(path, source, ext, facts)?.0)
}

/// Lower one file and report whether its parse tree contained errors.
///
/// tree-sitter does not fail on a syntax error: it hands back a tree full of
/// `ERROR`/missing nodes and the lowering extracts whatever survived, so a
/// file that is a third unparseable used to be analyzed as if it were intact
/// and reported as clean. The second element carries that fact so the scan
/// can say "partially analyzed" instead.
pub(crate) fn lower_source_detailed(
    path: &str,
    source: &str,
    ext: &str,
    facts: Option<&FactTable>,
) -> Result<(FxHashMap<String, FunctionIR>, bool), String> {
    let spec = frensense_lang::spec_for_path(std::path::Path::new(path))
        .or_else(|| frensense_lang::spec_for_ext(ext))
        .ok_or_else(|| format!("no language spec for extension '{ext}'"))?;

    // Single-file-container formats (e.g. Vue SFCs) rewrite the source
    // before parsing: the spec blanks non-code markup into same-length
    // whitespace, so every byte offset, and every reported line/column,
    // still points at the original file.
    let original = source;
    let rewritten = spec.preprocess(source);
    let source: &str = rewritten.as_ref();
    // Template writes are reported against the file as written; the engine
    // synthesizes the call instead of consuming bytes of the rewritten source.
    let template_writes = spec.template_writes(original);
    // Sanitized template expressions are lowered but do not synthesize a
    // write; they exist so a sink inside the expression (an Angular
    // `bypassSecurityTrust…`) is still analysed.
    let template_expressions = spec.template_expressions(original);
    // Component fields an inline template may read; bound before lowering.
    let template_bindings = spec.template_bindings(original);

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
    // Whether the module IR owns the root-level declarations: `const q =
    // req.query.q; eval(q)` links only if both live in the same IR.
    let module_owns_decls = crate::module_scope::owns_declarations(
        tree.root_node(),
        spec,
        !template_writes.is_empty() || !template_expressions.is_empty(),
    );
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        // Language-driven function detection: JS/TS `function_declaration` /
        // `method_definition`, Python `function_definition` (+ async),
        // Rust `function_item`, Go `function_declaration` / `method_declaration`.
        if spec.is_function_node(node.kind()) {
            let name = function_name_of(node, source, spec);
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
        if spec.is_variable_declaration_statement(node.kind()) {
            let mut dc = node.walk();
            for decl in node.named_children(&mut dc) {
                if !spec.is_variable_declarator(decl.kind()) {
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
                if spec.is_function_value(value.kind()) {
                    bound_fns.insert(value.start_byte());
                    let mut ir = lower_one(&name, value, source, spec, facts);
                    ir.enclosing_fn = enclosing_extracted_name(value, source, path, spec, facts);
                    insert_ir(&mut irs, ir, value.start_byte());
                } else if !module_owns_decls && !inside_function(node, spec) {
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
        if let NodeRole::Call {
            callee_field,
            args_field,
        } = spec.classify(node.kind())
            && let (Some(callee), Some(args)) = (
                node.child_by_field_name(callee_field.as_ref()),
                node.child_by_field_name(args_field.as_ref()),
            )
        {
            let callee_text = &source[callee.start_byte()..callee.end_byte()];
            if is_route_registration(callee_text, path, spec, facts) {
                let mut ac = args.walk();
                let arg_nodes: Vec<_> = args.named_children(&mut ac).collect();
                for a in &arg_nodes {
                    if spec.is_function_value(a.kind()) {
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
    // Top-level executable code. Taint and policy checks only ever saw
    // function bodies, so the same two statements that were reported inside
    // `def handler():` were silent at file scope - CLI tools, ETL/notebook
    // scripts, Django `settings.py`, and an
    // `if __name__ == "__main__": app.run(debug=True)` guard were invisible.
    if let Some(ir) = crate::module_scope::lower_module_scope(
        tree.root_node(),
        source,
        original,
        spec,
        facts,
        module_owns_decls,
        &crate::module_scope::TemplateSpans {
            writes: &template_writes,
            expressions: &template_expressions,
            bindings: &template_bindings,
        },
    ) {
        insert_ir(&mut irs, ir, tree.root_node().start_byte());
    }
    Ok((irs, tree.root_node().has_error()))
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
/// grammar's declarator chain (`function_definition -> declarator -> ...`),
/// which the language spec resolves.
fn function_name_of(
    node: tree_sitter::Node,
    source: &str,
    spec: &dyn frensense_lang::spec::LanguageSpec,
) -> Option<String> {
    spec.function_name_node(node)
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
    if let Some(name) = function_name_of(fn_node, source, spec) {
        return Some(name);
    }
    // Bound to a const/let: the lexical branch extracts it under the
    // binding's name (`const helper = (x) => …`).
    if let Some(parent) = fn_node.parent()
        && spec.is_variable_declarator(parent.kind())
        && parent.child_by_field_name("value") == Some(fn_node)
        && spec.is_function_value(fn_node.kind())
    {
        let name = parent
            .child_by_field_name("name")
            .map(|n| source[n.start_byte()..n.end_byte()].to_string())
            .unwrap_or_else(|| format!("<fn@{}>", parent.start_byte()));
        return Some(name);
    }
    // Route-registration handler: `app.get("/", handler)`.
    if let Some(args) = fn_node.parent()
        && matches!(spec.classify(args.kind()), NodeRole::Arguments)
        && let Some(call) = args.parent()
        && let NodeRole::Call { callee_field, .. } = spec.classify(call.kind())
        && let Some(callee) = call.child_by_field_name(callee_field.as_ref())
        && is_route_registration(
            &source[callee.start_byte()..callee.end_byte()],
            path,
            spec,
            facts,
        )
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

/// Route-registration predicate: a call site is a route handler when the
/// spec's hard verb suffixes match the callee, OR when pack vocabulary
/// (`facts.route_patterns`) lists a registration shape for that spec's
/// language - and the file it sits in may register routes at all.
///
/// File kind comes from [`frensense_lang::framework::resolve_file`], so the
/// decision uses the same framework model the corpus does. A single-file
/// component (`.vue`, `.svelte`, `.astro`, `.html` template) never registers
/// an HTTP route: its `.get`/`.use` calls are collection, store or plugin
/// reads, and treating them as handlers produced phantom route entries.
/// Library and server modules keep the verb/pattern behaviour that
/// Express-style apps rely on.
///
/// Used by the harness's IR lowering to extract route handlers, and by
/// the backward engine's per-call-site resolution (when wired via
/// [`EngineBuilder::route_registration`]) so a framework origin arms
/// only at route handlers (schema §5.1).
pub(crate) fn is_route_registration(
    callee_text: &str,
    path: &str,
    spec: &dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
) -> bool {
    if frensense_lang::framework::resolve_file(path, spec.fact_language()).kind
        == frensense_lang::framework::FileKind::Sfc
    {
        return false;
    }
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
        .and_then(|f| f.route_patterns.get(spec.fact_language()))
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

    // The list lives wherever the grammar puts it: a `parameters` field for
    // most languages, one declarator hop further for C (`function_definition →
    // declarator → function_declarator → parameters`). `function_params`
    // follows `NodeRole::Function::params_field` until it reaches a
    // `Parameters` node, so the engine carries no C-specific walk.
    if let Some(params) = spec.function_params(fn_node) {
        bind_params(&mut ctx, spec, params, source);
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
    let mut ir = SSABuilder::new(ctx.ir).build();
    ir.language = spec.fact_language().to_string();
    ir.entry_guards = spec
        .decorator_guard_calls(fn_node, source)
        .into_iter()
        .map(str::to_owned)
        .collect();
    ir
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
    let init = ctx.visit_node(value_node);
    // Module-level alias: `const zip = unzipper;`. An identifier has no call
    // or literal to lower, so the visit yields only the aliased value and the
    // pseudo-function came out empty - invisible to receiver-origin
    // resolution, because the consuming function's IR has no def for the
    // module-level name to walk. Record the binding as an assignment, the
    // module-level twin of the `Assign` the declaration path emits inside a
    // function body.
    if matches!(ctx.classify_node(value_node.kind()), NodeRole::Identifier)
        && let Some(Operand::Var(src)) = init
    {
        let dest = ctx.ir.new_var(VarMetadata {
            source_name: Some(name.to_string()),
            type_name: None,
            byte_range: Some((value_node.start_byte(), value_node.end_byte())),
            is_memory_state: false,
            object_keys: Vec::new(),
            declared: true,
        });
        let block = ctx.current_block;
        ctx.ir.push_instruction(
            block,
            Instruction::Assign {
                dest,
                src: Operand::Var(src),
            },
        );
    }
    let mut ir = SSABuilder::new(ctx.ir).build();
    ir.language = spec.fact_language().to_string();
    ir.is_static_data = true;
    ir
}

fn bind_params(
    ctx: &mut LoweringContext,
    spec: &dyn frensense_lang::spec::LanguageSpec,
    params: tree_sitter::Node,
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
            ctx.env.last_mut().unwrap().insert(name, v);
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
            ctx.env.last_mut().unwrap().insert(name, v);
        }
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

#[cfg(test)]
mod tests {
    use super::{lower_source, lower_source_with_facts};
    use crate::analysis::taint::facts::seeded_tables;

    /// Go parameters used to bind nothing at all: the C `declarator` field
    /// the old arm read does not exist on a Go `parameter_declaration`, so
    /// every body reference was an undeclared name and the parameter's type -
    /// the thing `classify_param_taint` keys on for `*http.Request` and
    /// `*gin.Context` - was never recorded. Grouped (`a, b string`) and
    /// variadic names share one declaration, so each name has to bind.
    #[test]
    fn go_parameters_are_bound_with_their_declared_types() {
        let src = r#"
package main

import "net/http"

func handle(request *http.Request, a, b string, rest ...int) {}
"#;
        let fns = lower_source("a.go", src, "go").unwrap();
        let ir = &fns["handle"];
        let bound: Vec<(&str, Option<&str>)> = ir
            .parameters
            .iter()
            .map(|&v| {
                let meta = &ir.var_metadata[&v];
                (
                    meta.source_name.as_deref().unwrap_or(""),
                    meta.type_name.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            bound,
            vec![
                ("request", Some("*http.Request")),
                ("a", Some("string")),
                ("b", Some("string")),
                ("rest", Some("int")),
            ],
            "every Go parameter must bind with its type: {bound:?}"
        );
    }

    /// A destructured parameter owns no name of its own, so the slot holds one
    /// load per bound name - and a nested pattern recurses through the load it
    /// just emitted. A rest parameter binds its inner name, not `...name`.
    #[test]
    fn destructured_parameters_bind_the_names_inside_them() {
        use crate::ir::function::Instruction;

        let src = r#"
function run({ body: { name } }: any, [first]: string[], ...rest: string[]) {}
"#;
        let fns = lower_source("a.ts", src, "ts").unwrap();
        let ir = &fns["run"];
        assert_eq!(ir.parameters.len(), 3, "one slot per parameter");
        let rest = &ir.var_metadata[&ir.parameters[2]];
        assert_eq!(rest.source_name.as_deref(), Some("rest"));

        let mut loads: Vec<(String, String)> = Vec::new();
        let mut elements = 0;
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                match instr {
                    Instruction::LoadField { dest, field, .. } => loads.push((
                        field.clone(),
                        ir.var_metadata[dest]
                            .source_name
                            .clone()
                            .unwrap_or_default(),
                    )),
                    Instruction::LoadElement { .. } => elements += 1,
                    _ => {}
                }
            }
        }
        assert_eq!(
            loads,
            vec![
                // The intermediate is the flat form's `body` binding.
                ("body".to_string(), "body".to_string()),
                ("name".to_string(), "name".to_string()),
            ],
            "nested pattern must load each part: {loads:?}"
        );
        assert_eq!(elements, 1, "the array pattern loads its element");
    }

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

    /// A single-file component never registers an HTTP route: `store.get(…)`
    /// in a Vue script is a collection read, not an Express handler. File
    /// kind comes from the framework model, so no separate allowlist is kept.
    #[test]
    fn component_calls_are_not_route_registrations() {
        let src = "<script>\nconst store = new Map()\nstore.get('/k', () => {})\n</script>\n";
        let fns = lower_source("src/App.vue", src, "vue").unwrap();
        assert!(
            fns.keys().all(|k| !k.contains("handler@")),
            "component call became a route handler: {fns:?}"
        );
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

    // ── Vue SFC lowering (the `vue` spec blanks the template in place) ─────

    const VUE_POSITIVE: &str = r#"<template>
  <div id="surface"></div>
</template>
<script setup lang="ts">
// FIXTURE: taint from a DOM location member into a code-execution sink.
function run() {
  const payload = location.hash;
  eval(payload);
}
</script>
<style scoped>
#surface { color: red; }
</style>
"#;

    const VUE_NEGATIVE: &str = r#"<template>
  <div id="surface"></div>
</template>
<script setup lang="ts">
// FIXTURE (safe twin): the evaluated string is a compile-time literal, so
// no taint source reaches the sink.
function run() {
  eval("1 + 1");
}
</script>
<style scoped>
#surface { color: red; }
</style>
"#;

    fn taint_findings(src: &str) -> Vec<crate::analysis::taint::engine::SinkFinding> {
        use crate::analysis::forward::ProgramSvfg;
        use crate::analysis::taint::config::TaintConfig;
        use crate::analysis::taint::engine::BackwardTaintEngine;
        use crate::ir::function::FunctionIR;
        use rustc_hash::FxHashMap;

        let fns = lower_source("probe.vue", src, "vue").expect("sfc must lower");
        let owned: Vec<FunctionIR> = fns.into_values().collect();
        let mut statics: FxHashMap<String, &FunctionIR> = FxHashMap::default();
        for ir in &owned {
            statics.insert(ir.name.clone(), ir);
        }
        let mut config = TaintConfig::default();
        config.sources.insert("location.hash".into());
        config.sinks.insert("eval".into());
        let prog = ProgramSvfg::new(&statics, &config);
        let mut engine = BackwardTaintEngine::new(&prog, &config);
        engine.run();
        engine.findings
    }

    /// The positive twin: a `.vue` script block taints `eval` from
    /// `location.hash`. The blanked template must not lose, duplicate or
    /// shift the finding: the sink span must still point INTO the script
    /// body of the ORIGINAL file (the position contract).
    #[test]
    fn vue_sfc_script_taint_is_found() {
        use crate::analysis::taint::engine::BackwardVerdict;
        let findings = taint_findings(VUE_POSITIVE);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            !vuln.is_empty(),
            "eval(location.hash) must alert: {findings:?}"
        );

        // Position contract: the sink span sits inside the `<script>` body
        // of the original SFC, not in blanked-out template/style bytes.
        let body = "eval(payload)";
        let expected = VUE_POSITIVE.find(body).expect("fixture shape");
        let span = vuln[0]
            .sink_span
            .expect("lowering must record the sink span");
        assert!(
            span.0 >= expected && span.0 <= expected + body.len(),
            "sink span {:?} must cover the eval call at byte {expected}",
            span
        );
    }

    /// The negative twin: the same sink, untainted argument, stays silent.
    /// Template-only components with no script block lower to nothing at
    /// all - never a phantom finding.
    #[test]
    fn vue_sfc_negative_stays_silent_and_template_only_lower_to_nothing() {
        let findings = taint_findings(VUE_NEGATIVE);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == crate::analysis::taint::engine::BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vuln.is_empty(),
            "literal eval must stay silent: {findings:?}"
        );

        let template_only = "<template>\n  <button>go</button>\n</template>\n";
        let fns = lower_source("t.vue", template_only, "vue").unwrap();
        assert!(fns.is_empty(), "template-only SFC lowered: {fns:?}");
    }
}
