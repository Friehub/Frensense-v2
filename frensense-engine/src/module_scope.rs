// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Lowering of the executable statements that sit directly in a file's module
//! scope into one pseudo-function IR.
//!
//! Dataflow used to see only function bodies, so a module-level sink was
//! silent. One pseudo-function per module fixes that, and it is also the unit
//! that makes `const q = req.query.q; eval(q)` link: the definition and the
//! sink must live in the same IR, because findings are deduplicated per
//! function and merging separate IRs after the fact would report the sink
//! twice under two names.
//!
//! Template writes (`<div v-html="q">`) are synthesized here too. A container
//! format reports the expression's span and no source bytes are rewritten, so
//! a write is not limited by the spare space next to a directive and always
//! sits after the script statements that define its value.

use crate::analysis::taint::facts::FactTable;
use crate::ir::function::{FunctionIR, Instruction};
use crate::ir::lowering::LoweringContext;
use crate::ir::ssa::SSABuilder;
use frensense_lang::NodeRole;
use tree_sitter::Node;

/// Program name of a file's module-scope pseudo-function. It is never a call
/// target, so no source name can collide with it.
pub(crate) const MODULE_SCOPE_FN: &str = "<module>";

/// Lower the module-scope statements into one SSA'd, static-function IR.
///
/// Only *root-level* named children of the parsed tree are visited: a function
/// is its own IR, an import contributes no code, and a declaration is owned by
/// the binding/static walk unless `owns_decls` is set (see
/// [`owns_declarations`]).
///
/// `None` when the file has no module-level code that produces an instruction,
/// so a function-only file (the common case) gains no empty pseudo-function.
pub(crate) fn lower_module_scope(
    root: Node,
    source: &str,
    original: &str,
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
    owns_decls: bool,
    template_writes: &[(usize, usize)],
) -> Option<FunctionIR> {
    // The parsed tree is the blanked source; a template expression exists only
    // in the original bytes. Overlaying those bytes onto the blanked text
    // gives one source whose offsets match both, so an identifier inside
    // `v-html="q"` still slices to `q` while lowering the synthesized write.
    let overlay = (!template_writes.is_empty())
        .then(|| overlay_expressions(source, original, template_writes))
        .flatten();
    // Without the overlay the expressions are not in the text, so lowering
    // them would read blanks: drop the writes rather than invent a flow.
    let writes: &[(usize, usize)] = if overlay.is_some() {
        template_writes
    } else {
        &[]
    };
    let text = overlay.as_deref().unwrap_or(source);

    let mut ctx = LoweringContext::new_with_facts(spec, text, MODULE_SCOPE_FN.to_string(), facts);
    let mut cursor = root.walk();
    let children: Vec<_> = root.named_children(&mut cursor).collect();
    for child in children {
        let owned = owns_decls && declares_at_module_scope(child, spec);
        if module_scope_skip(child, spec) && !owned {
            continue;
        }
        ctx.visit_node(child);
    }
    // Template writes go last: the script statements that define their values
    // are lowered by now, so the sink reads the same variable the declaration
    // assigned instead of a fresh undefined one.
    if !writes.is_empty() {
        emit_template_writes(&mut ctx, text, writes, spec);
    }
    if ctx.ir.blocks.values().all(|b| b.instructions.is_empty()) {
        return None;
    }
    let mut ir = SSABuilder::new(ctx.ir).build();
    ir.language = spec.fact_language().to_string();
    ir.is_static_data = true;
    Some(ir)
}

/// Should the module IR own the file's root-level declarations?
///
/// A declaration is executed in order with the statements around it, so its
/// definition belongs in the same dataflow unit as theirs. It only matters when
/// there IS module-level code - a file of nothing but function declarations and
/// initialisers keeps the per-binding static IRs it always had, which is what
/// keeps corpus fact extraction stable - or when a template write must read a
/// module-level value.
pub(crate) fn owns_declarations(
    root: Node,
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
    has_template_writes: bool,
) -> bool {
    let mut cursor = root.walk();
    let children: Vec<_> = root.named_children(&mut cursor).collect();
    (has_template_writes || children.iter().any(|c| !module_scope_skip(*c, spec)))
        && children.iter().any(|c| declares_at_module_scope(*c, spec))
}

/// Emit one template-write call per reported expression span.
///
/// The expression is parsed from the overlaid text at its own offsets, so the
/// identifiers and member chains inside it lower exactly as if they had been
/// written in the script. A span whose parse does not cover it exactly is
/// skipped: a missing finding is honest, a call on the wrong expression is not.
fn emit_template_writes(
    ctx: &mut LoweringContext<'_>,
    text: &str,
    spans: &[(usize, usize)],
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
) {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&spec.tree_sitter_language()).is_err() {
        return;
    }
    let Some(tree) = parser.parse(text, None) else {
        return;
    };
    for &(start, end) in spans {
        let node = tree
            .root_node()
            .descendant_for_byte_range(start, end)
            .filter(|n| n.start_byte() == start && n.end_byte() == end);
        let Some(node) = node else {
            continue;
        };
        let Some(value) = ctx.visit_node(node) else {
            continue;
        };
        // The result temp carries the expression's range, and a call's span is
        // its result's range, so the finding points at the template expression.
        let dest = ctx.new_temp(node);
        ctx.ir.push_instruction(
            ctx.current_block,
            Instruction::CallStatic {
                dest: Some(dest),
                mem_out: ctx.memory_var,
                mem_in: ctx.memory_var,
                func: crate::ir::TEMPLATE_SINK_CALL.to_string(),
                args: vec![value],
                arg_names: vec![String::new()],
            },
        );
    }
}

/// `blanked` with the original bytes at every `span` copied back in, or
/// `None` when the result would not be valid UTF-8.
///
/// Both strings share offsets by construction (the preprocessor preserves
/// length), and each span is a whole expression.
fn overlay_expressions(blanked: &str, original: &str, spans: &[(usize, usize)]) -> Option<String> {
    let mut bytes = blanked.as_bytes().to_vec();
    for &(start, end) in spans {
        let (Some(dst), Some(src)) = (
            bytes.get_mut(start..end),
            original.as_bytes().get(start..end),
        ) else {
            continue;
        };
        dst.copy_from_slice(src);
    }
    String::from_utf8(bytes).ok()
}

/// Does this root-level node declare a binding at module scope?
fn declares_at_module_scope(node: Node<'_>, spec: &dyn frensense_lang::spec::LanguageSpec) -> bool {
    if spec.is_variable_declaration_statement(node.kind()) {
        return true;
    }
    // `export const x = ...`: the declaration sits inside the export wrapper.
    if matches!(spec.classify(node.kind()), NodeRole::Export) {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .any(|child| spec.is_variable_declaration_statement(child.kind()));
    }
    false
}

/// Should the module-scope IR leave this root-level node to another lowering?
fn module_scope_skip(node: Node<'_>, spec: &dyn frensense_lang::spec::LanguageSpec) -> bool {
    let kind = node.kind();
    if spec.is_function_node(kind) || spec.import_node_kinds().contains(&kind) {
        return true;
    }
    if spec.is_variable_declaration_statement(kind) {
        return true;
    }
    // `export const x = ...` / `export function f` wrap the same nodes; a
    // default export of an expression (`export default runTool(cmd)`) does
    // execute at import time and stays in the module IR.
    if matches!(spec.classify(kind), NodeRole::Export) {
        let mut cursor = node.walk();
        return node.named_children(&mut cursor).any(|child| {
            spec.is_function_node(child.kind())
                || spec.is_variable_declaration_statement(child.kind())
        });
    }
    false
}
