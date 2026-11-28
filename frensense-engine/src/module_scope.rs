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

use std::borrow::Cow;

use crate::analysis::taint::facts::FactTable;
use crate::ir::function::{FunctionIR, Instruction};
use crate::ir::lowering::LoweringContext;
use crate::ir::ssa::SSABuilder;
use frensense_lang::NodeRole;
use frensense_lang::spec::TemplateBinding;
use tree_sitter::Node;

/// Program name of a file's module-scope pseudo-function. It is never a call
/// target, so no source name can collide with it.
pub(crate) const MODULE_SCOPE_FN: &str = "<module>";

/// Template expressions the spec asked to lower alongside the module body.
///
/// `writes` synthesize a template-write sink; `expressions` are analysis-only
/// (an Angular binding that Angular sanitizes but that may contain a
/// sanitizer bypass). Keeping them in one struct keeps the lowering entry
/// point's argument list small and the two channels visibly paired.
pub(crate) struct TemplateSpans<'a> {
    pub(crate) writes: &'a [(usize, usize)],
    pub(crate) expressions: &'a [(usize, usize)],
    /// Component fields the template may read: `(name, initializer span)`.
    pub(crate) bindings: &'a [TemplateBinding],
    /// A companion component source for an external template, and its field
    /// initializers. Their expressions are lowered into this module so the
    /// template's bindings link to the value the component class assigned.
    pub(crate) foreign: Option<(&'a str, &'a [TemplateBinding])>,
}

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
    templates: &TemplateSpans<'_>,
) -> Option<FunctionIR> {
    let TemplateSpans {
        writes: template_writes,
        expressions: template_expressions,
        bindings: template_bindings,
        foreign,
    } = *templates;
    // The parsed tree is the blanked source; a template expression exists only
    // in the original bytes. Overlaying those bytes onto the blanked text
    // gives one source whose offsets match both, so an identifier inside
    // `v-html="q"` still slices to `q` while lowering the synthesized write.
    let mut spans: Vec<(usize, usize)> = template_writes.to_vec();
    spans.extend_from_slice(template_expressions);
    let overlay = (!spans.is_empty())
        .then(|| overlay_expressions(source, original, &spans))
        .flatten();
    // Without the overlay the expressions are not in the text, so lowering
    // them would read blanks: drop them rather than invent a flow.
    let available = overlay.is_some();
    let writes = if available { template_writes } else { &[] };
    let expressions = if available { template_expressions } else { &[] };
    let base_text = overlay.as_deref().unwrap_or(source);
    // An external template's fields live in another file. Append their
    // initializers as assignments so the parser and lowering see one text; the
    // appended region starts at `base_text.len()`.
    let (text, foreign_start) = match foreign {
        Some((companion, fields)) if !fields.is_empty() => {
            let appended = foreign_assignments(companion, fields);
            if appended.is_empty() {
                (Cow::Borrowed(base_text), None)
            } else {
                let start = base_text.len();
                let mut joined = String::with_capacity(start + appended.len());
                joined.push_str(base_text);
                joined.push_str(&appended);
                (Cow::Owned(joined), Some(start))
            }
        }
        _ => (Cow::Borrowed(base_text), None),
    };

    let mut ctx = LoweringContext::new_with_facts(spec, &text, MODULE_SCOPE_FN.to_string(), facts);
    let mut cursor = root.walk();
    let children: Vec<_> = root.named_children(&mut cursor).collect();
    for child in children {
        let owned = owns_decls && declares_at_module_scope(child, spec);
        if module_scope_skip(child, spec) && !owned {
            continue;
        }
        ctx.visit_node(child);
    }
    // A template reads the component instance, so its fields are bound as
    // module values before the expressions that reference them.
    if !template_bindings.is_empty() {
        bind_template_fields(&mut ctx, &text, template_bindings, spec);
    }
    if let Some(start) = foreign_start {
        lower_foreign_bindings(&mut ctx, &text, start, spec);
    }
    // Template writes go last: the script statements that define their values
    // are lowered by now, so the sink reads the same variable the declaration
    // assigned instead of a fresh undefined one.
    if !writes.is_empty() || !expressions.is_empty() {
        emit_template_spans(&mut ctx, &text, writes, expressions, spec);
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

/// Lower the reported template spans from the overlaid text.
///
/// Each expression is parsed at its own offsets, so identifiers and member
/// chains inside it lower exactly as if they had been written in the script.
/// A span whose parse does not cover it exactly is skipped: a missing finding
/// is honest, a call on the wrong expression is not.
///
/// A **write** span also gets a synthesized [`TEMPLATE_SINK_CALL`] carrying
/// its value. An **analysis-only** span is lowered and dropped: it is not a
/// sink itself, but a sink inside it (Angular's `bypassSecurityTrust…`) must
/// still reach the taint engine.
/// `name = initializer;` lines for a companion component's fields.
fn foreign_assignments(companion: &str, fields: &[TemplateBinding]) -> String {
    let mut appended = String::new();
    for (name, (start, end)) in fields {
        let Some(expr) = companion.get(*start..*end).map(str::trim) else {
            continue;
        };
        if expr.is_empty() {
            continue;
        }
        appended.push('\n');
        appended.push_str(name);
        appended.push_str(" = ");
        appended.push_str(expr);
        appended.push(';');
    }
    appended
}

/// Lower the appended foreign field assignments into this module's scope.
fn lower_foreign_bindings(
    ctx: &mut LoweringContext<'_>,
    text: &str,
    start: usize,
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
) {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&spec.tree_sitter_language()).is_err() {
        return;
    }
    let Some(tree) = parser.parse(text, None) else {
        return;
    };
    let mut cursor = tree.root_node().walk();
    let statements: Vec<_> = tree
        .root_node()
        .named_children(&mut cursor)
        .filter(|node| node.start_byte() >= start)
        .collect();
    for node in statements {
        ctx.visit_node(node);
    }
}

/// Bind each template-visible component field to its initializer's value.
fn bind_template_fields(
    ctx: &mut LoweringContext<'_>,
    text: &str,
    bindings: &[TemplateBinding],
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
) {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&spec.tree_sitter_language()).is_err() {
        return;
    }
    let Some(tree) = parser.parse(text, None) else {
        return;
    };
    for (name, (start, end)) in bindings {
        let node = tree
            .root_node()
            .descendant_for_byte_range(*start, *end)
            .filter(|n| n.start_byte() == *start && n.end_byte() == *end);
        let Some(node) = node else {
            continue;
        };
        let Some(value) = ctx.visit_node(node) else {
            continue;
        };
        ctx.bind_instance_field(name, node, value);
    }
}

fn emit_template_spans(
    ctx: &mut LoweringContext<'_>,
    text: &str,
    writes: &[(usize, usize)],
    expressions: &[(usize, usize)],
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
) {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&spec.tree_sitter_language()).is_err() {
        return;
    }
    let Some(tree) = parser.parse(text, None) else {
        return;
    };
    for (spans, is_write) in [(writes, true), (expressions, false)] {
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
            if !is_write {
                continue;
            }
            // The result temp carries the expression's range, and a call's
            // span is its result's range, so the finding points at the
            // template expression.
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
