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

use crate::analysis::taint::facts::FactTable;
use crate::ir::function::FunctionIR;
use crate::ir::lowering::LoweringContext;
use crate::ir::ssa::SSABuilder;
use frensense_lang::NodeRole;
use tree_sitter::Node;

/// Program name of a file's module-scope pseudo-function. It is never a call
/// target, so no source name can collide with it.
pub(crate) const MODULE_SCOPE_FN: &str = "<module>";

/// Lower the module-scope statements into one SSA'd, static-function IR.
///
/// Only *root-level* named children are visited: a function is its own IR, an
/// import contributes no code, and a declaration is owned by the binding/static
/// walk unless `owns_decls` is set (see [`owns_declarations`]).
///
/// `None` when the file has no module-level code that produces an instruction,
/// so a function-only file (the common case) gains no empty pseudo-function.
pub(crate) fn lower_module_scope(
    root: Node,
    source: &str,
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
    owns_decls: bool,
) -> Option<FunctionIR> {
    let mut ctx = LoweringContext::new_with_facts(spec, source, MODULE_SCOPE_FN.to_string(), facts);
    let mut cursor = root.walk();
    let children: Vec<_> = root.named_children(&mut cursor).collect();
    for child in children {
        let owned = owns_decls && declares_at_module_scope(child, spec);
        if module_scope_skip(child, spec) && !owned {
            continue;
        }
        ctx.visit_node(child);
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
/// there IS module-level code: a file of nothing but function declarations and
/// initialisers keeps the per-binding static IRs it always had, which is what
/// keeps corpus fact extraction stable.
pub(crate) fn owns_declarations(
    root: Node,
    spec: &'static dyn frensense_lang::spec::LanguageSpec,
) -> bool {
    let mut cursor = root.walk();
    let children: Vec<_> = root.named_children(&mut cursor).collect();
    children.iter().any(|c| !module_scope_skip(*c, spec))
        && children.iter().any(|c| declares_at_module_scope(*c, spec))
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
