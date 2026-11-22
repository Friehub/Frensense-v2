// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Phase 1.5: AST Lowering Pass
//!
//! This module traverses the `tree-sitter` AST using `frensense-lang` and
//! builds the Unstructured FunctionIR.
//!
//! Integrates Memory SSA: heap state is tracked via `self.memory_var` and
//! versioned into memory states by the SSA Builder.

/// Lowering of assignments to variables, fields and elements.
pub mod assign;
/// Lowering of call expressions.
pub mod call;
mod const_eval;
/// The per-function lowering state.
pub mod context;
/// Lowering of loops, branches, conditionals, `match`, returns and jumps.
pub(crate) mod control_flow;
/// Lowering of declarations.
pub mod decl;
/// Lowering of expressions: operators, member access, composite literals, literals and casts.
pub mod expr;
/// Classification of assignment targets.
pub(crate) mod lvalue;

pub(crate) use context::LoopTarget;
pub use context::LoweringContext;

use crate::ir::function::Operand;
use frensense_lang::{JsxPart, JumpKind, NodeRole};
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    /// Lowers one AST node into the current block, dispatching on the node's role (a learned bundle role first, then the language spec).
    ///
    /// Dispatch is by role (declaration, assignment, member access, call, loop, branch, match, return, try, operators, identifier, literal, composite), with a few grammar-specific cases the language spec answers (`is_switch_statement`, `jsx_part`, `is_preproc_conditional`, `jump_kind`). Function definitions are skipped, and any other node is lowered by walking its children.
    ///
    /// Returns the operand holding the node's value, or `None` for statements and nodes that produce no value.
    pub fn visit_node(&mut self, node: Node) -> Option<Operand> {
        let role = self.classify_node(node.kind());

        match role {
            // ─── MEMORY & VARIABLES ───────────────────────────────────────────
            NodeRole::Declaration {
                name_field,
                value_field,
            } => self.visit_declaration(node, &name_field, &value_field),

            NodeRole::Assignment {
                lhs_field,
                rhs_field,
            } => self.visit_assignment(node, &lhs_field, &rhs_field),

            NodeRole::MemberAccess {
                object_field,
                property_field,
            } => self.visit_member_access(node, &object_field, &property_field),

            // ─── CALLS ────────────────────────────────────────────────────────
            NodeRole::Call {
                callee_field,
                args_field,
            } => self.visit_call(node, &callee_field, &args_field),

            // ─── CONTROL FLOW ─────────────────────────────────────────────────
            NodeRole::Loop => self.visit_loop(node),

            // `switch` gets a real condition chain (case labels as
            // conditions) instead of the coarse branch-with-sequential-body.
            _ if self.spec.is_switch_statement(node.kind()) => self.visit_switch(node),

            // JSX element attributes are writes to a props object. Lowering
            // them as spanned field stores lets `<div dangerouslySetInnerHTML={…} />`
            // reach property-sink matching exactly like `el.innerHTML = …`.
            // Only the element forms carry props and children: an opening
            // element or a children run is lowered by its enclosing element,
            // so routing every JSX part here would duplicate their stores.
            _ if matches!(
                self.spec.jsx_part(node.kind()),
                Some(JsxPart::Element | JsxPart::SelfClosingElement | JsxPart::Fragment)
            ) =>
            {
                self.visit_jsx_element(node)
            }

            // C preprocessor chains: alternatives are exclusive configs.
            _ if self.spec.is_preproc_conditional(node.kind()) => {
                self.visit_preproc_conditional(node)
            }

            NodeRole::Branch if self.is_ternary_straight_line(node.kind()) => {
                self.visit_ternary_straight_line(node)
            }

            NodeRole::Conditional => self.visit_conditional(node),

            NodeRole::Branch => self.visit_branch(node),

            NodeRole::Match => self.visit_match(node),

            NodeRole::Return => self.visit_return(node),

            NodeRole::Try => self.visit_try(node),

            // ─── OPERATORS ────────────────────────────────────────────────────
            NodeRole::BinaryOp => self.visit_binary_op(node),

            NodeRole::UnaryOp => self.visit_unary_op(node),

            // ─── PRIMITIVES & COMPOSITES ──────────────────────────────────────
            NodeRole::Identifier => Some(self.resolve_identifier(node)),

            NodeRole::Other if self.is_cast(node.kind()) => self.visit_cast(node),

            NodeRole::Literal => self.visit_literal(node),

            NodeRole::Composite => self.visit_composite(node),

            // Function values own their body: extraction lowers them into a
            // dedicated IR (named, bound, route, or positional `<fn@N>`).
            // The enclosing IR contributes nothing for the node itself -
            // inlining a copy here duplicated every finding, policy hit, and
            // sink walk under two function names. Call sites resolve by name
            // (`CallStatic`); captures flow through closure edges.
            NodeRole::Function { .. } => None,

            _ if self.spec.jump_kind(node.kind()) == Some(JumpKind::Goto) => self.visit_goto(node),
            _ if self.spec.jump_kind(node.kind()) == Some(JumpKind::Label) => {
                self.visit_labeled_statement(node)
            }
            _ if self.spec.jump_kind(node.kind()) == Some(JumpKind::Break) => {
                self.visit_break(node)
            }
            _ if self.spec.jump_kind(node.kind()) == Some(JumpKind::Continue) => {
                self.visit_continue(node)
            }

            _ => self.visit_children_generic(node),
        }
    }
}

#[cfg(test)]
mod kind_migration_tests;

#[cfg(test)]
mod tests;
