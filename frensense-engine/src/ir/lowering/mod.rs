// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Phase 1.5: AST Lowering Pass
//!
//! This module traverses the `tree-sitter` AST using `frensense-lang` and
//! builds the Unstructured FunctionIR.
//!
//! Integrates Memory SSA: heap state is tracked via `self.memory_var` and
//! versioned into memory states by the SSA Builder.

pub mod assign;
pub mod call;
pub mod context;
pub mod control_flow;
pub mod decl;
pub mod expr;
pub mod lvalue;

pub use context::{LoopTarget, LoweringContext};
pub use lvalue::LValue;

use crate::ir::function::Operand;
use frensense_lang::NodeRole;
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    pub fn visit_node(&mut self, node: Node) -> Option<Operand> {
        let role = self.classify_node(node.kind());

        match role {
            // ─── MEMORY & VARIABLES ───────────────────────────────────────────
            NodeRole::Declaration {
                name_field,
                value_field,
            } => self.visit_declaration(node, name_field, value_field),

            NodeRole::Assignment {
                lhs_field,
                rhs_field,
            } => self.visit_assignment(node, lhs_field, rhs_field),

            NodeRole::MemberAccess {
                object_field,
                property_field,
            } => self.visit_member_access(node, object_field, property_field),

            // ─── CALLS ────────────────────────────────────────────────────────
            NodeRole::Call {
                callee_field,
                args_field,
            } => self.visit_call(node, callee_field, args_field),

            // ─── CONTROL FLOW ─────────────────────────────────────────────────
            NodeRole::Loop => self.visit_loop(node),

            // `switch` gets a real condition chain (case labels as
            // conditions) instead of the coarse branch-with-sequential-body.
            _ if node.kind() == "switch_statement" => self.visit_switch(node),

            NodeRole::Branch if self.is_ternary_straight_line(node.kind()) => {
                self.visit_ternary_straight_line(node)
            }

            NodeRole::Conditional => self.visit_conditional(node),

            NodeRole::Branch => self.visit_branch(node),

            NodeRole::Return => self.visit_return(node),

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

            _ if node.kind() == "goto_statement" => self.visit_goto(node),
            _ if node.kind() == "labeled_statement" => self.visit_labeled_statement(node),
            _ if node.kind() == "break_statement" => self.visit_break(node),
            _ if node.kind() == "continue_statement" => self.visit_continue(node),

            _ => self.visit_children_generic(node),
        }
    }
}

#[cfg(test)]
mod tests;
