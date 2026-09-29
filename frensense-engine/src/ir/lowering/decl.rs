// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use crate::ir::lowering::lvalue::LValue;
use frensense_lang::NodeRole;
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    pub fn visit_declaration(
        &mut self,
        node: Node,
        name_field: &'static str,
        value_field: &'static str,
    ) -> Option<Operand> {
        // `const name = value;`, bind the name in the current scope.
        // If the node itself carries a name (variable_declarator),
        // lower the value and record the binding. Container statements
        // (lexical_declaration) have no name/value fields and fall
        // through to the child walk, which re-enters here per
        // declarator.
        let value_node = node.child_by_field_name(value_field);
        let name_node = node
            .child_by_field_name(name_field)
            .map(|n| self.spec.unwrap_declarator_node(n));

        match (name_node, value_node) {
            (Some(name_node), Some(value_node))
                if matches!(self.classify_node(name_node.kind()), NodeRole::Identifier) =>
            {
                // Simple `const name = value`.
                let rhs_op = self.visit_node(value_node).unwrap_or(Operand::Unknown);
                if let Operand::Var(dest) = self.resolve_identifier(name_node) {
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::Assign { dest, src: rhs_op },
                    );
                }
                None
            }
            (Some(pattern), Some(value_node)) if self.is_destructuring_pattern(pattern.kind()) => {
                // Destructuring: `const { a: x, b } = obj`.
                // Lower the RHS first (it defines the base value).
                let base_op = self.visit_node(value_node);
                if let Some(Operand::Var(base)) = base_op {
                    let mut pc = pattern.walk();
                    for sub in pattern.named_children(&mut pc) {
                        // `key: sub_name` or shorthand `name`.
                        let (prop, target) = if self.is_pair_pattern(sub.kind()) {
                            let k = sub.child_by_field_name("key");
                            let v = sub.child_by_field_name("value");
                            match (k, v) {
                                (Some(k), Some(v)) => (Some(k), Some(v)),
                                _ => (None, None),
                            }
                        } else {
                            (Some(sub), Some(sub))
                        };
                        if let (Some(k), Some(v)) = (prop, target) {
                            let field = self.source[k.start_byte()..k.end_byte()].to_string();
                            if let Operand::Var(dest) = self.resolve_identifier(v) {
                                self.ir.push_instruction(
                                    self.current_block,
                                    Instruction::LoadField {
                                        dest,
                                        mem_in: self.memory_var,
                                        base,
                                        field,
                                    },
                                );
                            }
                        }
                    }
                }
                None
            }
            (Some(lhs), Some(value_node)) if self.is_declaration_assignment(lhs.kind()) => {
                // Python-style member/element store: `m['k'] = v`,
                // `obj.attr = v`. Without this arm the Declaration
                // fall-through re-visits the LHS as an r-value read
                // and the store (and its taint) is lost entirely.
                let rhs_op = self.visit_node(value_node).unwrap_or(Operand::Unknown);
                if let Some(lval) = self.visit_lvalue(lhs) {
                    match lval {
                        LValue::Variable(dest) => {
                            self.ir.push_instruction(
                                self.current_block,
                                Instruction::Assign { dest, src: rhs_op },
                            );
                        }
                        LValue::Field { base, field } => {
                            self.ir.push_instruction(
                                self.current_block,
                                Instruction::StoreField {
                                    mem_out: self.memory_var,
                                    mem_in: self.memory_var,
                                    base,
                                    field,
                                    src: rhs_op,
                                },
                            );
                        }
                        LValue::Element { base, index } => {
                            self.ir.push_instruction(
                                self.current_block,
                                Instruction::StoreElement {
                                    mem_out: self.memory_var,
                                    mem_in: self.memory_var,
                                    base,
                                    index,
                                    src: rhs_op,
                                },
                            );
                        }
                    }
                }
                None
            }
            _ => {
                // Container: lower children (each declarator hits the
                // (name, value) arm above).
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.is_named() {
                        self.visit_node(child);
                    }
                }
                None
            }
        }
    }
}
