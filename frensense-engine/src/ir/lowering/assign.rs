// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use crate::ir::lowering::lvalue::LValue;
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    /// Compound part of an assignment node's operator: `*=` → `*`, `+=` → `+`.
    ///
    /// Languages spell compound assignment as an anonymous token between the
    /// lhs/rhs fields (`alloc *= 2` in C, `x += 1` in Python/Rust/Go/JS).
    /// Lowering it as a plain `=` silently drops the read-modify-write and
    /// const-folds the variable to the RHS literal - e.g. `alloc *= 2` became
    /// `alloc = 2`, shrinking malloc capacities and firing false overflows.
    /// Returns `None` for plain assignment (`=`, `:=`) or no operator token,
    /// which keep the plain-store lowering.
    fn compound_operator(&self, node: Node) -> Option<String> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.is_named() || child.kind() == "comment" {
                continue;
            }
            let text = self.source[child.start_byte()..child.end_byte()].trim();
            if text.is_empty() {
                continue;
            }
            if text == "=" || text == ":=" {
                return None;
            }
            let stripped = text.strip_suffix('=')?;
            if stripped.is_empty() || stripped == ":" {
                return None;
            }
            return Some(stripped.to_string());
        }
        None
    }

    pub fn visit_assignment(
        &mut self,
        node: Node,
        lhs_field: &str,
        rhs_field: &str,
    ) -> Option<Operand> {
        let left_node = node.child_by_field_name(lhs_field)?;
        let right_node = node.child_by_field_name(rhs_field)?;

        let rhs_op = self.visit_node(right_node).unwrap_or(Operand::Unknown);
        let compound = self.compound_operator(node);
        let lval = self.visit_lvalue(left_node);

        match lval {
            Some(LValue::Variable(dest)) => match &compound {
                Some(op) => {
                    // dest = dest <op> rhs
                    let tmp = self.new_temp(node);
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::BinaryOp {
                            dest: tmp,
                            op: op.clone(),
                            lhs: Operand::Var(dest),
                            rhs: rhs_op,
                        },
                    );
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::Assign {
                            dest,
                            src: Operand::Var(tmp),
                        },
                    );
                }
                None => {
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::Assign { dest, src: rhs_op },
                    );
                }
            },
            Some(LValue::Field { base, field }) => {
                let src = match &compound {
                    Some(op) => {
                        // Read the current field value before overwriting it.
                        let cur = self.new_temp(node);
                        self.ir.push_instruction(
                            self.current_block,
                            Instruction::LoadField {
                                dest: cur,
                                mem_in: self.memory_var,
                                base,
                                field: field.clone(),
                            },
                        );
                        let tmp = self.new_temp(node);
                        self.ir.push_instruction(
                            self.current_block,
                            Instruction::BinaryOp {
                                dest: tmp,
                                op: op.clone(),
                                lhs: Operand::Var(cur),
                                rhs: rhs_op,
                            },
                        );
                        Operand::Var(tmp)
                    }
                    None => rhs_op,
                };
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::StoreField {
                        mem_out: self.memory_var,
                        mem_in: self.memory_var,
                        base,
                        field,
                        src,
                    },
                );
            }
            Some(LValue::Element { base, index }) => {
                let src = match &compound {
                    Some(op) => {
                        let cur = self.new_temp(node);
                        self.ir.push_instruction(
                            self.current_block,
                            Instruction::LoadElement {
                                dest: cur,
                                mem_in: self.memory_var,
                                base,
                                index: index.clone(),
                            },
                        );
                        let tmp = self.new_temp(node);
                        self.ir.push_instruction(
                            self.current_block,
                            Instruction::BinaryOp {
                                dest: tmp,
                                op: op.clone(),
                                lhs: Operand::Var(cur),
                                rhs: rhs_op,
                            },
                        );
                        Operand::Var(tmp)
                    }
                    None => rhs_op,
                };
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::StoreElement {
                        mem_out: self.memory_var,
                        mem_in: self.memory_var,
                        base,
                        index,
                        src,
                    },
                );
            }
            None => {}
        }
        None
    }
}
