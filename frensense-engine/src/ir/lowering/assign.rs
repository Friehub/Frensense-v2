// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use crate::ir::lowering::lvalue::LValue;
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    pub fn visit_assignment(
        &mut self,
        node: Node,
        lhs_field: &'static str,
        rhs_field: &'static str,
    ) -> Option<Operand> {
        let left_node = node.child_by_field_name(lhs_field)?;
        let right_node = node.child_by_field_name(rhs_field)?;

        let rhs_op = self.visit_node(right_node).unwrap_or(Operand::Unknown);
        let lval = self.visit_lvalue(left_node);

        match lval {
            Some(LValue::Variable(dest)) => {
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::Assign { dest, src: rhs_op },
                );
            }
            Some(LValue::Field { base, field }) => {
                // Memory Mutation! Consumes self.memory_var, and re-assigns it.
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
            Some(LValue::Element { base, index }) => {
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
            None => {}
        }
        None
    }
}
