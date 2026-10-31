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

    /// `a, b` on the left of `=` / `:=`: a list of two or more targets.
    pub(super) fn is_multi_target(node: Node) -> bool {
        matches!(
            node.kind(),
            "expression_list" | "identifier_list" | "pattern_list" | "tuple_pattern"
        ) && node.named_child_count() > 1
    }

    /// Bind `rhs` to every plain-variable element of a multi-target list;
    /// `_` is skipped. The right side is a tuple, so any element may carry
    /// the taint.
    pub(super) fn bind_each_target(&mut self, list: Node, rhs: Operand) {
        let mut cursor = list.walk();
        let targets: Vec<Node> = list.named_children(&mut cursor).collect();
        for target in targets {
            if self.source[target.start_byte()..target.end_byte()].trim() == "_" {
                continue;
            }
            if let Some(LValue::Variable(dest)) = self.visit_lvalue(target) {
                self.mark_declared(dest);
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::Assign {
                        dest,
                        src: rhs.clone(),
                    },
                );
            }
        }
    }

    pub fn visit_assignment(
        &mut self,
        node: Node,
        lhs_field: &str,
        rhs_field: &str,
    ) -> Option<Operand> {
        // Some grammars wrap the target and/or value in a list node: Go's
        // `assignment_statement` gives `expression_list` for both sides, so
        // `q = v` reached `visit_lvalue(expression_list)` (role Other) and the
        // store was dropped entirely - taint assigned inside an `if`/loop
        // body never reached the variable read after the join. Unwrap the
        // single-target form the same way declarations already do
        // (`short_var_declaration` was unaffected, which is why its binding
        // survived while plain assignment did not).
        let left_node = self
            .spec
            .unwrap_declarator_node(node.child_by_field_name(lhs_field)?);
        let right_node = self
            .spec
            .unwrap_declarator_node(node.child_by_field_name(rhs_field)?);

        let rhs_op = self.visit_node(right_node).unwrap_or(Operand::Unknown);
        let compound = self.compound_operator(node);

        // Multi-target form (`body, err := f(x)`, `a, b = g()`): the call's
        // result is a tuple, and any element of it can carry the taint. The
        // single-target path below saw an `expression_list` lvalue and
        // dropped the binding, so every Go `v, err :=` and Python tuple
        // unpack lost its value flow.
        if compound.is_none() && Self::is_multi_target(left_node) {
            self.bind_each_target(left_node, rhs_op.clone());
            return Some(rhs_op);
        }
        let lval = self.visit_lvalue(left_node);
        // The value of an assignment expression is the assigned variable:
        // `if (!(p = malloc(n)))`, `while ((c = next()) != EOF)`,
        // `a = b = c`. It used to be Unknown, so a condition over an
        // assignment hid its operand and null-guard proofs never matched
        // (the leak check reported the failed-allocation path as a leak).
        let result = match &lval {
            Some(LValue::Variable(dest)) => Some(Operand::Var(*dest)),
            _ => None,
        };

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
        result
    }
}
