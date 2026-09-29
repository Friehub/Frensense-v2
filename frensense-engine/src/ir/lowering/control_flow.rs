// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use rustc_hash::FxHashMap;
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    pub fn visit_loop(&mut self, node: Node) -> Option<Operand> {
        // Find condition and body children by grammar convention.
        let mut cursor = node.walk();
        let children: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.is_named())
            .collect();

        // Heuristic across grammars: the last named child that is a
        // statement/block is the body; the condition is the operand
        // expression just before it (for `for` loops this is coarse,
        // acceptable: the condition only affects branch pruning).
        let body = children
            .iter()
            .rev()
            .find(|c| {
                let k = c.kind();
                k.contains("statement") || k == "block" || k.contains("block")
            })
            .copied();
        let cond = children
            .iter()
            .find(|c| {
                let k = c.kind();
                !k.contains("statement")
                    && k != "block"
                    && !k.contains("block")
                    && !k.contains("declarator")
                    && !k.contains("update")
                    && !k.contains("initializer")
            })
            .copied();

        let loop_header = self.ir.new_block();
        let loop_body = self.ir.new_block();
        let loop_exit = self.ir.new_block();

        self.ir
            .set_terminator(self.current_block, Terminator::Jump(loop_header));
        self.ir.add_edge(self.current_block, loop_header);

        // Header (Evaluate Condition)
        self.current_block = loop_header;
        let cond_op = cond
            .and_then(|c| self.visit_node(c))
            .unwrap_or(Operand::Unknown);
        self.ir.set_terminator(
            self.current_block,
            Terminator::Branch {
                cond: cond_op,
                true_block: loop_body,
                false_block: loop_exit,
            },
        );
        self.ir.add_edge(self.current_block, loop_body);
        self.ir.add_edge(self.current_block, loop_exit);

        // Body
        self.current_block = loop_body;
        self.env.push(FxHashMap::default());
        if let Some(body) = body {
            self.visit_node(body);
        }
        self.ir
            .set_terminator(self.current_block, Terminator::Jump(loop_header));
        self.ir.add_edge(self.current_block, loop_header);
        self.env.pop();

        self.current_block = loop_exit;
        None
    }

    pub fn visit_ternary_straight_line(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let children: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.is_named() && c.kind() != "comment")
            .collect();
        // JS grammar: [condition, consequence, alternative]
        if children.len() != 3 {
            // Malformed ternary: fall through to generic child walk.
            return self.visit_children_generic(node);
        }

        // Condition and both arms evaluated in the current block.
        // Side effects in the condition/arms still lower to their
        // instructions; only control-flow precision is lost.
        let _ = self.visit_node(children[0]).unwrap_or(Operand::Unknown);
        let true_val = self.visit_node(children[1]);
        let false_val = self.visit_node(children[2]);

        // Merge: prefer a fresh var assigned from the first var-valued
        // arm (preserves one def site for SVFG edges). A literal arm
        // carries no taint, so the var arm dominates the may-analysis.
        match (true_val, false_val) {
            (Some(Operand::Var(tv)), Some(Operand::Var(fv))) => {
                let dest = self.ir.new_var(VarMetadata {
                    source_name: None,
                    type_name: None,
                    byte_range: Some((node.start_byte(), node.end_byte())),
                    is_memory_state: false,
                    object_keys: Vec::new(),
                });
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::Assign {
                        dest,
                        src: Operand::Var(tv),
                    },
                );
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::Assign {
                        dest,
                        src: Operand::Var(fv),
                    },
                );
                Some(Operand::Var(dest))
            }
            // One arm is a var, other is a constant: the var survives;
            // only the tainted arm matters for alerts.
            (Some(Operand::Var(v)), Some(_)) | (Some(_), Some(Operand::Var(v))) => {
                Some(Operand::Var(v))
            }
            (Some(v), None) | (None, Some(v)) => Some(v),
            (None, None) => None,
            // Both constants: fold to the first, neither carries taint.
            (a, b) => a.or(b),
        }
    }

    pub fn visit_conditional(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let children: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.is_named())
            .collect();
        if children.len() < 3 {
            // Degenerate: fall through the generic child walk.
            return self.visit_children_generic(node);
        }
        let cond_idx = self.spec.ternary_cond_index().min(children.len() - 1);
        let cond_node = children[cond_idx];
        let (then_node, else_node) = if cond_idx == 0 {
            // JS/C layout: [cond, then, else].
            (children[1], children[2])
        } else {
            // Python layout: [then, cond, else].
            (children[0], children[2])
        };

        let cond_op = self.visit_node(cond_node).unwrap_or(Operand::Unknown);

        let dest = self.ir.new_var(VarMetadata {
            source_name: None,
            type_name: None,
            byte_range: Some((node.start_byte(), node.end_byte())),
            is_memory_state: false,
            object_keys: Vec::new(),
        });

        let true_block = self.ir.new_block();
        let false_block = self.ir.new_block();
        let merge_block = self.ir.new_block();
        self.ir.set_terminator(
            self.current_block,
            Terminator::Branch {
                cond: cond_op,
                true_block,
                false_block,
            },
        );
        self.ir.add_edge(self.current_block, true_block);
        self.ir.add_edge(self.current_block, false_block);

        // Then arm: bind the merge var.
        self.env.push(FxHashMap::default());
        self.current_block = true_block;
        let then_op = self.visit_node(then_node).unwrap_or(Operand::Unknown);
        self.ir.push_instruction(
            self.current_block,
            Instruction::Assign { dest, src: then_op },
        );
        self.ir
            .set_terminator(self.current_block, Terminator::Jump(merge_block));
        self.ir.add_edge(self.current_block, merge_block);
        self.env.pop();

        // Else arm: bind the same merge var.
        self.env.push(FxHashMap::default());
        self.current_block = false_block;
        let else_op = self.visit_node(else_node).unwrap_or(Operand::Unknown);
        self.ir.push_instruction(
            self.current_block,
            Instruction::Assign { dest, src: else_op },
        );
        self.ir
            .set_terminator(self.current_block, Terminator::Jump(merge_block));
        self.ir.add_edge(self.current_block, merge_block);
        self.env.pop();

        self.current_block = merge_block;
        Some(Operand::Var(dest))
    }

    pub fn visit_branch(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let children: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.is_named())
            .collect();

        let cond_node = children
            .iter()
            .find(|c| {
                let k = c.kind();
                !k.contains("statement") && k != "block" && k != "else_clause"
            })
            .copied();
        let cons_node = children
            .iter()
            .find(|c| {
                let k = c.kind();
                k.contains("statement") || k.contains("block")
            })
            .copied();
        let alt_node = children.iter().find(|c| c.kind().contains("else")).copied();

        let cond_op = cond_node
            .and_then(|c| self.visit_node(c))
            .unwrap_or(Operand::Unknown);

        let true_block = self.ir.new_block();
        let false_block = self.ir.new_block();
        let merge_block = self.ir.new_block();

        let false_target = if alt_node.is_some() {
            false_block
        } else {
            merge_block
        };

        self.ir.set_terminator(
            self.current_block,
            Terminator::Branch {
                cond: cond_op,
                true_block,
                false_block: false_target,
            },
        );
        self.ir.add_edge(self.current_block, true_block);
        self.ir.add_edge(self.current_block, false_target);

        // True Branch
        self.env.push(FxHashMap::default());
        self.current_block = true_block;
        if let Some(cons) = cons_node {
            self.visit_node(cons);
        }
        if self
            .ir
            .blocks
            .get(&self.current_block)
            .is_none_or(|b| matches!(b.terminator, Terminator::None))
        {
            self.ir
                .set_terminator(self.current_block, Terminator::Jump(merge_block));
            self.ir.add_edge(self.current_block, merge_block);
        }
        self.env.pop();

        // False Branch
        if let Some(alt) = alt_node {
            self.env.push(FxHashMap::default());
            self.current_block = false_block;
            self.visit_node(alt);
            if self
                .ir
                .blocks
                .get(&self.current_block)
                .is_none_or(|b| matches!(b.terminator, Terminator::None))
            {
                self.ir
                    .set_terminator(self.current_block, Terminator::Jump(merge_block));
                self.ir.add_edge(self.current_block, merge_block);
            }
            self.env.pop();
        }

        self.current_block = merge_block;
        None
    }

    pub fn visit_return(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let value: Option<Operand> = node
            .named_children(&mut cursor)
            .find(|c| c.kind() != "comment")
            .and_then(|c| self.visit_node(c));
        self.ir
            .set_terminator(self.current_block, Terminator::Return { src: value });
        None
    }
}
