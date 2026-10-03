// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::{LoopTarget, LoweringContext};
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

        // A preceding `break`/`return` already terminated this block.
        if self
            .ir
            .blocks
            .get(&self.current_block)
            .is_none_or(|b| matches!(b.terminator, Terminator::None))
        {
            self.ir
                .set_terminator(self.current_block, Terminator::Jump(loop_header));
            self.ir.add_edge(self.current_block, loop_header);
        }

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

        self.loop_stack.push(LoopTarget {
            break_target: loop_exit,
            continue_target: Some(loop_header),
        });

        // Body
        self.current_block = loop_body;
        self.env.push(FxHashMap::default());
        if let Some(body) = body {
            self.visit_node(body);
        }
        // A body ending in `break`/`continue`/`return` owns its edge.
        if self
            .ir
            .blocks
            .get(&self.current_block)
            .is_none_or(|b| matches!(b.terminator, Terminator::None))
        {
            self.ir
                .set_terminator(self.current_block, Terminator::Jump(loop_header));
            self.ir.add_edge(self.current_block, loop_header);
        }
        self.env.pop();
        self.loop_stack.pop();

        self.current_block = loop_exit;
        None
    }

    /// `switch (expr) { case v: ... default: ... }` lowers to a condition
    /// chain: each `expr == v` dispatches to its case body, and an unmatched
    /// value falls to `default` (or the merge when there is none). Case
    /// bodies fall through to the next body in source order, matching C/JS
    /// semantics; `break` jumps to the merge. The condition is evaluated
    /// once, in the dispatch block.
    pub fn visit_switch(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let children: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.is_named())
            .collect();

        let is_body =
            |k: &str| k.contains("block") || k.contains("statement") || k.ends_with("body");
        let body = node
            .child_by_field_name("body")
            .or_else(|| children.iter().copied().find(|c| is_body(c.kind())));
        let cond_node = node
            .child_by_field_name("condition")
            .or_else(|| children.iter().copied().find(|c| !is_body(c.kind())));

        // Clause layout: `case_statement` (C), `switch_case`/`switch_default`
        // (JS/TS). The value node (absent on `default`) is the first named
        // child that is not itself a statement.
        let mut clauses: Vec<(Option<Node>, Vec<Node>)> = Vec::new();
        if let Some(body) = body {
            let mut body_cursor = body.walk();
            for clause in body.named_children(&mut body_cursor) {
                let kind = clause.kind();
                if !(kind.contains("case") || kind.contains("default")) {
                    continue;
                }
                let mut clause_cursor = clause.walk();
                let kids: Vec<Node> = clause.named_children(&mut clause_cursor).collect();
                let value_pos = kids.iter().position(|n| {
                    let k = n.kind();
                    !k.contains("statement") && k != "compound_statement"
                });
                let value = value_pos.map(|i| kids[i]);
                let stmts: Vec<Node> = kids
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| Some(*i) != value_pos)
                    .map(|(_, n)| *n)
                    .collect();
                clauses.push((value, stmts));
            }
        }
        if clauses.is_empty() {
            // Not a recognized switch shape: keep the coarse generic walk.
            return self.visit_children_generic(node);
        }

        let cond_op = cond_node
            .and_then(|c| self.visit_node(c))
            .unwrap_or(Operand::Unknown);

        let merge_block = self.ir.new_block();
        let bodies: Vec<BlockId> = clauses.iter().map(|_| self.ir.new_block()).collect();
        let default_idx = clauses.iter().position(|(v, _)| v.is_none());
        let value_idx: Vec<usize> = (0..clauses.len())
            .filter(|&i| clauses[i].0.is_some())
            .collect();

        self.loop_stack.push(LoopTarget {
            break_target: merge_block,
            continue_target: None,
        });
        self.env.push(FxHashMap::default());

        // Condition chain: entries[0] is the dispatch block that just
        // evaluated `expr`; later entries are fresh blocks.
        let mut entries: Vec<BlockId> = Vec::with_capacity(value_idx.len());
        for n in 0..value_idx.len() {
            entries.push(if n == 0 {
                self.current_block
            } else {
                self.ir.new_block()
            });
        }
        for (n, &ci) in value_idx.iter().enumerate() {
            let entry = entries[n];
            let false_next = if n + 1 < value_idx.len() {
                entries[n + 1]
            } else if let Some(d) = default_idx {
                bodies[d]
            } else {
                merge_block
            };
            self.current_block = entry;
            let value_op = clauses[ci]
                .0
                .and_then(|v| self.visit_node(v))
                .unwrap_or(Operand::Unknown);
            let eq = self.new_temp(node);
            self.ir.push_instruction(
                entry,
                Instruction::BinaryOp {
                    dest: eq,
                    op: "==".to_string(),
                    lhs: cond_op.clone(),
                    rhs: value_op,
                },
            );
            self.ir.set_terminator(
                entry,
                Terminator::Branch {
                    cond: Operand::Var(eq),
                    true_block: bodies[ci],
                    false_block: false_next,
                },
            );
            self.ir.add_edge(entry, bodies[ci]);
            self.ir.add_edge(entry, false_next);
        }
        // A switch with only `default` (or no condition) always takes it.
        if value_idx.is_empty()
            && let Some(d) = default_idx
            && self
                .ir
                .blocks
                .get(&self.current_block)
                .is_none_or(|b| matches!(b.terminator, Terminator::None))
        {
            self.ir
                .set_terminator(self.current_block, Terminator::Jump(bodies[d]));
            self.ir.add_edge(self.current_block, bodies[d]);
        }

        // Case bodies, in source order: each falls through to the next.
        for (i, (_, stmts)) in clauses.iter().enumerate() {
            self.current_block = bodies[i];
            for stmt in stmts {
                self.visit_node(*stmt);
            }
            if self
                .ir
                .blocks
                .get(&self.current_block)
                .is_none_or(|b| matches!(b.terminator, Terminator::None))
            {
                let fall = if i + 1 < clauses.len() {
                    bodies[i + 1]
                } else {
                    merge_block
                };
                self.ir
                    .set_terminator(self.current_block, Terminator::Jump(fall));
                self.ir.add_edge(self.current_block, fall);
            }
        }

        self.env.pop();
        self.loop_stack.pop();
        self.current_block = merge_block;
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
                    declared: false,
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
            declared: false,
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

        // Go-style switches lower here as a branch; C/JS `switch` goes to
        // `visit_switch`. An unlabeled `break` inside such a branch must
        // exit the switch (jump to the merge), not the enclosing loop.
        let is_switch = node.kind().contains("switch");
        if is_switch {
            self.loop_stack.push(LoopTarget {
                break_target: merge_block,
                continue_target: None,
            });
        }

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

        if is_switch {
            self.loop_stack.pop();
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

    pub fn visit_goto(&mut self, node: Node) -> Option<Operand> {
        let label_name = node
            .child_by_field_name("label")
            .or_else(|| {
                let mut c = node.walk();
                node.named_children(&mut c)
                    .find(|n| n.kind() == "statement_identifier" || n.kind() == "identifier")
            })
            .map(|n| self.source[n.start_byte()..n.end_byte()].trim().to_string());

        if let Some(name) = label_name {
            let target_block = self.get_or_create_label_block(&name);
            if self
                .ir
                .blocks
                .get(&self.current_block)
                .is_none_or(|b| matches!(b.terminator, Terminator::None))
            {
                self.ir
                    .set_terminator(self.current_block, Terminator::Jump(target_block));
                self.ir.add_edge(self.current_block, target_block);
            }
            self.current_block = self.ir.new_block();
        }
        None
    }

    /// An unlabeled `break` leaves the innermost loop or switch. Labeled
    /// `break label;` keeps the generic walk: labels lower as goto targets,
    /// not break targets.
    pub fn visit_break(&mut self, node: Node) -> Option<Operand> {
        if has_break_label(node) {
            return None;
        }
        let target = self.loop_stack.last().map(|t| t.break_target)?;
        self.jump_to(target);
        None
    }

    /// An unlabeled `continue` jumps to the innermost loop header, skipping
    /// the rest of the body. Switches on the stack contribute no continue
    /// target, so a `continue` inside a switch still reaches the loop.
    pub fn visit_continue(&mut self, node: Node) -> Option<Operand> {
        if has_break_label(node) {
            return None;
        }
        let target = self
            .loop_stack
            .iter()
            .rev()
            .find_map(|t| t.continue_target)?;
        self.jump_to(target);
        None
    }

    /// Terminate the current block with a jump to `target`, then move to a
    /// fresh block so any following statements lower as unreachable code.
    fn jump_to(&mut self, target: BlockId) {
        if self
            .ir
            .blocks
            .get(&self.current_block)
            .is_none_or(|b| matches!(b.terminator, Terminator::None))
        {
            self.ir
                .set_terminator(self.current_block, Terminator::Jump(target));
            self.ir.add_edge(self.current_block, target);
        }
        self.current_block = self.ir.new_block();
    }

    pub fn visit_labeled_statement(&mut self, node: Node) -> Option<Operand> {
        let label_name = node
            .child_by_field_name("label")
            .or_else(|| {
                let mut c = node.walk();
                node.named_children(&mut c)
                    .find(|n| n.kind() == "statement_identifier" || n.kind() == "identifier")
            })
            .map(|n| self.source[n.start_byte()..n.end_byte()].trim().to_string());

        if let Some(name) = label_name {
            let label_block = self.get_or_create_label_block(&name);
            if self
                .ir
                .blocks
                .get(&self.current_block)
                .is_none_or(|b| matches!(b.terminator, Terminator::None))
            {
                self.ir
                    .set_terminator(self.current_block, Terminator::Jump(label_block));
                self.ir.add_edge(self.current_block, label_block);
            }
            self.current_block = label_block;
        }

        let inner_stmt = node.child_by_field_name("statement").or_else(|| {
            let mut c = node.walk();
            node.named_children(&mut c)
                .find(|n| n.kind() != "statement_identifier" && n.kind() != "identifier")
        });

        if let Some(stmt) = inner_stmt {
            self.visit_node(stmt);
        }
        None
    }
}

/// True for `break label;` / `continue label;` - the optional label is a
/// named `statement_identifier`/`identifier` child (never present in C).
fn has_break_label(node: Node) -> bool {
    if node.child_by_field_name("label").is_some() {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|n| matches!(n.kind(), "statement_identifier" | "identifier"))
}
