// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    pub fn visit_binary_op(&mut self, node: Node) -> Option<Operand> {
        let mut operands: Vec<Operand> = Vec::new();
        let mut operator: Option<String> = None;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if !child.is_named() {
                // The operator token (+, -, ||, ...) sits between
                // the operand children.
                let text = self.source[child.start_byte()..child.end_byte()].trim();
                if !text.is_empty() && operator.is_none() {
                    operator = Some(text.to_string());
                }
                continue;
            }
            if child.kind() == "comment" {
                continue;
            }
            if let Some(op) = self.visit_node(child) {
                operands.push(op);
            }
        }
        if operands.len() == 1 {
            // Degenerate single-operand form, pass through.
            return Some(operands.pop().unwrap());
        }
        if operands.is_empty() {
            return Some(Operand::Unknown);
        }
        // String concatenation is semantically significant for taint
        // (`"...' + id + "'"` builds a query); record the operator so
        // later constraint/value tracking can classify the shape.
        let op_name = match operator.as_deref() {
            Some("+") | None => "concat".to_string(),
            Some(o) => o.to_string(),
        };
        // Fold operands left-associative: ((a op b) op c).
        let mut it = operands.into_iter();
        let mut acc = it.next().unwrap();
        for rhs in it {
            let next_dest = self.ir.new_var(VarMetadata {
                source_name: None,
                type_name: None,
                byte_range: Some((node.start_byte(), node.end_byte())),
                is_memory_state: false,
                object_keys: Vec::new(),
            });
            self.ir.push_instruction(
                self.current_block,
                Instruction::BinaryOp {
                    dest: next_dest,
                    op: op_name.clone(),
                    lhs: acc,
                    rhs: rhs.clone(),
                },
            );
            acc = Operand::Var(next_dest);
        }
        Some(acc)
    }

    pub fn visit_unary_op(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let operand = node
            .children(&mut cursor)
            .find(|c| c.is_named() && c.kind() != "comment")
            .and_then(|c| self.visit_node(c))
            .unwrap_or(Operand::Unknown);
        let dest = self.ir.new_var(VarMetadata {
            source_name: None,
            type_name: None,
            byte_range: Some((node.start_byte(), node.end_byte())),
            is_memory_state: false,
            object_keys: Vec::new(),
        });
        self.ir.push_instruction(
            self.current_block,
            Instruction::UnaryOp {
                dest,
                op: "neg".into(),
                src: operand,
            },
        );
        Some(Operand::Var(dest))
    }

    pub fn visit_member_access(
        &mut self,
        node: Node,
        object_field: &'static str,
        property_field: &'static str,
    ) -> Option<Operand> {
        let obj_node = node.child_by_field_name(object_field)?;
        let prop_node = node.child_by_field_name(property_field)?;

        let base_op = self.visit_node(obj_node)?;

        if let Operand::Var(base_var) = base_op {
            let dest = self.ir.new_var(VarMetadata {
                source_name: None,
                type_name: None,
                // Span needed: sink findings resolve file/line from
                // the tainted operand's byte_range. Without it, a
                // member read passed directly to a sink reports line 0.
                byte_range: Some((node.start_byte(), node.end_byte())),
                is_memory_state: false,
                object_keys: Vec::new(),
            });
            match self.visit_node(prop_node) {
                Some(Operand::Var(index_var)) if !self.is_property_kind(prop_node.kind()) => {
                    // Subscript with a computed index.
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::LoadElement {
                            dest,
                            mem_in: self.memory_var,
                            base: base_var,
                            index: Operand::Var(index_var),
                        },
                    );
                }
                _ => {
                    let field_name =
                        self.source[prop_node.start_byte()..prop_node.end_byte()].to_string();
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::LoadField {
                            dest,
                            mem_in: self.memory_var,
                            base: base_var,
                            field: field_name,
                        },
                    );
                }
            }
            Some(Operand::Var(dest))
        } else {
            None
        }
    }

    pub fn visit_composite(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let child_ops: Vec<Operand> = node
            .children(&mut cursor)
            .filter(|c| c.is_named() && c.kind() != "comment")
            .filter_map(|c| self.visit_node(c))
            .collect();
        // Pair keys (`pair` = `key: value` inside an object literal)
        // are remembered on the composite's var so sinks can classify
        // the argument *shape* (object payload vs raw value).
        let mut pair_keys: Vec<String> = Vec::new();
        let mut kcursor = node.walk();
        for c in node.children(&mut kcursor) {
            if c.is_named()
                && self.is_pair_entry(c.kind())
                && let Some(key) = c.child_by_field_name("key")
            {
                let ktext = &self.source[key.start_byte()..key.end_byte()];
                pair_keys.push(ktext.trim_matches(|ch| ch == '"' || ch == '\'').to_string());
            }
        }
        let var_ops: Vec<Operand> = child_ops
            .iter()
            .filter(|op| matches!(op, Operand::Var(_)))
            .cloned()
            .collect();
        match var_ops.len() {
            0 => child_ops.into_iter().next(),
            // Single var child: collapse transparently, but carry the
            // pair keys over so shape classification still works.
            1 => {
                if let Some(Operand::Var(v)) = var_ops.first()
                    && let Some(meta) = self.ir.var_metadata.get_mut(v)
                {
                    meta.object_keys = pair_keys;
                }
                var_ops.into_iter().next()
            }
            _ => {
                let dest = self.ir.new_var(VarMetadata {
                    source_name: None,
                    type_name: None,
                    byte_range: Some((node.start_byte(), node.end_byte())),
                    is_memory_state: false,
                    object_keys: pair_keys,
                });
                for op in var_ops {
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::Assign { dest, src: op },
                    );
                }
                Some(Operand::Var(dest))
            }
        }
    }

    pub fn visit_literal(&mut self, node: Node) -> Option<Operand> {
        if self.is_template_string(node.kind())
            || node.kind() == "string"
            || node.kind() == "binary_expression"
        {
            let mut cursor = node.walk();
            let mut last_op = None;
            for child in node.children(&mut cursor) {
                if child.is_named()
                    && !self.is_template_fragment(child.kind())
                    && let Some(op) = self.visit_node(child)
                {
                    last_op = Some(op);
                }
            }
            match last_op {
                Some(op) => Some(op),
                None => {
                    let text = &self.source[node.start_byte()..node.end_byte()];
                    Some(Operand::StringLiteral(text.to_string()))
                }
            }
        } else {
            let text = &self.source[node.start_byte()..node.end_byte()];
            if let Ok(i) = text.parse::<i64>() {
                Some(Operand::IntLiteral(i))
            } else {
                Some(Operand::StringLiteral(text.to_string()))
            }
        }
    }

    pub fn visit_cast(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let mut first = None;
        for child in node.children(&mut cursor) {
            if child.is_named() && child.kind() != "comment" && first.is_none() {
                first = self.visit_node(child);
            }
        }
        first
    }
}
