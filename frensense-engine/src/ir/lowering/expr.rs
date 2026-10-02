// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use crate::ir::lowering::lvalue::LValue;
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
                declared: false,
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
        let mut operand_node = None;
        let mut op_node = None;
        for child in node.children(&mut cursor) {
            if child.kind() == "comment" {
                continue;
            }
            if child.is_named() {
                if operand_node.is_none() {
                    operand_node = Some(child);
                }
            } else if op_node.is_none() {
                let text = self.source[child.start_byte()..child.end_byte()].trim();
                if !text.is_empty() {
                    op_node = Some(child);
                }
            }
        }
        let op_text = op_node.map(|n| self.source[n.start_byte()..n.end_byte()].to_string());

        // Increment/decrement (`x++`, `--x`, `p[i]++`, `s->n++`): lowered as a
        // read-modify-write. Dropping it left the variable at its initial
        // value in the IR (every `i++` after a declaration collapsed to the
        // constant), corrupting bounds checks. Postfix yields the OLD value;
        // prefix yields the new one.
        if matches!(op_text.as_deref(), Some("++" | "--"))
            && let Some(arg_node) = operand_node
        {
            let bin_op = if op_text.as_deref() == Some("++") {
                "+"
            } else {
                "-"
            };
            // Postfix (`i++`) has the operator starting exactly at the
            // argument's exclusive end byte; prefix (`++i`) starts before it.
            let is_postfix = op_node.map(|o| o.start_byte() >= arg_node.end_byte()) != Some(false);
            if let Some(step) = self.lower_update(node, arg_node, bin_op, is_postfix) {
                return Some(step);
            }
            // Lvalue write-back unsupported (e.g. `(*ptr)++`): fall through to
            // the plain operand visit - same behavior as before the mapping.
        }

        let operand = operand_node
            .and_then(|c| self.visit_node(c))
            .unwrap_or(Operand::Unknown);

        if matches!(op_text.as_deref(), Some("&"))
            && let Operand::Var(src) = operand
        {
            let dest = self.new_temp(node);
            self.ir
                .push_instruction(self.current_block, Instruction::AddressOf { dest, src });
            return Some(Operand::Var(dest));
        }

        if matches!(op_text.as_deref(), Some("*")) {
            let dest = self.new_temp(node);
            self.ir.push_instruction(
                self.current_block,
                Instruction::Dereference {
                    dest,
                    mem_in: self.memory_var,
                    ptr: operand,
                },
            );
            return Some(Operand::Var(dest));
        }

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
            Instruction::UnaryOp {
                dest,
                op: op_text.unwrap_or_else(|| "neg".into()),
                src: operand,
            },
        );
        Some(Operand::Var(dest))
    }

    /// Read-modify-write for `arg++` / `++arg` style updates.
    /// Returns the operand the expression evaluates to (old value for
    /// postfix, new value for prefix), or `None` when the argument has no
    /// supported lvalue form (no write-back possible).
    fn lower_update(
        &mut self,
        node: Node,
        arg_node: Node,
        bin_op: &str,
        is_postfix: bool,
    ) -> Option<Operand> {
        let lval = self.visit_lvalue(arg_node)?;
        Some(match lval {
            LValue::Variable(dest) => {
                let cur = Operand::Var(dest);
                let result = if is_postfix {
                    // Freeze the old value before the increment redefines dest.
                    let old = self.new_temp(node);
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::Assign {
                            dest: old,
                            src: cur.clone(),
                        },
                    );
                    Operand::Var(old)
                } else {
                    cur.clone()
                };
                let step = self.new_temp(node);
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::BinaryOp {
                        dest: step,
                        op: bin_op.to_string(),
                        lhs: cur,
                        rhs: Operand::IntLiteral(1),
                    },
                );
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::Assign {
                        dest,
                        src: Operand::Var(step),
                    },
                );
                result
            }
            LValue::Field { base, field } => {
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
                let step = self.new_temp(node);
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::BinaryOp {
                        dest: step,
                        op: bin_op.to_string(),
                        lhs: Operand::Var(cur),
                        rhs: Operand::IntLiteral(1),
                    },
                );
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::StoreField {
                        mem_out: self.memory_var,
                        mem_in: self.memory_var,
                        base,
                        field,
                        src: Operand::Var(step),
                    },
                );
                if is_postfix {
                    Operand::Var(cur)
                } else {
                    Operand::Var(step)
                }
            }
            LValue::Element { base, index } => {
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
                let step = self.new_temp(node);
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::BinaryOp {
                        dest: step,
                        op: bin_op.to_string(),
                        lhs: Operand::Var(cur),
                        rhs: Operand::IntLiteral(1),
                    },
                );
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::StoreElement {
                        mem_out: self.memory_var,
                        mem_in: self.memory_var,
                        base,
                        index,
                        src: Operand::Var(step),
                    },
                );
                if is_postfix {
                    Operand::Var(cur)
                } else {
                    Operand::Var(step)
                }
            }
        })
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
                declared: false,
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
        // Evaluate every named child once; keyed pairs are remembered so the
        // composite can be lowered field-sensitively (allocation + stores)
        // instead of collapsing all children into one union variable.
        let mut cursor = node.walk();
        let children: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.is_named() && c.kind() != "comment")
            .collect();

        let mut child_ops: Vec<Operand> = Vec::new();
        let mut pair_keys: Vec<String> = Vec::new();
        // (field, value) entries for structural literals; field is `None`
        // for spread elements and other unkeyed children.
        let mut entries: Vec<(Option<String>, Operand)> = Vec::new();
        let mut all_keyed = true;

        for c in children {
            if self.is_pair_entry(c.kind()) {
                let key = c.child_by_field_name("key").map(|k| {
                    self.source[k.start_byte()..k.end_byte()]
                        .trim_matches(|ch| ch == '"' || ch == '\'')
                        .to_string()
                });
                if let Some(k) = &key {
                    pair_keys.push(k.clone());
                }
                if let Some(op) = self.visit_node(c) {
                    child_ops.push(op.clone());
                    match key {
                        Some(k) => entries.push((Some(k), op)),
                        None => {
                            all_keyed = false;
                            entries.push((None, op));
                        }
                    }
                } else {
                    // A pair without a value operand (e.g. a function-valued
                    // child) still proves the object is not uniformly keyed.
                    all_keyed = false;
                }
            } else if let Some(op) = self.visit_node(c) {
                all_keyed = false;
                child_ops.push(op.clone());
                entries.push((None, op));
            }
        }

        let kind_is_object = node.kind() == "object";
        let kind_is_array = node.kind() == "array";
        let byte_range = Some((node.start_byte(), node.end_byte()));

        // Structural literals: allocate a fresh container and store each
        // child under its own field/index. Field reads resolve through the
        // field-sensitive heap edges (store.src → load.dest), so taint in
        // one property stops polluting reads of the others, while whole-
        // container consumers still see every stored value via the
        // store→container edges.
        //
        // Objects with unkeyed children (spreads: `{...defaults, a}`) keep
        // the legacy union lowering: their per-field provenance is unknown,
        // and union is the conservative direction.
        if kind_is_array || (kind_is_object && all_keyed) {
            let dest = self.ir.new_var(VarMetadata {
                source_name: None,
                type_name: None,
                byte_range,
                is_memory_state: false,
                object_keys: if kind_is_object {
                    pair_keys
                } else {
                    Vec::new()
                },
                declared: false,
            });
            self.ir.push_instruction(
                self.current_block,
                Instruction::Allocate {
                    dest,
                    mem_out: self.memory_var,
                    mem_in: self.memory_var,
                    kind: if kind_is_object {
                        AllocationKind::Object
                    } else {
                        AllocationKind::Array
                    },
                },
            );
            if kind_is_object {
                for (field, src) in entries {
                    if let Some(field) = field {
                        self.ir.push_instruction(
                            self.current_block,
                            Instruction::StoreField {
                                mem_out: self.memory_var,
                                mem_in: self.memory_var,
                                base: dest,
                                field,
                                src,
                            },
                        );
                    }
                }
            } else {
                for (idx, (_, src)) in entries.into_iter().enumerate() {
                    self.ir.push_instruction(
                        self.current_block,
                        Instruction::StoreElement {
                            mem_out: self.memory_var,
                            mem_in: self.memory_var,
                            base: dest,
                            index: Operand::IntLiteral(idx as i64),
                            src,
                        },
                    );
                }
            }
            return Some(Operand::Var(dest));
        }

        // Legacy path: parenthesized expressions, patterns, and mixed
        // objects (spread entries) collapse to a single variable.
        // Pair keys (`pair` = `key: value` inside an object literal)
        // are remembered on the composite's var so sinks can classify
        // the argument *shape* (object payload vs raw value).
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
                    byte_range,
                    is_memory_state: false,
                    object_keys: pair_keys,
                    declared: false,
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
