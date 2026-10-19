// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use crate::ir::lowering::lvalue::LValue;
use frensense_lang::NodeRole;
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    pub fn visit_call(
        &mut self,
        node: Node,
        callee_field: &str,
        args_field: &str,
    ) -> Option<Operand> {
        let callee_node = node.child_by_field_name(callee_field)?;
        // Some grammars don't give the args child a field name
        // (tree-sitter-rust `macro_invocation` has `macro` but
        // `token_tree` is fieldless), fall back to the last named
        // child, which is the argument container in every grammar we
        // ship.
        let args_node = match node.child_by_field_name(args_field) {
            Some(a) => Some(a),
            None => {
                let mut fc = node.walk();
                let kids: Vec<_> = node.children(&mut fc).filter(|c| c.is_named()).collect();
                kids.last().copied()
            }
        }?;

        // `args` stays positionally ordered (existing slot-based facts keep
        // working); `arg_names[i]` carries the keyword name when the source
        // spelled one, empty otherwise. A name is metadata, not a slot: the
        // value still lands at its written position so an absent optional
        // argument cannot shift it.
        let mut args = Vec::new();
        let mut arg_names: Vec<String> = Vec::new();
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            if !child.is_named() {
                continue;
            }
            // Python spreads the keyword name right into the argument
            // node: `set_cookie("sid", "abc", secure=False)` is an
            // `assignment_expression` whose left is the flag name and
            // whose right is its value (`secure`, `False`). There is no
            // separate `keyword_argument` node in the py3.10 grammar, so
            // walk such a child directly into the argument list and keep
            // the slot at the written position (a name is metadata, not
            // a slot): an earlier omitted optional cannot shift it.
            if child.kind() == "assignment_expression"
                && let Some(name_node) = child.child_by_field_name("left")
                && child.child_by_field_name("right").is_some()
            {
                if let Some(op) = self.visit_node(child.child_by_field_name("right").unwrap()) {
                    args.push(op);
                    arg_names.push(
                        self.source[name_node.start_byte()..name_node.end_byte()].to_string(),
                    );
                }
                continue;
            }
            if let NodeRole::KeywordArgument {
                name_field,
                value_field,
            } = self.classify_node(child.kind())
            {
                let name = child
                    .child_by_field_name(&*name_field)
                    .map(|n| self.source[n.start_byte()..n.end_byte()].to_string())
                    .unwrap_or_default();
                let value = child.child_by_field_name(&*value_field).unwrap_or(child);
                if let Some(op) = self.visit_node(value) {
                    args.push(op);
                    arg_names.push(name);
                }
                continue;
            }
            if let Some(op) = self.visit_node(child) {
                args.push(op);
                arg_names.push(String::new());
            }
        }

        let dest = self.ir.new_var(VarMetadata {
            source_name: None,
            type_name: None,
            byte_range: Some((node.start_byte(), node.end_byte())),
            is_memory_state: false,
            object_keys: Vec::new(),
            declared: false,
        });

        let callee_role = self.classify_node(callee_node.kind());
        if matches!(callee_role, NodeRole::Identifier) {
            let func_name =
                self.source[callee_node.start_byte()..callee_node.end_byte()].to_string();
            self.ir.push_instruction(
                self.current_block,
                Instruction::CallStatic {
                    dest: Some(dest),
                    mem_out: self.memory_var, // Generates new memory state
                    mem_in: self.memory_var,
                    func: func_name,
                    args,
                    arg_names,
                },
            );
        } else if let Some(LValue::Field { base, field }) = self.visit_lvalue(callee_node) {
            self.ir.push_instruction(
                self.current_block,
                Instruction::CallVirtual {
                    dest: Some(dest),
                    mem_out: self.memory_var,
                    mem_in: self.memory_var,
                    method: field,
                    receiver: Operand::Var(base),
                    args,
                    arg_names,
                },
            );
        } else if let NodeRole::MemberAccess {
            object_field,
            property_field,
        } = callee_role
        {
            let obj_node = callee_node.child_by_field_name(&*object_field);
            let prop_node = callee_node.child_by_field_name(&*property_field);
            if let (Some(obj), Some(prop)) = (obj_node, prop_node) {
                let method = self.source[prop.start_byte()..prop.end_byte()].to_string();
                let obj_op = self.visit_node(obj).unwrap_or(Operand::Unknown);
                let recv_var = match obj_op {
                    Operand::Var(v) => v,
                    other => {
                        let temp = self.ir.new_var(VarMetadata {
                            source_name: None,
                            type_name: None,
                            byte_range: Some((obj.start_byte(), obj.end_byte())),
                            is_memory_state: false,
                            object_keys: Vec::new(),
                            declared: false,
                        });
                        self.ir.push_instruction(
                            self.current_block,
                            Instruction::Assign {
                                dest: temp,
                                src: other,
                            },
                        );
                        temp
                    }
                };
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::CallVirtual {
                        dest: Some(dest),
                        mem_out: self.memory_var,
                        mem_in: self.memory_var,
                        method,
                        receiver: Operand::Var(recv_var),
                        args,
                        arg_names,
                    },
                );
            } else {
                let func_op = self.visit_node(callee_node).unwrap_or(Operand::Unknown);
                self.ir.push_instruction(
                    self.current_block,
                    Instruction::CallPointer {
                        dest: Some(dest),
                        mem_out: self.memory_var,
                        mem_in: self.memory_var,
                        func_ptr: func_op,
                        args,
                        arg_names,
                    },
                );
            }
        } else {
            let func_op = self.visit_node(callee_node).unwrap_or(Operand::Unknown);
            self.ir.push_instruction(
                self.current_block,
                Instruction::CallPointer {
                    dest: Some(dest),
                    mem_out: self.memory_var,
                    mem_in: self.memory_var,
                    func_ptr: func_op,
                    args,
                    arg_names,
                },
            );
        }

        Some(Operand::Var(dest))
    }
}
