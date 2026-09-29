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
        callee_field: &'static str,
        args_field: &'static str,
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

        let mut args = Vec::new();
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            if child.is_named()
                && let Some(op) = self.visit_node(child)
            {
                args.push(op);
            }
        }

        let dest = self.ir.new_var(VarMetadata {
            source_name: None,
            type_name: None,
            byte_range: Some((node.start_byte(), node.end_byte())),
            is_memory_state: false,
            object_keys: Vec::new(),
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
                },
            );
        }

        Some(Operand::Var(dest))
    }
}
