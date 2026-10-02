// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::{Operand, VarId};
use crate::ir::lowering::LoweringContext;
use frensense_lang::NodeRole;
use tree_sitter::Node;

/// Helper to differentiate Assigning to a Variable vs Mutating an Object
#[derive(Debug, Clone, PartialEq)]
pub enum LValue {
    Variable(VarId),
    Field { base: VarId, field: String },
    Element { base: VarId, index: Operand },
}

impl<'a> LoweringContext<'a> {
    pub fn visit_lvalue(&mut self, node: Node) -> Option<LValue> {
        let role = self.classify_node(node.kind());
        match role {
            NodeRole::Identifier => {
                if let Operand::Var(v) = self.resolve_identifier(node) {
                    Some(LValue::Variable(v))
                } else {
                    None
                }
            }
            _ if node.kind() == "pointer_expression" => {
                let arg = node
                    .child_by_field_name("argument")
                    .or_else(|| node.named_child(0))?;
                if let Some(Operand::Var(base)) = self.visit_node(arg) {
                    Some(LValue::Element {
                        base,
                        index: Operand::IntLiteral(0),
                    })
                } else {
                    None
                }
            }
            // MemberAccess covers both `obj.field` and `obj[i]`: JS maps
            // subscript_expression here with property_field = "index". Distinguish
            // by attempting to evaluate the property node as an operand.
            NodeRole::MemberAccess {
                object_field,
                property_field,
            } => {
                let obj_node = node.child_by_field_name(object_field)?;
                let prop_node = node.child_by_field_name(property_field)?;

                let base_op = self.visit_node(obj_node)?;

                if let Operand::Var(base_var) = base_op {
                    match self.visit_node(prop_node) {
                        // Index-like (identifier/expression resolving to a var):
                        // prefer element semantics for lvalues. Property-name
                        // decision is language-driven (spec.is_property_kind):
                        // Python attributes are plain `identifier`, Go/Rust use
                        // `field_identifier`, substring guessing broke all
                        // three into LoadElement/CallPointer, losing sink names.
                        Some(Operand::Var(index_var)) => {
                            if self.is_property_kind(prop_node.kind()) {
                                let field_name = self.source
                                    [prop_node.start_byte()..prop_node.end_byte()]
                                    .to_string();
                                Some(LValue::Field {
                                    base: base_var,
                                    field: field_name,
                                })
                            } else {
                                Some(LValue::Element {
                                    base: base_var,
                                    index: Operand::Var(index_var),
                                })
                            }
                        }
                        _ => {
                            let field_name = self.source
                                [prop_node.start_byte()..prop_node.end_byte()]
                                .to_string();
                            Some(LValue::Field {
                                base: base_var,
                                field: field_name,
                            })
                        }
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
