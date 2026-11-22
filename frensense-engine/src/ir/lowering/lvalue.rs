// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

use crate::ir::function::{Operand, VarId, strip_quotes};
use crate::ir::lowering::LoweringContext;
use frensense_lang::NodeRole;
use tree_sitter::Node;

/// Helper to differentiate Assigning to a Variable vs Mutating an Object
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LValue {
    /// Assigning to a plain variable.
    Variable(VarId),
    /// Mutating a field of an object.
    Field {
        /// Variable holding the object.
        base: VarId,
        /// Name of the field.
        field: String,
    },
    /// Mutating an element of an array or collection (also used for `*ptr`, with index 0).
    Element {
        /// Variable holding the array or collection.
        base: VarId,
        /// Index or key operand.
        index: Operand,
    },
}

impl<'a> LoweringContext<'a> {
    /// Classifies the target of an assignment as a variable, field or element.
    ///
    /// An identifier is a variable and `*ptr` is an element at index 0. A member access is an element when its property evaluates to a variable and the language does not classify that node kind as a property name (`obj[i]`), and a field otherwise (`obj.name`). Returns `None` for any other shape, or when the object does not evaluate to a variable.
    pub(crate) fn visit_lvalue(&mut self, node: Node) -> Option<LValue> {
        let role = self.classify_node(node.kind());
        match role {
            NodeRole::Identifier => {
                if let Operand::Var(v) = self.resolve_identifier(node) {
                    Some(LValue::Variable(v))
                } else {
                    None
                }
            }
            _ if self.spec.is_pointer_expression(node.kind()) => {
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
                let obj_node = node.child_by_field_name(object_field.as_ref())?;
                let prop_node = node.child_by_field_name(property_field.as_ref())?;

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
                                let field_name = strip_quotes(
                                    &self.source[prop_node.start_byte()..prop_node.end_byte()],
                                )
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
                            let field_name = strip_quotes(
                                &self.source[prop_node.start_byte()..prop_node.end_byte()],
                            )
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
