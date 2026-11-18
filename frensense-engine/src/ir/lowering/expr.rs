// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::ir::function::*;
use crate::ir::lowering::LoweringContext;
use crate::ir::lowering::lvalue::LValue;
use tree_sitter::Node;

impl<'a> LoweringContext<'a> {
    /// Lowers a binary operation into a chain of `BinaryOp` instructions folded left to right over its operands.
    ///
    /// The operator is the first anonymous token among the node's children, recorded as written, except that `+` (or no token at all) is recorded as `concat`. A node with one operand passes that operand through; a node with none yields `Unknown`.
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the one `unwrap` pops the only operand and is guarded by a length check.
    pub(crate) fn visit_binary_op(&mut self, node: Node) -> Option<Operand> {
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
            let next_dest = self.new_temp(node);
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

    /// Lowers a unary operation.
    ///
    /// `++` and `--` become a read-modify-write of the operand, `&` becomes an `AddressOf` and `*` a `Dereference`; any other operator becomes a `UnaryOp` recording the token (or `neg` when no token is found).
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

        let dest = self.new_temp(node);
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
                let mem_in = self.memory_var;
                let load_field = field.clone();
                let (cur, step) = self.read_modify(node, bin_op, Operand::IntLiteral(1), |dest| {
                    Instruction::LoadField {
                        dest,
                        mem_in,
                        base,
                        field: load_field,
                    }
                });
                self.store_field(
                    base,
                    field,
                    Operand::Var(step),
                    Some((node.start_byte(), node.end_byte())),
                );
                if is_postfix {
                    Operand::Var(cur)
                } else {
                    Operand::Var(step)
                }
            }
            LValue::Element { base, index } => {
                let mem_in = self.memory_var;
                let load_index = index.clone();
                let (cur, step) = self.read_modify(node, bin_op, Operand::IntLiteral(1), |dest| {
                    Instruction::LoadElement {
                        dest,
                        mem_in,
                        base,
                        index: load_index,
                    }
                });
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

    /// Lowers `object.property` or `object[index]`.
    ///
    /// The result is a fresh variable carrying the access's byte range, defined by a `LoadField` when the language classifies the property node as a property name, a `LoadElement` when the property evaluates to a variable, and a `LoadField` on the property text otherwise. Returns `None` when the object does not evaluate to a variable.
    pub(crate) fn visit_member_access(
        &mut self,
        node: Node,
        object_field: &str,
        property_field: &str,
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
            if self.is_property_kind(prop_node.kind()) {
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
            } else if let Some(Operand::Var(index_var)) = self.visit_node(prop_node) {
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
            } else {
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
            Some(Operand::Var(dest))
        } else {
            None
        }
    }

    /// The field name and lowered value of one `key: value` child of a
    /// composite literal; the name is `None` when the grammar gives the pair
    /// no static key.
    fn composite_entry(&mut self, child: Node) -> (Option<String>, Option<Operand>) {
        let key = child.child_by_field_name("key").map(|k| {
            self.source[k.start_byte()..k.end_byte()]
                .trim_matches(|ch| ch == '"' || ch == '\'')
                .to_string()
        });
        (key, self.visit_node(child))
    }

    /// Lowers a composite literal (object, array). Uniformly keyed objects and arrays become an allocation with one store per property or element, so reads stay field-sensitive; objects with unkeyed children (such as spreads) are not allocated: the result is the child variable when there is exactly one, and a fresh variable merging the child variables otherwise.
    pub(crate) fn visit_composite(&mut self, node: Node) -> Option<Operand> {
        // Keyed pairs are remembered so the composite lowers field-sensitively.
        let mut cursor = node.walk();
        let children: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.is_named() && c.kind() != "comment")
            .collect();
        let mut child_ops: Vec<Operand> = Vec::new();
        let mut pair_keys: Vec<String> = Vec::new();
        // Field is `None` for spreads and other unkeyed children.
        let mut entries: Vec<(Option<String>, Operand)> = Vec::new();
        let mut all_keyed = true;

        for c in children {
            let pair = self.is_pair_entry(c.kind());
            let (key, op) = if pair {
                self.composite_entry(c)
            } else {
                (None, self.visit_node(c))
            };
            if let Some(k) = &key {
                pair_keys.push(k.clone());
            }
            let Some(op) = op else {
                // A pair without a value operand (e.g. a function-valued
                // child) still proves the object is not uniformly keyed; an
                // unkeyed child with no operand changes nothing.
                all_keyed &= !pair;
                continue;
            };
            // Only a pair with a static key keeps the literal uniformly keyed.
            all_keyed &= pair && key.is_some();
            child_ops.push(op.clone());
            entries.push((key, op));
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
                        self.store_field(dest, field, src, None);
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

    /// Lowers a literal.
    ///
    /// A string that mixes literal text with at least one interpolated or concatenated part is folded into a left-associative `concat` chain, so checks can see a fixed prefix before a tainted part. A string with no such mix yields its last non-fragment child's value, or its source text as a string literal. Any other literal is an integer literal when its text parses as `i64` and its source text as a string literal otherwise.
    pub(crate) fn visit_literal(&mut self, node: Node) -> Option<Operand> {
        if self.is_template_string(node.kind())
            || node.kind() == "string"
            || node.kind() == "binary_expression"
            || node.kind() == "concatenated_string"
        {
            // An *interpolated* string (JS template literal, Python f-string,
            // implicit concat with a substitution) carries both literal text
            // and tainted parts. Fold every part - literal fragments AND
            // substitutions - into a left-associative `concat` chain so the
            // literal PREFIX survives in the IR. This is what lets the SSRF
            // carve-out see a fixed `scheme://authority` that precedes the
            // attacker-controlled fragment (`fetch(\`https://host/?q=${id}\`)`
            // must not read as a fully attacker-chosen URL).
            if let Some(folded) = self.try_fold_interpolated_string(node) {
                return Some(folded);
            }
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

    /// Fold an interpolated string into a `concat` `BinaryOp` chain when it
    /// genuinely mixes literal text with at least one non-literal part.
    ///
    /// Returns `None` for a plain literal (no interpolation) or a single-part
    /// expression, leaving the caller's original single-value behaviour intact.
    fn try_fold_interpolated_string(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let children: Vec<Node> = node
            .children(&mut cursor)
            .filter(|c| c.is_named())
            .collect();

        let mut parts: Vec<Operand> = Vec::new();
        let mut has_interp = false;
        let mut has_literal = false;
        for child in &children {
            let kind = child.kind();
            if kind == "comment" {
                continue;
            }
            // A literal text fragment (JS `string_fragment`, or any node the
            // spec flags as an untainted template fragment).
            let is_literal_frag = kind == "string_fragment"
                || kind == "string_content"
                || self.is_template_fragment(kind);
            if is_literal_frag {
                let text = &self.source[child.start_byte()..child.end_byte()];
                if !text.is_empty() {
                    parts.push(Operand::StringLiteral(text.to_string()));
                    has_literal = true;
                }
            } else if let Some(op) = self.visit_node(*child) {
                parts.push(op);
                has_interp = true;
            }
        }

        // Only fold a true interpolation (literal text AND a dynamic part).
        // A single dynamic part with no literal prefix keeps the old
        // pass-through so behaviour is unchanged for `\`${id}\`` and friends.
        if !(has_interp && has_literal) || parts.len() < 2 {
            return None;
        }

        // Left-associative fold: ((p0 + p1) + p2) ...
        let mut it = parts.into_iter();
        let mut acc = it.next().unwrap();
        for rhs in it {
            let dest = self.new_temp(node);
            self.ir.push_instruction(
                self.current_block,
                Instruction::BinaryOp {
                    dest,
                    op: "concat".to_string(),
                    lhs: acc,
                    rhs,
                },
            );
            acc = Operand::Var(dest);
        }
        Some(acc)
    }

    /// Lowers a cast or type assertion as the value of its first value-producing child: the cast does not change the value.
    pub(crate) fn visit_cast(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let mut first = None;
        for child in node.children(&mut cursor) {
            if child.is_named() && child.kind() != "comment" && first.is_none() {
                first = self.visit_node(child);
            }
        }
        first
    }

    /// Lowers a JSX element into a props object and returns it.
    ///
    /// Attributes become spanned [`Instruction::StoreField`]s on a temporary
    /// standing for the props, so a sink name written as an attribute
    /// (`<div dangerouslySetInnerHTML={{ __html: html }} />`) travels the same
    /// property-sink path as `el.innerHTML = html`. Children are lowered in
    /// place so nested elements keep their own attribute stores.
    pub(crate) fn visit_jsx_element(&mut self, node: Node) -> Option<Operand> {
        let props = self.new_temp(node);
        self.ir.push_instruction(
            self.current_block,
            Instruction::Allocate {
                dest: props,
                mem_out: self.memory_var,
                mem_in: self.memory_var,
                kind: AllocationKind::Object,
            },
        );
        match node.kind() {
            "jsx_self_closing_element" => self.store_jsx_attributes(node, props),
            "jsx_fragment" => self.lower_jsx_children(node),
            _ => {
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    match child.kind() {
                        "jsx_opening_element" => self.store_jsx_attributes(child, props),
                        "jsx_children" => self.lower_jsx_children(child),
                        _ => {}
                    }
                }
            }
        }
        Some(Operand::Var(props))
    }

    /// Lowers every child node in place, so nested elements and expressions
    /// keep the stores and calls they lower into.
    fn lower_jsx_children(&mut self, node: Node) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.visit_node(child);
        }
    }

    /// Stores each attributed value of a JSX tag under the attribute's own
    /// name on `props`.
    ///
    /// An attribute node is `name={value}`: the first part that is not the
    /// value expression names the field, the rest produces the stored value.
    /// Valueless (`disabled`) and spread (`{...rest}`) attributes carry no
    /// name-value pair and only have their expression lowered.
    fn store_jsx_attributes(&mut self, tag: Node, props: VarId) {
        let mut cursor = tag.walk();
        for attr in tag.named_children(&mut cursor) {
            if attr.kind() != "jsx_attribute" {
                self.visit_node(attr);
                continue;
            }
            let mut parts = attr.walk();
            let mut name: Option<String> = None;
            let mut value: Option<Operand> = None;
            for part in attr.named_children(&mut parts) {
                if name.is_none() && !is_jsx_value(part.kind()) {
                    name = self
                        .source
                        .get(part.start_byte()..part.end_byte())
                        .map(str::to_string);
                } else if let Some(op) = self.visit_node(part) {
                    value = Some(op);
                }
            }
            if let (Some(field), Some(src)) = (name, value) {
                self.store_field(
                    props,
                    field,
                    src,
                    Some((attr.start_byte(), attr.end_byte())),
                );
            }
        }
    }
}

/// Node kinds that make up a JSX attribute's value rather than its name.
fn is_jsx_value(kind: &str) -> bool {
    matches!(
        kind,
        "jsx_expression" | "string" | "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
    )
}
