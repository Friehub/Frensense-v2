// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Compile-time evaluation for dead-branch elimination.
//!
//! A condition or `match` subject whose value is fixed at compile time selects
//! exactly one arm. Lowering the other arm anyway puts its assignments in the
//! join, and the backward walk then reports taint that can never reach the
//! sink. A table lookup that picks a fixed label is the everyday shape:
//!
//! ```python
//! possible = "ABC"
//! guess = possible[1]          # 'B'
//! match guess:
//!     case 'A':        bar = param   # unreachable, but merged into bar
//!     case 'B':        bar = 'bob'
//!     case 'C' | 'D':  bar = param   # unreachable
//!     case _:          bar = 'bob'
//! ```
//!
//! The evaluator is deliberately small and conservative: it answers only for
//! literals, variables bound to a literal (or another such value) earlier in
//! the same straight-line region, and the handful of operators whose result
//! on those values is unambiguous in every language we ship. `None` means
//! "not knowable without running the program", and the caller keeps the
//! existing over-approximate lowering.
//!
//! Values are *invalidated* at every control-flow join (`if`, loop, `match`,
//! `switch`, ternary, `try`), because a variable assigned on one path is not
//! constant after the merge. Recording is only sound if that rule is kept.

use frensense_lang::NodeRole;
use rustc_hash::FxHashMap;
use tree_sitter::Node;

use crate::ir::function::{Operand, VarId};
use crate::ir::lowering::LoweringContext;

/// A value that is fixed before the program runs.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum ConstValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Null,
}

impl ConstValue {
    /// Truthiness of a scalar constant. Python and JavaScript agree on every
    /// value this evaluator produces (empty string, `0`, `0.0`, `None`/`null`
    /// are false; everything else is true); containers are not modelled.
    pub(super) fn truthy(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::Null => false,
        }
    }
}

impl<'a> LoweringContext<'a> {
    /// The compile-time value of an expression, or `None` when it depends on
    /// runtime state.
    pub(super) fn const_value(&self, node: Node) -> Option<ConstValue> {
        let role = self.classify_node(node.kind());
        match role {
            NodeRole::Literal => return self.const_literal(node),
            NodeRole::Identifier => {
                let name = &self.source[node.start_byte()..node.end_byte()];
                let var = self
                    .env
                    .iter()
                    .rev()
                    .find_map(|scope| scope.get(name).copied())?;
                return self.const_values.get(&var).cloned();
            }
            NodeRole::UnaryOp => return self.const_unary(node),
            NodeRole::BinaryOp => return self.const_binary(node),
            _ => {}
        }

        // Parenthesized expression: a single named child wrapped in `(`/`)`.
        let text = self.source[node.start_byte()..node.end_byte()].trim();
        if text.starts_with('(') && text.ends_with(')') && node.named_child_count() == 1 {
            return self.const_value(node.named_child(0)?);
        }

        // Indexing (`possible[1]`). Field names, not node kinds: Python's
        // `subscript` and the other grammars' index expressions expose the
        // collection and the index under these fields.
        if let (Some(base), Some(index)) = (
            node.child_by_field_name("value"),
            node.child_by_field_name("subscript"),
        ) {
            return self.const_index(base, index);
        }
        None
    }

    /// `Some(truthiness)` when the node's boolean value is fixed.
    pub(super) fn const_truth(&self, node: Node) -> Option<bool> {
        self.const_value(node).map(|v| v.truthy())
    }

    /// Record the constant value of `dest` after an assignment, or forget it
    /// when the assigned value depends on runtime state.
    ///
    /// The AST node is evaluated first - that is what folds a derived value
    /// such as `guess = possible[1]` - and the already-lowered operand is the
    /// fallback for shapes where the node is not the value expression itself.
    pub(super) fn record_const(&mut self, dest: VarId, value_node: Node, src: &Operand) {
        let known = self.const_value(value_node).or_else(|| match src {
            Operand::BoolLiteral(b) => Some(ConstValue::Bool(*b)),
            Operand::IntLiteral(i) => Some(ConstValue::Int(*i)),
            Operand::FloatLiteral(f) => Some(ConstValue::Float(*f)),
            Operand::StringLiteral(s) => unquote(s).map(ConstValue::Str),
            Operand::Null => Some(ConstValue::Null),
            Operand::Var(v) => self.const_values.get(v).cloned(),
            Operand::Unknown => None,
        });
        match known {
            Some(value) => {
                self.const_values.insert(dest, value);
            }
            None => {
                self.const_values.remove(&dest);
            }
        }
    }

    /// Forget `dest`'s constant (compound assignment, destructuring, or a
    /// merged ternary result).
    pub(super) fn forget_const(&mut self, dest: VarId) {
        self.const_values.remove(&dest);
    }

    /// Snapshot taken before a control-flow construct whose arms may assign.
    pub(super) fn const_snapshot(&self) -> FxHashMap<VarId, ConstValue> {
        self.const_values.clone()
    }

    /// Invalidate every binding an arm changed: after a join the variable is
    /// constant only if *all* paths left it at the same value.
    pub(super) fn const_join(&mut self, before: &FxHashMap<VarId, ConstValue>) {
        self.const_values
            .retain(|var, value| before.get(var) == Some(value));
    }

    fn const_literal(&self, node: Node) -> Option<ConstValue> {
        let text = self.source[node.start_byte()..node.end_byte()].trim();
        match text {
            "True" | "true" => return Some(ConstValue::Bool(true)),
            "False" | "false" => return Some(ConstValue::Bool(false)),
            "None" | "null" | "nil" | "undefined" => return Some(ConstValue::Null),
            _ => {}
        }
        if let Some(s) = unquote(text) {
            return Some(ConstValue::Str(s));
        }
        if let Ok(i) = text.parse::<i64>() {
            return Some(ConstValue::Int(i));
        }
        if let Ok(f) = text.parse::<f64>() {
            return Some(ConstValue::Float(f));
        }
        None
    }

    fn const_unary(&self, node: Node) -> Option<ConstValue> {
        let mut cursor = node.walk();
        let mut operand = None;
        let mut operator = None;
        for child in node.children(&mut cursor) {
            if child.kind() == "comment" {
                continue;
            }
            if child.is_named() && operand.is_none() {
                operand = Some(child);
            } else if !child.is_named() && operator.is_none() {
                let text = self.source[child.start_byte()..child.end_byte()].trim();
                if !text.is_empty() {
                    operator = Some(text.to_string());
                }
            }
        }
        let value = self.const_value(operand?)?;
        match operator.as_deref() {
            Some("-") => match value {
                ConstValue::Int(i) => Some(ConstValue::Int(-i)),
                ConstValue::Float(f) => Some(ConstValue::Float(-f)),
                _ => None,
            },
            Some("not") | Some("!") => Some(ConstValue::Bool(!value.truthy())),
            _ => None,
        }
    }

    fn const_binary(&self, node: Node) -> Option<ConstValue> {
        // `and`/`or` carry an explicit `operator` field. Both short-circuit
        // and yield one of their operands in Python/JavaScript; those
        // operands are scalars here, so the boolean result is the pair's
        // truthiness.
        if let Some(op) = node.child_by_field_name("operator") {
            let text = self.source[op.start_byte()..op.end_byte()].trim();
            if matches!(text, "and" | "&&" | "or" | "||") {
                let left = self.const_value(node.child_by_field_name("left")?)?;
                let right = self.const_value(node.child_by_field_name("right")?)?;
                let result = match text {
                    "and" | "&&" => left.truthy() && right.truthy(),
                    _ => left.truthy() || right.truthy(),
                };
                return Some(ConstValue::Bool(result));
            }
        }

        // General chains: operands are the named children, the operator
        // tokens the anonymous ones. Python spells `not in` / `is not` as
        // aliased named nodes, so those are operators even though named.
        let mut operands: Vec<Node> = Vec::new();
        let mut operators: Vec<String> = Vec::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "comment" {
                continue;
            }
            let text = self.source[child.start_byte()..child.end_byte()].trim();
            if text.is_empty() {
                continue;
            }
            // `not in` / `is not` are aliased named nodes in Python: they are
            // operators even though the grammar marks them named.
            if !child.is_named() || text == "not in" || text == "is not" {
                operators.push(text.to_string());
            } else {
                operands.push(child);
            }
        }
        if operators.is_empty() || operands.len() != operators.len() + 1 {
            return None;
        }
        let values: Vec<ConstValue> = operands
            .into_iter()
            .map(|n| self.const_value(n))
            .collect::<Option<_>>()?;

        if operators.iter().all(|op| is_comparison(op)) {
            let mut all = true;
            for (i, op) in operators.iter().enumerate() {
                all &= compare_const(op, &values[i], &values[i + 1])?;
            }
            return Some(ConstValue::Bool(all));
        }
        if operators.iter().all(|op| is_arithmetic(op)) {
            let mut acc = values[0].clone();
            for (op, rhs) in operators.iter().zip(&values[1..]) {
                acc = arithmetic_const(op, &acc, rhs)?;
            }
            return Some(acc);
        }
        None
    }

    /// `collection[index]` where both sides are compile-time constants.
    fn const_index(&self, base: Node, index: Node) -> Option<ConstValue> {
        let base = self.const_value(base)?;
        let index = self.const_value(index)?;
        let ConstValue::Str(text) = base else {
            return None;
        };
        let ConstValue::Int(i) = index else {
            return None;
        };
        let chars: Vec<char> = text.chars().collect();
        let len = chars.len() as i64;
        let at = if i < 0 { len.checked_add(i)? } else { i };
        usize::try_from(at)
            .ok()
            .and_then(|i| chars.get(i))
            .copied()
            .map(|c| ConstValue::Str(c.to_string()))
    }
}

/// Strip a string literal to its contents, or `None` when it is not a plain
/// literal. String prefixes (`r""`, `b""`) are skipped; an interpolated
/// (`f""`) or escaped body is not a compile-time constant this evaluator can
/// safely compare.
fn unquote(text: &str) -> Option<String> {
    let prefix_len = text
        .char_indices()
        .find(|(_, c)| !c.is_ascii_alphabetic())
        .map_or(0, |(i, _)| i);
    let (prefix, rest) = text.split_at(prefix_len);
    if prefix.chars().any(|c| matches!(c, 'f' | 'F')) {
        return None;
    }
    let quote = rest.chars().next()?;
    if !matches!(quote, '"' | '\'' | '`') {
        return None;
    }
    let body = rest.strip_prefix(quote)?.strip_suffix(quote)?;
    if body.contains('\\') || body.contains(quote) {
        return None;
    }
    Some(body.to_string())
}

/// Evaluate one comparison or membership operator between two constants.
fn compare_const(op: &str, left: &ConstValue, right: &ConstValue) -> Option<bool> {
    use ConstValue::{Bool, Float, Int, Null, Str};
    match op {
        "==" | "===" | "!=" | "!==" => {
            let equal = match (left, right) {
                (Bool(a), Bool(b)) => a == b,
                (Int(a), Int(b)) => a == b,
                (Int(a), Float(b)) | (Float(b), Int(a)) => (*a as f64) == *b,
                (Float(a), Float(b)) => a == b,
                (Str(a), Str(b)) => a == b,
                (Null, Null) => true,
                // Mixed-variant equality is false in Python and JS only for
                // some pairs (`1 == True` is true in Python); do not guess.
                _ => return None,
            };
            Some(if op.starts_with('!') { !equal } else { equal })
        }
        "<" | "<=" | ">" | ">=" => {
            let ord = match (left, right) {
                (Int(a), Int(b)) => a.partial_cmp(b),
                (Int(a), Float(b)) => (*a as f64).partial_cmp(b),
                (Float(a), Int(b)) => a.partial_cmp(&(*b as f64)),
                (Float(a), Float(b)) => a.partial_cmp(b),
                (Str(a), Str(b)) => a.partial_cmp(b),
                _ => return None,
            }?;
            Some(match op {
                "<" => ord.is_lt(),
                "<=" => ord.is_le(),
                ">" => ord.is_gt(),
                _ => ord.is_ge(),
            })
        }
        "in" | "not in" => {
            // `needle in haystack`: the LEFT operand is the needle.
            let (Str(needle), Str(haystack)) = (left, right) else {
                return None;
            };
            let contained = haystack.contains(needle.as_str());
            Some(if op == "in" { contained } else { !contained })
        }
        "is" | "is not" => {
            let identical = matches!((left, right), (Null, Null));
            Some(if op == "is" { identical } else { !identical })
        }
        _ => None,
    }
}

/// Operators [`compare_const`] can answer.
fn is_comparison(op: &str) -> bool {
    matches!(
        op,
        "<" | "<="
            | "=="
            | "==="
            | "!="
            | "!=="
            | ">="
            | ">"
            | "<>"
            | "in"
            | "not in"
            | "is"
            | "is not"
    )
}

/// Operators [`arithmetic_const`] can answer.
fn is_arithmetic(op: &str) -> bool {
    matches!(op, "+" | "-" | "*")
}

/// Fold one arithmetic step. Only the integer/string cases whose result is
/// identical in every language we ship - no division, no number/string
/// coercion, no overflow wrapping.
fn arithmetic_const(op: &str, left: &ConstValue, right: &ConstValue) -> Option<ConstValue> {
    match (op, left, right) {
        ("+", ConstValue::Int(a), ConstValue::Int(b)) => Some(ConstValue::Int(a + b)),
        ("+", ConstValue::Str(a), ConstValue::Str(b)) => {
            let mut joined = String::with_capacity(a.len() + b.len());
            joined.push_str(a);
            joined.push_str(b);
            Some(ConstValue::Str(joined))
        }
        ("-", ConstValue::Int(a), ConstValue::Int(b)) => Some(ConstValue::Int(a - b)),
        ("*", ConstValue::Int(a), ConstValue::Int(b)) => Some(ConstValue::Int(a * b)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Match-arm selection
// ---------------------------------------------------------------------------

/// The pattern node of a `match` arm / `case` clause.
pub(super) fn match_arm_pattern<'t>(arm: Node<'t>) -> Option<Node<'t>> {
    arm.child_by_field_name("pattern").or_else(|| {
        let mut cursor = arm.walk();
        arm.children(&mut cursor)
            .find(|n| n.is_named() && n.kind().contains("pattern"))
    })
}

/// The body node of a `match` arm / `case` clause.
pub(super) fn match_arm_body<'t>(arm: Node<'t>) -> Option<Node<'t>> {
    arm.child_by_field_name("value")
        .or_else(|| arm.child_by_field_name("body"))
        .or_else(|| arm.child_by_field_name("consequence"))
        .or_else(|| {
            let mut cursor = arm.walk();
            let kids: Vec<Node> = arm.children(&mut cursor).filter(|n| n.is_named()).collect();
            kids.last().copied()
        })
}

impl<'a> LoweringContext<'a> {
    /// Pick the arm a constant subject executes.
    ///
    /// `None` means "cannot decide" - the caller must keep the
    /// over-approximate lowering of every arm. `Some(None)` means the subject
    /// matches no arm (nothing executes). `Some(Some(i))` names the first
    /// matching arm.
    ///
    /// Any undecidable pattern *before* a match makes the whole question
    /// undecidable: it could have matched instead. Guards turn an arm into a
    /// runtime predicate, so they always bail.
    pub(super) fn select_const_arm(
        &self,
        arms: &[Node<'_>],
        subject: &ConstValue,
    ) -> Option<Option<usize>> {
        for (i, arm) in arms.iter().enumerate() {
            if arm.child_by_field_name("guard").is_some() {
                return None;
            }
            let mut cursor = arm.walk();
            if arm
                .children(&mut cursor)
                .any(|n| matches!(n.kind(), "if_clause" | "match_guard"))
            {
                return None;
            }
            let pat = match_arm_pattern(*arm)?;
            match self.pattern_matches(subject, pat) {
                Some(true) => return Some(Some(i)),
                Some(false) => {}
                None => return None,
            }
        }
        Some(None)
    }

    /// Does `pat` provably match `subject`? `None` when the pattern is not a
    /// compile-time literal (a capture, a class/struct/dict shape, a constant
    /// reference the evaluator cannot resolve).
    fn pattern_matches(&self, subject: &ConstValue, pat: Node) -> Option<bool> {
        let text = self.source[pat.start_byte()..pat.end_byte()].trim();
        match pat.kind() {
            // The discard pattern matches anything; it binds nothing.
            "_" => (text == "_").then_some(true),
            // Python wraps every case pattern in `case_pattern`, and `_`
            // arrives as an anonymous child, leaving no named child.
            "case_pattern" => {
                let mut cursor = pat.walk();
                let named: Vec<Node> = pat.named_children(&mut cursor).collect();
                if named.is_empty() {
                    return (text == "_").then_some(true);
                }
                self.pattern_const(pat).map(|v| v == *subject)
            }
            // `case 'C' | 'D':` - the arm executes if any alternative matches.
            "union_pattern" => {
                let mut saw_unknown = false;
                let mut cursor = pat.walk();
                for child in pat.named_children(&mut cursor) {
                    match self.pattern_matches(subject, child) {
                        Some(true) => return Some(true),
                        Some(false) => {}
                        None => saw_unknown = true,
                    }
                }
                if saw_unknown { None } else { Some(false) }
            }
            _ => self.pattern_const(pat).map(|v| v == *subject),
        }
    }

    /// The literal a pattern compares against.
    ///
    /// Deliberately narrow: a bare identifier is a *capture* in Python's
    /// `case` and a binding in Rust's `match`, so it is never looked up as a
    /// constant here even when a same-named variable has a recorded value.
    fn pattern_const(&self, pat: Node) -> Option<ConstValue> {
        let text = self.source[pat.start_byte()..pat.end_byte()].trim();
        match pat.kind() {
            "string" | "concatenated_string" | "integer" | "float" => {
                if preceded_by_minus(self.source, pat) {
                    return None;
                }
                self.const_value(pat)
            }
            "true" => Some(ConstValue::Bool(true)),
            "false" => Some(ConstValue::Bool(false)),
            "none" | "null" => Some(ConstValue::Null),
            "case_pattern" => {
                let mut cursor = pat.walk();
                let named: Vec<Node> = pat.named_children(&mut cursor).collect();
                let [only] = named.as_slice() else {
                    return None;
                };
                // `case -1:` - the sign is an anonymous sibling of the
                // literal, so the wrapper is the only node that sees it.
                if text.starts_with('-') {
                    return match self.const_value(*only)? {
                        ConstValue::Int(i) => Some(ConstValue::Int(-i)),
                        ConstValue::Float(f) => Some(ConstValue::Float(-f)),
                        _ => None,
                    };
                }
                self.pattern_const(*only)
            }
            _ => None,
        }
    }
}

/// Is the token immediately before `node` a `-` sign? Used to refuse reading
/// `-1` as the positive literal `1` when the sign is a sibling token.
fn preceded_by_minus(source: &str, node: Node) -> bool {
    for &b in source.as_bytes()[..node.start_byte()].iter().rev() {
        if b.is_ascii_whitespace() {
            continue;
        }
        return b == b'-';
    }
    false
}
