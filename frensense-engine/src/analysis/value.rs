// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Per-function constant/interval value lattice (an abstract-interpretation
//! pass over the lowered IR).
//!
//! Taint answers "whose data is this?"; this module answers "what data is
//! this?". The two questions are orthogonal, and the second unlocks bug
//! classes taint cannot see: integer bounds, weak crypto key sizes, literal
//! selectors, constant-condition dead code, and hard evidence that a value
//! is attacker-independent (taint verdict promotion).
//!
//! The lattice per variable is the classic constant-propagation domain lifted
//! to a two-dimensional interval for integers:
//!
//! ```text
//!            Const(i64)  |  Const(String)  |  Const(bool)      (precise)
//!            Range(lo..=hi)                                   (interval)
//!            Top                                              (unknown)
//! ```
//!
//! Join is value-wise: `Const(a) ⊔ Const(b) = Top` unless equal;
//! intervals widen to their hull; anything else degrades to `Top`. The
//! transfer functions cover `Assign`, `BinaryOp`, `UnaryOp`, `Cast`, and the
//! block-level `Phi` merge; every other definition (calls, loads, externals)
//! yields `Top` for its destination, which is the sound over-approximation.
//!
//! The analysis runs a standard worklist fixpoint over the CFG with edge-state
//! branch sharpening: conditional branches narrow numeric intervals along
//! true and false paths (e.g. `x < 10` refines `x` to `[MIN, 9]` on true and
//! `[10, MAX]` on false).

use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;

use crate::ir::function::{BlockId, FunctionIR, Instruction, Operand, Terminator, VarId};

/// One variable's abstract value at a program point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A provably constant integer.
    IntConst(i64),
    /// A provably constant string (quotes already stripped by the lowering).
    StrConst(String),
    /// A provably constant boolean.
    BoolConst(bool),
    /// A known integer interval (inclusive). `Const(n)` is the degenerate
    /// `Range(n, n)`; the separate `IntConst` variant keeps precise equality
    /// joins cheap and makes callers' intent explicit.
    Range(i64, i64),
    /// Unknown / not provably constant. Sound default.
    Top,
}

impl Value {
    /// The interval hull of this value, for range arithmetic and joins.
    /// Non-integer values have no interval (`None`).
    pub fn interval(&self) -> Option<(i64, i64)> {
        match self {
            Value::IntConst(n) => Some((*n, *n)),
            Value::Range(lo, hi) => Some((*lo, *hi)),
            _ => None,
        }
    }

    /// Least upper bound (the join). Associative and commutative; `Top` is
    /// the identity for soundness (unknown absorbs anything).
    pub fn join(&self, other: &Value) -> Value {
        use Value::*;
        match (self, other) {
            (IntConst(a), IntConst(b)) if a == b => IntConst(*a),
            (IntConst(a), IntConst(b)) => Range((*a).min(*b), (*a).max(*b)),
            (StrConst(a), StrConst(b)) if a == b => StrConst(a.clone()),
            (BoolConst(a), BoolConst(b)) if a == b => BoolConst(*a),
            (Range(a, b), Range(c, d)) => Range((*a).min(*c), (*b).max(*d)),
            (IntConst(a), Range(c, d)) | (Range(c, d), IntConst(a)) => {
                Range((*c).min(*a), (*d).max(*a))
            }
            _ => Top,
        }
    }

    /// Is this a definite constant (the precise strata)?
    pub fn is_const(&self) -> bool {
        matches!(
            self,
            Value::IntConst(_) | Value::StrConst(_) | Value::BoolConst(_)
        )
    }

    /// Intersect an integer value/range with an inclusive interval `[min_lo, max_hi]`.
    pub fn intersect_interval(&self, min_lo: Option<i64>, max_hi: Option<i64>) -> Value {
        match self {
            Value::IntConst(n) => {
                if min_lo.map_or(true, |lo| *n >= lo) && max_hi.map_or(true, |hi| *n <= hi) {
                    Value::IntConst(*n)
                } else {
                    self.clone()
                }
            }
            Value::Range(lo, hi) => {
                let new_lo = min_lo.map_or(*lo, |m| (*lo).max(m));
                let new_hi = max_hi.map_or(*hi, |m| (*hi).min(m));
                if new_lo > new_hi {
                    self.clone()
                } else if new_lo == new_hi {
                    Value::IntConst(new_lo)
                } else {
                    Value::Range(new_lo, new_hi)
                }
            }
            Value::Top => match (min_lo, max_hi) {
                (Some(lo), Some(hi)) if lo == hi => Value::IntConst(lo),
                (Some(lo), Some(hi)) if lo <= hi => Value::Range(lo, hi),
                (Some(lo), None) => Value::Range(lo, i64::MAX),
                (None, Some(hi)) => Value::Range(i64::MIN, hi),
                _ => Value::Top,
            },
            _ => self.clone(),
        }
    }
}

/// Abstract state: one entry per var that has a non-`Top` value.
pub type AbsState = FxHashMap<VarId, Value>;

/// Merge state `b` into `a` using the lattice join operation.
fn merge_states(a: &mut AbsState, b: &AbsState) {
    for (v, val) in b {
        let merged = match a.get(v) {
            None => val.clone(),
            Some(cur) => cur.join(val),
        };
        if merged == Value::Top {
            a.remove(v);
        } else {
            a.insert(*v, merged);
        }
    }
}

/// Evaluate one `Operand` under a state.
fn operand_value(state: &AbsState, op: &Operand) -> Value {
    match op {
        Operand::IntLiteral(n) => Value::IntConst(*n),
        Operand::StringLiteral(s) => Value::StrConst(s.clone()),
        Operand::BoolLiteral(b) => Value::BoolConst(*b),
        Operand::Var(v) => state.get(v).cloned().unwrap_or(Value::Top),
        Operand::FloatLiteral(_) | Operand::Null | Operand::Unknown => Value::Top,
    }
}

/// Apply a binary operator to two integer intervals.
fn binary_interval(op: &str, (al, ah): (i64, i64), (bl, bh): (i64, i64)) -> Value {
    let add = |x: i64, y: i64| x.saturating_add(y);
    match op {
        "+" | "concat" => Value::Range(add(al, bl), add(ah, bh)),
        "-" => Value::Range(add(al, -bh), add(ah, -bl)),
        "*" => {
            let p = [al * bl, al * bh, ah * bl, ah * bh];
            Value::Range(*p.iter().min().unwrap_or(&al), *p.iter().max().unwrap_or(&ah))
        }
        "<<" if bl == bh && (0..=32).contains(&bl) => Value::Range(al << bl, ah << bh),
        ">>" if bl == bh && (0..=63).contains(&bl) => Value::Range(al >> bl, ah >> bh),
        _ => Value::Top,
    }
}

/// Transfer function for one instruction.
fn transfer(state: &AbsState, instr: &Instruction) -> Option<(VarId, Value)> {
    match instr {
        Instruction::Assign { dest, src } => Some((*dest, operand_value(state, src))),
        Instruction::BinaryOp { dest, op, lhs, rhs } => {
            let lv = operand_value(state, lhs);
            let rv = operand_value(state, rhs);
            let out = match op.as_str() {
                "==" | "===" | "!=" | "!==" => {
                    let eq = match (&lv, &rv) {
                        (Value::IntConst(a), Value::IntConst(b)) => Some(a == b),
                        (Value::StrConst(a), Value::StrConst(b)) => Some(a == b),
                        (Value::BoolConst(a), Value::BoolConst(b)) => Some(a == b),
                        _ => None,
                    };
                    eq.map(|e| Value::BoolConst(if op.starts_with('!') { !e } else { e }))
                        .unwrap_or(Value::Top)
                }
                "<" | ">" | "<=" | ">=" => match (lv.interval(), rv.interval()) {
                    (Some((al, ah)), Some((bl, bh))) => match op.as_str() {
                        "<" if ah < bl => Value::BoolConst(true),
                        "<" if al >= bh => Value::BoolConst(false),
                        "<=" if ah <= bl => Value::BoolConst(true),
                        "<=" if al > bh => Value::BoolConst(false),
                        ">" if al > bh => Value::BoolConst(true),
                        ">" if ah <= bl => Value::BoolConst(false),
                        ">=" if al >= bh => Value::BoolConst(true),
                        ">=" if ah < bl => Value::BoolConst(false),
                        _ => Value::Top,
                    },
                    _ => Value::Top,
                },
                _ => match (lv.interval(), rv.interval()) {
                    (Some(a), Some(b)) => binary_interval(op, a, b),
                    _ => Value::Top,
                },
            };
            Some((*dest, out))
        }
        Instruction::UnaryOp { dest, op, src } => {
            let v = operand_value(state, src);
            let out = match op.as_str() {
                "-" => v.interval().map_or(Value::Top, |(lo, hi)| Value::Range(-hi, -lo)),
                "!" => match v {
                    Value::BoolConst(b) => Value::BoolConst(!b),
                    _ => Value::Top,
                },
                "~" => match v {
                    Value::IntConst(n) => Value::IntConst(!n),
                    _ => Value::Top,
                },
                _ => Value::Top,
            };
            Some((*dest, out))
        }
        Instruction::Cast { dest, src, .. } => Some((*dest, operand_value(state, src))),
        _ => None,
    }
}

/// Sharpen variable bounds along a branch condition.
fn sharpen_branch(
    mut state: AbsState,
    cond: &Operand,
    is_true: bool,
    defs: &FxHashMap<VarId, &Instruction>,
) -> AbsState {
    let mut cur = cond;
    let mut sense = is_true;
    loop {
        match cur {
            Operand::Var(c) => {
                state.insert(*c, Value::BoolConst(sense));
                match defs.get(c) {
                    Some(Instruction::UnaryOp { op, src, .. }) if op == "!" => {
                        cur = src;
                        sense = !sense;
                    }
                    Some(Instruction::Assign { src, .. }) => cur = src,
                    Some(Instruction::BinaryOp { op, lhs, rhs, .. }) => {
                        let (var, norm_op, bound) = match (lhs, rhs) {
                            (Operand::Var(v), r) => match operand_value(&state, r) {
                                Value::IntConst(k) => (*v, op.as_str(), k),
                                _ => return state,
                            },
                            (l, Operand::Var(v)) => match operand_value(&state, l) {
                                Value::IntConst(k) => {
                                    let inv = match op.as_str() {
                                        "<" => ">",
                                        "<=" => ">=",
                                        ">" => "<",
                                        ">=" => "<=",
                                        eq => eq,
                                    };
                                    (*v, inv, k)
                                }
                                _ => return state,
                            },
                            _ => return state,
                        };

                        let (lo, hi) = match (norm_op, sense) {
                            ("<", true) | (">=", false) => (None, bound.checked_sub(1)),
                            ("<=", true) | (">", false) => (None, Some(bound)),
                            (">", true) | ("<=", false) => (bound.checked_add(1), None),
                            (">=", true) | ("<", false) => (Some(bound), None),
                            ("==" | "===", true) | ("!=" | "!==", false) => {
                                (Some(bound), Some(bound))
                            }
                            _ => (None, None),
                        };

                        if lo.is_some() || hi.is_some() {
                            let cur_val = state.get(&var).cloned().unwrap_or(Value::Top);
                            let narrowed = cur_val.intersect_interval(lo, hi);
                            if narrowed == Value::Top {
                                state.remove(&var);
                            } else {
                                state.insert(var, narrowed);
                            }
                        }
                        return state;
                    }
                    _ => return state,
                }
            }
            _ => return state,
        }
    }
}

/// Compute fixpoint abstract states with edge-sensitive branch sharpening.
fn fixpoint(ir: &FunctionIR) -> FxHashMap<BlockId, AbsState> {
    // Pre-index definition instructions for fast predicate inspection.
    let mut defs: FxHashMap<VarId, &Instruction> = FxHashMap::default();
    for blk in ir.blocks.values() {
        for instr in &blk.instructions {
            match instr {
                Instruction::Assign { dest, .. }
                | Instruction::BinaryOp { dest, .. }
                | Instruction::UnaryOp { dest, .. }
                | Instruction::Cast { dest, .. } => {
                    defs.insert(*dest, instr);
                }
                _ => {}
            }
        }
    }

    // Reverse postorder from entry block.
    let mut po = Vec::new();
    let mut seen: FxHashSet<BlockId> = FxHashSet::default();
    let mut stack = vec![(ir.entry_block, 0usize)];
    while let Some((b, i)) = stack.pop() {
        if i == 0 {
            if !seen.insert(b) {
                continue;
            }
            stack.push((b, 1));
            if let Some(blk) = ir.blocks.get(&b) {
                for &s in &blk.successors {
                    stack.push((s, 0));
                }
            }
        } else {
            po.push(b);
        }
    }
    let rpo: Vec<BlockId> = po.into_iter().rev().collect();

    let mut in_state: FxHashMap<BlockId, AbsState> = FxHashMap::default();
    let mut edge_state: FxHashMap<(BlockId, BlockId), AbsState> = FxHashMap::default();

    let mut queue: VecDeque<BlockId> = VecDeque::new();
    let mut queued: FxHashSet<BlockId> = FxHashSet::default();
    let mut iterations: usize = 0;
    const MAX_ITERATIONS: usize = 64;

    for &b in &rpo {
        queue.push_back(b);
        queued.insert(b);
    }

    while let Some(bid) = queue.pop_front() {
        iterations += 1;
        if iterations > MAX_ITERATIONS * (ir.blocks.len() + 1) {
            break;
        }
        queued.remove(&bid);

        // 1. Entry state = join of incoming predecessor edge states.
        let mut entry = AbsState::default();
        let preds = ir
            .blocks
            .get(&bid)
            .map(|b| b.predecessors.as_slice())
            .unwrap_or(&[]);
        let mut first = true;
        for &p in preds {
            if let Some(pstate) = edge_state.get(&(p, bid)) {
                if first {
                    entry = pstate.clone();
                    first = false;
                } else {
                    merge_states(&mut entry, pstate);
                }
            }
        }

        // Phi merges: join over incoming operands.
        if let Some(blk) = ir.blocks.get(&bid) {
            for phi in &blk.phis {
                let mut acc: Option<Value> = None;
                for (_, v) in &phi.incoming {
                    let val = entry.get(v).cloned().unwrap_or(Value::Top);
                    acc = Some(acc.map_or(val.clone(), |a| a.join(&val)));
                }
                match acc.unwrap_or(Value::Top) {
                    Value::Top => entry.remove(&phi.dest),
                    v => entry.insert(phi.dest, v),
                };
            }
        }
        in_state.insert(bid, entry.clone());

        // 2. Transfer through the block's instructions.
        let mut exit = entry;
        if let Some(blk) = ir.blocks.get(&bid) {
            for instr in &blk.instructions {
                if let Some((dest, val)) = transfer(&exit, instr) {
                    if val == Value::Top {
                        exit.remove(&dest);
                    } else {
                        exit.insert(dest, val);
                    }
                }
            }
        }

        // 3. Propagate refined edge states to CFG successors.
        if let Some(blk) = ir.blocks.get(&bid) {
            let edges: Vec<(BlockId, AbsState)> = match &blk.terminator {
                Terminator::Jump(s) => vec![(*s, exit)],
                Terminator::Branch {
                    cond,
                    true_block,
                    false_block,
                } => {
                    if true_block == false_block {
                        vec![(*true_block, exit)]
                    } else {
                        vec![
                            (*true_block, sharpen_branch(exit.clone(), cond, true, &defs)),
                            (*false_block, sharpen_branch(exit, cond, false, &defs)),
                        ]
                    }
                }
                Terminator::Switch {
                    cases,
                    default_block,
                    ..
                } => {
                    let mut e: Vec<_> = cases.iter().map(|(_, b)| (*b, exit.clone())).collect();
                    e.push((*default_block, exit));
                    e
                }
                _ => vec![],
            };

            for (succ, new_state) in edges {
                let edge_key = (bid, succ);
                let changed = match edge_state.get(&edge_key) {
                    None => true,
                    Some(old) => old != &new_state,
                };
                if changed {
                    edge_state.insert(edge_key, new_state);
                    if queued.insert(succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }
    }

    in_state
}

/// The per-function analysis result: each variable's value at the point
/// where its defining instruction executes, plus block-entry states.
pub struct ValueInfo {
    /// var → abstract value (only non-`Top` entries).
    pub values: FxHashMap<VarId, Value>,
    /// Number of CFG blocks analysed (diagnostics).
    pub blocks: usize,
    /// Block-entry abstract states (keyed by block ID).
    pub block_entry_states: FxHashMap<BlockId, AbsState>,
}

/// Analyse one function.
pub fn analyze(ir: &FunctionIR) -> ValueInfo {
    let in_states = fixpoint(ir);

    let mut values: FxHashMap<VarId, Value> = FxHashMap::default();
    for (bid, mut state) in in_states.clone() {
        let Some(blk) = ir.blocks.get(&bid) else {
            continue;
        };
        for phi in &blk.phis {
            if let Some(val) = state.get(&phi.dest) {
                values.insert(phi.dest, val.clone());
            }
        }
        for instr in &blk.instructions {
            if let Some((dest, val)) = transfer(&state, instr) {
                values.insert(dest, val.clone());
                if val == Value::Top {
                    state.remove(&dest);
                } else {
                    state.insert(dest, val);
                }
            }
        }
    }
    values.retain(|_, v| *v != Value::Top);
    ValueInfo {
        values,
        blocks: ir.blocks.len(),
        block_entry_states: in_states,
    }
}

impl ValueInfo {
    /// The constant value of `var`, if provably constant.
    pub fn const_int(&self, var: VarId) -> Option<i64> {
        match self.values.get(&var)? {
            Value::IntConst(n) => Some(*n),
            Value::Range(lo, hi) if lo == hi => Some(*lo),
            _ => None,
        }
    }

    /// The string constant of `var`, if provably constant.
    pub fn const_str(&self, var: VarId) -> Option<&str> {
        match self.values.get(&var)? {
            Value::StrConst(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The interval of `var`, if an integer with a known range.
    pub fn range(&self, var: VarId) -> Option<(i64, i64)> {
        self.values.get(&var).and_then(Value::interval)
    }

    /// The constant integer value of `var` at the entry of `block`.
    pub fn const_int_at(&self, block: BlockId, var: VarId) -> Option<i64> {
        match self.block_entry_states.get(&block)?.get(&var)? {
            Value::IntConst(n) => Some(*n),
            Value::Range(lo, hi) if lo == hi => Some(*lo),
            _ => None,
        }
    }

    /// The interval of `var` at the entry of `block`.
    pub fn range_at(&self, block: BlockId, var: VarId) -> Option<(i64, i64)> {
        self.block_entry_states
            .get(&block)?
            .get(&var)
            .and_then(Value::interval)
    }
}
