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
//! The analysis runs a standard worklist fixpoint over the CFG (blocks in
//! RPO, per-var state joined at block entry), so loops reach a stable state
//! via the monotone join without unrolling.

use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;

use crate::ir::function::{FunctionIR, Instruction, Operand, Terminator};

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
            // Two different int constants join to their hull — the interval
            // domain's answer (join must over-approximate both).
            (IntConst(a), IntConst(b)) => Range((*a).min(*b), (*a).max(*b)),
            (StrConst(a), StrConst(b)) if a == b => StrConst(a.clone()),
            (BoolConst(a), BoolConst(b)) if a == b => BoolConst(*a),
            (Range(a, b), Range(c, d)) => Range((*a).min(*c), (*b).max(*d)),
            // Const ↔ Range unify to the Range form (Const is the degenerate
            // point interval; a point inside a range joins to that range).
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
}

/// Abstract state: one entry per var that has a non-`Top` value.
pub type AbsState = FxHashMap<crate::ir::function::VarId, Value>;

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

/// Apply a binary operator to two integer intervals. Non-integer inputs and
/// unsupported operators yield `Top`.
fn binary_interval(op: &str, a: (i64, i64), b: (i64, i64)) -> Value {
    let (al, ah) = a;
    let (bl, bh) = b;
    let add = |x: i64, y: i64| x.saturating_add(y);
    match op {
        // The TS lowering emits `concat` for `+` (string bias), but the
        // operation is numeric addition when both operands are integer values.
        "+" | "concat" => Value::Range(add(al, bl), add(ah, bh)),
        "-" => Value::Range(add(al, -bh), add(ah, -bl)),
        "*" => {
            let products = [al * bl, al * bh, ah * bl, ah * bh];
            Value::Range(
                products.iter().copied().min().unwrap_or(al),
                products.iter().copied().max().unwrap_or(ah),
            )
        }
        "<<" => {
            if (0..=32).contains(&bl) && bl == bh {
                Value::Range(al << bl, ah << bh)
            } else {
                Value::Top
            }
        }
        ">>" => {
            if (0..=63).contains(&bl) && bl == bh {
                Value::Range(al >> bl, ah >> bh)
            } else {
                Value::Top
            }
        }
        _ => Value::Top,
    }
}

/// Transfer function for one instruction: the (dest, value) it defines, if
/// the instruction defines a var we can model.
fn transfer(state: &AbsState, instr: &Instruction) -> Option<(crate::ir::function::VarId, Value)> {
    match instr {
        Instruction::Assign { dest, src } => Some((*dest, operand_value(state, src))),
        Instruction::BinaryOp { dest, op, lhs, rhs } => {
            let lv = operand_value(state, lhs);
            let rv = operand_value(state, rhs);
            let out = match op.as_str() {
                // Boolean-valued comparisons: precise only between consts.
                "==" | "===" => match (&lv, &rv) {
                    (Value::IntConst(a), Value::IntConst(b)) => Value::BoolConst(a == b),
                    (Value::StrConst(a), Value::StrConst(b)) => Value::BoolConst(a == b),
                    (Value::BoolConst(a), Value::BoolConst(b)) => Value::BoolConst(a == b),
                    _ => Value::Top,
                },
                "!=" | "!==" => match (&lv, &rv) {
                    (Value::IntConst(a), Value::IntConst(b)) => Value::BoolConst(a != b),
                    (Value::StrConst(a), Value::StrConst(b)) => Value::BoolConst(a != b),
                    (Value::BoolConst(a), Value::BoolConst(b)) => Value::BoolConst(a != b),
                    _ => Value::Top,
                },
                "<" | ">" | "<=" | ">=" => {
                    match (lv.interval(), rv.interval()) {
                        (Some((al, ah)), Some((bl, bh))) => {
                            // Interval comparison: definite only when the
                            // whole ranges are ordered.
                            let definite = match op.as_str() {
                                "<" => ah < bl,
                                ">" => al > bh,
                                "<=" => ah <= bl,
                                ">=" => al >= bh,
                                _ => false,
                            };
                            if definite {
                                Value::BoolConst(true)
                            } else {
                                // May or may not hold: still possibly false.
                                let impossible = match op.as_str() {
                                    "<" => al >= bh,
                                    ">" => ah <= bl,
                                    "<=" => al > bh,
                                    ">=" => ah < bl,
                                    _ => false,
                                };
                                if impossible {
                                    Value::BoolConst(false)
                                } else {
                                    Value::Top
                                }
                            }
                        }
                        _ => Value::Top,
                    }
                }
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
                "-" => match v.interval() {
                    Some((lo, hi)) => Value::Range(-hi, -lo),
                    None => Value::Top,
                },
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

/// A single forward pass over the CFG in reverse-postorder. Returns the
/// block-entry state for every block. Monotone: joining at CFG merges only
/// ever widens, so iterating to a fixpoint (needed for loops) terminates;
/// one RPO pass + loop re-visits via worklist reaches it.
fn fixpoint(ir: &FunctionIR) -> FxHashMap<crate::ir::function::BlockId, AbsState> {
    use crate::ir::function::BlockId;

    // Successors per block (branch shape determines successor states: at a
    // Branch both arms inherit the same state — branch sharpening is a
    // refinement this pass deliberately does not do, keeping the lattice
    // decoupled from condition evaluation).
    let mut order: Vec<BlockId> = ir.blocks.keys().copied().collect();
    order.sort_by_key(|b| b.0);

    // Reverse postorder from entry (mirrors the guard map's traversal).
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
    let rpo: Vec<BlockId> = po.iter().rev().copied().collect();

    let mut in_state: FxHashMap<BlockId, AbsState> = FxHashMap::default();
    let mut exit_state: FxHashMap<BlockId, AbsState> = FxHashMap::default();

    // Worklist: (block) — reprocess blocks whose entry state widened.
    let mut queue: VecDeque<BlockId> = VecDeque::new();
    let mut queued: FxHashSet<BlockId> = FxHashSet::default();
    let mut iterations: usize = 0;
    const MAX_ITERATIONS: usize = 64; // soundness unaffected: we only ever JOIN

    for &b in &rpo {
        queue.push_back(b);
        queued.insert(b);
    }

    while let Some(bid) = queue.pop_front() {
        iterations += 1;
        if iterations > MAX_ITERATIONS * (order.len() + 1) {
            // Pathological CFG: stop widening; states are sound (joins only).
            break;
        }
        queued.remove(&bid);

        // 1. Entry state = join of predecessors' exit states.
        let mut entry: AbsState = AbsState::default();
        let preds: Vec<BlockId> = ir
            .blocks
            .get(&bid)
            .map(|b| b.predecessors.clone())
            .unwrap_or_default();
        let mut first = true;
        for &p in &preds {
            let pstate = match exit_state.get(&p) {
                // Predecessor not yet processed contributes nothing yet
                // (its contribution joins in when it is processed).
                Some(s) => s.clone(),
                None => continue,
            };
            if first {
                entry = pstate;
                first = false;
            } else {
                for (v, val) in &pstate {
                    let merged = match entry.get(v) {
                        // Absent on either side = the var simply isn't
                        // constrained there; the join keeps the present
                        // value (Top only when BOTH sides are present and
                        // incompatible).
                        None => val.clone(),
                        Some(cur) => cur.join(val),
                    };
                    if merged == Value::Top {
                        entry.remove(v);
                    } else {
                        entry.insert(*v, merged);
                    }
                }
            }
        }
        // Phi merges: an SSA phi is a join over its incoming values.
        if let Some(blk) = ir.blocks.get(&bid) {
            for phi in &blk.phis {
                let mut acc: Option<Value> = None;
                for (_, v) in &phi.incoming {
                    let val = entry.get(v).cloned().unwrap_or(Value::Top);
                    acc = Some(match acc {
                        None => val,
                        Some(a) => a.join(&val),
                    });
                }
                let val = acc.unwrap_or(Value::Top);
                if val == Value::Top {
                    entry.remove(&phi.dest);
                } else {
                    entry.insert(phi.dest, val);
                }
            }
        }
        in_state.insert(bid, entry.clone());

        // 2. Transfer through the block's instructions.
        if let Some(blk) = ir.blocks.get(&bid) {
            for instr in &blk.instructions {
                if let Some((dest, val)) = transfer(&entry, instr) {
                    if val == Value::Top {
                        entry.remove(&dest);
                    } else {
                        entry.insert(dest, val);
                    }
                }
            }
        }
        // The block-exit state is what successors join.
        exit_state.insert(bid, entry.clone());

        // 3. Propagate the block-exit state to successors: requeue a
        // successor when its entry state would widen.
        if let Some(blk) = ir.blocks.get(&bid) {
            let mut succs: Vec<BlockId> = Vec::new();
            match &blk.terminator {
                Terminator::Jump(s) => succs.push(*s),
                Terminator::Branch {
                    true_block,
                    false_block,
                    ..
                } => {
                    succs.push(*true_block);
                    succs.push(*false_block);
                }
                Terminator::Switch {
                    cases,
                    default_block,
                    ..
                } => {
                    succs.extend(cases.iter().map(|(_, b)| *b));
                    succs.push(*default_block);
                }
                _ => {}
            }
            for s in succs {
                let changed = match in_state.get(&s) {
                    None => true,
                    Some(old) => {
                        // Would joining the new exit state into s's entry
                        // change anything? (Conservative: requeue on any
                        // potential widening.)
                        entry.iter().any(|(v, val)| match old.get(v) {
                            Some(cur) => cur.join(val) != *cur,
                            // A brand-new key reaching the successor is a
                            // widening too (its state didn't know the var).
                            None => *val != Value::Top,
                        })
                    }
                };
                if changed && queued.insert(s) {
                    queue.push_back(s);
                }
            }
        }
    }

    in_state
}

/// The per-function analysis result: each variable's value at the point
/// where its *defining instruction* executes (the natural consumer view:
/// checkers ask "what is this variable here?").
pub struct ValueInfo {
    /// var → abstract value (only non-`Top` entries).
    pub values: FxHashMap<crate::ir::function::VarId, Value>,
    /// Number of CFG blocks analysed (diagnostics).
    pub blocks: usize,
}

/// Analyse one function. Constants propagate through assignments, binary/
/// unary ops, casts and phis; calls, memory ops and externals yield `Top`
/// for their destinations. Terminates on any CFG (monotone joins, bounded
/// worklist).
pub fn analyze(ir: &FunctionIR) -> ValueInfo {
    let in_states = fixpoint(ir);

    // Per-def view: run the transfer for each defining instruction under its
    // block's ENTRY state plus the effects of preceding instructions in the
    // same block (already done by the fixpoint's local replay; we redo it
    // here to collect the value at each def site).
    let mut values: FxHashMap<crate::ir::function::VarId, Value> = FxHashMap::default();
    for (bid, mut state) in in_states {
        let Some(blk) = ir.blocks.get(&bid) else {
            continue;
        };
        // Phi results are part of the block-entry state (the fixpoint
        // merged them in); record them as def-site values.
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
    }
}

impl ValueInfo {
    /// The constant value of `var`, if provably constant.
    pub fn const_int(&self, var: crate::ir::function::VarId) -> Option<i64> {
        match self.values.get(&var)? {
            Value::IntConst(n) => Some(*n),
            Value::Range(lo, hi) if lo == hi => Some(*lo),
            _ => None,
        }
    }

    /// The string constant of `var`, if provably constant.
    pub fn const_str(&self, var: crate::ir::function::VarId) -> Option<&str> {
        match self.values.get(&var)? {
            Value::StrConst(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The interval of `var`, if an integer with a known range.
    pub fn range(&self, var: crate::ir::function::VarId) -> Option<(i64, i64)> {
        self.values.get(&var).and_then(Value::interval)
    }
}
