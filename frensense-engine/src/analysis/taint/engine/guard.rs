// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

// ---------------------------------------------------------------------------
// Guard map (task 8.3, minimal form)
// ---------------------------------------------------------------------------

/// Per-function guard analysis: which variables are *checked* by a
/// guard-style call (`.test(x)`, `includes(x)`, allowlist `has(x)`) in which
/// blocks, plus dominator sets.
///
/// A value-flow graph alone cannot see guards: `if (SAFE.test(x)) sink(x)`
/// has the guard on a *sibling* use of `x`, so a backward walk from the sink
/// never passes through it. The fix is structural: the branch condition is
/// derived from a guard call on `x`; if that branch dominates the block the
/// sink lives in, any `x` value flowing there was checked.
#[derive(Default)]
pub(super) struct GuardMap {
    /// var → blocks whose terminator branch is derived from a guard-style
    /// call on that var.
    guards: FxHashMap<VarId, Vec<BlockId>>,
    /// block → set of blocks that dominate it (reflexive), computed once.
    dominators: FxHashMap<BlockId, FxHashSet<BlockId>>,
}

impl GuardMap {
    pub(super) fn build(ir: &FunctionIR, facts: &FactTable, config: &TaintConfig) -> Self {
        let mut guards: FxHashMap<VarId, Vec<BlockId>> = FxHashMap::default();

        // Walk: cond var → def instruction, up to 3 hops, collecting
        // guard-call vars along the way (handles `!ALLOWED.has(x)`,
        // `x != null && SAFE.test(x)` shape fragments).
        fn defs_of(instr: &Instruction) -> Vec<VarId> {
            let mut v = Vec::with_capacity(2);
            match instr {
                Instruction::Assign { dest, .. }
                | Instruction::AddressOf { dest, .. }
                | Instruction::LoadField { dest, .. }
                | Instruction::LoadElement { dest, .. }
                | Instruction::LoadGlobal { dest, .. }
                | Instruction::Cast { dest, .. }
                | Instruction::ExtractValue { dest, .. }
                | Instruction::BinaryOp { dest, .. }
                | Instruction::UnaryOp { dest, .. } => v.push(*dest),
                Instruction::CallStatic { dest, .. }
                | Instruction::CallVirtual { dest, .. }
                | Instruction::CallPointer { dest, .. } => {
                    if let Some(d) = dest {
                        v.push(*d);
                    }
                }
                _ => {}
            }
            v
        }
        fn def_site_of(ir: &FunctionIR, v: VarId) -> Option<&Instruction> {
            for b in ir.blocks.values() {
                for i in &b.instructions {
                    if defs_of(i).contains(&v) {
                        return Some(i);
                    }
                }
            }
            None
        }

        // Find guard calls and the vars they check.
        // A guard call is a CallVirtual/CallStatic whose method has a
        // guard-style SanitizerFact. The checked var is the first Var arg
        // (predicate on an argument) or the receiver (predicate on the
        // receiver, e.g. `file.includes('..')`).
        let checked_vars = |instr: &Instruction| -> Vec<VarId> {
            let (method, receiver, args) = match instr {
                Instruction::CallVirtual {
                    method,
                    receiver,
                    args,
                    ..
                } => (method, Some(receiver), args),
                Instruction::CallStatic { func, args, .. } => (func, None, args),
                _ => return Vec::new(),
            };
            let Some(f) = facts.sanitizer_fact(method) else {
                return Vec::new();
            };
            if !f.guard_style {
                return Vec::new();
            }
            // The call is guard-style; also confirm the method really is one
            // of the configured/known guards (fact table already ensures
            // this). Collect checked vars.
            let mut out = Vec::new();
            if let Some(Operand::Var(r)) = receiver {
                out.push(*r);
            }
            for a in args {
                if let Operand::Var(v) = a {
                    out.push(*v);
                    let mut cur_v = *v;
                    for _ in 0..3 {
                        if let Some(def) = def_site_of(ir, cur_v) {
                            match def {
                                Instruction::AddressOf { src, .. } => {
                                    out.push(*src);
                                    cur_v = *src;
                                }
                                Instruction::Assign {
                                    src: Operand::Var(s),
                                    ..
                                } => {
                                    out.push(*s);
                                    cur_v = *s;
                                }
                                _ => break,
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
            out
        };

        let exits = |bid: BlockId| -> bool {
            let mut cur = bid;
            for _ in 0..5 {
                match ir.blocks.get(&cur).map(|b| &b.terminator) {
                    Some(Terminator::Return { .. } | Terminator::Throw { .. }) => return true,
                    Some(Terminator::Jump(next)) => cur = *next,
                    _ => return false,
                }
            }
            false
        };

        let mut block_ids: Vec<BlockId> = ir.blocks.keys().copied().collect();
        block_ids.sort_by_key(|b| b.0);
        for &bid in &block_ids {
            let blk = &ir.blocks[&bid];
            let (cond_var, true_block, false_block) = match &blk.terminator {
                Terminator::Branch {
                    cond: Operand::Var(c),
                    true_block,
                    false_block,
                } => (Some(*c), *true_block, *false_block),
                _ => continue,
            };
            let Some(cond_var) = cond_var else { continue };
            // Hop 0..3 up the def chain from the condition, tracking polarity/sense.
            let mut frontier = vec![(cond_var, true)];
            for _hop in 0..3 {
                let mut next = Vec::new();
                for (v, sense) in &frontier {
                    let Some(instr) = def_site_of(ir, *v) else {
                        continue;
                    };
                    match instr {
                        Instruction::CallStatic { .. } | Instruction::CallVirtual { .. } => {
                            for cv in checked_vars(instr) {
                                let true_exits = exits(true_block);
                                let false_exits = exits(false_block);
                                let safe_block = if true_exits && !false_exits {
                                    false_block
                                } else if (false_exits && !true_exits) || *sense {
                                    true_block
                                } else {
                                    false_block
                                };
                                guards.entry(cv).or_default().push(safe_block);
                            }
                        }
                        Instruction::UnaryOp {
                            op,
                            src: Operand::Var(u),
                            ..
                        } => {
                            let new_sense = if op == "!" || op == "neg" || op == "not" {
                                !*sense
                            } else {
                                *sense
                            };
                            next.push((*u, new_sense));
                        }
                        Instruction::BinaryOp { op, lhs, rhs, .. } => {
                            let literal_sibling = matches!(
                                (lhs, rhs),
                                (Operand::StringLiteral(_), _)
                                    | (_, Operand::StringLiteral(_))
                                    | (Operand::IntLiteral(_), _)
                                    | (_, Operand::IntLiteral(_))
                            );
                            let is_comparison = op.contains("in")
                                || op == "=="
                                || op == "==="
                                || op == "!="
                                || op == "!=="
                                || op == "not";
                            if literal_sibling && is_comparison {
                                let is_inverted = op == "!=" || op == "!==" || op == "not in";
                                let is_denylist = match (lhs, rhs) {
                                    (Operand::StringLiteral(s), _)
                                        if facts.is_guard_denylist(s) =>
                                    {
                                        true
                                    }
                                    (_, Operand::StringLiteral(s))
                                        if facts.is_guard_denylist(s) =>
                                    {
                                        true
                                    }
                                    _ => false,
                                };
                                let effective_sense = if is_inverted ^ is_denylist {
                                    !*sense
                                } else {
                                    *sense
                                };
                                let safe_block = if effective_sense {
                                    true_block
                                } else {
                                    false_block
                                };
                                for op in [lhs, rhs] {
                                    if let Operand::Var(u) = op {
                                        guards.entry(*u).or_default().push(safe_block);
                                        if let Some(Instruction::UnaryOp {
                                            op: uop,
                                            src: Operand::Var(inner),
                                            ..
                                        }) = def_site_of(ir, *u)
                                            && uop == "typeof"
                                        {
                                            guards.entry(*inner).or_default().push(safe_block);
                                        }
                                    }
                                }
                            }
                            for op in [lhs, rhs] {
                                if let Operand::Var(u) = op {
                                    next.push((*u, *sense));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if next.is_empty() {
                    break;
                }
                frontier = next;
            }
        }
        let _ = config;

        // Dominators: shared structural module (also serves policy guard
        // dominance and control-dependence queries in checks).
        let dominators = crate::ir::control::dominators(ir);

        Self { guards, dominators }
    }

    /// Is `var` checked by a guard that dominates `sink_block`?
    pub(super) fn is_guarded(&self, var: VarId, sink_block: BlockId) -> bool {
        let Some(gs) = self.guards.get(&var) else {
            return false;
        };
        let Some(doms) = self.dominators.get(&sink_block) else {
            return false;
        };
        gs.iter().any(|g| doms.contains(g))
    }
}
