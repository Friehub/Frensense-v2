// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

use super::*;

use std::collections::VecDeque;

use crate::analysis::forward::{is_sanitizer_effective_for_role, is_source, sink_alert_with_facts};
use crate::dbg_trace;
use crate::debug_flags::DebugFlags;
use crate::graph::svfg::NodeKind;

// ---------------------------------------------------------------------------
// Constant evaluation + branch feasibility
// ---------------------------------------------------------------------------

/// Constant-fold a variable's definition chain to an integer value.
///
/// Handles the literal-arithmetic shapes that decide ternary/if branches:
/// `Assign` from an `IntLiteral`, and `BinaryOp` arithmetic over literal
/// operands (`7 * 18 + num > 200` folds bottom-up). Bounded hops keep
/// pathological chains cheap. `None` = not a constant.
fn const_eval(ir: &FunctionIR, var: VarId) -> Option<i64> {
    fn operand_const(ir: &FunctionIR, op: &Operand, hops: u8) -> Option<i64> {
        match op {
            Operand::IntLiteral(i) => Some(*i),
            Operand::Var(v) => const_eval_hops(ir, *v, hops),
            _ => None,
        }
    }
    fn const_eval_hops(ir: &FunctionIR, var: VarId, hops: u8) -> Option<i64> {
        if hops == 0 {
            return None;
        }
        let def = defs_of_var(ir, var)?;
        match def {
            Instruction::Assign {
                src: Operand::IntLiteral(i),
                ..
            } => Some(*i),
            Instruction::BinaryOp { op, lhs, rhs, .. } => {
                let l = operand_const(ir, lhs, hops - 1)?;
                let r = operand_const(ir, rhs, hops - 1)?;
                // The lowering maps `+` to op "concat" (the generic
                // additive fold); arithmetic on IntLiterals is still
                // integer addition there.
                Some(match op.as_str() {
                    "concat" | "+" => l.wrapping_add(r),
                    "-" => l.wrapping_sub(r),
                    "*" => l.wrapping_mul(r),
                    "/" => {
                        if r == 0 {
                            return None;
                        }
                        l.wrapping_div(r)
                    }
                    "%" => {
                        if r == 0 {
                            return None;
                        }
                        l.wrapping_rem(r)
                    }
                    _ => return None,
                })
            }
            _ => None,
        }
    }
    const_eval_hops(ir, var, 8)
}

/// Find the single instruction defining `var` (bounded scan).
fn defs_of_var(ir: &FunctionIR, var: VarId) -> Option<&Instruction> {
    for b in ir.blocks.values() {
        for i in &b.instructions {
            let dests: Vec<VarId> = match i {
                Instruction::Assign { dest, .. }
                | Instruction::BinaryOp { dest, .. }
                | Instruction::UnaryOp { dest, .. }
                | Instruction::LoadField { dest, .. }
                | Instruction::LoadElement { dest, .. }
                | Instruction::LoadGlobal { dest, .. }
                | Instruction::Cast { dest, .. } => vec![*dest],
                Instruction::CallStatic { dest: Some(d), .. }
                | Instruction::CallVirtual { dest: Some(d), .. } => vec![*d],
                _ => Vec::new(),
            };
            if dests.contains(&var) {
                return Some(i);
            }
        }
    }
    None
}

/// Evaluate a comparison over two constant operands.
fn compare_consts(op: &str, l: i64, r: i64) -> Option<bool> {
    Some(match op {
        ">" => l > r,
        "<" => l < r,
        ">=" => l >= r,
        "<=" => l <= r,
        "==" => l == r,
        "!=" => l != r,
        _ => return None,
    })
}

/// Record a silent stop site on the current root's exploration, keeping
/// the list free of duplicates (a walk can hit the same cut on many nodes).
fn record_cut(cuts: &mut Vec<&'static str>, reason: &'static str) {
    if !cuts.contains(&reason) {
        cuts.push(reason);
    }
}

/// Most stop sites kept per sink argument: enough to name the blind spot,
/// bounded so a wide fan-in cannot bloat every finding.
const MAX_CUT_SITES: usize = 4;

/// [`CutSite::kind`] for a call with no analysed callee that the walk flowed
/// *through* (its arguments were followed, assuming the result carries them).
const PASSED_THROUGH: &str = "passed-through";

/// Standard-library adapters, sorted: they are defined to forward their
/// operands into the result, so naming one as a pass-through tells a reader
/// nothing. Keeping them out leaves the list to calls the engine genuinely
/// has no model for (`mystery.read(req.params)`), which is the point of it.
/// Detection never consults this: it only filters the explanation.
const STD_FORWARDERS: &[&str] = &[
    "and_then",
    "any",
    "as_deref",
    "as_mut",
    "as_ref",
    "as_str",
    "clone",
    "collect",
    "filter",
    "filter_map",
    "flat_map",
    "fold",
    "into",
    "into_iter",
    "iter",
    "iter_mut",
    "keys",
    "map",
    "map_err",
    "ok_or",
    "ok_or_else",
    "or",
    "or_else",
    "take",
    "then",
    "then_some",
    "unwrap_or",
    "unwrap_or_default",
    "unwrap_or_else",
    "values",
];

/// Whether `callee` is a standard-library adapter (see [`STD_FORWARDERS`]).
fn is_std_forwarder(callee: &str) -> bool {
    STD_FORWARDERS.binary_search(&callee).is_ok()
}

/// Keep stop sites distinct and bounded.
fn record_cut_site(sites: &mut Vec<CutSite>, site: CutSite) {
    // Pass-throughs are context, not stops: they get their own budget so a
    // long chain of them cannot crowd out the stop that made the verdict.
    let same_class = |s: &&CutSite| (s.kind == PASSED_THROUGH) == (site.kind == PASSED_THROUGH);
    if sites.iter().filter(same_class).count() < MAX_CUT_SITES
        && !sites
            .iter()
            .any(|s| s.kind == site.kind && s.function == site.function && s.detail == site.detail)
    {
        sites.push(site);
    }
}

/// For the Phi `dest_var` in `merge_block`, return the incoming edges whose
/// arm block is unreachable because the branch condition is a constant
/// comparison with a decided outcome. Empty = nothing prunable.
fn phi_infeasible_incoming(
    ir: &FunctionIR,
    merge_block: BlockId,
    dest_var: VarId,
) -> Vec<(BlockId, VarId)> {
    let block = match ir.blocks.get(&merge_block) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let Some(phi) = block.phis.iter().find(|p| p.dest == dest_var) else {
        return Vec::new();
    };
    // An incoming (pred_block, var) is infeasible when pred_block is
    // reached by a Branch whose condition is a decided constant and the
    // edge taken is the OTHER side.
    let mut out = Vec::new();
    for &(pred_block, inc_var) in &phi.incoming {
        // Find the branch that targets pred_block.
        for b in ir.blocks.values() {
            let (cond, true_block, false_block) = match &b.terminator {
                Terminator::Branch {
                    cond: Operand::Var(c),
                    true_block,
                    false_block,
                } => (*c, *true_block, *false_block),
                _ => continue,
            };
            if true_block != pred_block && false_block != pred_block {
                continue;
            }
            let taken = match defs_of_var(ir, cond) {
                Some(Instruction::BinaryOp { op, lhs, rhs, .. }) => {
                    let l = match lhs {
                        Operand::IntLiteral(i) => Some(*i),
                        Operand::Var(v) => const_eval(ir, *v),
                        _ => None,
                    };
                    let r = match rhs {
                        Operand::IntLiteral(i) => Some(*i),
                        Operand::Var(v) => const_eval(ir, *v),
                        _ => None,
                    };
                    match (l, r) {
                        (Some(l), Some(r)) => compare_consts(op, l, r),
                        _ => None,
                    }
                }
                Some(Instruction::Assign {
                    src: Operand::IntLiteral(i),
                    ..
                }) => Some(*i != 0),
                _ => None,
            };
            let Some(taken) = taken else {
                continue;
            };
            let feasible_block = if taken { true_block } else { false_block };
            if feasible_block != pred_block {
                out.push((pred_block, inc_var));
            }
            break;
        }
    }
    out
}

/// What the engine knows about one sink site before exploring its arguments.
#[derive(Clone, Copy)]
struct SinkSite<'a> {
    /// Sink name as configured or declared (`innerHTML`, `send`, `write`).
    name: &'a str,
    /// Role the finding is ranked under.
    role: crate::analysis::taint::role::SinkRole,
    /// Human-readable label from the vocabulary, when one is declared.
    label: Option<&'a str>,
    /// Package the sink signature was scoped to, when known.
    origin_package: Option<&'a str>,
    /// Language of the site, for language-keyed sink facts.
    language: Option<&'a str>,
}

mod explore;
mod origin;
mod sink;
mod sink_gate;

#[inline]
fn is_receiver_only_verb(name: &str) -> bool {
    matches!(
        name,
        "get"
            | "post"
            | "put"
            | "delete"
            | "patch"
            | "head"
            | "options"
            | "request"
            | "set"
            | "render"
            | "aggregate"
    )
}

#[cfg(test)]
mod forwarder_tests {
    use super::{STD_FORWARDERS, is_std_forwarder};

    /// `is_std_forwarder` binary-searches [`STD_FORWARDERS`], so an entry
    /// inserted out of order (or duplicated) is not a compile error - the
    /// lookup just stops finding it, and std adapters creep back into the
    /// pass-through list. `windows(2)` with a strict `<` fails on both.
    #[test]
    fn the_std_forwarder_list_is_sorted_and_unique() {
        for pair in STD_FORWARDERS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "`{}` must sort before `{}`; binary_search silently stops \
                 filtering once the list is out of order",
                pair[0],
                pair[1]
            );
        }
    }

    /// The list is the whole answer: every entry is found, and a call the
    /// engine has no model for is not treated as an adapter.
    #[test]
    fn every_entry_is_found_and_unknown_calls_are_not() {
        for name in STD_FORWARDERS {
            assert!(is_std_forwarder(name), "`{name}` is in the list");
        }
        assert!(is_std_forwarder("iter"));
        assert!(!is_std_forwarder("mystery.read"));
        assert!(!is_std_forwarder(""));
    }
}
