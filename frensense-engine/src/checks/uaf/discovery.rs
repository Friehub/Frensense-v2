// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use rustc_hash::FxHashMap;

use crate::analysis::forward::ProgramSvfg;
use crate::checks::memory_summary::MemorySummaryRegistry;
use crate::graph::heap::PointsToAnalysis;
use crate::graph::svfg::NodeKey;
use crate::ir::function::{BlockId, FunctionIR, Instruction, Operand, VarId};

use super::types::FreeSite;

/// Above this many instructions the points-to analysis uses the two-phase
/// (Steensgaard-gated Andersen) mode, mirroring `SvfgBuilder`'s choice.
pub const TWO_PHASE_MIN_INSTRS: usize = 4096;

pub fn last_segment(call: &str) -> &str {
    call.rsplit('.').next().unwrap_or(call)
}

/// Every (block, idx, var) that releases `var` in this function.
pub fn collect_frees(ir: &FunctionIR, summaries: &MemorySummaryRegistry) -> Vec<FreeSite> {
    let mut out = Vec::new();
    for (&bid, block) in &ir.blocks {
        for (idx, instr) in block.instructions.iter().enumerate() {
            if let Instruction::CallStatic { args, .. } = instr {
                for (slot, a) in args.iter().enumerate() {
                    if let Operand::Var(v) = a
                        && free_slot(instr, slot, summaries)
                    {
                        out.push(FreeSite {
                            block: bid,
                            idx,
                            var: *v,
                        });
                    }
                }
            }
        }
    }
    out
}

/// Every walk start: pointer use sites (load/store/deref bases) plus the
/// free sites themselves (double-free pairs are use-after-free on free
/// instructions).
pub fn collect_start_sites(ir: &FunctionIR, frees: &[FreeSite]) -> Vec<(BlockId, usize, VarId)> {
    let mut out: Vec<(BlockId, usize, VarId)> = Vec::new();
    for (&bid, block) in &ir.blocks {
        for (idx, instr) in block.instructions.iter().enumerate() {
            let base = match instr {
                Instruction::LoadField { base, .. }
                | Instruction::LoadElement { base, .. }
                | Instruction::StoreField { base, .. }
                | Instruction::StoreElement { base, .. } => Some(*base),
                Instruction::Dereference {
                    ptr: Operand::Var(base),
                    ..
                } => Some(*base),
                _ => None,
            };
            if let Some(b) = base {
                out.push((bid, idx, b));
            }
        }
    }
    out.extend(frees.iter().map(|f| (f.block, f.idx, f.var)));
    out.sort_by_key(|&(b, i, v)| (b.0, i, v.0));
    out.dedup();
    out
}

/// True when `instr` releases `var` (builtin free or summary-consumed slot).
pub fn free_of(instr: &Instruction, var: VarId, summaries: &MemorySummaryRegistry) -> bool {
    match instr {
        Instruction::CallStatic { func: _, args, .. } => {
            for (slot, a) in args.iter().enumerate() {
                if matches!(a, Operand::Var(v) if *v == var) && free_slot(instr, slot, summaries) {
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// True when argument slot `slot` of `instr` is a consumed (freed) slot.
///
/// Deallocator vocabulary lives in the registry (spec's
/// `known_memory_functions`, bootstrap fallback): `free(p)` consumes
/// slot 0 because the vocabulary says so, not because the engine
/// hardcodes the name.
pub fn free_slot(instr: &Instruction, slot: usize, summaries: &MemorySummaryRegistry) -> bool {
    let Instruction::CallStatic { func, .. } = instr else {
        return false;
    };
    summaries.consumes_params(func).contains(&slot)
}

/// The instruction at `(block, idx)`, when the index addresses a real
/// instruction (phi keys / terminator sentinels yield `None`).
pub fn instr_at(ir: &FunctionIR, block: BlockId, idx: Option<usize>) -> Option<&Instruction> {
    let idx = idx?;
    ir.blocks.get(&block)?.instructions.get(idx)
}

/// Points-to overlap; empty sets are NOT aliases (unknown ≠ aliased, the
/// zero-FP direction).
pub fn may_alias(pts: &PointsToAnalysis, a: VarId, b: VarId) -> bool {
    if a == b {
        return true;
    }
    match (pts.pts.get(&a), pts.pts.get(&b)) {
        (Some(pa), Some(pb)) if !pa.is_empty() && !pb.is_empty() => !pa.is_disjoint(pb),
        _ => false,
    }
}

/// `(callee_fn, FormalRet) → caller ActualRet` reverse index, derived from
/// the forward cross-edge map.
pub fn reverse_cross(prog: &ProgramSvfg<'_>) -> FxHashMap<(usize, NodeKey), Vec<(usize, NodeKey)>> {
    let mut rev: FxHashMap<(usize, NodeKey), Vec<(usize, NodeKey)>> = FxHashMap::default();
    for ((from_f, from_k), edges) in &prog.cross_edges {
        for (to_f, to_k) in edges {
            rev.entry((*to_f, *to_k))
                .or_default()
                .push((*from_f, *from_k));
        }
    }
    rev
}
