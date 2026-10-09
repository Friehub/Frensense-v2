// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::forward::ProgramSvfg;
use crate::ir::function::{BlockId, FunctionIR};

/// Greatest-fixpoint "must pass through `sources`" dataflow: `out[b]` is
/// `true` when every execution path reaching the end of `b` has executed
/// at least one source block. Optimistic init (`in = true` for non-entry
/// blocks) converges downward; `do { free } while` fires, `while (c) free`
/// after the loop stays silent (0-iteration path).
pub fn must_out(ir: &FunctionIR, sources: &[BlockId]) -> FxHashMap<BlockId, bool> {
    let mut preds: FxHashMap<BlockId, Vec<BlockId>> = FxHashMap::default();
    for (&b, blk) in &ir.blocks {
        for s in &blk.successors {
            preds.entry(*s).or_default().push(b);
        }
    }

    let is_source = |b: BlockId| sources.contains(&b);

    let mut out_state: FxHashMap<BlockId, bool> = FxHashMap::default();
    for &b in ir.blocks.keys() {
        out_state.insert(b, is_source(b) || b != ir.entry_block);
    }

    let mut changed = true;
    while changed {
        changed = false;
        for &b in ir.blocks.keys() {
            let in_val = if b == ir.entry_block {
                false
            } else {
                preds
                    .get(&b)
                    .map(|ps| {
                        !ps.is_empty()
                            && ps
                                .iter()
                                .all(|p| out_state.get(p).copied().unwrap_or(false))
                    })
                    .unwrap_or(false)
            };
            let new_out = in_val || is_source(b);
            if out_state.get(&b).copied() != Some(new_out) {
                out_state.insert(b, new_out);
                changed = true;
            }
        }
    }

    out_state
}

/// True when every execution path to `to` passes through `from` (strict
/// must-reach; if `from` is unreachable this returns `false`).
pub fn must_reach(ir: &FunctionIR, from: BlockId, to: BlockId) -> bool {
    let outs = must_out(ir, &[from]);
    let mut preds: FxHashMap<BlockId, Vec<BlockId>> = FxHashMap::default();
    for (&b, blk) in &ir.blocks {
        for s in &blk.successors {
            preds.entry(*s).or_default().push(b);
        }
    }
    match preds.get(&to) {
        Some(ps) if !ps.is_empty() => ps.iter().all(|p| outs.get(p).copied().unwrap_or(false)),
        _ => false,
    }
}

/// Collective domination: true when every execution path to `to` passes
/// through at least one block in `sources` (e.g. free on every branch of a diamond).
pub fn must_reach_any(ir: &FunctionIR, to: BlockId, sources: &[BlockId]) -> bool {
    let outs = must_out(ir, sources);
    let mut preds: FxHashMap<BlockId, Vec<BlockId>> = FxHashMap::default();
    for (&b, blk) in &ir.blocks {
        for s in &blk.successors {
            preds.entry(*s).or_default().push(b);
        }
    }
    match preds.get(&to) {
        Some(ps) if !ps.is_empty() => ps.iter().all(|p| outs.get(p).copied().unwrap_or(false)),
        _ => false,
    }
}

/// True when every normal exit of the callee passes at least one of the
/// collected free blocks (the callee definitely frees the parameter before
/// returning to the caller).
pub fn callee_always_frees(
    prog: &ProgramSvfg<'_>,
    callee_fi: usize,
    free_blocks: &FxHashSet<BlockId>,
) -> bool {
    if free_blocks.is_empty() {
        return false;
    }
    let ir = prog.functions[callee_fi].ir;
    let sources: Vec<BlockId> = free_blocks.iter().copied().collect();
    let outs = must_out(ir, &sources);
    let mut exits = 0;
    for (&b, blk) in &ir.blocks {
        if blk.successors.is_empty() {
            exits += 1;
            if !outs.get(&b).copied().unwrap_or(false) {
                return false;
            }
        }
    }
    exits > 0
}
