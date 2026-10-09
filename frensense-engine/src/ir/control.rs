// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Dominance over the lowered CFG.
//!
//! **Does X always run before Y?** - dominance. A policy guard must
//! *dominate* its trigger to count as enforcement; a guard that may be
//! skipped on some path enforces nothing.
//!
//! Pure functions over [`FunctionIR`]; no dataflow facts. The iterative
//! solver is the small-graph intersection algorithm (Cooper-Harvey-Kennedy
//! style), fine at basic-block granularity.

use crate::ir::function::{BlockId, FunctionIR};
use rustc_hash::{FxHashMap, FxHashSet};

/// Reflexive dominance sets: node -> the node itself plus everything that
/// must precede it on every path.
pub type DomSets = FxHashMap<BlockId, FxHashSet<BlockId>>;

/// Blocks in deterministic id order (fixpoints iterate in this order so
/// results are reproducible across runs).
fn sorted_blocks(ir: &FunctionIR) -> Vec<BlockId> {
    let mut blocks: Vec<BlockId> = ir.blocks.keys().copied().collect();
    blocks.sort_by_key(|b| b.0);
    blocks
}

/// Reflexive dominators: `dominators[b]` contains every block that lies on
/// every path from the entry to `b` (including `b` itself). Unreachable
/// blocks get the conservative universal set minus nothing meaningful -
/// callers should only ask about reachable ones.
pub fn dominators(ir: &FunctionIR) -> DomSets {
    let blocks = sorted_blocks(ir);
    let all: FxHashSet<BlockId> = blocks.iter().copied().collect();
    let mut preds: FxHashMap<BlockId, Vec<BlockId>> = FxHashMap::default();
    for &b in &blocks {
        for &s in &ir.blocks[&b].successors {
            preds.entry(s).or_default().push(b);
        }
    }
    let mut doms: DomSets = blocks
        .iter()
        .map(|&b| {
            let set = if b == ir.entry_block {
                let mut s = FxHashSet::default();
                s.insert(b);
                s
            } else {
                all.clone()
            };
            (b, set)
        })
        .collect();
    loop {
        let mut changed = false;
        for &b in &blocks {
            if b == ir.entry_block {
                continue; // entry dominates only itself, back-edges and all
            }
            let mut new: Option<FxHashSet<BlockId>> = None;
            if let Some(ps) = preds.get(&b)
                && !ps.is_empty()
            {
                for p in ps {
                    let pd = &doms[p];
                    new = Some(match new {
                        None => pd.clone(),
                        Some(acc) => acc.intersection(pd).copied().collect(),
                    });
                }
            }
            let mut new = new.unwrap_or_else(|| all.clone());
            new.insert(b);
            if doms.get(&b) != Some(&new) {
                doms.insert(b, new);
                changed = true;
            }
        }
        if !changed {
            return doms;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::function::{BasicBlock, FunctionIR, Terminator};

    /// Build `entry -> {then, else} -> merge -> (return)` diamond.
    fn diamond() -> FunctionIR {
        let mut ir = FunctionIR::new("f".into());
        for id in 1..4u64 {
            ir.blocks
                .insert(BlockId(id as usize), BasicBlock::new(BlockId(id as usize)));
        }
        let (e, t, x, m) = (BlockId(0), BlockId(1), BlockId(2), BlockId(3));
        ir.set_terminator(
            e,
            Terminator::Branch {
                cond: crate::ir::function::Operand::IntLiteral(1),
                true_block: t,
                false_block: x,
            },
        );
        ir.set_terminator(t, Terminator::Jump(m));
        ir.set_terminator(x, Terminator::Jump(m));
        ir.set_terminator(m, Terminator::Return { src: None });
        for (a, b) in [(e, t), (e, x), (t, m), (x, m)] {
            ir.add_edge(a, b);
        }
        ir
    }

    /// `entry -> header`, `header -> {body, exit}`, `body -> header`.
    fn loop_ir() -> FunctionIR {
        let mut ir = FunctionIR::new("f".into());
        for id in 1..4u64 {
            ir.blocks
                .insert(BlockId(id as usize), BasicBlock::new(BlockId(id as usize)));
        }
        let (e, h, body, exit) = (BlockId(0), BlockId(1), BlockId(2), BlockId(3));
        ir.set_terminator(e, Terminator::Jump(h));
        ir.set_terminator(
            h,
            Terminator::Branch {
                cond: crate::ir::function::Operand::IntLiteral(1),
                true_block: body,
                false_block: exit,
            },
        );
        ir.set_terminator(body, Terminator::Jump(h));
        ir.set_terminator(exit, Terminator::Return { src: None });
        for (a, b) in [(e, h), (h, body), (h, exit), (body, h)] {
            ir.add_edge(a, b);
        }
        ir
    }

    fn set(items: &[usize]) -> FxHashSet<BlockId> {
        items.iter().map(|&i| BlockId(i)).collect()
    }

    #[test]
    fn dominators_diamond() {
        let ir = diamond();
        let d = dominators(&ir);
        assert_eq!(d[&BlockId(0)], set(&[0]));
        assert_eq!(d[&BlockId(1)], set(&[0, 1]));
        assert_eq!(d[&BlockId(2)], set(&[0, 2]));
        assert_eq!(d[&BlockId(3)], set(&[0, 3]));
    }

    #[test]
    fn dominators_loop_carried() {
        let ir = loop_ir();
        let d = dominators(&ir);
        assert_eq!(d[&BlockId(1)], set(&[0, 1]));
        assert_eq!(d[&BlockId(2)], set(&[0, 1, 2]));
        assert_eq!(d[&BlockId(3)], set(&[0, 1, 3]));
    }
}
