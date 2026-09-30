// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Control-flow structure over the lowered CFG: dominators,
//! post-dominators, and control dependence (Ferrante–Ottenstein–Warren).
//!
//! Two structural questions that value flow alone cannot answer:
//!
//! * **Does X always run before Y?** - dominance. A policy guard must
//!   *dominate* its trigger to count as enforcement; a guard that may be
//!   skipped on some path enforces nothing.
//! * **Which branch gates Z?** - control dependence. Z executes differently
//!   depending on a controlling branch's edge; derived from the
//!   post-dominator tree so "gates" means "on some path to exit", not just
//!   "lexically near".
//!
//! Pure functions over [`FunctionIR`]; no dataflow facts. The iterative
//! solvers are the small-graph intersection algorithms (Cooper–Harvey–Kennedy
//! style), fine at basic-block granularity.

use crate::ir::function::{BasicBlock, BlockId, FunctionIR, Terminator};
use rustc_hash::{FxHashMap, FxHashSet};

/// Reflexive dominance sets: node → the node itself plus everything that
/// must precede it on every path (for post-dominance: everything that must
/// follow it on every path). [`VIRTUAL_EXIT`] participates as a normal node
/// in post-dominance sets.
pub type DomSets = FxHashMap<BlockId, FxHashSet<BlockId>>;

/// Sentinel standing for the synthetic exit every real exit flows into.
/// Never a key of [`FunctionIR::blocks`].
pub const VIRTUAL_EXIT: BlockId = BlockId(usize::MAX);

/// `block`'s execution depends on which successor edge `controller` took:
/// the two differ in whether `block` runs (or runs the same number of
/// times). `edge` labels the taken successor (Branch: 0 = true, 1 = false;
/// Switch: case index, default = `cases.len()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlDependence {
    pub controller: BlockId,
    pub edge: usize,
}

/// Blocks in deterministic id order (fixpoints iterate in this order so
/// results are reproducible across runs).
fn sorted_blocks(ir: &FunctionIR) -> Vec<BlockId> {
    let mut blocks: Vec<BlockId> = ir.blocks.keys().copied().collect();
    blocks.sort_by_key(|b| b.0);
    blocks
}

/// Successor lists for post-dominance: real successors, with exit blocks
/// (no successors) routed to [`VIRTUAL_EXIT`].
fn postdom_succs(ir: &FunctionIR, blocks: &[BlockId]) -> FxHashMap<BlockId, Vec<BlockId>> {
    let mut out = FxHashMap::default();
    for &b in blocks {
        let succs = &ir.blocks[&b].successors;
        if succs.is_empty() {
            out.insert(b, vec![VIRTUAL_EXIT]);
        } else {
            out.insert(b, succs.clone());
        }
    }
    out.insert(VIRTUAL_EXIT, Vec::new());
    out
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

/// Immediate dominators: `b → d` where `d` is the *closest* strict
/// dominator of `b` (the entry has none).
pub fn immediate_dominators(ir: &FunctionIR) -> FxHashMap<BlockId, BlockId> {
    let doms = dominators(ir);
    closest_strict(&doms, ir.entry_block)
}

/// Reflexive post-dominators with the virtual exit: `postdominators[b]`
/// contains every block on every path from `b` to exit (plus `b` and
/// [`VIRTUAL_EXIT`]).
pub fn postdominators(ir: &FunctionIR) -> DomSets {
    let blocks = sorted_blocks(ir);
    let mut nodes: Vec<BlockId> = blocks.clone();
    nodes.push(VIRTUAL_EXIT);
    let all: FxHashSet<BlockId> = nodes.iter().copied().collect();
    let succs = postdom_succs(ir, &blocks);
    let mut pdom: DomSets = nodes.iter().map(|&n| (n, all.clone())).collect();
    pdom.insert(VIRTUAL_EXIT, {
        let mut s = FxHashSet::default();
        s.insert(VIRTUAL_EXIT);
        s
    });
    loop {
        let mut changed = false;
        for &b in &nodes {
            if b == VIRTUAL_EXIT {
                continue;
            }
            let mut acc: Option<FxHashSet<BlockId>> = None;
            for s in &succs[&b] {
                let sd = &pdom[s];
                acc = Some(match acc {
                    None => sd.clone(),
                    Some(a) => a.intersection(sd).copied().collect(),
                });
            }
            let mut new = acc.unwrap_or_else(|| all.clone());
            new.insert(b);
            if pdom.get(&b) != Some(&new) {
                pdom.insert(b, new);
                changed = true;
            }
        }
        if !changed {
            return pdom;
        }
    }
}

/// Immediate post-dominators: `b → d` where `d` is the *closest* strict
/// post-dominator (exit blocks map to [`VIRTUAL_EXIT`]).
pub fn immediate_postdominators(ir: &FunctionIR) -> FxHashMap<BlockId, BlockId> {
    let pdom = postdominators(ir);
    closest_strict(&pdom, VIRTUAL_EXIT)
}

/// Among a node's strict dominators (or post-dominators), the closest one
/// is the element whose own set is largest: the sets nest strictly along
/// the chain, so the immediate relation has the biggest set. Ties (only
/// possible in unreachable fragments) break to the lowest id.
fn closest_strict(sets: &DomSets, skip: BlockId) -> FxHashMap<BlockId, BlockId> {
    let mut out = FxHashMap::default();
    for (&b, set) in sets {
        if b == skip {
            continue;
        }
        let mut best: Option<(BlockId, usize)> = None;
        for &d in set {
            if d == b {
                continue;
            }
            let size = sets.get(&d).map(|s| s.len()).unwrap_or(0);
            let better = match best {
                None => true,
                Some((bd, bs)) => size > bs || (size == bs && d.0 < bd.0),
            };
            if better {
                best = Some((d, size));
            }
        }
        if let Some((d, _)) = best {
            out.insert(b, d);
        }
    }
    out
}

/// Label each successor edge from the terminator (identity match against
/// the maintained successor list).
fn edge_labels(blk: &BasicBlock) -> Vec<usize> {
    match &blk.terminator {
        Terminator::Branch {
            true_block,
            false_block,
            ..
        } => blk
            .successors
            .iter()
            .map(|s| {
                if s == true_block {
                    0
                } else if s == false_block {
                    1
                } else {
                    usize::MAX
                }
            })
            .collect(),
        Terminator::Switch {
            cases,
            default_block,
            ..
        } => blk
            .successors
            .iter()
            .map(|s| {
                cases
                    .iter()
                    .position(|(_, b)| b == s)
                    .or_else(|| (*s == *default_block).then_some(cases.len()))
                    .unwrap_or(usize::MAX)
            })
            .collect(),
        _ => (0..blk.successors.len()).collect(),
    }
}

/// Ferrante–Ottenstein–Warren control dependence: for each controller
/// branch edge, walk the post-dominator tree from the edge target up to
/// the controller's immediate post-dominator; every node on that walk is
/// control-dependent on the edge. Loop headers come out control-dependent
/// on their own back-edge branch, which is correct: whether the header runs
/// again is exactly what that branch decides.
pub fn control_dependence(ir: &FunctionIR) -> FxHashMap<BlockId, Vec<ControlDependence>> {
    let blocks = sorted_blocks(ir);
    let ipdom = immediate_postdominators(ir);
    let mut out: FxHashMap<BlockId, Vec<ControlDependence>> = FxHashMap::default();
    let budget = blocks.len() + 1;
    for &b in &blocks {
        let blk = &ir.blocks[&b];
        let labels = edge_labels(blk);
        let stop = ipdom.get(&b).copied();
        for (i, &s) in blk.successors.iter().enumerate() {
            let dep = ControlDependence {
                controller: b,
                edge: labels.get(i).copied().unwrap_or(i),
            };
            let mut runner = s;
            for _ in 0..budget {
                if Some(runner) == stop || runner == VIRTUAL_EXIT {
                    break;
                }
                let deps = out.entry(runner).or_default();
                if !deps.contains(&dep) {
                    deps.push(dep);
                }
                match ipdom.get(&runner) {
                    Some(&p) => runner = p,
                    None => break,
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::function::FunctionIR;

    /// Build `entry → {then, else} → merge → (return)` diamond.
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

    /// `entry → header`, `header → {body, exit}`, `body → header`.
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
        let idom = immediate_dominators(&ir);
        assert_eq!(idom.get(&BlockId(1)), Some(&BlockId(0)));
        assert_eq!(idom.get(&BlockId(2)), Some(&BlockId(0)));
        assert_eq!(idom.get(&BlockId(3)), Some(&BlockId(0)));
    }

    #[test]
    fn dominators_loop_carried() {
        let ir = loop_ir();
        let d = dominators(&ir);
        assert_eq!(d[&BlockId(1)], set(&[0, 1]));
        assert_eq!(d[&BlockId(2)], set(&[0, 1, 2]));
        assert_eq!(d[&BlockId(3)], set(&[0, 1, 3]));
    }

    #[test]
    fn postdominators_diamond() {
        let ir = diamond();
        let p = postdominators(&ir);
        assert_eq!(p[&BlockId(0)], set(&[0, 3, usize::MAX]));
        assert_eq!(p[&BlockId(1)], set(&[1, 3, usize::MAX]));
        assert_eq!(p[&BlockId(2)], set(&[2, 3, usize::MAX]));
        assert_eq!(p[&BlockId(3)], set(&[3, usize::MAX]));
        let ip = immediate_postdominators(&ir);
        assert_eq!(ip.get(&BlockId(0)), Some(&BlockId(3)));
        assert_eq!(ip.get(&BlockId(1)), Some(&BlockId(3)));
        assert_eq!(ip.get(&BlockId(3)), Some(&VIRTUAL_EXIT));
    }

    /// The diamond's arms are control-dependent on the entry branch; the
    /// merge (which both arms reach) is not.
    #[test]
    fn control_dependence_diamond() {
        let ir = diamond();
        let cd = control_dependence(&ir);
        assert_eq!(
            cd.get(&BlockId(1)),
            Some(&vec![ControlDependence {
                controller: BlockId(0),
                edge: 0
            }])
        );
        assert_eq!(
            cd.get(&BlockId(2)),
            Some(&vec![ControlDependence {
                controller: BlockId(0),
                edge: 1
            }])
        );
        assert!(!cd.contains_key(&BlockId(3)), "merge is unconditional");
        assert!(!cd.contains_key(&BlockId(0)));
    }

    /// The loop body is gated by the header's true edge; the header itself
    /// is control-dependent on its own back-edge branch (whether it runs a
    /// second time is exactly what that branch decides).
    #[test]
    fn control_dependence_loop() {
        let ir = loop_ir();
        let cd = control_dependence(&ir);
        let body_deps = cd.get(&BlockId(2)).cloned().unwrap_or_default();
        assert_eq!(
            body_deps,
            vec![ControlDependence {
                controller: BlockId(1),
                edge: 0
            }]
        );
        let header_deps = cd.get(&BlockId(1)).cloned().unwrap_or_default();
        assert!(
            header_deps.contains(&ControlDependence {
                controller: BlockId(1),
                edge: 0
            }),
            "loop header self-dependence: {:?}",
            header_deps
        );
    }

    /// Straight-line code: no branches, no control dependence anywhere.
    #[test]
    fn control_dependence_straight_line() {
        let mut ir = FunctionIR::new("f".into());
        ir.blocks.insert(BlockId(1), BasicBlock::new(BlockId(1)));
        ir.set_terminator(BlockId(0), Terminator::Jump(BlockId(1)));
        ir.set_terminator(BlockId(1), Terminator::Return { src: None });
        ir.add_edge(BlockId(0), BlockId(1));
        let cd = control_dependence(&ir);
        assert!(cd.is_empty(), "{:?}", cd);
    }
}
