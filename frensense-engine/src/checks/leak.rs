// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Missing release of memory after its effective lifetime (CWE-401).
//!
//! Path-sensitive may-leak accounting over the intraprocedural CFG: an
//! allocation is reported when some concrete path reaches function exit
//! with the allocation still frame-owned - never released, returned, or
//! stored anywhere that outlives the call.
//!
//! Lang declares / corpus teaches / engine computes: which calls allocate
//! fresh memory and which consume their arguments comes from the
//! lang-declared memory vocabulary merged into the registry
//! (`MemorySummaryRegistry::from_facts` - bootstrap `MemoryFuncSpec`s plus
//! bundle-learned contracts), never from hardcoded names here. Stack
//! allocators (`alloca` and friends) come from the lang-declared
//! `BOOTSTRAP_STACK_ALLOCATORS` list and are never leak candidates: their
//! storage dies with the frame. The analysis itself (join, phi merge,
//! escape, null-guard skip) is the stable engine "how".
//!
//! Zero-FP by construction:
//! - The live state is a flow-sensitive variable -> allocations map:
//!   SSA copies bind the values that actually flow there and phi nodes
//!   merge per-edge, so a `free(phi)` or `store(phi)` sees every
//!   allocation the merge can carry.
//! - Exit states are may-live (union join over predecessors): a finding
//!   means an actual path to `return` exists on which nothing released
//!   the allocation.
//! - Ownership escapes remove the candidate: returned operands, values
//!   stored to fields/elements/globals, ownership assigned to a
//!   parameter, derived handles (`&p->field` / load chains) passed to
//!   callees, and arguments the callee's contract consumes. Direct
//!   pointer arguments to unknown callees keep frame ownership (read and
//!   I/O calls receive the buffer without retaining it), so they neither
//!   release nor escape it - a retained direct argument is a false
//!   negative, never a false positive.
//! - A branch whose condition compares an allocation against NULL
//!   (`== NULL`, `!= NULL`, `!p`) kills it on the null edge: the failed
//!   allocation path is not a live object. The proof covers every
//!   version of that *storage* (SSA re-assignments and the phi that
//!   merges them): a stale binding a loop join carried along cannot hold
//!   a live object where the storage itself is NULL. Pointer identity
//!   guards (`p != buf` taken false) likewise drop allocations bound to
//!   one side only - `buf` (a stack buffer) holds none, so the edge
//!   cannot carry the heap object.
//! - A branch on a literal condition (`while (1)` lowering) propagates
//!   only along the statically live edge; the placeholder block on the
//!   dead edge is unreachable code, not a function exit.
//! - The exit scan counts only *reaching* definitions: per storage cell
//!   (SSA versions of one variable, grouped by copy/phi edges and shared
//!   source name), only the deepest definition that dominates the exit is
//!   live there. Stale versions a loop join carried into an earlier
//!   block's state are superseded by the reaching key (or its phi), so
//!   their lingering bindings are not separate leaks.
//! - Unknown (unsummarized) callees consume nothing.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::checks::CheckerFinding;
use crate::checks::memory_summary::MemorySummaryRegistry;
use crate::ir::control::{DomSets, dominators};
use crate::ir::function::{
    BasicBlock, BlockId, FunctionIR, Instruction, Operand, Terminator, VarId,
};

/// One tracked allocation: the call instruction's result variable plus the
/// vocabulary name that produced it.
#[derive(Clone)]
struct Alloc {
    name: String,
}

/// Alias edge from `src` to `dest`: value-preserving copies
/// (`Assign`/`Cast`/phi merges) and derived handles (`&p->field`,
/// loads, dereferences) alike. Resolution decides directness by
/// whether the live state binds the variable itself.
#[derive(Clone, Copy)]
struct Edge {
    src: VarId,
    dest: VarId,
}

/// Frame-owned allocations per variable at a program point. Direct
/// bindings only: SSA copies and phi merges bind exactly the values that
/// flow there, and releases/stores remove the allocation from every
/// variable holding it.
type PointsTo = FxHashMap<VarId, FxHashSet<VarId>>;

fn last_segment(call: &str) -> &str {
    let s = call.rsplit('.').next().unwrap_or(call);
    s.rsplit("::").next().unwrap_or(s)
}

fn var_span(ir: &FunctionIR, var: VarId) -> Option<(usize, usize)> {
    ir.var_metadata.get(&var).and_then(|m| m.byte_range)
}

/// Fresh allocations (lang vocabulary) and the alias edges between
/// variables that can denote them. Stack allocators are excluded: their
/// storage is frame-local by definition and can never leak.
fn collect(
    ir: &FunctionIR,
    summaries: &MemorySummaryRegistry,
) -> (FxHashMap<VarId, Alloc>, Vec<Edge>) {
    let mut allocs: FxHashMap<VarId, Alloc> = FxHashMap::default();
    let mut edges: Vec<Edge> = Vec::new();
    for block in ir.blocks.values() {
        for phi in &block.phis {
            for (_, arg) in &phi.incoming {
                edges.push(Edge {
                    src: *arg,
                    dest: phi.dest,
                });
            }
        }
        for instr in &block.instructions {
            match instr {
                Instruction::CallStatic {
                    dest: Some(dest),
                    func,
                    ..
                } if summaries.returns_fresh(func)
                    && !frensense_lang::memory::is_stack_allocator(func) =>
                {
                    allocs.insert(
                        *dest,
                        Alloc {
                            name: last_segment(func).to_string(),
                        },
                    );
                }
                Instruction::CallVirtual {
                    dest: Some(dest),
                    method,
                    ..
                } if summaries.returns_fresh(method)
                    && !frensense_lang::memory::is_stack_allocator(method) =>
                {
                    allocs.insert(
                        *dest,
                        Alloc {
                            name: last_segment(method).to_string(),
                        },
                    );
                }
                Instruction::Assign {
                    dest,
                    src: Operand::Var(src),
                }
                | Instruction::Cast {
                    dest,
                    src: Operand::Var(src),
                    ..
                } => edges.push(Edge {
                    src: *src,
                    dest: *dest,
                }),
                Instruction::AddressOf { dest, src } => edges.push(Edge {
                    src: *src,
                    dest: *dest,
                }),
                Instruction::LoadField { dest, base, .. }
                | Instruction::LoadElement { dest, base, .. } => edges.push(Edge {
                    src: *base,
                    dest: *dest,
                }),
                Instruction::Dereference {
                    dest,
                    ptr: Operand::Var(v),
                    ..
                }
                | Instruction::ExtractValue {
                    dest,
                    tuple: Operand::Var(v),
                    ..
                } => edges.push(Edge {
                    src: *v,
                    dest: *dest,
                }),
                _ => {}
            }
        }
    }
    (allocs, edges)
}

/// Reverse alias graph: `dest -> [src, ...]` over every alias edge, for
/// resolving a variable the live state does not bind directly (a derived
/// handle, or a value whose binding was killed on this path).
fn alias_parents(edges: &[Edge]) -> FxHashMap<VarId, Vec<VarId>> {
    let mut parents: FxHashMap<VarId, Vec<VarId>> = FxHashMap::default();
    for e in edges {
        parents.entry(e.dest).or_default().push(e.src);
    }
    parents
}

/// Resolve `op` to the live frame-owned allocations it may denote.
/// State-first: if the variable itself holds allocations, the callee
/// receives that very pointer value (direct). Otherwise walk the reverse
/// alias edges into the state - a derived handle or a stale copy, which
/// hands the object off when passed along. Never resurrects an
/// allocation the state no longer holds.
fn resolve(
    op: &Operand,
    state: &PointsTo,
    parents: &FxHashMap<VarId, Vec<VarId>>,
) -> (FxHashSet<VarId>, bool) {
    let Operand::Var(v) = op else {
        return (FxHashSet::default(), false);
    };
    if let Some(set) = state.get(v) {
        return (set.clone(), true);
    }
    let mut found: FxHashSet<VarId> = FxHashSet::default();
    let mut seen: FxHashSet<VarId> = FxHashSet::default();
    let mut stack: Vec<VarId> = vec![*v];
    while let Some(u) = stack.pop() {
        for p in parents.get(&u).into_iter().flatten() {
            if !seen.insert(*p) {
                continue;
            }
            if let Some(set) = state.get(p) {
                found.extend(set.iter().copied());
            } else {
                stack.push(*p);
            }
        }
    }
    (found, false)
}

/// Drop an allocation from every variable that holds it.
fn drop_alloc(state: &mut PointsTo, id: VarId) {
    for set in state.values_mut() {
        set.remove(&id);
    }
}

/// Statically dead edge: a branch on a literal condition (`while (1)`
/// lowering) never takes one side. Lowering parks post-loop code and
/// empty placeholder blocks behind that dead edge - propagating state
/// there would invent a function exit that no execution can reach.
fn dead_edge(pred: &BasicBlock, succ: BlockId) -> bool {
    let Terminator::Branch {
        cond: Operand::IntLiteral(n),
        true_block,
        false_block,
    } = &pred.terminator
    else {
        return false;
    };
    if true_block == false_block {
        return false;
    }
    let taken = if *n != 0 { *true_block } else { *false_block };
    taken != succ
}

/// Union-find root of `v`'s storage cell, with path compression. Cells
/// are keyed by every member variable; an unregistered variable is its
/// own root.
fn cell_find(cell: &mut FxHashMap<VarId, VarId>, v: VarId) -> VarId {
    let mut root = v;
    while let Some(&p) = cell.get(&root) {
        if p == root {
            break;
        }
        root = p;
    }
    let mut cur = v;
    while cur != root {
        let Some(&p) = cell.get(&cur) else {
            break;
        };
        cell.insert(cur, root);
        cur = p;
    }
    root
}

/// `a` and `b` are versions of the same storage cell.
fn cell_union(cell: &mut FxHashMap<VarId, VarId>, a: VarId, b: VarId) {
    cell.entry(a).or_insert(a);
    cell.entry(b).or_insert(b);
    let (ra, rb) = (cell_find(cell, a), cell_find(cell, b));
    if ra != rb {
        cell.insert(rb, ra);
    }
}

/// Definition block plus the two variable groupings the check needs:
///
/// * the exit-scan *cell* - union over value-preserving edges (copies,
///   casts, phi merges) and shared source names, so SSA versions of one
///   source variable form one cell (derived handles are excluded:
///   `&p->field` is a different value, not another version of `p`);
/// * the *storage* - phi merges and shared source names only, no plain
///   copies: `q = p` gives two variables the same value, not the same
///   storage, so a proof about `q` says nothing about `p`.
fn reaching_index(
    ir: &FunctionIR,
) -> (
    FxHashMap<VarId, BlockId>,
    FxHashMap<VarId, VarId>,
    FxHashMap<VarId, VarId>,
) {
    let mut def_block: FxHashMap<VarId, BlockId> = FxHashMap::default();
    let mut cell: FxHashMap<VarId, VarId> = FxHashMap::default();
    let mut storage: FxHashMap<VarId, VarId> = FxHashMap::default();
    let mut blocks: Vec<BlockId> = ir.blocks.keys().copied().collect();
    blocks.sort_by_key(|b| b.0);
    for bid in blocks {
        let Some(block) = ir.blocks.get(&bid) else {
            continue;
        };
        for phi in &block.phis {
            def_block.entry(phi.dest).or_insert(bid);
            for (_, arg) in &phi.incoming {
                cell_union(&mut cell, *arg, phi.dest);
                cell_union(&mut storage, *arg, phi.dest);
            }
        }
        for instr in &block.instructions {
            let dest = match instr {
                Instruction::Assign { dest, .. }
                | Instruction::Cast { dest, .. }
                | Instruction::BinaryOp { dest, .. }
                | Instruction::UnaryOp { dest, .. }
                | Instruction::LoadField { dest, .. }
                | Instruction::LoadElement { dest, .. }
                | Instruction::LoadGlobal { dest, .. }
                | Instruction::AddressOf { dest, .. }
                | Instruction::Dereference { dest, .. }
                | Instruction::ExtractValue { dest, .. }
                | Instruction::Allocate { dest, .. }
                | Instruction::Await { dest, .. }
                | Instruction::CallStatic {
                    dest: Some(dest), ..
                }
                | Instruction::CallVirtual {
                    dest: Some(dest), ..
                }
                | Instruction::CallPointer {
                    dest: Some(dest), ..
                }
                | Instruction::Yield {
                    dest: Some(dest), ..
                } => *dest,
                _ => continue,
            };
            def_block.entry(dest).or_insert(bid);
            match instr {
                Instruction::Assign {
                    dest,
                    src: Operand::Var(src),
                }
                | Instruction::Cast {
                    dest,
                    src: Operand::Var(src),
                    ..
                } => cell_union(&mut cell, *src, *dest),
                _ => {
                    cell.entry(dest).or_insert(dest);
                }
            }
        }
    }
    // A shared source name is the same storage cell even when no copy
    // edge links the versions (declared, then re-assigned).
    let mut by_name: FxHashMap<String, VarId> = FxHashMap::default();
    for (v, meta) in &ir.var_metadata {
        cell.entry(*v).or_insert(*v);
        storage.entry(*v).or_insert(*v);
        if let Some(name) = &meta.source_name {
            if let Some(&first) = by_name.get(name) {
                cell_union(&mut cell, first, *v);
                cell_union(&mut storage, first, *v);
            } else {
                by_name.insert(name.clone(), *v);
            }
        }
    }
    let resolve = |mut map: FxHashMap<VarId, VarId>| {
        let members: Vec<VarId> = map.keys().copied().collect();
        let mut root_of: FxHashMap<VarId, VarId> = FxHashMap::default();
        for v in members {
            let root = cell_find(&mut map, v);
            root_of.insert(v, root);
        }
        root_of
    };
    (def_block, resolve(cell), resolve(storage))
}

/// The keys of `state` whose definitions actually reach `exit`. Per
/// storage cell only the deepest definition dominating the exit counts:
/// older versions of the cell that survived a join are stale - the
/// reaching key (or the phi at the join) carries their values - so an
/// allocation still bound only to a stale key is not live here. With no
/// reaching candidate the group is kept whole (parameters and lowering
/// temps without an indexed definition).
fn reaching_keys(
    state: &PointsTo,
    exit: BlockId,
    doms: &DomSets,
    def_block: &FxHashMap<VarId, BlockId>,
    cell_root: &FxHashMap<VarId, VarId>,
) -> Vec<VarId> {
    let mut groups: FxHashMap<VarId, Vec<VarId>> = FxHashMap::default();
    for (v, set) in state {
        if set.is_empty() {
            continue;
        }
        let root = cell_root.get(v).copied().unwrap_or(*v);
        groups.entry(root).or_default().push(*v);
    }
    let mut keep = Vec::new();
    for keys in groups.into_values() {
        let mut deepest: Option<BlockId> = None;
        for k in &keys {
            let Some(d) = def_block.get(k).copied() else {
                continue;
            };
            if !doms.get(&exit).is_some_and(|s| s.contains(&d)) {
                continue;
            }
            // Dominators of one node are totally ordered: the deeper
            // definition is the one the current candidate dominates.
            deepest = Some(match deepest {
                None => d,
                Some(cur) if doms.get(&d).is_some_and(|s| s.contains(&cur)) => d,
                Some(cur) => cur,
            });
        }
        match deepest {
            None => keep.extend(keys),
            Some(best) => keep.extend(keys.into_iter().filter(|k| def_block.get(k) == Some(&best))),
        }
    }
    keep
}

/// Add the allocations live at `exit` that reach it (see
/// [`reaching_keys`]).
fn extend_leaks(
    leaked: &mut FxHashSet<VarId>,
    state: &PointsTo,
    exit: BlockId,
    doms: &DomSets,
    def_block: &FxHashMap<VarId, BlockId>,
    cell_root: &FxHashMap<VarId, VarId>,
) {
    for k in reaching_keys(state, exit, doms, def_block, cell_root) {
        if let Some(set) = state.get(&k) {
            leaked.extend(set.iter().copied());
        }
    }
}

/// Run the allocation-lifetime check over one function.
pub fn check(ir: &FunctionIR, summaries: &MemorySummaryRegistry) -> Vec<CheckerFinding> {
    let (allocs, edges) = collect(ir, summaries);
    if allocs.is_empty() {
        return Vec::new();
    }
    let parents = alias_parents(&edges);

    // Definition index for branch-condition inspection (null guards).
    let mut defs: FxHashMap<VarId, &Instruction> = FxHashMap::default();
    for block in ir.blocks.values() {
        for instr in &block.instructions {
            match instr {
                Instruction::Assign { dest, .. }
                | Instruction::Cast { dest, .. }
                | Instruction::BinaryOp { dest, .. }
                | Instruction::UnaryOp { dest, .. }
                | Instruction::CallStatic {
                    dest: Some(dest), ..
                }
                | Instruction::LoadField { dest, .. }
                | Instruction::LoadElement { dest, .. }
                | Instruction::AddressOf { dest, .. } => {
                    defs.insert(*dest, instr);
                }
                _ => {}
            }
        }
    }

    let params: FxHashSet<VarId> = ir.parameters.iter().copied().collect();

    // Reaching-definition index for the exit scan: dominators plus the
    // storage-cell grouping of SSA versions.
    let doms = dominators(ir);
    let (def_block, cell_root, storage) = reaching_index(ir);

    // Per-block exit state (variable -> live allocations), Jacobi rounds
    // from the bottom, capped like the value analysis.
    let mut out_state: FxHashMap<BlockId, PointsTo> = FxHashMap::default();
    let max_iters = 64 * (ir.blocks.len() + 1);
    for _ in 0..max_iters {
        let mut next: FxHashMap<BlockId, PointsTo> = FxHashMap::default();
        for (bid, block) in &ir.blocks {
            let mut state = join_edges(ir, &defs, &parents, &storage, &out_state, *bid);
            transfer(summaries, &allocs, &parents, &params, block, &mut state);
            next.insert(*bid, state);
        }
        if next == out_state {
            break;
        }
        out_state = next;
    }

    // Final pass over converged states: leaks are allocations still live
    // at a `return` after the return operand's own escape.
    let mut leaked: FxHashSet<VarId> = FxHashSet::default();
    for (bid, block) in &ir.blocks {
        let mut state = join_edges(ir, &defs, &parents, &storage, &out_state, *bid);
        transfer(summaries, &allocs, &parents, &params, block, &mut state);
        // Explicit returns and fall-off-the-end blocks (`Terminator::None`,
        // void functions with no trailing `return`) are function exits.
        match &block.terminator {
            Terminator::Return { src } => {
                if let Some(op) = src {
                    let (ids, _) = resolve(op, &state, &parents);
                    for id in ids {
                        drop_alloc(&mut state, id);
                    }
                }
                extend_leaks(&mut leaked, &state, *bid, &doms, &def_block, &cell_root);
            }
            Terminator::None => {
                extend_leaks(&mut leaked, &state, *bid, &doms, &def_block, &cell_root);
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    let mut emitted: FxHashSet<VarId> = FxHashSet::default();
    for id in leaked {
        let Some(alloc) = allocs.get(&id) else {
            continue;
        };
        if !emitted.insert(id) {
            continue;
        }
        let span = var_span(ir, id);
        out.push(CheckerFinding {
            learned: false,
            function: ir.name.clone(),
            rule: frensense_lang::rules::MEMORY_LEAK.to_string(),
            message: format!(
                "Memory leak: `{}` result in `{}` is never released, returned, \
                 or stored before the function returns",
                alloc.name, ir.name
            ),
            span,
            severity: String::new(),
        });
    }
    out
}

/// Apply one block's instructions to the state: releases kill,
/// ownership escapes remove, SSA copies rebind, fresh allocations gen.
fn transfer(
    summaries: &MemorySummaryRegistry,
    allocs: &FxHashMap<VarId, Alloc>,
    parents: &FxHashMap<VarId, Vec<VarId>>,
    params: &FxHashSet<VarId>,
    block: &BasicBlock,
    state: &mut PointsTo,
) {
    for instr in &block.instructions {
        match instr {
            Instruction::CallStatic {
                dest, func, args, ..
            } => {
                call_transfer(
                    summaries,
                    allocs,
                    parents,
                    params,
                    state,
                    Some(func.as_str()),
                    args,
                    *dest,
                    &[],
                );
            }
            Instruction::CallVirtual {
                dest,
                method,
                receiver,
                args,
                ..
            } => {
                call_transfer(
                    summaries,
                    allocs,
                    parents,
                    params,
                    state,
                    Some(method.as_str()),
                    args,
                    *dest,
                    std::slice::from_ref(receiver),
                );
            }
            Instruction::CallPointer { dest, args, .. } => {
                call_transfer(
                    summaries,
                    allocs,
                    parents,
                    params,
                    state,
                    None,
                    args,
                    *dest,
                    &[],
                );
            }
            Instruction::StoreField { src, .. }
            | Instruction::StoreElement { src, .. }
            | Instruction::StoreGlobal { src, .. } => {
                let (ids, _) = resolve(src, state, parents);
                for id in ids {
                    drop_alloc(state, id);
                }
            }
            Instruction::Assign { dest, src } | Instruction::Cast { dest, src, .. } => {
                let held = match src {
                    Operand::Var(s) => state.get(s).cloned(),
                    _ => None,
                };
                match held {
                    // Ownership reassigned to a parameter leaves the frame.
                    Some(set) if params.contains(dest) => {
                        for id in set {
                            drop_alloc(state, id);
                        }
                    }
                    Some(set) => {
                        state.insert(*dest, set);
                    }
                    None => {
                        state.remove(dest);
                    }
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn call_transfer(
    summaries: &MemorySummaryRegistry,
    allocs: &FxHashMap<VarId, Alloc>,
    parents: &FxHashMap<VarId, Vec<VarId>>,
    params: &FxHashSet<VarId>,
    state: &mut PointsTo,
    func: Option<&str>,
    args: &[Operand],
    dest: Option<VarId>,
    extra: &[Operand],
) {
    // Consumed arguments are released / ownership-transferred by contract.
    let consumes: Vec<usize> = func
        .and_then(|f| {
            let c = summaries.consumes_params(f);
            if c.is_empty() { None } else { Some(c) }
        })
        .unwrap_or_default();
    for (i, arg) in args.iter().enumerate() {
        if !consumes.contains(&i) {
            continue;
        }
        let (ids, _) = resolve(arg, state, parents);
        for id in ids {
            drop_alloc(state, id);
        }
    }
    // Derived handles passed to a callee hand off the object; direct
    // pointers keep frame ownership (reads and I/O never retain).
    for arg in args.iter().chain(extra.iter()) {
        let (ids, direct) = resolve(arg, state, parents);
        if direct {
            continue;
        }
        for id in ids {
            drop_alloc(state, id);
        }
    }
    // Fresh result joins the frame's live set - unless the call writes it
    // straight into a parameter, which belongs to the caller's frame.
    if let Some(d) = dest
        && allocs.contains_key(&d)
        && !params.contains(&d)
    {
        let mut held = FxHashSet::default();
        held.insert(d);
        state.insert(d, held);
    }
}

/// State at `bid`'s entry: union over predecessor exits, each with its
/// own edge applied - a null-guard edge drops the allocation before the
/// join (the failed-allocation path carries no live object), and phi
/// nodes take the predecessor's value for their argument. Predecessors
/// behind a statically dead edge contribute nothing.
fn join_edges(
    ir: &FunctionIR,
    defs: &FxHashMap<VarId, &Instruction>,
    parents: &FxHashMap<VarId, Vec<VarId>>,
    storage: &FxHashMap<VarId, VarId>,
    out_state: &FxHashMap<BlockId, PointsTo>,
    bid: BlockId,
) -> PointsTo {
    let mut live: PointsTo = PointsTo::default();
    if bid == ir.entry_block {
        return live;
    }
    let Some(block) = ir.blocks.get(&bid) else {
        return live;
    };
    for pred in &block.predecessors {
        let Some(pred_block) = ir.blocks.get(pred) else {
            continue;
        };
        if dead_edge(pred_block, bid) {
            continue;
        }
        let Some(mut p) = out_state.get(pred).cloned() else {
            continue;
        };
        edge_guard_kill(ir, defs, parents, storage, *pred, bid, &mut p);
        // Phi nodes merge per-edge: this predecessor contributes its own
        // value for the phi argument.
        for phi in &block.phis {
            if let Some((_, arg)) = phi.incoming.iter().find(|(b, _)| b == pred)
                && let Some(set) = p.get(arg)
            {
                let carried: Vec<VarId> = set.iter().copied().collect();
                p.entry(phi.dest).or_default().extend(carried);
            }
        }
        for (v, set) in p {
            live.entry(v).or_default().extend(set);
        }
    }
    live
}

/// On edge `pred -> succ`, a guard condition proves facts that make the
/// live state inconsistent with the edge: `== NULL`/`!= NULL`/`!p` says
/// the storage is NULL on the null edge (a failed allocation, not a
/// live object) - every version of it, so stale bindings a loop join
/// carried along go too - and pointer identity (`p != buf` taken false,
/// `p == buf` taken true) says both variables denote the same object -
/// so an allocation bound to one but absent from the other cannot be
/// live here (`buf` itself, a stack buffer or another pointer, never
/// holds it).
fn edge_guard_kill(
    ir: &FunctionIR,
    defs: &FxHashMap<VarId, &Instruction>,
    parents: &FxHashMap<VarId, Vec<VarId>>,
    storage: &FxHashMap<VarId, VarId>,
    pred: BlockId,
    succ: BlockId,
    state: &mut PointsTo,
) {
    let Some(block) = ir.blocks.get(&pred) else {
        return;
    };
    let Terminator::Branch {
        cond,
        true_block,
        false_block,
    } = &block.terminator
    else {
        return;
    };
    let on_true = *true_block == succ;
    let on_false = *false_block == succ;
    let Operand::Var(c) = cond else {
        return;
    };
    // The C lowering renders the NULL macro as either a Null operand or
    // the string literal "NULL" - both compare as the null pointer.
    let is_nullish = |o: &Operand| match o {
        Operand::Null | Operand::IntLiteral(0) => true,
        Operand::StringLiteral(s) => s == "NULL",
        _ => false,
    };
    let compared = match defs.get(c) {
        Some(Instruction::BinaryOp { op, lhs, rhs, .. }) => {
            let eq = matches!(op.as_str(), "==" | "===");
            let ne = matches!(op.as_str(), "!=" | "!==");
            if (eq && on_true) || (ne && on_false) {
                match (lhs, rhs) {
                    (Operand::Var(v), r) if is_nullish(r) => Some(*v),
                    (l, Operand::Var(v)) if is_nullish(l) => Some(*v),
                    (Operand::Var(a), Operand::Var(b)) => {
                        identity_kill(state, *a, *b);
                        None
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
        Some(Instruction::UnaryOp {
            op,
            src: Operand::Var(v),
            ..
        }) if (op == "!" || op == "not") && on_true => Some(*v),
        _ => None,
    };
    if let Some(v) = compared {
        let (ids, _) = resolve(&Operand::Var(v), state, parents);
        for id in ids {
            drop_alloc(state, id);
        }
        // The proof is about the storage, not one binding: where `v` is
        // NULL, no version of the same storage can hold a live object.
        for id in storage_held(state, storage, v) {
            drop_alloc(state, id);
        }
    }
}

/// Allocations bound to any version of `v`'s storage (phi-linked
/// versions and shared source names) in `state`.
fn storage_held(state: &PointsTo, storage: &FxHashMap<VarId, VarId>, v: VarId) -> Vec<VarId> {
    let root = storage.get(&v).copied().unwrap_or(v);
    let mut out = Vec::new();
    for (k, set) in state {
        if !set.is_empty() && storage.get(k).copied().unwrap_or(*k) == root {
            out.extend(set.iter().copied());
        }
    }
    out
}

/// On an edge proven to hold `a == b`, allocations bound to exactly one
/// of the two are dropped: one pointer value cannot be a live object on
/// one side and a different object (or non-heap address) on the other.
fn identity_kill(state: &mut PointsTo, a: VarId, b: VarId) {
    let a_held = state.get(&a).cloned().unwrap_or_default();
    let b_held = state.get(&b).cloned().unwrap_or_default();
    let mut dead: Vec<VarId> = a_held.difference(&b_held).copied().collect();
    dead.extend(b_held.difference(&a_held).copied());
    for id in dead {
        drop_alloc(state, id);
    }
}
