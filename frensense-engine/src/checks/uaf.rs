// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Free-then-use / double-free checker over backward SVFG value-flow paths
//! (SABER/Pinpoint-style free→use discovery), replaced from the original
//! intraprocedural RPO state machine.
//!
//! Taint and policy checks never see this bug class: use-after-free is a
//! *temporal* property - the same object must be (1) allocated, (2) freed,
//! and (3) used, in that order. The mechanism:
//!
//! 1. **Discovery - backward walk.** For every pointer use site (load /
//!    store / dereference base) and every free site, walk the Sparse
//!    Value-Flow Graph backwards from the site's SSA def chain. At each
//!    definition reached, *sibling* uses of that definition are scanned for
//!    frees of the same value (`def(p) ─▶ use(free, p)` is a sibling of
//!    `def(p) ─▶ use(deref, p)`), which is exact SSA-alias discovery with
//!    no points-to approximation needed for copy chains. Cross-function
//!    edges extend the walk: a callee that consumes its parameter frees the
//!    caller's object, a callee that returns an allocation proves caller
//!    provenance, and a caller that frees before the call is seen from a
//!    use inside the callee.
//!
//! 2. **Provenance - must-reachable allocation.** Every backward path from
//!    the use must root at a provable in-function allocation (an
//!    `Allocate` instruction, a `malloc`-family call result, or a callee
//!    summary that returns fresh memory). A path rooting at a formal
//!    parameter or an unknown external call result disqualifies the site,
//!    keeping the checker zero-FP by construction on unprovable pointers
//!    (same contract as the original class-based checker).
//!
//! 3. **Must-validation - CFG fixpoint.** A discovered (free, use) pair
//!    fires only when the free *must* execute before the use on every path:
//!    an optimistic-init boolean dataflow (`in[b] = ∧ out[preds]`,
//!    `out[b] = in[b] ∨ b_contains_free`) solved to its greatest fixpoint.
//!    `if (c) free(p); use(p)` stays silent (the skip path reaches the use
//!    unfreed), `free` on both arms / straight-line / do-while fires, and
//!    a free after the use in the same block is rejected by index order.
//!    For a free inside a callee, every normal exit of the callee must pass
//!    a free of the parameter; for a use inside a callee, the caller must
//!    free unconditionally before the call.
//!
//! The checker consumes [`PointsToAnalysis`] (Andersen, field-sensitive)
//! for the coarse alias channel: free-sites whose pointer may-alias the use
//! pointer even when no SSA copy chain connects them (load-after-free
//! through a shared field). Generation tracking is inherent to SSA: a
//! re-assignment is a new definition, so `p = malloc(); free(p);
//! p = malloc(); use(p)` pairs the use only with frees of its own def.
//!
//! Scope notes: a loop-carried "freed on iteration *n*, used on iteration
//! *n+1*" ordering inside one basic block is rejected by index order -
//! proving ≥2 iterations is out of the must-analysis contract. Findings
//! dedup by (span, rule) as before (`use_after_free` / `double_free`).

use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::forward::ProgramSvfg;
use crate::checks::CheckerFinding;
use crate::checks::memory_summary::MemorySummaryRegistry;
use crate::graph::heap::PointsToAnalysis;
use crate::graph::svfg::{NodeKey, NodeKind, Svfg, SvfgBuilder};
use crate::ir::function::{BlockId, FunctionIR, Instruction, Operand, VarId};

/// Callee last segments that release heap memory.
const FREE_CALLS: &[&str] = &["free"];
// Deliberately not in the list: `realloc` moves the object (its result is a
// fresh generation). C++ `delete` arrives once lowering handles it.

/// Callee last segments that allocate heap memory (provable provenance).
const ALLOC_CALLS: &[&str] = &["malloc", "calloc", "realloc", "aligned_alloc"];

/// Backward-walk budget per start site: bounds provenance + discovery work
/// on deep or cyclic value-flow chains (exhaustion = unprovable = silent).
const MAX_WALK_NODES: usize = 512;

/// Forward-scan budget inside a callee when looking for parameter frees.
const MAX_SCAN_NODES: usize = 256;

/// Above this many instructions the points-to analysis uses the two-phase
/// (Steensgaard-gated Andersen) mode, mirroring `SvfgBuilder`'s choice.
const TWO_PHASE_MIN_INSTRS: usize = 4096;

fn last_segment(call: &str) -> &str {
    call.rsplit('.').next().unwrap_or(call)
}

/// A violation of the object lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Violation {
    /// Memory used after free (read or write through an aliasing var).
    UseAfterFree,
    /// The same object freed twice.
    DoubleFree,
}

/// One site that releases the object held by `var`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FreeSite {
    block: BlockId,
    idx: usize,
    var: VarId,
}

/// How a discovered (free, use) pair must be validated before firing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairCheck {
    /// Free and use are both in the scanned function: must-reach in this CFG.
    Local,
    /// Free lives in the callee entered at `call`; the call must precede the
    /// use AND every normal exit of `callee_fi` must pass a free.
    Callee {
        call: (BlockId, usize),
        callee_fi: usize,
    },
    /// Free lives in the caller that entered *this* function at `call`; the
    /// free must precede the call in the caller's CFG.
    Caller {
        call: (BlockId, usize),
        caller_fi: usize,
    },
}

/// One discovered pair awaiting must-validation.
#[derive(Debug, Clone, Copy)]
struct Pair {
    violation: Violation,
    check: PairCheck,
    /// Location of the free (its block / instruction index).
    free_block: BlockId,
    free_idx: usize,
}

/// Which function a walk step currently sits in, relative to the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrossCtx {
    /// Inside the scanned (start) function.
    None,
    /// Inside a callee entered from the start function at `call`.
    InCallee {
        call: (BlockId, usize),
        callee_fi: usize,
    },
    /// Inside the caller that entered the start function at `call`.
    InCaller {
        call: (BlockId, usize),
        caller_fi: usize,
    },
}

/// Run the UAF / double-free check over one function with default summaries.
pub fn check(ir: &FunctionIR) -> Vec<CheckerFinding> {
    check_with_summaries(ir, &MemorySummaryRegistry::default())
}

/// Run the UAF / double-free check over one function with an interprocedural
/// memory summary registry (intraprocedural graph mode: frees of parameters
/// are recognised at consuming call sites via `summaries.consumes_params`).
pub fn check_with_summaries(
    ir: &FunctionIR,
    summaries: &MemorySummaryRegistry,
) -> Vec<CheckerFinding> {
    check_impl(ir, summaries, None)
}

/// Run the check with access to the whole-program graph: adds
/// cross-function discovery (callee-internal frees, caller-side frees seen
/// from a use inside the callee, callee-returned allocations proving
/// provenance) through the program's interprocedural edges.
///
/// `fi` must be `prog.function_index(&ir.name)` for the same function.
pub fn check_with_prog(
    fi: usize,
    prog: &ProgramSvfg<'_>,
    summaries: &MemorySummaryRegistry,
) -> Vec<CheckerFinding> {
    let ir = prog.functions[fi].ir;
    check_impl(ir, summaries, Some((prog, fi)))
}

fn check_impl(
    ir: &FunctionIR,
    summaries: &MemorySummaryRegistry,
    graph: Option<(&ProgramSvfg<'_>, usize)>,
) -> Vec<CheckerFinding> {
    let frees = collect_frees(ir, summaries);
    if frees.is_empty() {
        // No free can exist in this function: no lifecycle to violate.
        return Vec::new();
    }

    // The program graph supplies the per-function SVFG; without it (direct
    // `check` / test entry points) build one locally.
    let local_svfg;
    let svfg: &Svfg = match graph {
        Some((prog, fi)) => &prog.functions[fi].svfg,
        None => {
            local_svfg = SvfgBuilder::new(ir).build().0;
            &local_svfg
        }
    };

    // Reverse cross-edge index (caller ActualArg ⇄ callee FormalParam,
    // callee FormalRet → caller ActualRet), built once per program graph.
    let empty_rev: FxHashMap<(usize, NodeKey), Vec<(usize, NodeKey)>> = FxHashMap::default();
    let rev = match graph {
        Some((prog, _)) => reverse_cross(prog),
        None => empty_rev,
    };

    // Points-to sets for the coarse alias channel (field-mediated frees
    // with no SSA copy chain to the use).
    let mut pts = PointsToAnalysis::new();
    let instr_count: usize = ir
        .blocks
        .values()
        .map(|b| b.instructions.len() + b.phis.len())
        .sum();
    if instr_count >= TWO_PHASE_MIN_INSTRS {
        pts.analyze_two_phase(ir);
    } else {
        pts.analyze(ir);
    }

    let starts = collect_start_sites(ir, &frees);
    let mut findings: Vec<CheckerFinding> = Vec::new();

    for &(sb, si, sv) in &starts {
        // A start that IS a free site yields double-free findings; a pointer
        // use yields use-after-free.
        let violation = if instr_at(ir, sb, Some(si)).is_some_and(|i| free_of(i, sv, summaries)) {
            Violation::DoubleFree
        } else {
            Violation::UseAfterFree
        };

        let mut walker = Walker {
            start_fi: graph.map(|(_, fi)| fi).unwrap_or(0),
            start_ir: ir,
            start_svfg: svfg,
            prog: graph.map(|(p, _)| p),
            rev: &rev,
            summaries,
            violation,
            state: FxHashMap::default(),
            prov_memo: FxHashMap::default(),
            pairs: Vec::new(),
            cross_frees: FxHashMap::default(),
            nodes: 0,
        };
        let start_key = NodeKey::instr(sb, si, sv);
        let provable = walker.visit_walker(walker.start_fi, start_key, 0, CrossCtx::None);

        if !provable {
            continue;
        }

        // Coarse channel: points-to-aliasing frees of the start pointer
        // (intraprocedural pairs only; cross-function pairs come from the
        // value-flow walk above).
        for f in &frees {
            if (f.block, f.idx, f.var) == (sb, si, sv) {
                continue;
            }
            if may_alias(&pts, f.var, sv) {
                walker.pairs.push(Pair {
                    violation,
                    check: PairCheck::Local,
                    free_block: f.block,
                    free_idx: f.idx,
                });
            }
        }

        // Local pairs validate COLLECTIVELY: the use is violated when
        // every path from entry to it passes at least one free, even when
        // no single free dominates (free on both arms of a diamond).
        let mut local_blocks: Vec<BlockId> = Vec::new();
        let mut local_fire = false;
        for pair in &walker.pairs {
            match pair.check {
                PairCheck::Local => {
                    if pair.free_block == sb {
                        if pair.free_idx < si {
                            local_fire = true;
                        }
                    } else if !local_blocks.contains(&pair.free_block) {
                        local_blocks.push(pair.free_block);
                    }
                }
                _ => {
                    if let Some(finding) = validate_pair(pair, ir, sb, si, sv, graph, &walker) {
                        findings.push(finding);
                    }
                }
            }
        }
        if !local_fire && !local_blocks.is_empty() {
            local_fire = must_reach_any(ir, sb, &local_blocks);
        }
        if local_fire {
            findings.push(finding(
                ir,
                violation,
                &sv,
                match violation {
                    Violation::UseAfterFree => Some(sv),
                    Violation::DoubleFree => None,
                },
            ));
        }
    }

    // Deterministic order: by span start (falling back to function order is
    // fine - findings come from one function).
    findings.sort_by_key(|f| f.span.map(|s| s.0).unwrap_or(usize::MAX));
    findings.dedup_by(|a, b| a.span == b.span && a.rule == b.rule);
    findings
}

/// Validate one discovered pair against its must-execution contract and,
/// on success, build the finding.
#[allow(clippy::too_many_arguments)]
fn validate_pair(
    pair: &Pair,
    ir: &FunctionIR,
    start_block: BlockId,
    start_idx: usize,
    start_var: VarId,
    graph: Option<(&ProgramSvfg<'_>, usize)>,
    walker: &Walker<'_>,
) -> Option<CheckerFinding> {
    let ok = match pair.check {
        PairCheck::Local => {
            if pair.free_block == start_block {
                pair.free_idx < start_idx
            } else {
                must_reach(ir, pair.free_block, start_block)
            }
        }
        PairCheck::Callee { call, callee_fi } => {
            let (prog, _) = graph?;
            // The call must precede the use in the start function...
            let call_before_use = if call.0 == start_block {
                call.1 < start_idx
            } else {
                must_reach(ir, call.0, start_block)
            };
            // ...and the callee must free on every normal exit.
            let blocks = walker
                .cross_frees
                .get(&(call, callee_fi))
                .cloned()
                .unwrap_or_default();
            call_before_use && callee_always_frees(prog, callee_fi, &blocks)
        }
        PairCheck::Caller { call, caller_fi } => {
            let (prog, _) = graph?;
            let cir = prog.functions[caller_fi].ir;
            // The free must precede the call that entered this function.
            if pair.free_block == call.0 {
                pair.free_idx < call.1
            } else {
                must_reach(cir, pair.free_block, call.0)
            }
        }
    };
    if !ok {
        return None;
    }
    Some(finding(
        ir,
        pair.violation,
        &start_var,
        match pair.violation {
            Violation::UseAfterFree => Some(start_var),
            // Legacy parity: double-free findings carry the name/message
            // but no byte span.
            Violation::DoubleFree => None,
        },
    ))
}

// ---------------------------------------------------------------------------
// Discovery helpers
// ---------------------------------------------------------------------------

/// Every (block, idx, var) that releases `var` in this function.
fn collect_frees(ir: &FunctionIR, summaries: &MemorySummaryRegistry) -> Vec<FreeSite> {
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
fn collect_start_sites(ir: &FunctionIR, frees: &[FreeSite]) -> Vec<(BlockId, usize, VarId)> {
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
fn free_of(instr: &Instruction, var: VarId, summaries: &MemorySummaryRegistry) -> bool {
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
fn free_slot(instr: &Instruction, slot: usize, summaries: &MemorySummaryRegistry) -> bool {
    let Instruction::CallStatic { func, .. } = instr else {
        return false;
    };
    if FREE_CALLS.contains(&last_segment(func)) {
        return slot == 0;
    }
    summaries.consumes_params(func).contains(&slot)
}

/// The instruction at `(block, idx)`, when the index addresses a real
/// instruction (phi keys / terminator sentinels yield `None`).
fn instr_at(ir: &FunctionIR, block: BlockId, idx: Option<usize>) -> Option<&Instruction> {
    let idx = idx?;
    ir.blocks.get(&block)?.instructions.get(idx)
}

/// Points-to overlap; empty sets are NOT aliases (unknown ≠ aliased, the
/// zero-FP direction).
fn may_alias(pts: &PointsToAnalysis, a: VarId, b: VarId) -> bool {
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
fn reverse_cross(prog: &ProgramSvfg<'_>) -> FxHashMap<(usize, NodeKey), Vec<(usize, NodeKey)>> {
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

// ---------------------------------------------------------------------------
// Backward walker
// ---------------------------------------------------------------------------

struct Walker<'a> {
    /// Index of the function the walk started in (the use's function).
    start_fi: usize,
    start_ir: &'a FunctionIR,
    start_svfg: &'a Svfg,
    prog: Option<&'a ProgramSvfg<'a>>,
    rev: &'a FxHashMap<(usize, NodeKey), Vec<(usize, NodeKey)>>,
    summaries: &'a MemorySummaryRegistry,
    /// Frees of the start function (coarse alias channel).
    violation: Violation,
    /// 1 = in progress (cycle), 2 = done.
    state: FxHashMap<(usize, NodeKey), u8>,
    prov_memo: FxHashMap<(usize, NodeKey), bool>,
    pairs: Vec<Pair>,
    /// `(call, callee) → blocks in that callee containing a free` (for the
    /// all-returns exit check).
    cross_frees: FxHashMap<((BlockId, usize), usize), FxHashSet<BlockId>>,
    nodes: usize,
}

impl<'a> Walker<'a> {
    fn ir_of(&self, fi: usize) -> &'a FunctionIR {
        if fi == self.start_fi {
            self.start_ir
        } else {
            self.prog
                .expect("cross-fn walk requires a program graph")
                .functions[fi]
                .ir
        }
    }

    fn svfg_of(&self, fi: usize) -> &'a Svfg {
        if fi == self.start_fi {
            self.start_svfg
        } else {
            &self
                .prog
                .expect("cross-fn walk requires a program graph")
                .functions[fi]
                .svfg
        }
    }

    /// Visit one node: memoised provenance ("every reachable root is a
    /// provable allocation") with candidate collection on first visit.
    fn visit_walker(&mut self, fi: usize, key: NodeKey, depth: u8, ctx: CrossCtx) -> bool {
        self.nodes += 1;
        if self.nodes > MAX_WALK_NODES {
            return false;
        }
        match self.state.get(&(fi, key)) {
            Some(&2) => return self.prov_memo.get(&(fi, key)).copied().unwrap_or(false),
            // Cycle through a loop-carried value: optimistic for the AND
            // fixpoint (other roots still veto if unprovable).
            Some(&1) => return true,
            _ => {}
        }
        self.state.insert((fi, key), 1);
        let prov = self.visit_inner(fi, key, depth, ctx);
        self.state.insert((fi, key), 2);
        self.prov_memo.insert((fi, key), prov);
        prov
    }

    fn visit_inner(&mut self, fi: usize, key: NodeKey, depth: u8, ctx: CrossCtx) -> bool {
        let ir = self.ir_of(fi);
        let svfg = self.svfg_of(fi);
        let Some(node) = svfg.node(&key) else {
            return false;
        };
        let collect = depth <= 1;

        // --- Candidate collection at definition nodes -------------------
        let is_def = matches!(
            node.kind,
            NodeKind::InstrDef | NodeKind::Phi | NodeKind::FormalParam | NodeKind::ActualRet { .. }
        );
        if is_def && collect {
            for s in node.successors() {
                if let Some(instr) = instr_at(ir, s.block, s.instr_idx)
                    && free_of(instr, s.var, self.summaries)
                {
                    self.record_free(s.block, s.instr_idx.unwrap_or(0), ctx);
                }
            }
            // Callee-internal frees of a passed argument (only from the
            // start function: cross-function discovery entry point).
            if depth == 0 && fi == self.start_fi {
                for s in node.successors() {
                    let Some(sn) = svfg.node(&s) else { continue };
                    let NodeKind::ActualArg { arg_index, .. } = sn.kind else {
                        continue;
                    };
                    if arg_index == usize::MAX {
                        continue;
                    }
                    let Some(callee_fi) = self.single_callee(fi, &s) else {
                        continue;
                    };
                    let Some(blocks) = self.scan_callee_frees(callee_fi, arg_index) else {
                        continue;
                    };
                    if blocks.is_empty() {
                        continue;
                    }
                    let call = (s.block, s.instr_idx.unwrap_or(0));
                    let group = self.cross_frees.entry((call, callee_fi)).or_default();
                    let mut first = None;
                    for b in &blocks {
                        if group.insert(*b) && first.is_none() {
                            first = Some(*b);
                        }
                    }
                    if let Some(fb) = first {
                        self.pairs.push(Pair {
                            violation: self.violation,
                            check: PairCheck::Callee { call, callee_fi },
                            free_block: fb,
                            free_idx: 0,
                        });
                    }
                }
            }
        }

        // --- Provenance --------------------------------------------------
        match &node.kind {
            NodeKind::FormalParam => {
                // A parameter's provenance comes from the callers' actual
                // arguments. Zero-FP contract: no callers = external entry
                // = unprovable; multiple callers = only claim provenance
                // when EVERY call site's argument is provable (AND).
                let Some(callers) = self.rev.get(&(fi, key)) else {
                    return false;
                };
                if callers.is_empty() {
                    return false;
                }
                if depth == 0 && callers.len() > 1 {
                    return false;
                }
                let mut ok = true;
                for &(cfi, ck) in callers {
                    let call = (ck.block, ck.instr_idx.unwrap_or(0));
                    ok &= self.visit_walker(
                        cfi,
                        ck,
                        depth + 1,
                        CrossCtx::InCaller {
                            call,
                            caller_fi: cfi,
                        },
                    );
                }
                ok
            }
            NodeKind::ActualRet { .. } => {
                // Call destination: fresh only for malloc-family callees or
                // summary-declared factories; otherwise provenance flows from
                // what the callee returns (cross edge), never from the args.
                if let Some(instr) = instr_at(ir, key.block, key.instr_idx) {
                    match instr {
                        Instruction::CallStatic {
                            func,
                            dest: Some(d),
                            ..
                        } if *d == key.var => {
                            if ALLOC_CALLS.contains(&last_segment(func))
                                || self.summaries.returns_fresh(func)
                            {
                                return true;
                            }
                        }
                        Instruction::CallVirtual { dest: Some(d), .. }
                        | Instruction::CallPointer { dest: Some(d), .. }
                            if *d == key.var => {}
                        _ => {
                            // Not a call dest (shouldn't happen for
                            // ActualRet): fall through to generic preds.
                            return self.and_preds(fi, svfg, key, depth, ctx);
                        }
                    }
                }
                let Some(targets) = self.rev.get(&(fi, key)) else {
                    return false;
                };
                if targets.is_empty() {
                    return false;
                }
                let call = (key.block, key.instr_idx.unwrap_or(0));
                let mut ok = true;
                for &(tfi, tk) in targets {
                    ok &= self.visit_walker(
                        tfi,
                        tk,
                        depth + 1,
                        CrossCtx::InCallee {
                            call,
                            callee_fi: tfi,
                        },
                    );
                }
                ok
            }
            _ => self.and_preds(fi, svfg, key, depth, ctx),
        }
    }

    /// Provenance = AND over backward edges (every feeding value must be
    /// provably allocated); a dead end (no preds, unresolvable root) is
    /// unprovable.
    fn and_preds(
        &mut self,
        fi: usize,
        svfg: &Svfg,
        key: NodeKey,
        depth: u8,
        ctx: CrossCtx,
    ) -> bool {
        let Some(node) = svfg.node(&key) else {
            return false;
        };
        let preds = node.predecessors();
        if preds.is_empty() {
            return false;
        }
        let mut ok = true;
        for p in preds {
            ok &= self.visit_walker(fi, p, depth, ctx);
        }
        ok
    }

    fn single_callee(&self, fi: usize, arg_node: &NodeKey) -> Option<usize> {
        let fe = &self.prog?.functions[fi];
        let (bi, _) = fe.arg_slots.get(arg_node)?;
        let callees = &fe.bindings[*bi].callees;
        if callees.len() == 1 {
            Some(callees[0])
        } else {
            None
        }
    }

    /// Forward scan from a callee's formal parameter: blocks in that callee
    /// that release the parameter. External / unresolved callees yield
    /// `None` (covered at the call site by FREE_CALLS / summaries when
    /// known).
    fn scan_callee_frees(&self, callee_fi: usize, param_idx: usize) -> Option<FxHashSet<BlockId>> {
        let prog = self.prog?;
        let fe = &prog.functions[callee_fi];
        let ir = fe.ir;
        let param_var = *ir.parameters.get(param_idx)?;
        let start = NodeKey::instr(ir.entry_block, usize::MAX - 2 - param_idx, param_var);
        let svfg = &fe.svfg;
        svfg.node(&start)?;
        let mut seen: FxHashSet<NodeKey> = FxHashSet::default();
        let mut queue: std::collections::VecDeque<NodeKey> = std::collections::VecDeque::new();
        let mut blocks: FxHashSet<BlockId> = FxHashSet::default();
        seen.insert(start);
        queue.push_back(start);
        let mut budget = MAX_SCAN_NODES;
        while let Some(n) = queue.pop_front() {
            budget = budget.saturating_sub(1);
            if budget == 0 {
                break;
            }
            if let Some(instr) = instr_at(ir, n.block, n.instr_idx)
                && free_of(instr, n.var, self.summaries)
            {
                blocks.insert(n.block);
            }
            let Some(node) = svfg.node(&n) else {
                continue;
            };
            for s in node.successors() {
                if seen.insert(s) {
                    queue.push_back(s);
                }
            }
        }
        Some(blocks)
    }

    fn record_free(&mut self, block: BlockId, idx: usize, ctx: CrossCtx) {
        let violation = self.violation;
        match ctx {
            CrossCtx::None => self.pairs.push(Pair {
                violation,
                check: PairCheck::Local,
                free_block: block,
                free_idx: idx,
            }),
            CrossCtx::InCallee { call, callee_fi } => {
                self.cross_frees
                    .entry((call, callee_fi))
                    .or_default()
                    .insert(block);
                self.pairs.push(Pair {
                    violation,
                    check: PairCheck::Callee { call, callee_fi },
                    free_block: block,
                    free_idx: idx,
                });
            }
            CrossCtx::InCaller { call, caller_fi } => self.pairs.push(Pair {
                violation,
                check: PairCheck::Caller { call, caller_fi },
                free_block: block,
                free_idx: idx,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Must-execution dataflow
// ---------------------------------------------------------------------------

/// Greatest-fixpoint "must pass through `sources`" dataflow: `out[b]` is
/// `true` when every execution path reaching the end of `b` has executed
/// at least one source block. Optimistic init (`in = true` for non-entry
/// blocks) converges downward; `do { free } while` fires, `while (c) free`
/// after the loop stays silent (0-iteration path).
fn must_out(ir: &FunctionIR, sources: &[BlockId]) -> FxHashMap<BlockId, bool> {
    let mut preds: FxHashMap<BlockId, Vec<BlockId>> = FxHashMap::default();
    for (&b, blk) in &ir.blocks {
        for s in &blk.successors {
            preds.entry(*s).or_default().push(b);
        }
    }
    let src: FxHashSet<BlockId> = sources.iter().copied().collect();
    let mut out: FxHashMap<BlockId, bool> = FxHashMap::default();
    for &b in ir.blocks.keys() {
        let in_v = if b == ir.entry_block {
            false
        } else {
            preds.get(&b).is_some_and(|ps| !ps.is_empty())
        };
        out.insert(b, in_v || src.contains(&b));
    }
    loop {
        let mut changed = false;
        for &b in ir.blocks.keys() {
            let new_in = if b == ir.entry_block {
                false
            } else {
                match preds.get(&b) {
                    Some(ps) if !ps.is_empty() => {
                        ps.iter().all(|p| out.get(p).copied().unwrap_or(false))
                    }
                    _ => false,
                }
            };
            let new_out = new_in || src.contains(&b);
            if out.get(&b) != Some(&new_out) {
                out.insert(b, new_out);
                changed = true;
            }
        }
        if !changed {
            return out;
        }
    }
}

/// True when every path from entry to `to` executes `from` first (blocks
/// must differ; same-block ordering is the caller's index comparison).
fn must_reach(ir: &FunctionIR, from: BlockId, to: BlockId) -> bool {
    if from == to {
        return true;
    }
    must_reach_any(ir, to, std::slice::from_ref(&from))
}

/// True when EVERY path from entry to `to` passes through at least one of
/// `sources` (collective domination: free on every branch of a diamond).
fn must_reach_any(ir: &FunctionIR, to: BlockId, sources: &[BlockId]) -> bool {
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
fn callee_always_frees(
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

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

fn finding(
    ir: &FunctionIR,
    violation: Violation,
    var: &VarId,
    span_var: Option<VarId>,
) -> CheckerFinding {
    let name = ir
        .var_metadata
        .get(var)
        .and_then(|m| m.source_name.clone())
        .unwrap_or_else(|| format!("v{}", var.0));
    let span = span_var.and_then(|v| ir.var_metadata.get(&v).and_then(|m| m.byte_range));
    let (rule, message) = match violation {
        Violation::UseAfterFree => (
            "use_after_free",
            format!(
                "`{name}` is used after the memory it points to was freed \
                 (free-then-use). Remove the use or the free."
            ),
        ),
        Violation::DoubleFree => (
            "double_free",
            format!(
                "`{name}` is freed twice (double-free). Remove the second \
                 free or null the pointer after the first."
            ),
        ),
    };
    CheckerFinding {
        function: ir.name.clone(),
        rule: rule.to_string(),
        message,
        span,
        learned: false,
    }
}
