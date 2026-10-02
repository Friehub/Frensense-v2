// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Free-then-use / double-free checker over backward SVFG value-flow paths
//! and uninitialized pointer deallocation checks.
//!
//! Modularized components:
//! - `types`: Core data structures (`Violation`, `FreeSite`, `PairCheck`, `Pair`, `CrossCtx`, `finding`)
//! - `discovery`: Candidate collection and alias checks
//! - `must_exec`: Greatest-fixpoint must-reach dataflow
//! - `walker`: Backward SVFG traversal for provenance and free-site discovery
//! - `uninit`: Uninitialized pointer deallocation detection on error paths

pub mod discovery;
pub mod must_exec;
pub mod types;
pub mod uninit;
pub mod walker;

use rustc_hash::FxHashMap;

use crate::analysis::forward::ProgramSvfg;
use crate::checks::CheckerFinding;
use crate::checks::memory_summary::MemorySummaryRegistry;
use crate::graph::heap::PointsToAnalysis;
use crate::graph::svfg::{NodeKey, Svfg, SvfgBuilder};
use crate::ir::function::{BlockId, FunctionIR, VarId};

pub use discovery::{
    TWO_PHASE_MIN_INSTRS, collect_frees, collect_start_sites, free_of, free_slot, instr_at,
    last_segment, may_alias, reverse_cross,
};
pub use must_exec::{callee_always_frees, must_out, must_reach, must_reach_any};
pub use types::{CrossCtx, FreeSite, Pair, PairCheck, Violation, finding};
pub use uninit::check_uninitialized_frees;
pub use walker::{MAX_SCAN_NODES, MAX_WALK_NODES, Walker};

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
        return Vec::new();
    }

    let mut findings: Vec<CheckerFinding> = Vec::new();

    // Check for uninitialized / error-path double-frees (e.g. CVE-2026-56109 pattern).
    findings.extend(check_uninitialized_frees(ir, &frees));

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

    for &(sb, si, sv) in &starts {
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
                    if let Some(f_item) = validate_pair(pair, ir, sb, si, sv, graph, &walker) {
                        findings.push(f_item);
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
                    Violation::DoubleFree | Violation::UninitializedFree => None,
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
            let call_before_use = if call.0 == start_block {
                call.1 < start_idx
            } else {
                must_reach(ir, call.0, start_block)
            };
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
            Violation::DoubleFree | Violation::UninitializedFree => None,
        },
    ))
}
