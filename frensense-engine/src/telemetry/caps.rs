// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The safety-valve ledger: which analysis bound truncated a scan, and
//! how often it fired.
//!
//! Split out of `telemetry` so the cap table, its thread-local counters
//! and the one drain path sit together; `telemetry` re-exports them.

use std::cell::RefCell;

use super::CapHit;

/// One safety valve that truncates analysis, when it fires.
///
/// Every bound in the engine that trades precision (or coverage) for
/// termination is a variant here. Reporting one is not an error: the analysis
/// stays sound and bounded by design. It is a *caveat*, and a report that
/// hides its own caveats is not reviewable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub(crate) enum Cap {
    /// The value lattice stopped iterating after
    /// `MAX_ITERATIONS * (blocks + 1)` worklist rounds; branch sharpening for
    /// the affected function is whatever the truncated state held.
    ValueIterations,
    /// A k=1 call-site stack hit the depth ceiling (`MAX_CTX_DEPTH`) and
    /// collapsed to the empty stack (k=0) for that walk.
    CallContextDepth,
    /// The interned call-site chain table hit `MAX_CTX_CHAINS`; further
    /// contexts collapse to k=0.
    CallContextChains,
    /// One function held `MAX_CONTEXTS_PER_FN` contexts; later call sites
    /// merge into an existing one, i.e. become context-insensitive.
    ContextsPerFunction,
    /// The lexical `enclosing_fn` chain hit the forward hop limit while
    /// resolving a free name; the binding was not resolved.
    ForwardHops,
    /// The alias chain walk in the call graph hit its hop limit.
    CallgraphHops,
    /// The points-to fixed point spent `MAX_PASSES` without converging;
    /// field precision was dropped for that function.
    PointsToPasses,
    /// The UAF walker's backward provenance walk hit `MAX_WALK_NODES`; the
    /// free/use pair stayed unprovable and was dropped.
    UafWalkNodes,
    /// The UAF walker's forward callee scan hit `MAX_SCAN_NODES`; frees in
    /// the unvisited tail of the callee were not seen.
    UafCalleeScanNodes,
    /// SSA construction exhausted its work budget; the function was returned
    /// flow-insensitive and flagged `analysis_incomplete`.
    SsaDegraded,
    /// A re-export/barrel chain exceeded `MAX_REEXPORT_RESOLVE_DEPTH`; the
    /// import stayed unresolved, which the fact layer then reads as an
    /// unknown origin (package-scoped facts go inert for that call).
    ReexportResolveDepth,
}

/// Slots in [`CAP_COUNTS`]. Keep in sync with [`Cap::slot`].
const CAP_SLOTS: usize = 11;

thread_local! {
    static CAP_COUNTS: RefCell<[u64; CAP_SLOTS]> = const { RefCell::new([0; CAP_SLOTS]) };
    /// One announcement per cap per report window, so a debug run says each
    /// silent cap fired without flooding stderr from a hot loop.
    static CAP_ANNOUNCED: RefCell<[bool; CAP_SLOTS]> = const { RefCell::new([false; CAP_SLOTS]) };
}

impl Cap {
    const fn slot(self) -> usize {
        match self {
            Cap::ValueIterations => 0,
            Cap::CallContextDepth => 1,
            Cap::CallContextChains => 2,
            Cap::ContextsPerFunction => 3,
            Cap::ForwardHops => 4,
            Cap::CallgraphHops => 5,
            Cap::PointsToPasses => 6,
            Cap::UafWalkNodes => 7,
            Cap::UafCalleeScanNodes => 8,
            Cap::SsaDegraded => 9,
            Cap::ReexportResolveDepth => 10,
        }
    }

    /// Stable identifier used in the JSON report.
    #[must_use]
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Cap::ValueIterations => "value_iterations",
            Cap::CallContextDepth => "call_context_depth",
            Cap::CallContextChains => "call_context_chains",
            Cap::ContextsPerFunction => "contexts_per_function",
            Cap::ForwardHops => "forward_hops",
            Cap::CallgraphHops => "callgraph_hops",
            Cap::PointsToPasses => "points_to_passes",
            Cap::UafWalkNodes => "uaf_walk_nodes",
            Cap::UafCalleeScanNodes => "uaf_callee_scan_nodes",
            Cap::SsaDegraded => "ssa_degraded",
            Cap::ReexportResolveDepth => "reexport_resolve_depth",
        }
    }

    /// What the truncation cost, in analysis terms. Advisory prose only: the
    /// engine never branches on it.
    #[must_use]
    pub(crate) const fn effect(self) -> &'static str {
        match self {
            Cap::ValueIterations => {
                "value lattice stopped early; branch constants may be less precise"
            }
            Cap::CallContextDepth => {
                "call-site stack hit its depth ceiling; that walk became context-insensitive"
            }
            Cap::CallContextChains => {
                "call-site context table was full; later contexts became context-insensitive"
            }
            Cap::ContextsPerFunction => {
                "one function held too many call contexts; later call sites merged"
            }
            Cap::ForwardHops => "lexical chain hit the hop limit; a free name was not resolved",
            Cap::CallgraphHops => "alias chain hit the hop limit; a call target was not resolved",
            Cap::PointsToPasses => {
                "points-to did not converge in its pass budget; field precision was dropped"
            }
            Cap::UafWalkNodes => {
                "UAF provenance walk hit its node budget; the site was treated as unprovable"
            }
            Cap::UafCalleeScanNodes => {
                "UAF callee scan hit its node budget; frees past the cap were not seen"
            }
            Cap::SsaDegraded => {
                "SSA construction hit its work budget; the function stayed flow-insensitive"
            }
            Cap::ReexportResolveDepth => {
                "re-export chain hit the resolve depth cap; the import stayed unresolved (unknown origin)"
            }
        }
    }

    /// Record one firing of this cap in the current scan thread.
    ///
    /// Set `FRENSdbg_CAPS` to announce each cap once per report window on
    /// stderr. The counter is always updated; only the announcement is
    /// debug-gated.
    pub(crate) fn record(self) {
        CAP_COUNTS.with(|counts| {
            let mut counts = counts.borrow_mut();
            counts[self.slot()] = counts[self.slot()].saturating_add(1);
        });
        let first = CAP_ANNOUNCED.with(|announced| {
            let mut announced = announced.borrow_mut();
            match announced.get_mut(self.slot()) {
                Some(flag) => {
                    let first = !*flag;
                    *flag = true;
                    first
                }
                None => false,
            }
        });
        if first {
            crate::dbg_trace!(
                crate::debug_flags::DebugFlags::caps_enabled(),
                "frensense: cap fired: {} - {}",
                self.id(),
                self.effect()
            );
        }
    }

    /// How many times this cap has fired on the current thread since its
    /// counters were last drained.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn recorded(self) -> u64 {
        CAP_COUNTS.with(|counts| counts.borrow()[self.slot()])
    }
}

/// Drain the cap counters into reportable hits and reset them.
///
/// Called once per scan so the numbers belong to that scan rather than
/// accumulating across a long-lived process (MCP/LSP servers scan
/// repeatedly).
#[must_use]
pub(crate) fn drain_caps() -> Vec<CapHit> {
    let all = [
        Cap::ValueIterations,
        Cap::CallContextDepth,
        Cap::CallContextChains,
        Cap::ContextsPerFunction,
        Cap::ForwardHops,
        Cap::CallgraphHops,
        Cap::PointsToPasses,
        Cap::UafWalkNodes,
        Cap::UafCalleeScanNodes,
        Cap::SsaDegraded,
        Cap::ReexportResolveDepth,
    ];
    let counts = CAP_COUNTS.with(|counts| std::mem::take(&mut *counts.borrow_mut()));
    // The announcement is per report window: re-arm it for the next scan.
    CAP_ANNOUNCED.with(|announced| {
        *announced.borrow_mut() = [false; CAP_SLOTS];
    });
    all.into_iter()
        .filter_map(|cap| {
            let hits = counts[cap.slot()];
            (hits > 0).then_some(CapHit {
                cap: cap.id().to_string(),
                hits: hits as usize,
                effect: cap.effect().to_string(),
            })
        })
        .collect()
}
