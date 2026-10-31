// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Everything a scan measured and used to throw away.
//!
//! A scan used to answer one question - "are there findings?" - and discard
//! the evidence behind the answer. `BackwardStats` was computed and dropped,
//! lowering errors went to `tracing::warn!` with no subscriber installed so
//! nobody ever saw them, every safety valve in the analysis truncated
//! silently, and a file that could not be lowered was indistinguishable from
//! a clean one. All four made a "Clean" report unfalsifiable: the reader had
//! no way to tell "nothing here" from "we never looked properly".
//!
//! This module is the accounting. It is pure bookkeeping - no analysis
//! decision reads it - and every counter here exists so the report can say
//! how much of the program was actually analyzed, and what stopped it.

use std::cell::RefCell;

use crate::analysis::taint::engine::BackwardStats;

/// One safety valve that truncates analysis, when it fires.
///
/// Every bound in the engine that trades precision (or coverage) for
/// termination is a variant here. Reporting one is not an error: the analysis
/// stays sound and bounded by design. It is a *caveat*, and a report that
/// hides its own caveats is not reviewable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Cap {
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
}

/// Slots in [`CAP_COUNTS`]. Keep in sync with [`Cap::slot`].
const CAP_SLOTS: usize = 7;

thread_local! {
    static CAP_COUNTS: RefCell<[u64; CAP_SLOTS]> = const { RefCell::new([0; CAP_SLOTS]) };
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
        }
    }

    /// Stable identifier used in the JSON report.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Cap::ValueIterations => "value_iterations",
            Cap::CallContextDepth => "call_context_depth",
            Cap::CallContextChains => "call_context_chains",
            Cap::ContextsPerFunction => "contexts_per_function",
            Cap::ForwardHops => "forward_hops",
            Cap::CallgraphHops => "callgraph_hops",
            Cap::PointsToPasses => "points_to_passes",
        }
    }

    /// What the truncation cost, in analysis terms. Advisory prose only: the
    /// engine never branches on it.
    #[must_use]
    pub const fn effect(self) -> &'static str {
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
        }
    }

    /// Record one firing of this cap in the current scan thread.
    pub fn record(self) {
        CAP_COUNTS.with(|counts| {
            let mut counts = counts.borrow_mut();
            counts[self.slot()] = counts[self.slot()].saturating_add(1);
        });
    }

    /// How many times this cap has fired on the current thread since its
    /// counters were last drained.
    #[must_use]
    pub fn recorded(self) -> u64 {
        CAP_COUNTS.with(|counts| counts.borrow()[self.slot()])
    }
}

/// Drain the cap counters into reportable hits and reset them.
///
/// Called once per scan so the numbers belong to that scan rather than
/// accumulating across a long-lived process (MCP/LSP servers scan
/// repeatedly).
#[must_use]
pub fn drain_caps() -> Vec<CapHit> {
    let all = [
        Cap::ValueIterations,
        Cap::CallContextDepth,
        Cap::CallContextChains,
        Cap::ContextsPerFunction,
        Cap::ForwardHops,
        Cap::CallgraphHops,
        Cap::PointsToPasses,
    ];
    let counts = CAP_COUNTS.with(|counts| std::mem::take(&mut *counts.borrow_mut()));
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

/// How long one analysis phase took, in wall-clock milliseconds.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseTiming {
    /// Phase name (`lower`, `graph`, `checks`, `taint`, `total`).
    pub phase: String,
    /// Elapsed wall-clock milliseconds.
    pub ms: u128,
}

/// A source file ranked by how long it took to lower.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTiming {
    /// Path as the scanner knows it.
    pub file: String,
    /// Milliseconds spent lowering this file alone.
    pub ms: u128,
    /// Functions extracted from it.
    pub functions: usize,
}

/// A function ranked by how long its taint exploration took.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionTiming {
    /// Function key (`handle`, `file::handler`).
    pub function: String,
    /// File it was lowered from, when known.
    pub file: String,
    /// Milliseconds spent exploring its sink arguments.
    pub ms: u128,
    /// Sink arguments explored in it.
    pub sink_args: usize,
}

/// One fired safety valve, with what it cost.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapHit {
    /// [`Cap::id`] of the valve.
    pub cap: String,
    /// How many times it fired in this scan.
    pub hits: usize,
    /// [`Cap::effect`] of the valve, in prose.
    pub effect: String,
}

/// A finding that reached the reporting gate and was dropped, by reason.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionCount {
    /// `not-reportable`, `exact-duplicate`, `shape-duplicate`, `below-tier`,
    /// `below-confidence`, or `below-severity`.
    pub reason: String,
    /// How many findings were dropped for it.
    pub count: usize,
}

/// What the scan was handed, and what it could actually read.
///
/// The distinction matters because the two used to be the same number: a
/// file with a syntax-error-riddled tree still parsed (tree-sitter returns a
/// tree of `ERROR` nodes rather than failing), so it was analyzed as if it
/// were intact and reported "Clean".
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputAccounting {
    /// Supported source files submitted for analysis, including files that
    /// could not be read or lowered.
    pub submitted: usize,
    /// Files successfully read, parsed, and lowered (including files with no
    /// function declarations).
    pub scanned: usize,
    /// Files that could not be read, parsed, or lowered.
    pub failed: usize,
    /// An explicit input path was not a supported source file, or the target
    /// contained no supported source files.
    pub unsupported: usize,
    /// Paths of failed files, capped at [`PARTIAL_SAMPLE`].
    pub failed_files: Vec<String>,
    /// Files whose parse tree contains errors: partially analyzed.
    pub parse_partial: usize,
    /// Paths of those files, capped at [`PARTIAL_SAMPLE`] so a corpus of
    /// broken files cannot bloat the report.
    pub parse_partial_files: Vec<String>,
    /// Functions extracted across every successfully lowered file.
    pub functions: usize,
}

/// How many `parse_partial_files` paths the report keeps per scan.
pub const PARTIAL_SAMPLE: usize = 25;

/// The outcome of executing one check.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    Ok,
    Panicked(String),
    Skipped(String),
}

/// Execution metrics for one check class.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckTelemetry {
    pub id: String,
    pub scope: String,
    pub ran: usize,
    pub findings: usize,
    pub millis: u128,
    pub outcome: CheckOutcome,
}

/// Everything one scan measured.
///
/// Merged across the per-language-group scans the CLI performs; see
/// [`ScanTelemetry::merge`].
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default)]
pub struct ScanTelemetry {
    /// Wall-clock cost per phase.
    pub phases: Vec<PhaseTiming>,
    /// Files that dominated the lowering phase.
    pub slowest_files: Vec<FileTiming>,
    /// Functions that dominated the taint phase.
    pub slowest_functions: Vec<FunctionTiming>,
    /// Safety valves that fired, and what each cost.
    pub caps: Vec<CapHit>,
    /// Findings dropped at the reporting gate, by reason.
    pub suppressed: Vec<SuppressionCount>,
    /// What the scan was handed vs. what it could read.
    pub input: InputAccounting,
    /// Backward-taint traversal counters (the demand-driven cost model).
    pub taint: BackwardStats,
    /// Check-by-check execution timings, findings count, and outcomes.
    pub checks: Vec<CheckTelemetry>,
    /// Non-fatal scan errors (failed files, worker failures, unsupported input).
    pub errors: Vec<String>,
}

/// How many entries the slow-file and slow-function lists keep.
pub const SLOW_SAMPLE: usize = 10;

impl ScanTelemetry {
    /// Fold another scan's telemetry in (the CLI scans one group per
    /// language family).
    pub fn merge(&mut self, other: ScanTelemetry) {
        self.phases.extend(other.phases);
        self.slowest_files.extend(other.slowest_files);
        self.slowest_functions.extend(other.slowest_functions);
        self.caps.extend(other.caps);
        self.suppressed.extend(other.suppressed);
        self.errors.extend(other.errors);
        self.input.submitted += other.input.submitted;
        self.input.scanned += other.input.scanned;
        self.input.failed += other.input.failed;
        self.input.unsupported += other.input.unsupported;
        self.input.failed_files.extend(other.input.failed_files);
        self.input.parse_partial += other.input.parse_partial;
        self.input
            .parse_partial_files
            .extend(other.input.parse_partial_files);
        self.input.functions += other.input.functions;
        self.taint.nodes_visited += other.taint.nodes_visited;
        self.taint.functions_visited += other.taint.functions_visited;
        self.taint.sink_args_explored += other.taint.sink_args_explored;
        self.taint.vulnerable += other.taint.vulnerable;
        self.taint.sanitized += other.taint.sanitized;
        self.taint.unknown += other.taint.unknown;
        self.taint.clean += other.taint.clean;
        self.checks.extend(other.checks);
    }

    /// Collapse per-group rows into one per-phase row, cap hits summed by
    /// name, suppressions summed by reason, and the slow lists trimmed to
    /// [`SLOW_SAMPLE`]. Call once, after every group has been merged.
    pub fn finalize(&mut self) {
        let mut phases: Vec<PhaseTiming> = Vec::new();
        for p in &self.phases {
            match phases.iter_mut().find(|e| e.phase == p.phase) {
                Some(e) => e.ms += p.ms,
                None => phases.push(p.clone()),
            }
        }
        self.phases = phases;

        let mut caps: Vec<CapHit> = Vec::new();
        for c in self.caps.drain(..) {
            match caps.iter_mut().find(|e| e.cap == c.cap) {
                Some(e) => e.hits += c.hits,
                None => caps.push(c),
            }
        }
        self.caps = caps;

        let mut suppressed: Vec<SuppressionCount> = Vec::new();
        for s in self.suppressed.drain(..) {
            match suppressed.iter_mut().find(|e| e.reason == s.reason) {
                Some(e) => e.count += s.count,
                None => suppressed.push(s),
            }
        }
        self.suppressed = suppressed;

        let mut checks: Vec<CheckTelemetry> = Vec::new();
        for c in self.checks.drain(..) {
            match checks
                .iter_mut()
                .find(|e| e.id == c.id && e.scope == c.scope)
            {
                Some(e) => {
                    e.ran += c.ran;
                    e.findings += c.findings;
                    e.millis += c.millis;
                    if matches!(e.outcome, CheckOutcome::Ok)
                        && !matches!(c.outcome, CheckOutcome::Ok)
                    {
                        e.outcome = c.outcome;
                    }
                }
                None => checks.push(c),
            }
        }
        self.checks = checks;

        self.slowest_files.sort_by_key(|b| std::cmp::Reverse(b.ms));
        self.slowest_files.truncate(SLOW_SAMPLE);
        self.slowest_functions
            .sort_by_key(|b| std::cmp::Reverse(b.ms));
        self.slowest_functions.truncate(SLOW_SAMPLE);
        self.input.failed_files.sort();
        self.input.failed_files.dedup();
        self.input.failed_files.truncate(PARTIAL_SAMPLE);
        self.input.parse_partial_files.truncate(PARTIAL_SAMPLE);
        self.errors.sort();
        self.errors.dedup();
        self.errors.truncate(PARTIAL_SAMPLE);
    }

    /// True when nothing truncated, nothing degraded, every check succeeded, and every file parsed
    /// cleanly - i.e. when "no findings" actually means "nothing to find".
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.caps.is_empty()
            && self.input.failed == 0
            && self.input.unsupported == 0
            && self.errors.is_empty()
            && self.input.parse_partial == 0
            && self
                .checks
                .iter()
                .all(|c| matches!(c.outcome, CheckOutcome::Ok))
    }
}

/// Milliseconds elapsed since `start`, as a reportable number.
#[must_use]
pub fn millis_since(start: std::time::Instant) -> u128 {
    start.elapsed().as_millis()
}
