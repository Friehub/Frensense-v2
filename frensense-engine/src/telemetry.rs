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
}

/// Slots in [`CAP_COUNTS`]. Keep in sync with [`Cap::slot`].
const CAP_SLOTS: usize = 10;

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
    /// `Cap::id` of the valve.
    pub cap: String,
    /// How many times it fired in this scan.
    pub hits: usize,
    /// `Cap::effect` of the valve, in prose.
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
    /// contained no supported source files. [`crate::scan::scan`] always
    /// leaves this at 0; a frontend that discovers input sets it. A file whose
    /// extension has no language spec is counted in `failed` instead.
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

/// What the program graph contained when the taint phase started walking.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct GraphSize {
    /// Functions in the analysed program.
    pub functions: usize,
    /// Value-flow nodes across every function.
    pub nodes: usize,
    /// Value-flow edges within functions.
    pub edges: usize,
    /// Call and parameter edges between functions.
    pub cross_edges: usize,
}

/// One callee the sink matcher ran on and rejected, with how often it was
/// called.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnmatchedCallee {
    /// Callee name as the matcher saw it (a package symbol when the call is
    /// an import).
    pub callee: String,
    /// Call sites that named it and matched no sink fact.
    pub calls: usize,
}

impl UnmatchedCallee {
    /// A callee name and how often the matcher rejected it.
    #[must_use]
    pub fn new(callee: impl Into<String>, calls: usize) -> Self {
        Self {
            callee: callee.into(),
            calls,
        }
    }
}

/// Where call sites left the taint phase: examined, skipped before matching,
/// matched no sink fact, or armed a sink whose arguments were then walked.
///
/// The counters partition the call sites, so
/// `calls_examined = skipped_* + not_a_sink + sink_calls` for every scan, and
/// a scan whose `not_a_sink` is large is a scan whose vocabulary the engine
/// never walks.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TaintFunnel {
    /// Call instructions the analysis looked at.
    pub calls_examined: usize,
    /// Skipped: the callee names a local variable or closure in this function.
    pub skipped_local_callable: usize,
    /// Skipped: the callee is a function defined in the analysed program.
    pub skipped_program_local: usize,
    /// Skipped: a receiver-only verb (`get`, `post`, ...) called without a
    /// receiver, so it cannot be a client method invocation.
    pub skipped_receiver_only_verb: usize,
    /// Ran the sink matcher and matched no sink fact.
    pub not_a_sink: usize,
    /// Matched a sink fact; its arguments were the walk's seeds.
    pub sink_calls: usize,
    /// The callees behind `not_a_sink`, with their call counts. Bounded at 32
    /// distinct names while scanning; see [`TaintFunnel::top_unmatched`] for
    /// the busiest few.
    pub unmatched_callees: Vec<UnmatchedCallee>,
}

/// Distinct unmatched callees one funnel keeps while scanning. Bounded
/// because [`TaintFunnel::record_unmatched`] runs per call site: a lookup over
/// a few dozen names stays cheap, and names past the bound are still counted
/// in `not_a_sink`.
const MISSED_CALLEE_TRACKED: usize = 32;

/// Unmatched callees [`TaintFunnel::top_unmatched`] reports: the busiest
/// handful, so a wide vocabulary does not print a page of one-call names.
const MISSED_CALLEE_SAMPLE: usize = 8;

/// Busiest first; the name breaks ties so two reports of the same scan print
/// the same order.
fn busiest_first(a: &UnmatchedCallee, b: &UnmatchedCallee) -> std::cmp::Ordering {
    b.calls.cmp(&a.calls).then_with(|| a.callee.cmp(&b.callee))
}

impl GraphSize {
    /// A measured graph size; the scan builds it, frontends read it.
    #[must_use]
    pub fn new(functions: usize, nodes: usize, edges: usize, cross_edges: usize) -> Self {
        Self {
            functions,
            nodes,
            edges,
            cross_edges,
        }
    }

    /// Fold another group's size in: every count adds.
    pub fn merge(&mut self, other: &Self) {
        self.functions += other.functions;
        self.nodes += other.nodes;
        self.edges += other.edges;
        self.cross_edges += other.cross_edges;
    }
}

impl TaintFunnel {
    /// A funnel whose counters partition `calls_examined`: the skip reasons as
    /// `(local callable, program-local callee, receiver-only verb)`, then the
    /// calls that matched no sink fact and the calls that armed one.
    #[must_use]
    pub fn new(
        calls_examined: usize,
        skipped: (usize, usize, usize),
        not_a_sink: usize,
        sink_calls: usize,
    ) -> Self {
        let (skipped_local_callable, skipped_program_local, skipped_receiver_only_verb) = skipped;
        Self {
            calls_examined,
            skipped_local_callable,
            skipped_program_local,
            skipped_receiver_only_verb,
            not_a_sink,
            sink_calls,
            unmatched_callees: Vec::new(),
        }
    }

    /// Record one call site that ran the sink matcher and matched no sink
    /// fact, keeping a running count per callee name.
    ///
    /// The tracked list holds the first 32 distinct names seen; a call to a
    /// name past that bound is still counted in [`Self::not_a_sink`], because
    /// the total is what the funnel partitions on.
    pub fn record_unmatched(&mut self, callee: &str) {
        self.not_a_sink += 1;
        if let Some(entry) = self
            .unmatched_callees
            .iter_mut()
            .find(|entry| entry.callee == callee)
        {
            entry.calls += 1;
        } else if self.unmatched_callees.len() < MISSED_CALLEE_TRACKED {
            self.unmatched_callees.push(UnmatchedCallee::new(callee, 1));
        }
    }

    /// The busiest callees that matched no sink fact, most calls first and
    /// the name as the tie-break, at most eight of them.
    #[must_use]
    pub fn top_unmatched(&self) -> Vec<&UnmatchedCallee> {
        let mut top: Vec<&UnmatchedCallee> = self.unmatched_callees.iter().collect();
        top.sort_by(|a, b| busiest_first(a, b));
        top.truncate(MISSED_CALLEE_SAMPLE);
        top
    }

    /// Fold another group's funnel in: every counter adds.
    pub fn merge(&mut self, other: &Self) {
        self.calls_examined += other.calls_examined;
        self.skipped_local_callable += other.skipped_local_callable;
        self.skipped_program_local += other.skipped_program_local;
        self.skipped_receiver_only_verb += other.skipped_receiver_only_verb;
        self.not_a_sink += other.not_a_sink;
        for entry in &other.unmatched_callees {
            match self
                .unmatched_callees
                .iter_mut()
                .find(|seen| seen.callee == entry.callee)
            {
                Some(seen) => seen.calls += entry.calls,
                None => self.unmatched_callees.push(entry.clone()),
            }
        }
        // Two wide groups can exceed the bound together; keep the busiest.
        self.unmatched_callees.sort_by(busiest_first);
        self.unmatched_callees.truncate(MISSED_CALLEE_TRACKED);
        self.sink_calls += other.sink_calls;
    }

    /// Calls skipped before the matcher ran, for any of the three reasons.
    #[must_use]
    pub fn skipped(&self) -> usize {
        self.skipped_local_callable + self.skipped_program_local + self.skipped_receiver_only_verb
    }
}

/// The outcome of executing one check.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The check ran to completion.
    Ok,
    /// The check panicked; the message is the panic payload.
    Panicked(String),
    /// The check did not run; the message gives the reason.
    Skipped(String),
}

/// Execution metrics for one check class.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckTelemetry {
    /// Stable identifier of the check.
    pub id: String,
    /// Granularity the check runs at, for example `function` or `program`.
    pub scope: String,
    /// Number of times the check ran.
    pub ran: usize,
    /// Findings the check produced.
    pub findings: usize,
    /// Wall time spent in the check, in milliseconds.
    pub millis: u128,
    /// How the check ended.
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
    /// Size of the program graph the taint phase walked.
    pub graph: GraphSize,
    /// Where the taint phase's call sites left the analysis.
    pub funnel: TaintFunnel,
    /// Check-by-check execution timings, findings count, and outcomes.
    pub checks: Vec<CheckTelemetry>,
    /// Non-fatal scan errors (failed files, worker failures, unsupported input).
    pub errors: Vec<String>,
}

/// How many entries the slow-file and slow-function lists keep.
pub(crate) const SLOW_SAMPLE: usize = 10;

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
        self.graph.merge(&other.graph);
        self.funnel.merge(&other.funnel);
        self.checks.extend(other.checks);
    }

    /// Collapse per-group rows into one per-phase row, cap hits summed by
    /// name, suppressions summed by reason, and the slow lists trimmed to
    /// `SLOW_SAMPLE`. Call once, after every group has been merged.
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
    ///
    /// ```
    /// use frensense_engine::analysis::taint::config::TaintConfig;
    /// use frensense_engine::analysis::taint::facts::FactTable;
    /// use frensense_engine::scan::scan;
    ///
    /// let config = TaintConfig::default();
    /// let facts = FactTable::from_config(&config);
    /// let run = |path: &str, src: &str, ext: &str| {
    ///     scan(&[(path.into(), src.into(), ext.into())], &config, &facts).telemetry
    /// };
    ///
    /// // Every file parsed and every check ran: "no findings" means nothing to find.
    /// assert!(run("a.ts", "export function f() { return 1 }", "ts").is_complete());
    /// // A file the engine could not read is counted, so an empty result is not "clean".
    /// let t = run("a.zzz", "hello", "zzz");
    /// assert_eq!(t.input.failed, 1);
    /// assert!(!t.is_complete());
    /// // A file with syntax errors is analyzed from the recovered tree and flagged partial.
    /// let t = run("a.ts", "export function f( { return 1 ", "ts");
    /// assert_eq!(t.input.parse_partial, 1);
    /// assert!(!t.is_complete());
    /// ```
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
pub(crate) fn millis_since(start: std::time::Instant) -> u128 {
    start.elapsed().as_millis()
}

#[cfg(test)]
mod tests {
    use super::{
        Cap, GraphSize, MISSED_CALLEE_SAMPLE, MISSED_CALLEE_TRACKED, ScanTelemetry, TaintFunnel,
        drain_caps,
    };

    /// The CLI scans one group per language family and merges the results: a
    /// group that walked no calls must not erase another group's counters, and
    /// the partition has to survive the fold.
    #[test]
    fn merge_adds_the_graph_size_and_the_funnel() {
        let mut a = ScanTelemetry {
            graph: GraphSize::new(3, 10, 12, 2),
            // 1 + 2 + 0 skipped + 4 unmatched + 2 sinks = 9 examined.
            funnel: TaintFunnel::new(9, (1, 2, 0), 4, 2),
            ..ScanTelemetry::default()
        };
        let b = ScanTelemetry {
            graph: GraphSize::new(5, 20, 25, 7),
            // 0 + 1 + 3 skipped + 5 unmatched + 2 sinks = 11 examined.
            funnel: TaintFunnel::new(11, (0, 1, 3), 5, 2),
            ..ScanTelemetry::default()
        };

        a.merge(b);

        assert_eq!(a.graph.functions, 8);
        assert_eq!(a.graph.nodes, 30);
        assert_eq!(a.graph.edges, 37);
        assert_eq!(a.graph.cross_edges, 9);
        assert_eq!(a.funnel.calls_examined, 20);
        assert_eq!(a.funnel.skipped(), 7);
        assert_eq!(a.funnel.not_a_sink, 9);
        assert_eq!(a.funnel.sink_calls, 4);
        assert_eq!(
            a.funnel.calls_examined,
            a.funnel.skipped() + a.funnel.not_a_sink + a.funnel.sink_calls,
            "the partition must survive the merge"
        );

        // A group that analysed nothing contributes nothing.
        a.merge(ScanTelemetry::default());
        assert_eq!(a.graph.nodes, 30);
        assert_eq!(a.funnel.calls_examined, 20);
    }

    /// The funnel names the callees it rejected, and a per-group fold sums
    /// the same name instead of duplicating it.
    #[test]
    fn the_funnel_names_and_merges_the_callees_it_rejected() {
        let mut a = TaintFunnel::default();
        a.record_unmatched("read");
        a.record_unmatched("read");
        a.record_unmatched("noop");

        let mut b = TaintFunnel::default();
        b.record_unmatched("read");
        b.record_unmatched("deserialize");

        a.merge(&b);

        assert_eq!(a.not_a_sink, 5);
        let top: Vec<(&str, usize)> = a
            .top_unmatched()
            .into_iter()
            .map(|entry| (entry.callee.as_str(), entry.calls))
            .collect();
        assert_eq!(
            top,
            vec![("read", 3), ("deserialize", 1), ("noop", 1)],
            "busiest first, then by name: {top:?}"
        );
    }

    /// The tracked list is bounded so a wide vocabulary cannot turn every
    /// report into a name dump; the count it explains is not.
    #[test]
    fn the_tracked_callee_list_is_bounded_and_the_count_is_not() {
        let mut wide = TaintFunnel::default();
        for i in 0..(MISSED_CALLEE_TRACKED + 5) {
            wide.record_unmatched(&format!("callee_{i}"));
        }
        assert_eq!(
            wide.not_a_sink,
            MISSED_CALLEE_TRACKED + 5,
            "every rejected call is counted, even when its name is not kept"
        );
        assert_eq!(wide.unmatched_callees.len(), MISSED_CALLEE_TRACKED);
        assert_eq!(
            wide.top_unmatched().len(),
            MISSED_CALLEE_SAMPLE,
            "the report keeps only the busiest handful"
        );

        // Folding a second wide group in cannot grow the list past the bound.
        let mut other = TaintFunnel::default();
        for i in 0..MISSED_CALLEE_TRACKED {
            other.record_unmatched(&format!("other_{i}"));
        }
        wide.merge(&other);
        assert_eq!(wide.unmatched_callees.len(), MISSED_CALLEE_TRACKED);
        assert_eq!(
            wide.top_unmatched()[0].callee,
            "callee_0",
            "every count is tied, so the name decides the order"
        );
    }

    /// The caps that used to truncate silently must reach the report with
    /// their stable ids, and a drain must reset them for the next scan.
    #[test]
    fn formerly_silent_caps_reach_the_report() {
        let _ = drain_caps();

        Cap::UafWalkNodes.record();
        Cap::UafWalkNodes.record();
        Cap::UafCalleeScanNodes.record();
        Cap::SsaDegraded.record();

        let hits = drain_caps();
        let hits_for = |id: &str| hits.iter().find(|hit| hit.cap == id).map(|hit| hit.hits);
        assert_eq!(hits_for("uaf_walk_nodes"), Some(2));
        assert_eq!(hits_for("uaf_callee_scan_nodes"), Some(1));
        assert_eq!(hits_for("ssa_degraded"), Some(1));
        assert!(drain_caps().is_empty(), "drain resets every cap counter");
    }
}
