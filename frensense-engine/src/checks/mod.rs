// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Non-dataflow checks: policy assertions over the lowered IR that need no
//! taint analysis.
//!
//! Two tiers, deliberately separated:
//!
//! **Built-in seed checks** (`weak_hash` and future structural rules) supply
//! only *mechanism*, how to look at the IR. They are the bootstrapping
//! oracle, kept minimal so shape-thinking cannot creep back in.
//!
//! **Corpus-learned checks** (`LearnedCheckFact` in the fact table) supply
//! the *conclusions*, which calls are violations, with bundle-authored
//! advisory text. They arrive through `.frc` bundles, were verified by the
//! bundler's replay gate (fire on positives, silent on negatives), and are
//! the scale path: nobody writes 45k rules.
//!
//! Line drawn: **built-in = how to look; learned = what to conclude.**

pub mod guard_bypass;
pub mod health;
pub(crate) mod int_overflow;
pub mod leak;
pub mod memory_summary;
pub(crate) mod noreturn;
pub(crate) mod oob;
pub mod policy;
pub mod registry;
pub mod schema_policy;
pub mod uaf;
pub mod weak_hash;

/// Text of a caught panic payload (`&str` and `String` payloads; anything else
/// is reported as `unknown panic`).
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[cfg(test)]
mod divergence_tests;
#[cfg(test)]
mod guard_bypass_tests;
#[cfg(test)]
mod int_overflow_tests;
#[cfg(test)]
mod leak_tests;
#[cfg(test)]
mod memory_summary_tests;
#[cfg(test)]
mod oob_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod schema_policy_tests;
#[cfg(test)]
mod uaf_tests;
#[cfg(test)]
mod weak_hash_tests;

use crate::analysis::forward::ProgramSvfg;
use crate::analysis::taint::facts::FactTable;
use crate::ir::function::FunctionIR;
use rustc_hash::FxHashSet;

pub use crate::analysis::taint::facts::Provenance;
pub(crate) use registry::{CheckContext, CheckScope};

/// Last segment of a call reference: everything after the last `.`, then
/// after the last `::` (Rust/C++ paths), so `security.hash`, `sha2::digest`
/// and `ns::mod.fn` all reduce to the bare method name the check
/// vocabularies are keyed by.
pub(crate) fn last_segment(call: &str) -> &str {
    let s = call.rsplit('.').next().unwrap_or(call);
    s.rsplit("::").next().unwrap_or(s)
}

/// One non-dataflow policy finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckerFinding {
    /// Function containing the violating instruction.
    pub function: String,
    /// Stable rule id (e.g. `"weak_hash_md5"`, or a bundle's rule id).
    /// Built-in rules use `&'static str` ids; learned rules carry their
    /// bundle-supplied id, interned here.
    pub rule: String,
    /// Short human description of the violation. Carried verbatim when the
    /// driving knowledge (bundle fact, authored policy) supplied prose.
    /// Spec checks leave it empty and emit `params` instead; the consumer
    /// then renders the observation from a `frensense-lang` template
    /// keyed by `rule`.
    pub message: String,
    /// Structured observation parameters `(template key, value)` for
    /// findings whose `message` is empty. Empty when `message` is set.
    pub params: Vec<(&'static str, String)>,
    /// Byte range of the violating call in the source file, when known.
    pub span: Option<(usize, usize)>,
    /// Advisory severity declared by the driving fact (learned check,
    /// authored policy, or spec rule), copied verbatim. Empty when the
    /// driving rule declares none; consumers then resolve severity from
    /// their own rule registry.
    pub severity: String,
    /// Knowledge source: spec seed, authored policy, or bundle-learned fact.
    pub provenance: Provenance,
}

/// The single finding identity: two findings from the same function with
/// the same rule at the same span are the same finding. This is the only
/// dedup key - [`check_all`] is the one place findings are deduplicated.
fn finding_key(f: &CheckerFinding) -> (String, String, usize) {
    (
        f.function.clone(),
        f.rule.clone(),
        f.span.map(|s| s.0).unwrap_or(usize::MAX),
    )
}

/// Name each learned-check finding that only one evaluator produced.
///
/// `LearnedChecks` (function-scoped: last-segment matching, a guard anywhere
/// in the function suppresses) and `Policies` (program-scoped: the same
/// facts via `PolicyFact::from_legacy`, import-alias resolution, the guard
/// must dominate the trigger) both consume `facts.learned_checks`. The
/// driver keeps the union, so a disagreement silently widens or narrows the
/// reported set. `FRENSdbg_CHECKS` makes that visible without changing the
/// result, which is the prerequisite for choosing one evaluator deliberately.
fn trace_learned_divergence(
    irs: &[&FunctionIR],
    facts: &FactTable,
    pkg_scope: Option<&policy::PackageScope<'_>>,
) {
    if !crate::debug_flags::DebugFlags::checks_enabled() || facts.learned_checks.is_empty() {
        return;
    }
    let (legacy_only, policy_only) = learned_divergence(irs, facts, pkg_scope);
    for (path, only) in [("legacy", legacy_only), ("policy", policy_only)] {
        for (function, rule, span) in only {
            crate::dbg_trace!(
                true,
                "frensense: learned-check divergence ({path} only): {function} {rule} @{span}"
            );
        }
    }
}

/// Findings that only one of the two learned-check evaluators produced.
///
/// Returns `(legacy_only, policy_only)`, each sorted by
/// `(function, rule, span)`. Exposed to the test module so a change to either
/// path's semantics shows up as a fixture failure rather than a silent shift
/// in the reported union.
type FindingKey = (String, String, usize);

fn learned_divergence(
    irs: &[&FunctionIR],
    facts: &FactTable,
    pkg_scope: Option<&policy::PackageScope<'_>>,
) -> (Vec<FindingKey>, Vec<FindingKey>) {
    let key = |f: &CheckerFinding| {
        (
            f.function.clone(),
            f.rule.clone(),
            f.span.map(|s| s.0).unwrap_or(usize::MAX),
        )
    };
    let legacy: std::collections::BTreeSet<_> = irs
        .iter()
        .flat_map(|ir| learned::check(ir, facts))
        .map(|f| key(&f))
        .collect();
    let learned_rules: FxHashSet<&str> = facts
        .learned_checks
        .iter()
        .map(|(fact, _)| fact.rule.as_str())
        .collect();
    let policy: std::collections::BTreeSet<_> = policy::check_program_scoped(irs, facts, pkg_scope)
        .into_iter()
        .filter(|f| learned_rules.contains(f.rule.as_str()))
        .map(|f| key(&f))
        .collect();
    (
        legacy.difference(&policy).cloned().collect(),
        policy.difference(&legacy).cloned().collect(),
    )
}

/// Push a finding unless an earlier check already reported the same
/// `(function, rule, span)` identity.
fn push_unique(
    all: &mut Vec<CheckerFinding>,
    seen: &mut FxHashSet<(String, String, usize)>,
    f: CheckerFinding,
) {
    if seen.insert(finding_key(&f)) {
        all.push(f);
    }
}

/// Run every registered check over every function, deduped and ordered by
/// (function, span) so output is deterministic.
///
/// `facts` carries the bundle-learned checks; pass `&FactTable::default()`
/// when scanning without a bundle.
pub(crate) fn check_all<'a>(
    irs: impl IntoIterator<Item = &'a FunctionIR>,
    facts: &FactTable,
) -> Vec<CheckerFinding> {
    check_all_with_telemetry(irs, facts, None, None).0
}

/// [`check_all`] with the program value-flow graph and package scope, while
/// also collecting execution telemetry (timings, run counts, findings, and
/// outcomes with catch_unwind failure isolation).
///
/// `prog` lets the UAF checker walk interprocedural free/use edges (callee
/// parameter frees, caller-side frees, factory provenance) that intraprocedural
/// IR alone cannot see. `pkg_scope`: policies carrying `package: Some(pkg)`
/// only fire in functions whose file imports `pkg`; `None` disables filtering.
pub(crate) fn check_all_with_telemetry<'a>(
    irs: impl IntoIterator<Item = &'a FunctionIR>,
    facts: &FactTable,
    prog: Option<&ProgramSvfg<'_>>,
    pkg_scope: Option<&policy::PackageScope<'_>>,
) -> (Vec<CheckerFinding>, Vec<crate::telemetry::CheckTelemetry>) {
    let registry = registry::default_registry();
    check_all_with_registry_and_telemetry(&registry, irs, facts, prog, pkg_scope)
}

/// [`check_all_with_telemetry`] with an explicit [`registry::CheckRegistry`].
pub(crate) fn check_all_with_registry_and_telemetry<'a>(
    registry: &registry::CheckRegistry,
    irs: impl IntoIterator<Item = &'a FunctionIR>,
    facts: &FactTable,
    prog: Option<&ProgramSvfg<'_>>,
    pkg_scope: Option<&policy::PackageScope<'_>>,
) -> (Vec<CheckerFinding>, Vec<crate::telemetry::CheckTelemetry>) {
    let irs: Vec<&FunctionIR> = irs.into_iter().collect();
    trace_learned_divergence(&irs, facts, pkg_scope);
    // One memory-summary registry per scan: program summaries are inferred
    // from the whole IR set once, then shared by every memory check.
    let summaries =
        memory_summary::MemorySummaryRegistry::from_facts(facts).infer_program_summaries_into(&irs);
    let program_ctx = CheckContext {
        irs: &irs,
        current: None,
        prog,
        facts,
        pkg_scope,
        summaries: &summaries,
    };

    let mut seen: FxHashSet<(String, String, usize)> = FxHashSet::default();
    let mut all = Vec::new();
    let mut telemetries = Vec::new();

    // Program-scoped checks run once over the whole IR set (they correlate
    // guards in one function with definitions in another).
    for check in registry
        .checks()
        .filter(|c| c.scope() == CheckScope::Program)
    {
        let id = check.id().to_string();
        let start = std::time::Instant::now();
        let res =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check.run(&program_ctx)));
        let ms = start.elapsed().as_millis();
        let mut count = 0;
        let outcome = match res {
            Ok(findings) => {
                count = findings.len();
                for f in findings {
                    push_unique(&mut all, &mut seen, f);
                }
                crate::telemetry::CheckOutcome::Ok
            }
            Err(payload) => {
                let msg = panic_message(payload.as_ref());
                eprintln!("frensense: check `{id}` panicked: {msg}");
                crate::telemetry::CheckOutcome::Panicked(msg)
            }
        };
        telemetries.push(crate::telemetry::CheckTelemetry {
            id,
            scope: "program".to_string(),
            ran: 1,
            findings: count,
            millis: ms,
            outcome,
        });
    }

    // Function-scoped checks are grouped by check so we time and isolate per-check:
    for check in registry
        .checks()
        .filter(|c| c.scope() == CheckScope::Function)
    {
        let id = check.id().to_string();
        let start = std::time::Instant::now();
        let mut ran = 0;
        let mut count = 0;
        let mut outcome = crate::telemetry::CheckOutcome::Ok;

        for ir in &irs {
            ran += 1;
            let ctx = CheckContext {
                current: Some(*ir),
                ..program_ctx
            };
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check.run(&ctx)));
            match res {
                Ok(findings) => {
                    count += findings.len();
                    for f in findings {
                        push_unique(&mut all, &mut seen, f);
                    }
                }
                Err(payload) => {
                    let msg = panic_message(payload.as_ref());
                    eprintln!(
                        "frensense: check `{id}` panicked on function `{}`: {msg}",
                        ir.name
                    );
                    if matches!(outcome, crate::telemetry::CheckOutcome::Ok) {
                        outcome = crate::telemetry::CheckOutcome::Panicked(msg);
                    }
                }
            }
        }
        let ms = start.elapsed().as_millis();
        telemetries.push(crate::telemetry::CheckTelemetry {
            id,
            scope: "function".to_string(),
            ran,
            findings: count,
            millis: ms,
            outcome,
        });
    }

    all.sort_by_key(|f| {
        (
            f.function.clone(),
            f.span.map(|s| s.0).unwrap_or(usize::MAX),
        )
    });
    (all, telemetries)
}

/// The learned-check rule: apply corpus-verified checks from the fact
/// table. Mechanism identical to the seed checks (call matching over the
/// IR); the conclusions are the bundle's.
pub(crate) mod learned {
    use super::CheckerFinding;
    use crate::analysis::taint::facts::FactTable;
    use crate::ir::function::{FunctionIR, Instruction, Operand};

    /// Last-segment names of every call in the function (one pass).
    pub(crate) fn call_segments(ir: &FunctionIR) -> Vec<String> {
        let mut segs = Vec::new();
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                match instr {
                    Instruction::CallStatic { func, .. } => {
                        segs.push(super::last_segment(func).to_string());
                    }
                    Instruction::CallVirtual { method, .. } => {
                        segs.push(super::last_segment(method).to_string());
                    }
                    _ => {}
                }
            }
        }
        segs
    }

    /// True when `var` (or its def chain) is compared against a literal
    /// with one of `ops` in this function, inline range enforcement
    /// (`if (d < 0 || d > MAX) …`). Walks one BinaryOp hop up from `var`
    /// and one down (comparisons may be written in either order).
    pub(crate) fn has_range_check(
        ir: &FunctionIR,
        var: crate::ir::function::VarId,
        ops: &[String],
    ) -> bool {
        // Collect BinaryOps involving `var` on either side.
        let involved = |lhs: &Operand, rhs: &Operand| {
            matches!(lhs, Operand::Var(v) if *v == var)
                || matches!(rhs, Operand::Var(v) if *v == var)
        };
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                if let Instruction::BinaryOp { op, lhs, rhs, .. } = instr
                    && ops.contains(op)
                    && involved(lhs, rhs)
                {
                    // The OTHER side must be a literal (the bound).
                    let other = match (lhs, rhs) {
                        (Operand::Var(v), r) if *v == var => r,
                        (l, Operand::Var(v)) if *v == var => l,
                        _ => continue,
                    };
                    if matches!(
                        other,
                        Operand::StringLiteral(_)
                            | Operand::IntLiteral(_)
                            | Operand::FloatLiteral(_)
                    ) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check whether `var` is guarded by a range check at `block`.
    /// First evaluates concrete intervals via `ValueInfo::range_at(block, var)`.
    /// If an interval exists, verifies that it satisfies the bounds implied by `ops`.
    /// If no interval exists (e.g. non-integer or complex unmodeled flow), falls
    /// back to syntactic presence `has_range_check`.
    pub(crate) fn is_range_guarded(
        ir: &FunctionIR,
        var: crate::ir::function::VarId,
        ops: &[String],
        block: crate::ir::function::BlockId,
        val_info: &crate::analysis::value::ValueInfo,
    ) -> bool {
        if let Some((lo, hi)) = val_info.range_at(block, var) {
            let requires_upper = ops.iter().any(|op| op == "<" || op == "<=");
            let requires_lower = ops.iter().any(|op| op == ">" || op == ">=");
            let satisfies_upper = !requires_upper || hi < i64::MAX;
            let satisfies_lower = !requires_lower || lo > i64::MIN;
            if satisfies_upper && satisfies_lower && (requires_upper || requires_lower) {
                return true;
            }
            return false;
        }
        has_range_check(ir, var, ops)
    }

    /// Apply every learned check to one function.
    pub(super) fn check(ir: &FunctionIR, facts: &FactTable) -> Vec<CheckerFinding> {
        if facts.learned_checks.is_empty() {
            return Vec::new();
        }
        let segs = call_segments(ir);
        let val_info = crate::analysis::value::analyze(ir);
        let mut findings = Vec::new();
        for (&bid, block) in &ir.blocks {
            for instr in &block.instructions {
                let (callee, args) = match instr {
                    Instruction::CallStatic { func, args, .. } => (func, args),
                    Instruction::CallVirtual {
                        method: func, args, ..
                    } => (func, args),
                    _ => continue,
                };
                let last = super::last_segment(callee);
                for (fact, provenance) in facts.learned_checks_for(last) {
                    // Guard qualification: a rule with `unless_guard` is
                    // silent when the guard call is present in the same
                    // function, the corpus says "trigger without
                    // enforcement" is the violation.
                    if let Some(guard) = &fact.unless_guard {
                        let gseg = super::last_segment(guard);
                        if segs.iter().any(|s| s == gseg) {
                            continue;
                        }
                    }
                    // Range qualification: silent when any trigger argument
                    // var is compared against a literal bound, inline
                    // enforcement without a named helper.
                    if let Some(ops) = &fact.unless_range_check {
                        let guarded = args.iter().any(|a| match a {
                            Operand::Var(v) => is_range_guarded(ir, *v, ops, bid, &val_info),
                            _ => false,
                        });
                        if guarded {
                            continue;
                        }
                    }
                    findings.push(CheckerFinding {
                        function: ir.name.clone(),
                        rule: fact.rule.clone(),
                        message: fact.message.clone(),
                        params: Vec::new(),
                        span: ir.instr_span(instr),
                        severity: fact.severity.clone(),
                        provenance,
                    });
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod panic_message_tests {
    use super::panic_message;
    use std::panic::{catch_unwind, panic_any};

    #[test]
    fn extracts_str_string_and_unknown_payloads() {
        let str_payload = catch_unwind(|| panic!("plain")).unwrap_err();
        assert_eq!(panic_message(str_payload.as_ref()), "plain");
        let string_payload = catch_unwind(|| panic!("n={}", 3)).unwrap_err();
        assert_eq!(panic_message(string_payload.as_ref()), "n=3");
        let other = catch_unwind(|| panic_any(7_u8)).unwrap_err();
        assert_eq!(panic_message(other.as_ref()), "unknown panic");
    }
}
