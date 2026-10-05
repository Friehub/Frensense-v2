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
//! **Corpus-learned checks** ([`LearnedCheckFact`] in the fact table) supply
//! the *conclusions*, which calls are violations, with bundle-authored
//! advisory text. They arrive through `.frc` bundles, were verified by the
//! bundler's replay gate (fire on positives, silent on negatives), and are
//! the scale path: nobody writes 45k rules.
//!
//! Line drawn: **built-in = how to look; learned = what to conclude.**

pub mod guard_bypass;
pub mod int_overflow;
pub mod leak;
pub mod memory_summary;
pub mod oob;
pub mod policy;
pub mod schema_policy;
pub mod uaf;
pub mod weak_hash;

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

/// Run every registered check over every function, deduped and ordered by
/// (function, span) so output is deterministic.
///
/// `facts` carries the bundle-learned checks; pass `&FactTable::default()`
/// when scanning without a bundle.
pub fn check_all<'a>(
    irs: impl IntoIterator<Item = &'a FunctionIR>,
    facts: &FactTable,
) -> Vec<CheckerFinding> {
    check_all_with_graph(irs, facts, None)
}

/// [`check_all`] with the program value-flow graph: the UAF checker walks
/// interprocedural free/use edges (callee parameter frees, caller-side
/// frees, factory provenance) that intraprocedural IR alone cannot see.
pub fn check_all_with_graph<'a>(
    irs: impl IntoIterator<Item = &'a FunctionIR>,
    facts: &FactTable,
    prog: Option<&ProgramSvfg<'_>>,
) -> Vec<CheckerFinding> {
    let mut seen: FxHashSet<(String, String, usize)> = FxHashSet::default();
    let mut all = Vec::new();
    let irs: Vec<&FunctionIR> = irs.into_iter().collect();
    // Program-level rules run once over the whole IR set (they correlate
    // guards in one function with definitions in another).
    for f in guard_bypass::check_allowlist_definitions(&irs, facts) {
        let key = (
            f.function.clone(),
            f.rule.clone(),
            f.span.map(|s| s.0).unwrap_or(usize::MAX),
        );
        if seen.insert(key) {
            all.push(f);
        }
    }
    // Co-occurrence policies: function-scoped ones run per function,
    // module-scoped ones run once over the whole scanned set. Legacy
    // learned checks fire through the same evaluator after conversion.
    for f in policy::check_program(&irs, facts) {
        let key = (
            f.function.clone(),
            f.rule.clone(),
            f.span.map(|s| s.0).unwrap_or(usize::MAX),
        );
        if seen.insert(key) {
            all.push(f);
        }
    }
    let mem_summaries =
        memory_summary::MemorySummaryRegistry::from_facts(facts).infer_program_summaries_into(&irs);
    for ir in &irs {
        let findings = weak_hash::check(ir, facts)
            .into_iter()
            .chain(guard_bypass::check(ir, facts))
            .chain(guard_bypass::check_credentials(ir, facts))
            .chain(schema_policy::check(ir, facts))
            .chain(
                match prog.and_then(|p| p.function_index(&ir.name).map(|fi| (p, fi))) {
                    Some((p, fi)) => uaf::check_with_prog(fi, p, &mem_summaries),
                    None => uaf::check_with_summaries(ir, &mem_summaries),
                },
            )
            .chain(oob::check_with_summaries(ir, &mem_summaries, facts))
            .chain(int_overflow::check(ir, &mem_summaries, facts))
            .chain(leak::check(ir, &mem_summaries, facts))
            .chain(learned::check(ir, facts));
        for f in findings {
            let key = (
                f.function.clone(),
                f.rule.clone(),
                f.span.map(|s| s.0).unwrap_or(usize::MAX),
            );
            if seen.insert(key) {
                all.push(f);
            }
        }
    }
    all.sort_by_key(|f| {
        (
            f.function.clone(),
            f.span.map(|s| s.0).unwrap_or(usize::MAX),
        )
    });
    all
}

/// The learned-check rule: apply corpus-verified checks from the fact
/// table. Mechanism identical to the seed checks (call matching over the
/// IR); the conclusions are the bundle's.
pub(crate) mod learned {
    use super::CheckerFinding;
    use super::Provenance;
    use crate::analysis::taint::facts::FactTable;
    use crate::ir::function::{FunctionIR, Instruction, Operand};

    /// Last-segment names of every call in the function (one pass).
    pub(crate) fn call_segments(ir: &FunctionIR) -> Vec<String> {
        let mut segs = Vec::new();
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                match instr {
                    Instruction::CallStatic { func, .. } => {
                        segs.push(func.rsplit('.').next().unwrap_or(func).to_string());
                    }
                    Instruction::CallVirtual { method, .. } => {
                        segs.push(method.rsplit('.').next().unwrap_or(method).to_string());
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
    pub fn check(ir: &FunctionIR, facts: &FactTable) -> Vec<CheckerFinding> {
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
                for fact in facts.learned_checks_for(callee) {
                    // Guard qualification: a rule with `unless_guard` is
                    // silent when the guard call is present in the same
                    // function, the corpus says "trigger without
                    // enforcement" is the violation.
                    if let Some(guard) = &fact.unless_guard {
                        let gseg = guard.rsplit('.').next().unwrap_or(guard);
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
                        span: instr_span(ir, instr),
                        severity: fact.severity.clone(),
                        provenance: Provenance::Learned,
                    });
                }
            }
        }
        findings
    }

    fn instr_span(ir: &FunctionIR, instr: &Instruction) -> Option<(usize, usize)> {
        let dest = match instr {
            Instruction::CallStatic { dest, .. }
            | Instruction::CallVirtual { dest, .. }
            | Instruction::CallPointer { dest, .. } => (*dest)?,
            _ => return None,
        };
        ir.var_metadata.get(&dest)?.byte_range
    }

    // Silence unused-import warning if Operand becomes unused in future
    // refinements; kept in the destructure for symmetry with seed checks.
    #[allow(dead_code)]
    fn _assert_operand_used(_: &[Operand]) {}
}
