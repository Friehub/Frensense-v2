// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Co-occurrence policy checks: the generalized learned-check evaluator.
//!
//! A [`PolicyFact`] poses a question at every trigger call: do the policy's
//! requirements hold in the trigger's scope? A function violating the policy
//! (trigger present, at least one requirement unsatisfied) yields a
//! [`CheckerFinding`]. This complements and operates alongside `LearnedCheckFact`
//! — `unless_guard` is evaluated as a `GuardCall` requirement,
//! `unless_range_check` as a `RangeCheck` — and adds the presence
//! forms (`RequireCall`, `NotCall`) plus a cross-function scope, so bundles
//! can express "privileged action without its audit log", "dangerous call
//! without any of its sanctioned wrappers", or "trigger helper defined in a
//! sibling module still counts as enforcement".

use rustc_hash::FxHashMap;

use super::CheckerFinding;
use super::learned::{call_segments, is_range_guarded};
use crate::analysis::taint::facts::{FactTable, PolicyFact, PolicyRequirement, PolicyScope};
use crate::ir::function::{BlockId, FunctionIR, Instruction, Operand};

/// Evaluate every policy fact in `facts` over the scanned program.
///
/// Function-scoped policies evaluate per function; module-scoped policies
/// evaluate against the union of all scanned functions (the check pipeline
/// passes one scan's IR set here, which is the module the policy author
/// refers to). Active `learned_checks` participate alongside native policies,
/// ensuring both check representations fire harmoniously.
pub fn check_program(irs: &[&FunctionIR], facts: &FactTable) -> Vec<CheckerFinding> {
    if facts.learned_checks.is_empty() && facts.policy_facts.is_empty() {
        return Vec::new();
    }

    // Function index by name for stable ordering; segment sets per function
    // (computed once per function, not per trigger).
    let mut segsets: FxHashMap<&str, Vec<String>> = FxHashMap::default();
    for ir in irs {
        segsets.insert(ir.name.as_str(), call_segments(ir));
    }
    // Program-wide segment set for module-scoped requirements: every call
    // segment anywhere PLUS every defined function name (a sibling module
    // that DEFINES the enforcement helper counts as enforcement available;
    // the definition is the strongest evidence a helper is in scope even if
    // this scan never sees its call site).
    let mut module_segs: Vec<String> = segsets.values().flatten().cloned().collect();
    module_segs.extend(irs.iter().map(|ir| ir.name.clone()));
    module_segs.sort();
    module_segs.dedup();

    // Learned checks evaluate alongside native policies (deduped by rule id:
    // a bundle shipping both shapes of the same rule must not fire twice).
    let mut native_rules: Vec<&str> = facts.policy_facts.iter().map(|p| p.rule.as_str()).collect();
    native_rules.sort();
    native_rules.dedup();
    let mut all_policies: Vec<PolicyFact> = Vec::new();
    all_policies.extend(facts.policy_facts.iter().cloned());
    for check in &facts.learned_checks {
        if native_rules.contains(&check.rule.as_str()) {
            continue;
        }
        all_policies.push(PolicyFact::from_legacy(check));
    }

    let mut findings = Vec::new();
    for policy in &all_policies {
        let trigger_seg = policy
            .when_call
            .rsplit('.')
            .next()
            .unwrap_or(&policy.when_call);
        for ir in irs {
            let segs = match segsets.get(ir.name.as_str()) {
                Some(s) => s,
                None => continue,
            };
            if !segs.iter().any(|s| s == trigger_seg) {
                continue;
            }
            let val_info = crate::analysis::value::analyze(ir);
            // Collect every trigger call site in this function with its args.
            for (bid, args, span) in trigger_sites(ir, trigger_seg) {
                let satisfied = policy.require.iter().all(|req| {
                    requirement_holds(
                        req,
                        ir,
                        bid,
                        &val_info,
                        args,
                        segs,
                        &module_segs,
                        policy.scope,
                    )
                });
                if !satisfied {
                    findings.push(CheckerFinding {
                        function: ir.name.clone(),
                        rule: policy.rule.clone(),
                        message: policy.message.clone(),
                        span,
                        learned: true,
                    });
                }
            }
        }
    }
    findings
}

/// Every call instruction in `ir` whose callee's last segment is `seg`,
/// as (bid, args, span) tuples.
type TriggerSite<'a> = (BlockId, &'a [Operand], Option<(usize, usize)>);

fn trigger_sites<'a>(ir: &'a FunctionIR, seg: &str) -> Vec<TriggerSite<'a>> {
    let mut out = Vec::new();
    for (&bid, block) in &ir.blocks {
        for instr in &block.instructions {
            let (name, args) = match instr {
                Instruction::CallStatic { func, args, .. } => (func, args),
                Instruction::CallVirtual { method, args, .. } => (method, args),
                _ => continue,
            };
            let last = name.rsplit('.').next().unwrap_or(name);
            if last != seg {
                continue;
            }
            out.push((bid, args.as_slice(), instr_span(ir, instr)));
        }
    }
    out
}

/// Does one requirement hold for this trigger site?
fn requirement_holds(
    req: &PolicyRequirement,
    ir: &FunctionIR,
    block: BlockId,
    val_info: &crate::analysis::value::ValueInfo,
    args: &[Operand],
    fn_segs: &[String],
    module_segs: &[String],
    scope: PolicyScope,
) -> bool {
    match req {
        PolicyRequirement::GuardCall { call } => {
            // Enforcement by a named helper: the requirement holds when the
            // guard call is PRESENT in the scope (legacy `unless_guard`
            // semantics inverted into the positive form).
            let seg = call.rsplit('.').next().unwrap_or(call);
            scope_segs(scope, fn_segs, module_segs)
                .iter()
                .any(|s| s == seg)
        }
        PolicyRequirement::RequireCall { any_of } => {
            let wanted: Vec<&str> = any_of
                .iter()
                .map(|c| c.rsplit('.').next().unwrap_or(c))
                .collect();
            scope_segs(scope, fn_segs, module_segs)
                .iter()
                .any(|s| wanted.contains(&s.as_str()))
        }
        PolicyRequirement::NotCall { call } => {
            let seg = call.rsplit('.').next().unwrap_or(call);
            !scope_segs(scope, fn_segs, module_segs)
                .iter()
                .any(|s| s == seg)
        }
        PolicyRequirement::RangeCheck { ops } => args.iter().any(|a| match a {
            Operand::Var(v) => is_range_guarded(ir, *v, ops, block, val_info),
            _ => false,
        }),
    }
}

/// The segment set a requirement is evaluated against.
fn scope_segs<'a>(
    scope: PolicyScope,
    fn_segs: &'a [String],
    module_segs: &'a [String],
) -> &'a [String] {
    match scope {
        PolicyScope::Function => fn_segs,
        PolicyScope::Module => module_segs,
    }
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
