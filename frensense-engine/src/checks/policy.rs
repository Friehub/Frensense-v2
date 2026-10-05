// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Co-occurrence policy checks: the generalized learned-check evaluator.
//!
//! A [`PolicyFact`] poses a question at every trigger call: do the policy's
//! requirements hold in the trigger's scope? A function violating the policy
//! (trigger present, at least one requirement unsatisfied) yields a
//! [`CheckerFinding`]. This complements and operates alongside
//! `LearnedCheckFact` - `unless_guard` is evaluated as a `GuardCall`
//! requirement, `unless_range_check` as a `RangeCheck` - and adds the
//! presence forms (`RequireCall`, `NotCall`) plus a cross-function scope,
//! so bundles can express "privileged action without its audit log",
//! "dangerous call without any of its sanctioned wrappers", or "trigger
//! helper defined in a sibling module still counts as enforcement".

use rustc_hash::FxHashMap;

use super::CheckerFinding;
use super::Provenance;
use super::learned::{call_segments, is_range_guarded};
use crate::analysis::taint::facts::{FactTable, PolicyFact, PolicyRequirement, PolicyScope};
use crate::ir::control::{self, DomSets};
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
    // Dominance for function-scoped guard/require presence: cached per
    // function across policies (computed at most once per scanned IR).
    let mut dom_cache: FxHashMap<&str, DomSets> = FxHashMap::default();
    for policy in &all_policies {
        let trigger_seg = policy
            .when_call
            .rsplit('.')
            .next()
            .unwrap_or(&policy.when_call);
        let needs_dom = policy.scope == PolicyScope::Function
            && policy.require.iter().any(|r| {
                matches!(
                    r,
                    PolicyRequirement::GuardCall { .. } | PolicyRequirement::RequireCall { .. }
                )
            });
        for ir in irs {
            let segs = match segsets.get(ir.name.as_str()) {
                Some(s) => s,
                None => continue,
            };
            if !segs.iter().any(|s| s == trigger_seg) {
                continue;
            }
            let doms: Option<&DomSets> = if needs_dom {
                let d: &DomSets = dom_cache
                    .entry(ir.name.as_str())
                    .or_insert_with(|| control::dominators(ir));
                Some(d)
            } else {
                None
            };
            let val_info = crate::analysis::value::analyze(ir);
            // Collect every trigger call site in this function with its args.
            for (bid, idx, args, span) in trigger_sites(ir, trigger_seg) {
                let satisfied = policy.require.iter().all(|req| {
                    requirement_holds(
                        req,
                        ir,
                        bid,
                        idx,
                        doms,
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
                        params: Vec::new(),
                        span,
                        severity: policy.severity.clone(),
                        provenance: Provenance::Learned,
                    });
                }
            }
        }
    }
    findings
}

/// Every call instruction in `ir` whose callee's last segment is `seg`,
/// as (bid, instr index, args, span) tuples. The index orders same-block
/// guard/trigger pairs.
type TriggerSite<'a> = (BlockId, usize, &'a [Operand], Option<(usize, usize)>);

fn trigger_sites<'a>(ir: &'a FunctionIR, seg: &str) -> Vec<TriggerSite<'a>> {
    let mut out = Vec::new();
    for (&bid, block) in &ir.blocks {
        for (idx, instr) in block.instructions.iter().enumerate() {
            let (name, args) = match instr {
                Instruction::CallStatic { func, args, .. } => (func, args),
                Instruction::CallVirtual { method, args, .. } => (method, args),
                _ => continue,
            };
            let last = name.rsplit('.').next().unwrap_or(name);
            if last != seg {
                continue;
            }
            out.push((bid, idx, args.as_slice(), instr_span(ir, instr)));
        }
    }
    out
}

/// Does one requirement hold for this trigger site?
#[allow(clippy::too_many_arguments)]
fn requirement_holds(
    req: &PolicyRequirement,
    ir: &FunctionIR,
    block: BlockId,
    trigger_idx: usize,
    doms: Option<&DomSets>,
    val_info: &crate::analysis::value::ValueInfo,
    args: &[Operand],
    fn_segs: &[String],
    module_segs: &[String],
    scope: PolicyScope,
) -> bool {
    match req {
        PolicyRequirement::GuardCall { call } => {
            // Enforcement by a named helper. Function scope is spatial: the
            // guard must EXECUTE before the trigger on every path (its block
            // dominates the trigger's, or same block with the guard first) -
            // a call that may be skipped enforces nothing. Module scope
            // stays presence (the helper exists somewhere in the module).
            let seg = call.rsplit('.').next().unwrap_or(call);
            if scope == PolicyScope::Module {
                module_segs.iter().any(|s| s == seg)
            } else {
                guard_executes_before(ir, seg, block, trigger_idx, doms)
            }
        }
        PolicyRequirement::RequireCall { any_of } => {
            if scope == PolicyScope::Module {
                let wanted: Vec<&str> = any_of
                    .iter()
                    .map(|c| c.rsplit('.').next().unwrap_or(c))
                    .collect();
                return module_segs.iter().any(|s| wanted.contains(&s.as_str()));
            }
            any_of.iter().any(|c| {
                let seg = c.rsplit('.').next().unwrap_or(c);
                guard_executes_before(ir, seg, block, trigger_idx, doms)
            })
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
        PolicyRequirement::BannedArgLiteral { slot, values } => {
            if let Some(arg) = args.get(*slot)
                && let Some(s) = extract_literal_string(arg, ir, val_info)
            {
                let s_lower = s.to_ascii_lowercase();
                return !values.iter().any(|v| v.to_ascii_lowercase() == s_lower);
            }
            true
        }
        PolicyRequirement::RequiredArgLiteral { slot, values } => {
            if let Some(arg) = args.get(*slot)
                && let Some(s) = extract_literal_string(arg, ir, val_info)
            {
                let s_lower = s.to_ascii_lowercase();
                return values.iter().any(|v| v.to_ascii_lowercase() == s_lower);
            }
            false
        }
    }
}

fn strip_quotes(lit: &str) -> &str {
    let lit = lit.trim();
    let bytes = lit.as_bytes();
    let (core, _) = match bytes.first() {
        Some(b'\'') | Some(b'"') | Some(b'`') => {
            let end = bytes.len().saturating_sub(1);
            (&lit[1..end], true)
        }
        _ => (lit, false),
    };
    core
}

/// Extract constant literal string/bool/int representation from an operand.
fn extract_literal_string(
    op: &Operand,
    ir: &FunctionIR,
    val_info: &crate::analysis::value::ValueInfo,
) -> Option<String> {
    match op {
        Operand::StringLiteral(s) => Some(strip_quotes(s).to_string()),
        Operand::IntLiteral(i) => Some(i.to_string()),
        Operand::BoolLiteral(b) => Some(b.to_string()),
        Operand::Var(v) => {
            if let Some(s) = val_info.const_str(*v) {
                return Some(strip_quotes(s).to_string());
            }
            if let Some(c) = val_info.const_int(*v) {
                return Some(c.to_string());
            }
            if let Some(b) = val_info.const_bool(*v) {
                return Some(b.to_string());
            }
            for block in ir.blocks.values() {
                for instr in &block.instructions {
                    match instr {
                        Instruction::Assign { dest, src } if dest == v => {
                            return extract_literal_string(src, ir, val_info);
                        }
                        Instruction::Cast { dest, src, .. } if dest == v => {
                            return extract_literal_string(src, ir, val_info);
                        }
                        _ => {}
                    }
                }
            }
            None
        }
        _ => None,
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

/// True when some call to `seg` provably executes before the trigger:
/// its block dominates the trigger's block, or both share a block with the
/// guard at a lower instruction index. Falls back to mere presence when no
/// dominance information was computed (caller contract: function-scoped
/// guard/require requirements always pass one).
fn guard_executes_before(
    ir: &FunctionIR,
    seg: &str,
    trigger_block: BlockId,
    trigger_idx: usize,
    doms: Option<&DomSets>,
) -> bool {
    let mut sites: Vec<(BlockId, usize)> = Vec::new();
    for (&bid, block) in &ir.blocks {
        for (idx, instr) in block.instructions.iter().enumerate() {
            let name = match instr {
                Instruction::CallStatic { func, .. } => func,
                Instruction::CallVirtual { method, .. } => method,
                _ => continue,
            };
            if name.rsplit('.').next().unwrap_or(name) == seg {
                sites.push((bid, idx));
            }
        }
    }
    if sites.is_empty() {
        return false;
    }
    let Some(doms) = doms else {
        return true;
    };
    sites.iter().any(|&(gb, gi)| {
        if gb == trigger_block {
            gi < trigger_idx
        } else {
            doms.get(&trigger_block).is_some_and(|d| d.contains(&gb))
        }
    })
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
