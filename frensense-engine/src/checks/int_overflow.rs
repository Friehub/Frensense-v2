// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Integer overflow in allocation-size arithmetic (CWE-190 -> CWE-680):
//! `malloc(count * elem_size)` where the multiplication can wrap past the
//! platform's allocation-size limit yields an undersized buffer that the
//! subsequent fill overruns. Modeled on the 2026 CVE class (llama.cpp
//! CVE-2026-27940, Perl CVE-2026-8376, glibc CVE-2026-0861).
//!
//! Built-in = how to look; learned = what to conclude: the prover below is
//! the stable, language-agnostic "how" (provable ranges, wrap threshold,
//! allocation-capacity provenance). Which rule fires - id, threshold, and
//! advisory - comes from the rule table: the lang bootstrap seed unioned
//! with `FactTable::integer_overflow_rules`, which a corpus bundle extends
//! from a family's `[frensense] check-rule:` declaration
//! (`LearnedFactEntry::IntegerOverflowRule`). New rules of this class are
//! corpus-only; the engine does not change.
//!
//! Zero-FP by construction:
//! - Both operand intervals must be provable and non-negative at the
//!   multiplication's block (guards narrow via branch sharpening;
//!   unknown operands skip the site).
//! - The product corner (computed in `i128`, never wrapped) must exceed
//!   the rule's wrap threshold (u64::MAX == SIZE_MAX on LP64/LLP64).
//! - The product must flow into an allocation's capacity argument, whose
//!   index comes from the lang-declared capacity spec. `calloc`-style
//!   `ParamProduct` allocators multiply internally and are excluded, as
//!   are deallocations (no capacity spec).

use rustc_hash::FxHashSet;

use crate::analysis::taint::facts::FactTable;
use crate::analysis::value::{self, ValueInfo};
use crate::checks::CheckerFinding;
use crate::checks::Provenance;
use crate::checks::memory_summary::{CapacitySpec, MemorySummaryRegistry};
use crate::ir::function::{BlockId, FunctionIR, Instruction, Operand, VarId};

fn last_segment(call: &str) -> &str {
    let s = call.rsplit('.').next().unwrap_or(call);
    s.rsplit("::").next().unwrap_or(s)
}

/// Evaluate an operand's inclusive integer interval at a block entry,
/// mirroring the spatial checker's range lookup (block-entry sharpened
/// state first, then the merged per-definition value).
fn range_of(op: &Operand, block: BlockId, val_info: &ValueInfo) -> Option<(i64, i64)> {
    match op {
        Operand::IntLiteral(k) => Some((*k, *k)),
        Operand::Var(v) => {
            if let Some(r) = val_info.range_at(block, *v) {
                return Some(r);
            }
            if let Some(c) = val_info.const_int_at(block, *v) {
                return Some((c, c));
            }
            if let Some(r) = val_info.range(*v) {
                return Some(r);
            }
            val_info.const_int(*v).map(|c| (c, c))
        }
        _ => None,
    }
}

/// Argument index carrying a single caller-computed capacity for `func`,
/// when the callee allocates fresh memory whose size is that argument.
/// Capacity shapes come from the lang-declared vocabulary: `Param(i)` is
/// the caller-computed size; `ParamProduct` multiplies internally
/// (calloc-style, overflow-checked there); `Exact`/`Unknown` have no
/// caller size expression. Non-allocators (no fresh return) yield `None`.
fn alloc_capacity_arg(func: &str, summaries: &MemorySummaryRegistry) -> Option<usize> {
    match summaries.return_capacity(func)? {
        CapacitySpec::Param(i) => Some(*i),
        CapacitySpec::ParamProduct(..) | CapacitySpec::Exact(_) | CapacitySpec::Unknown => None,
    }
}

/// Forward closure of `start` through value-preserving copies
/// (`Assign`/`Cast`), then check whether any copy reaches an allocation
/// call's capacity argument. Returns the allocator's name when it does.
fn flows_into_alloc_capacity(
    ir: &FunctionIR,
    start: VarId,
    summaries: &MemorySummaryRegistry,
) -> Option<String> {
    let mut set: FxHashSet<VarId> = FxHashSet::default();
    set.insert(start);
    loop {
        let mut grew = false;
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let flow = match instr {
                    Instruction::Assign {
                        dest,
                        src: Operand::Var(v),
                    }
                    | Instruction::Cast {
                        dest,
                        src: Operand::Var(v),
                        ..
                    } => Some((*dest, *v)),
                    _ => None,
                };
                if let Some((dest, v)) = flow {
                    grew |= set.contains(&v) && set.insert(dest);
                }
            }
        }
        if !grew {
            break;
        }
    }
    for block in ir.blocks.values() {
        for instr in &block.instructions {
            if let Instruction::CallStatic { func, args, .. } = instr
                && let Some(idx) = alloc_capacity_arg(func, summaries)
                && let Some(Operand::Var(v)) = args.get(idx)
                && set.contains(v)
            {
                return Some(last_segment(func).to_string());
            }
        }
    }
    None
}

fn var_name(ir: &FunctionIR, var: VarId) -> String {
    ir.var_metadata
        .get(&var)
        .and_then(|m| m.source_name.clone())
        .unwrap_or_else(|| format!("v{}", var.0))
}

fn var_span(ir: &FunctionIR, var: VarId) -> Option<(usize, usize)> {
    ir.var_metadata.get(&var).and_then(|m| m.byte_range)
}

fn operand_label(ir: &FunctionIR, op: &Operand) -> String {
    match op {
        Operand::Var(v) => var_name(ir, *v),
        Operand::IntLiteral(k) => k.to_string(),
        other => format!("{:?}", other),
    }
}

/// Run the allocation-size integer overflow check over one function for
/// every active rule: the lang bootstrap seed unioned with the corpus
/// (bundle-) extended rule table, deduplicated by id + threshold.
pub fn check(
    ir: &FunctionIR,
    summaries: &MemorySummaryRegistry,
    facts: &FactTable,
) -> Vec<CheckerFinding> {
    let val_info = value::analyze(ir);
    let mut out = Vec::new();
    let mut seen: FxHashSet<(String, u128)> = FxHashSet::default();
    for (rule, provenance) in frensense_lang::policy::bootstrap_integer_overflow_rules()
        .iter()
        .map(|r| (r, Provenance::Spec))
        .chain(
            facts
                .integer_overflow_rules
                .iter()
                .map(|r| (r, Provenance::Learned)),
        )
    {
        if !seen.insert((rule.rule_id.clone(), rule.wrap_threshold)) {
            continue;
        }
        check_rule(ir, &val_info, summaries, rule, provenance, &mut out);
    }
    out
}

/// The prover for one rule: find wrap-capable size multiplications whose
/// product flows into an allocation capacity argument.
fn check_rule(
    ir: &FunctionIR,
    val_info: &ValueInfo,
    summaries: &MemorySummaryRegistry,
    rule: &frensense_lang::policy::IntegerOverflowRule,
    provenance: Provenance,
    out: &mut Vec<CheckerFinding>,
) {
    let threshold = i128::try_from(rule.wrap_threshold).unwrap_or(i128::MAX);
    for (bid, block) in &ir.blocks {
        for instr in &block.instructions {
            let Instruction::BinaryOp { dest, op, lhs, rhs } = instr else {
                continue;
            };
            if op != "*" {
                continue;
            }
            let (Some((al, ah)), Some((bl, bh))) =
                (range_of(lhs, *bid, val_info), range_of(rhs, *bid, val_info))
            else {
                continue;
            };
            // Only non-negative sizes participate (signed/unknown ranges skip).
            if al < 0 || bl < 0 {
                continue;
            }
            let corners = [
                i128::from(al) * i128::from(bl),
                i128::from(al) * i128::from(bh),
                i128::from(ah) * i128::from(bl),
                i128::from(ah) * i128::from(bh),
            ];
            let max_corner = corners.iter().max().copied().unwrap_or(0);
            if max_corner <= threshold {
                continue;
            }
            let Some(allocator) = flows_into_alloc_capacity(ir, *dest, summaries) else {
                continue;
            };
            out.push(CheckerFinding {
                provenance,
                function: ir.name.clone(),
                rule: rule.rule_id.clone(),
                severity: rule.severity.clone(),
                message: format!(
                    "{}: `{}` ({}..{}) * `{}` ({}..{}) can wrap past {}, \
                     undersizing the `{}` result",
                    rule.message,
                    operand_label(ir, lhs),
                    al,
                    ah,
                    operand_label(ir, rhs),
                    bl,
                    bh,
                    rule.wrap_threshold,
                    allocator,
                ),
                span: var_span(ir, *dest).or_else(|| match lhs {
                    Operand::Var(v) => var_span(ir, *v),
                    _ => None,
                }),
            });
        }
    }
}
