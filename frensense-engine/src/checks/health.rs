// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Structural health: functions whose control flow has outgrown review.
//!
//! This is the first "algorithm class" check that is not a security proof:
//! it measures the lowered IR instead of matching vocabulary, so it needs
//! no library or framework names and works for every language the
//! providers lower. Findings are `Hygiene` tier (see
//! `frensense_lang::severity::checker_rule_tier`), which keeps them out of
//! the default and recommended profiles.
//!
//! Metric: McCabe cyclomatic complexity over the IR control-flow graph,
//! `1 + (two-way branches) + (switch arms)`. Straight-line code and
//! unconditional jumps add nothing, so the number is stable across
//! providers that lower the same source differently.

use crate::checks::{CheckerFinding, Provenance};
use crate::ir::function::{FunctionIR, Terminator};

/// Rule id emitted by this check.
pub const FUNCTION_COMPLEXITY: &str = "function_complexity";

/// Complexity above which a function is reported. 25 is deliberately high:
/// the first goal is to surface the outliers, not to police every
/// function.
pub const MAX_COMPLEXITY: usize = 25;

/// Cyclomatic complexity of one lowered function.
pub fn cyclomatic_complexity(ir: &FunctionIR) -> usize {
    let decisions: usize = ir
        .blocks
        .values()
        .map(|b| match &b.terminator {
            Terminator::Branch { .. } => 1,
            Terminator::Switch { cases, .. } => cases.len(),
            _ => 0,
        })
        .sum();
    1 + decisions
}

/// Number of IR instructions, a size proxy that is independent of
/// formatting.
pub fn instruction_count(ir: &FunctionIR) -> usize {
    ir.blocks.values().map(|b| b.instructions.len()).sum()
}

/// Report `ir` when its complexity exceeds `max`.
pub fn check_with_limit(ir: &FunctionIR, max: usize) -> Vec<CheckerFinding> {
    let complexity = cyclomatic_complexity(ir);
    if complexity <= max {
        return Vec::new();
    }
    // Anchor at the earliest known source byte of the function so the
    // advisory lands at the top of the body.
    let span = ir
        .var_metadata
        .values()
        .filter_map(|m| m.byte_range)
        .min_by_key(|r| r.0);
    vec![CheckerFinding {
        provenance: Provenance::Spec,
        function: ir.name.clone(),
        rule: FUNCTION_COMPLEXITY.to_string(),
        message: String::new(),
        params: vec![
            ("complexity", complexity.to_string()),
            ("limit", max.to_string()),
            ("ops", instruction_count(ir).to_string()),
        ],
        span,
        severity: "low".to_string(),
    }]
}

/// Default-threshold entry point used by the registry.
pub fn check(ir: &FunctionIR) -> Vec<CheckerFinding> {
    check_with_limit(ir, MAX_COMPLEXITY)
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
