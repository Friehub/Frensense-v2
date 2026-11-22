// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub

//! Pins the semantic differences between the two learned-check evaluators.
//!
//! `FRENSdbg_CHECKS` reports these at runtime. These fixtures state the
//! differences the debug output is expected to find, so a change to either
//! path fails here instead of silently changing the reported union.

use super::learned_divergence;
use crate::analysis::taint::facts::{FactTable, LearnedCheckFact};
use crate::checks::Provenance;
use crate::harness::lower_source;
use crate::ir::function::FunctionIR;

fn fact(call: &str, guard: Option<&str>) -> (LearnedCheckFact, Provenance) {
    (
        LearnedCheckFact {
            rule: "audit_rule".into(),
            call: call.into(),
            message: "message".into(),
            severity: "warning".into(),
            unless_guard: guard.map(str::to_string),
            unless_range_check: None,
        },
        Provenance::Learned,
    )
}

/// A qualified fact (`payments.runTool`) matches a bare `runTool` only on
/// the legacy path: `learned_checks_for` compares last segments, while
/// `policy::callee_matches` requires the qualified spelling.
#[test]
fn qualified_fact_matches_bare_call_only_on_legacy_path() {
    let src = r#"
declare function runTool(x: string): void;
export function handler(cmd: string) { runTool(cmd) }
"#;
    let fns = lower_source("t.ts", src, "ts").unwrap();
    let irs: Vec<&FunctionIR> = fns.values().collect();
    let mut facts = FactTable::default();
    facts.learned_checks.push(fact("payments.runTool", None));

    let (legacy_only, policy_only) = learned_divergence(&irs, &facts, None);

    let legacy_keys: Vec<(&str, &str)> = legacy_only
        .iter()
        .map(|(function, rule, _)| (function.as_str(), rule.as_str()))
        .collect();
    assert_eq!(
        legacy_keys,
        vec![("handler", "audit_rule")],
        "legacy path must report the bare call"
    );
    assert!(
        policy_only.is_empty(),
        "policy path must not match a qualified fact on a bare call: {policy_only:?}"
    );
}

/// A guard on one branch is "present anywhere" to the legacy path but does
/// not dominate the trigger, so only the policy path reports the violation.
#[test]
fn non_dominating_guard_is_reported_only_on_policy_path() {
    let src = r#"
declare function runTool(x: string): void;
declare function checkPermission(x: string): void;
export function handler(cmd: string, audit: boolean) {
  if (audit) { checkPermission(cmd) }
  runTool(cmd)
}
"#;
    let fns = lower_source("t.ts", src, "ts").unwrap();
    let irs: Vec<&FunctionIR> = fns.values().collect();
    let mut facts = FactTable::default();
    facts
        .learned_checks
        .push(fact("runTool", Some("checkPermission")));

    let (legacy_only, policy_only) = learned_divergence(&irs, &facts, None);

    assert!(
        legacy_only.is_empty(),
        "legacy path suppresses on any guard call: {legacy_only:?}"
    );
    let policy_keys: Vec<(&str, &str)> = policy_only
        .iter()
        .map(|(function, rule, _)| (function.as_str(), rule.as_str()))
        .collect();
    assert_eq!(
        policy_keys,
        vec![("handler", "audit_rule")],
        "policy path must require the guard to dominate the trigger"
    );
}
