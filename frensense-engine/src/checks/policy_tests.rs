// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for co-occurrence policy checks (`PolicyFact`), including the
//! lossless legacy-`LearnedCheckFact` conversion path.

#[cfg(test)]
pub mod policy_spec {
    use crate::analysis::taint::facts::{
        FactTable, LearnedCheckFact, LearnedFactEntry, PolicyFact, PolicyRequirement, PolicyScope,
    };
    use crate::checks::policy;
    use crate::harness::lower_source;

    fn lower(src: &str) -> Vec<&'static FunctionIR> {
        let fns = lower_source("t.ts", src, "ts").unwrap();
        // Leak into static refs: check_program borrows IRs for its lifetime.
        fns.into_values()
            .map(|ir| -> &'static FunctionIR { Box::leak(Box::new(ir)) })
            .collect()
    }

    use crate::ir::function::FunctionIR;

    fn legacy(guard: Option<&str>, range: Option<Vec<&str>>) -> LearnedCheckFact {
        LearnedCheckFact {
            rule: "policy_run_tool".into(),
            call: "runTool".into(),
            message: "tool executed without policy check".into(),
            severity: "warning".into(),
            unless_guard: guard.map(|g| g.to_string()),
            unless_range_check: range.map(|r| r.into_iter().map(String::from).collect()),
        }
    }

    /// The privileged-tool shape: `runTool` present without the
    /// `checkPermission` helper = violation (positive); with it = compliant.
    const POSITIVE: &str = r#"
export function handler (cmd: string) {
  return runTool(cmd)
}
"#;
    const NEGATIVE: &str = r#"
export function handler (cmd: string) {
  if (!checkPermission(cmd)) return null
  return runTool(cmd)
}
"#;

    #[test]
    fn legacy_guard_check_fires_on_positive() {
        let mut facts = FactTable::default();
        facts
            .learned_checks
            .push(legacy(Some("checkPermission"), None));
        let irs = lower(POSITIVE);
        let hits = policy::check_program(&irs, &facts);
        assert_eq!(hits.len(), 1, "positive must fire: {:?}", hits);
        assert_eq!(hits[0].rule, "policy_run_tool");
    }

    #[test]
    fn legacy_guard_check_stays_silent_on_negative() {
        let mut facts = FactTable::default();
        facts
            .learned_checks
            .push(legacy(Some("checkPermission"), None));
        let irs = lower(NEGATIVE);
        let hits = policy::check_program(&irs, &facts);
        assert!(
            hits.is_empty(),
            "guarded negative must stay silent: {:?}",
            hits
        );
    }

    /// The same rule expressed as a native PolicyFact must fire/suppress
    /// identically: `from_legacy` is the lossless inverse.
    #[test]
    fn native_policy_matches_legacy_semantics() {
        let mut facts = FactTable::default();
        facts.policy_facts.push(PolicyFact {
            rule: "policy_run_tool".into(),
            when_call: "runTool".into(),
            require: vec![PolicyRequirement::GuardCall {
                call: "checkPermission".into(),
            }],
            scope: PolicyScope::Function,
            message: "tool executed without policy check".into(),
            severity: "warning".into(),
        });
        let pos = policy::check_program(&lower(POSITIVE), &facts);
        let neg = policy::check_program(&lower(NEGATIVE), &facts);
        assert_eq!(pos.len(), 1, "native positive must fire: {:?}", pos);
        assert!(
            neg.is_empty(),
            "native negative must stay silent: {:?}",
            neg
        );
    }

    /// Shipping BOTH shapes of the same rule must not double-fire.
    #[test]
    fn legacy_suppressed_when_native_policy_exists() {
        let mut facts = FactTable::default();
        facts.policy_facts.push(PolicyFact {
            rule: "policy_run_tool".into(),
            when_call: "runTool".into(),
            require: vec![PolicyRequirement::GuardCall {
                call: "checkPermission".into(),
            }],
            scope: PolicyScope::Function,
            message: "tool executed without policy check".into(),
            severity: "warning".into(),
        });
        facts
            .learned_checks
            .push(legacy(Some("checkPermission"), None));
        let hits = policy::check_program(&lower(POSITIVE), &facts);
        assert_eq!(
            hits.len(),
            1,
            "same rule in both shapes must fire once: {:?}",
            hits
        );
    }

    /// RequireCall: an audit-log write must accompany the privileged call.
    #[test]
    fn require_call_policy() {
        let with_log = r#"
export function handler (cmd: string) {
  audit.log(cmd)
  return runTool(cmd)
}
"#;
        let without_log = r#"
export function handler (cmd: string) {
  return runTool(cmd)
}
"#;
        let mut facts = FactTable::default();
        facts.policy_facts.push(PolicyFact {
            rule: "policy_run_tool_audited".into(),
            when_call: "runTool".into(),
            require: vec![PolicyRequirement::RequireCall {
                any_of: vec!["audit.log".into(), "auditLog".into()],
            }],
            scope: PolicyScope::Function,
            message: "privileged tool call without audit log".into(),
            severity: "warning".into(),
        });
        let hits_no = policy::check_program(&lower(without_log), &facts);
        assert_eq!(hits_no.len(), 1, "unaudited call must fire: {:?}", hits_no);
        let hits_with = policy::check_program(&lower(with_log), &facts);
        assert!(
            hits_with.is_empty(),
            "audited call must stay silent: {:?}",
            hits_with
        );
    }

    /// NotCall: a token-echo trigger must not co-occur with console.log.
    #[test]
    fn not_call_policy() {
        let clean = r#"
export function handler (t: string) {
  return renderToken(t)
}
"#;
        let dirty = r#"
export function handler (t: string) {
  console.log(t)
  return renderToken(t)
}
"#;
        let mut facts = FactTable::default();
        facts.policy_facts.push(PolicyFact {
            rule: "policy_no_token_echo".into(),
            when_call: "renderToken".into(),
            require: vec![PolicyRequirement::NotCall {
                call: "console.log".into(),
            }],
            scope: PolicyScope::Function,
            message: "token echoed to console".into(),
            severity: "critical".into(),
        });
        let hits_clean = policy::check_program(&lower(clean), &facts);
        assert!(hits_clean.is_empty());
        let hits_dirty = policy::check_program(&lower(dirty), &facts);
        assert_eq!(
            hits_dirty.len(),
            1,
            "echoing fn must fire: {:?}",
            hits_dirty
        );
    }

    /// Module scope: the enforcement helper lives in ANOTHER function of the
    /// scanned set; function scope must fire, module scope must stay silent.
    #[test]
    fn module_scope_sees_sibling_enforcement() {
        let split_pos = r#"
export function handler (cmd: string) {
  return runTool(cmd)
}
export function checkPermission (cmd: string) {
  return cmd.length > 0
}
"#;
        let mut facts_fn = FactTable::default();
        facts_fn.policy_facts.push(PolicyFact {
            rule: "policy_run_tool".into(),
            when_call: "runTool".into(),
            require: vec![PolicyRequirement::GuardCall {
                call: "checkPermission".into(),
            }],
            scope: PolicyScope::Function,
            message: "tool executed without policy check".into(),
            severity: "warning".into(),
        });
        let irs = lower(split_pos);
        let hits_fn = policy::check_program(&irs, &facts_fn);
        assert_eq!(
            hits_fn.len(),
            1,
            "function scope cannot see the sibling helper: {:?}",
            hits_fn
        );

        let mut facts_mod = FactTable::default();
        facts_mod.policy_facts.push(PolicyFact {
            rule: "policy_run_tool".into(),
            when_call: "runTool".into(),
            require: vec![PolicyRequirement::GuardCall {
                call: "checkPermission".into(),
            }],
            scope: PolicyScope::Module,
            message: "tool executed without policy check".into(),
            severity: "warning".into(),
        });
        let hits_mod = policy::check_program(&irs, &facts_mod);
        assert!(
            hits_mod.is_empty(),
            "module scope must credit the sibling helper: {:?}",
            hits_mod
        );
    }

    /// Bundle round-trip: a Policy entry decodes through LearnedFactEntry
    /// and lands in the fact table.
    #[test]
    fn bundle_entry_applies_to_table() {
        let mut table = FactTable::default();
        LearnedFactEntry::Policy {
            rule: "policy_run_tool".into(),
            when_call: "runTool".into(),
            require: vec![PolicyRequirement::GuardCall {
                call: "checkPermission".into(),
            }],
            scope: PolicyScope::Module,
            message: "m".into(),
            severity: "warning".into(),
        }
        .apply(&mut table);
        assert_eq!(table.policy_facts.len(), 1);
        LearnedFactEntry::Policy {
            rule: "policy_run_tool".into(),
            when_call: "runTool".into(),
            require: vec![],
            scope: PolicyScope::Function,
            message: "m".into(),
            severity: "warning".into(),
        }
        .apply(&mut table);
        assert_eq!(table.policy_facts.len(), 1, "dedup on (rule, when_call)");
    }

    /// Positive & negative test for PolicyRequirement::BannedArgLiteral.
    #[test]
    fn policy_banned_arg_literal_positive_and_negative() {
        let mut facts = FactTable::default();
        facts.policy_facts.push(PolicyFact {
            rule: "policy_banned_insecure_transport".into(),
            when_call: "initConnection".into(),
            require: vec![PolicyRequirement::BannedArgLiteral {
                slot: 1,
                values: vec!["false".into(), "insecure".into()],
            }],
            scope: PolicyScope::Function,
            message: "Insecure transport option used".into(),
            severity: "critical".into(),
        });

        // Positive sample: slot 1 is banned literal "false"
        let pos_src = r#"
export function connectClient (host: string) {
  return initConnection(host, false);
}
"#;
        let hits_pos = policy::check_program(&lower(pos_src), &facts);
        assert_eq!(hits_pos.len(), 1, "banned arg literal must fire on positive sample");
        assert_eq!(hits_pos[0].rule, "policy_banned_insecure_transport");

        // Negative sample: slot 1 is safe literal "true"
        let neg_src = r#"
export function connectClient (host: string) {
  return initConnection(host, true);
}
"#;
        let hits_neg = policy::check_program(&lower(neg_src), &facts);
        assert!(hits_neg.is_empty(), "safe arg literal must stay silent on negative sample");
    }

    /// Positive & negative test for PolicyRequirement::RequiredArgLiteral.
    #[test]
    fn policy_required_arg_literal_positive_and_negative() {
        let mut facts = FactTable::default();
        facts.policy_facts.push(PolicyFact {
            rule: "policy_require_secure_algorithm".into(),
            when_call: "signToken".into(),
            require: vec![PolicyRequirement::RequiredArgLiteral {
                slot: 2,
                values: vec!["RS256".into(), "ES256".into()],
            }],
            scope: PolicyScope::Function,
            message: "Must use approved asymmetric signature algorithm".into(),
            severity: "critical".into(),
        });

        // Positive sample: slot 2 uses unapproved algorithm "HS256"
        let pos_src = r#"
export function generateToken (payload: string, key: string) {
  return signToken(payload, key, "HS256");
}
"#;
        let hits_pos = policy::check_program(&lower(pos_src), &facts);
        assert_eq!(hits_pos.len(), 1, "unapproved arg literal must violate required arg policy");
        assert_eq!(hits_pos[0].rule, "policy_require_secure_algorithm");

        // Negative sample: slot 2 uses approved algorithm "RS256"
        let neg_src = r#"
export function generateToken (payload: string, key: string) {
  return signToken(payload, key, "RS256");
}
"#;
        let hits_neg = policy::check_program(&lower(neg_src), &facts);
        assert!(hits_neg.is_empty(), "approved required literal must stay silent on negative sample");
    }
}
