// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for co-occurrence policy checks (`PolicyFact`), including the
//! lossless legacy-`LearnedCheckFact` conversion path.

#[cfg(test)]
pub mod policy_spec {
    use crate::analysis::taint::facts::{
        FactTable, LearnedCheckFact, LearnedFactEntry, PolicyFact, PolicyRequirement, PolicyScope,
        Provenance,
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
            .push((legacy(Some("checkPermission"), None), Provenance::Learned));
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
            .push((legacy(Some("checkPermission"), None), Provenance::Learned));
        let irs = lower(NEGATIVE);
        let hits = policy::check_program(&irs, &facts);
        assert!(
            hits.is_empty(),
            "guarded negative must stay silent: {:?}",
            hits
        );
    }

    /// Rust path-qualified trigger calls (`storage::ops::wipe_volume`)
    /// match the bare callable the corpus taught (`wipe_volume`): the
    /// learned-check matching reduces every callee through `.` and `::`
    /// separators, the same mechanism-first rule the sink vocabulary uses.
    /// The bare-statement guard still suppresses when scanning — the
    /// dominance check only requires the guard to execute before the
    /// trigger on every path.
    fn rust_lower(src: &str) -> Vec<&'static FunctionIR> {
        let fns = lower_source("t.rs", src, "rs").unwrap();
        fns.into_values()
            .map(|ir| -> &'static FunctionIR { Box::leak(Box::new(ir)) })
            .collect()
    }

    fn wipe_check_at(call: &str, guard: Option<&str>) -> LearnedCheckFact {
        LearnedCheckFact {
            rule: "policy_wipe_without_owner".into(),
            call: call.to_string(),
            message: format!("{call} executed without owner check"),
            severity: "high".into(),
            unless_guard: guard.map(|g| g.to_string()),
            unless_range_check: None,
        }
    }

    const RUST_QUALIFIED_POSITIVE: &str = r#"
pub fn wipe(vol: &Volume) {
    storage::ops::wipe_volume(vol);
}
"#;
    const RUST_QUALIFIED_NEGATIVE: &str = r#"
pub fn wipe(vol: &Volume) {
    ensure_owner(&vol);
    storage::ops::wipe_volume(vol);
}
"#;

    /// Import-aliased Python trigger (`from billing import issue_refund as
    /// refund`): the call site is spelled with the local alias; the check
    /// taught at the shipped name must still fire on it.
    #[test]
    fn python_import_alias_trigger_matches_shipped_name() {
        use crate::checks::policy::PackageScope;
        use crate::graph::module::PackageImport;
        use rustc_hash::FxHashMap;

        let src = r#"
            from billing import issue_refund as refund

            def pay(amount):
                refund(amount)
            "#;
        let fns = lower_source("t.py", src, "py").unwrap();
        let irs: Vec<&'static FunctionIR> = fns
            .into_values()
            .map(|ir| -> &'static FunctionIR { Box::leak(Box::new(ir)) })
            .collect();
        let mut facts = FactTable::default();
        facts
            .learned_checks
            .push((wipe_check_at("issue_refund", None), Provenance::Learned));

        let mut fn_file = FxHashMap::default();
        fn_file.insert("pay".to_string(), "t.py".to_string());
        let mut imports = FxHashMap::default();
        imports.insert(
            "refund".to_string(),
            PackageImport {
                package: "billing".to_string(),
                symbol: Some("issue_refund".to_string()),
            },
        );
        let mut file_package_imports = FxHashMap::default();
        file_package_imports.insert("t.py".to_string(), imports);
        let scope = PackageScope {
            fn_file: &fn_file,
            file_package_imports: &file_package_imports,
        };

        let hits = policy::check_program_scoped(&irs, &facts, Some(&scope));
        assert_eq!(
            hits.len(),
            1,
            "alias-triggering call must match the taught shipped name: {:?}",
            hits
        );
        assert_eq!(hits[0].rule, "policy_wipe_without_owner");
    }

    #[test]
    fn rust_path_qualified_trigger_matches_bare_vocabulary() {
        let mut facts = FactTable::default();
        facts.learned_checks.push((
            wipe_check_at("wipe_volume", Some("ensure_owner")),
            Provenance::Learned,
        ));

        let irs = rust_lower(RUST_QUALIFIED_POSITIVE);
        let hits = policy::check_program(&irs, &facts);
        assert_eq!(
            hits.len(),
            1,
            "qualified unguarded trigger must fire: {:?}",
            hits
        );
        assert_eq!(hits[0].rule, "policy_wipe_without_owner");

        let irs = rust_lower(RUST_QUALIFIED_NEGATIVE);
        let hits = policy::check_program(&irs, &facts);
        assert!(
            hits.is_empty(),
            "qualified trigger behind an executing guard must stay silent: {:?}",
            hits
        );
    }

    /// Full-callee qualification: a policy taught at a member path
    /// (`payments.issue_refund`) matches trigger sites through their
    /// written callee path, so an unrelated object sharing the bare verb
    /// (`billing.issue_refund`) no longer fires. Bare-taught facts keep
    /// matching through the last segment. The qualified guard name
    /// (`user.can`) likewise matches its member-call sites.
    #[test]
    fn qualified_trigger_is_path_aware_bare_stays_verb_aware() {
        let qualified = |guards: Option<Vec<&str>>| -> PolicyFact {
            PolicyFact {
                package: None,
                rule: "policy_qualified_refund".into(),
                when_call: "payments.issue_refund".into(),
                require: guards
                    .map(|gs| vec![PolicyRequirement::GuardCall { call: gs[0].into() }])
                    .unwrap_or_default(),
                scope: PolicyScope::Function,
                message: "refund requires finance authorization".into(),
                severity: "high".into(),
            }
        };
        let mut facts = FactTable::default();
        facts
            .policy_facts
            .push((qualified(None), Provenance::Learned));

        const PY_MATCHED_PATH: &str = r#"
def pay(user, amount):
    payments.issue_refund(amount)
"#;
        const PY_OTHER_OBJECT: &str = r#"
def pay(user, amount):
    billing.issue_refund(amount)
"#;
        const PY_METHOD_OWNER: &str = r#"
def pay(self, amount):
    self.payments.issue_refund(amount)
"#;
        // Unguarded on the taught path: fires.
        let hits = policy::check_program(&py_lower(PY_MATCHED_PATH), &facts);
        assert_eq!(hits.len(), 1, "taught path, unguarded: {:?}", hits);
        // Bare fact semantics do not widen a qualified fact: the same
        // verb on a different object is NOT the taught trigger.
        let hits = policy::check_program(&py_lower(PY_OTHER_OBJECT), &facts);
        assert!(
            hits.is_empty(),
            "qualified fact must not collide on another object's verb: {:?}",
            hits
        );
        // A deeper owner of the same member stimulates through the
        // dotted-tail (`self.payments.issue_refund`).
        let hits = policy::check_program(&py_lower(PY_METHOD_OWNER), &facts);
        assert_eq!(
            hits.len(),
            1,
            "dotted-tail owner of the taught member still fires: {:?}",
            hits
        );

        // Qualified guard: `user.can` matches only its member-call sites.
        facts.policy_facts.clear();
        facts
            .policy_facts
            .push((qualified(Some(vec!["user.can"])), Provenance::Learned));

        const PY_MEMBER_GUARDED: &str = r#"
def pay(user, amount):
    if not user.can("refunds"):
        return
    payments.issue_refund(amount)
"#;
        const PY_BARE_GUARD: &str = r#"
def pay(user, amount):
    if not can("refunds"):
        return
    payments.issue_refund(amount)
"#;
        let hits = policy::check_program(&py_lower(PY_MEMBER_GUARDED), &facts);
        assert!(
            hits.is_empty(),
            "qualified guard matches its member-call site: {:?}",
            hits
        );
        let hits = policy::check_program(&py_lower(PY_BARE_GUARD), &facts);
        assert_eq!(
            hits.len(),
            1,
            "a bare same-verb guard is not the qualified taught helper: {:?}",
            hits
        );
    }

    /// Guard synonyms, engine side (WI-13 remainder): a RequireCall
    /// `any_of` taught across family variants accepts every declared
    /// spelling before the trigger - including a member-qualified inline
    /// predicate (`user.can(...)`), which matches through its last
    /// segment on the same last-segment rule every guard comparison
    /// uses. Files guarded under an unrelated helper still fire.
    fn py_lower(src: &str) -> Vec<&'static FunctionIR> {
        let fns = lower_source("t.py", src, "py").unwrap();
        fns.into_values()
            .map(|ir| -> &'static FunctionIR { Box::leak(Box::new(ir)) })
            .collect()
    }

    #[test]
    fn guard_synonym_union_accepts_member_qualified_predicate() {
        let mut facts = FactTable::default();
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_issue_refund".into(),
                when_call: "issue_refund".into(),
                require: vec![PolicyRequirement::RequireCall {
                    any_of: vec!["require_finance_role".into(), "user.can".into()],
                }],
                scope: PolicyScope::Function,
                message: "refund requires finance authorization".into(),
                severity: "high".into(),
            },
            Provenance::Learned,
        ));

        const PY_MEMBER_GUARDED: &str = r#"
def pay(user, amount):
    if not user.can("issue_refunds"):
        return
    payments.issue_refund(amount)
"#;
        const PY_UNRELATED_GUARD: &str = r#"
def pay(user, amount):
    audit_log(amount)
    payments.issue_refund(amount)
"#;
        const PY_UNGUARDED: &str = r#"
def pay(user, amount):
    payments.issue_refund(amount)
"#;

        let hits = policy::check_program(&py_lower(PY_MEMBER_GUARDED), &facts);
        assert!(
            hits.is_empty(),
            "member-qualified declared synonym guard suppresses: {:?}",
            hits
        );
        let hits = policy::check_program(&py_lower(PY_UNRELATED_GUARD), &facts);
        assert_eq!(
            hits.len(),
            1,
            "an unrelated helper is not one of the taught guards: {:?}",
            hits
        );
        let hits = policy::check_program(&py_lower(PY_UNGUARDED), &facts);
        assert_eq!(hits.len(), 1, "unguarded trigger fires: {:?}", hits);
    }

    /// Decorator-as-guard: a definition decorated with the taught helper
    /// (`@ensure_owner`) enforces before ANY statement of the body, so a
    /// trigger inside it is guarded with no guard call present - the
    /// caller-side enforcement shape that otherwise fires as a false
    /// positive (WI-08).
    #[test]
    fn decorator_guard_suppresses_policy_finding() {
        const PY_DECORATED_TRIGGER: &str = r#"
@ensure_owner
def wipe(vol):
    ops.wipe_volume(vol)
"#;
        const PY_UNDECORATED_TRIGGER: &str = r#"
def wipe(vol):
    ops.wipe_volume(vol)
"#;
        let mut facts = FactTable::default();
        facts.learned_checks.push((
            wipe_check_at("wipe_volume", Some("ensure_owner")),
            Provenance::Learned,
        ));

        let fns = lower_source("t.py", PY_DECORATED_TRIGGER, "py").unwrap();
        let irs: Vec<&'static FunctionIR> = fns
            .into_values()
            .map(|ir| -> &'static FunctionIR { Box::leak(Box::new(ir)) })
            .collect();
        let hits = policy::check_program(&irs, &facts);
        assert!(
            hits.is_empty(),
            "decorated definition is an entry guard that dominates every statement: {:?}",
            hits
        );

        let fns = lower_source("t.py", PY_UNDECORATED_TRIGGER, "py").unwrap();
        let irs: Vec<&'static FunctionIR> = fns
            .into_values()
            .map(|ir| -> &'static FunctionIR { Box::leak(Box::new(ir)) })
            .collect();
        let hits = policy::check_program(&irs, &facts);
        assert_eq!(
            hits.len(),
            1,
            "undecorated trigger must still fire: {:?}",
            hits
        );
        assert_eq!(hits[0].rule, "policy_wipe_without_owner");
    }

    /// The same rule expressed as a native PolicyFact must fire/suppress
    /// identically: `from_legacy` is the lossless inverse.
    #[test]
    fn native_policy_matches_legacy_semantics() {
        let mut facts = FactTable::default();
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::GuardCall {
                    call: "checkPermission".into(),
                }],
                scope: PolicyScope::Function,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
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
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::GuardCall {
                    call: "checkPermission".into(),
                }],
                scope: PolicyScope::Function,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
        facts
            .learned_checks
            .push((legacy(Some("checkPermission"), None), Provenance::Learned));
        let hits = policy::check_program(&lower(POSITIVE), &facts);
        assert_eq!(
            hits.len(),
            1,
            "same rule in both shapes must fire once: {:?}",
            hits
        );
    }

    /// Function-scope enforcement is SPATIAL: a guard call that runs only
    /// on one branch does not dominate the trigger, so it enforces nothing
    /// and the policy must still fire.
    #[test]
    fn non_dominating_guard_still_fires() {
        let src = r#"
export function handler (cmd: string, doAudit: boolean) {
  if (doAudit) {
    checkPermission(cmd)
  }
  return runTool(cmd)
}
"#;
        let mut facts = FactTable::default();
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::GuardCall {
                    call: "checkPermission".into(),
                }],
                scope: PolicyScope::Function,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
        let hits = policy::check_program(&lower(src), &facts);
        assert_eq!(
            hits.len(),
            1,
            "conditional guard cannot enforce the trigger: {:?}",
            hits
        );
    }

    /// Same block, guard AFTER the trigger: the check runs after the
    /// privileged call, too late to enforce it - must fire.
    #[test]
    fn guard_after_trigger_in_same_block_fires() {
        let src = r#"
export function handler (cmd: string) {
  runTool(cmd)
  checkPermission(cmd)
}
"#;
        let mut facts = FactTable::default();
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::GuardCall {
                    call: "checkPermission".into(),
                }],
                scope: PolicyScope::Function,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
        let hits = policy::check_program(&lower(src), &facts);
        assert_eq!(
            hits.len(),
            1,
            "guard executing after the trigger enforces nothing: {:?}",
            hits
        );
    }

    /// Regression: `const r = runTool(cmd)` nested in a handler must not be
    /// re-extracted by the harness as a phantom top-level function - that
    /// produced a second, spurious policy hit attributed to a function that
    /// exists nowhere in the source.
    #[test]
    fn nested_const_call_fires_policy_exactly_once() {
        let src = r#"
export function handler (cmd: string) {
  const r = runTool(cmd)
  return r
}
"#;
        let mut facts = FactTable::default();
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::GuardCall {
                    call: "checkPermission".into(),
                }],
                scope: PolicyScope::Function,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
        let hits = policy::check_program(&lower(src), &facts);
        assert_eq!(
            hits.len(),
            1,
            "nested const must not double-fire policy: {:?}",
            hits
        );
        assert_eq!(hits[0].function, "handler");
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
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_run_tool_audited".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::RequireCall {
                    any_of: vec!["audit.log".into(), "auditLog".into()],
                }],
                scope: PolicyScope::Function,
                message: "privileged tool call without audit log".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
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
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_no_token_echo".into(),
                when_call: "renderToken".into(),
                require: vec![PolicyRequirement::NotCall {
                    call: "console.log".into(),
                }],
                scope: PolicyScope::Function,
                message: "token echoed to console".into(),
                severity: "critical".into(),
            },
            Provenance::Learned,
        ));
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
        facts_fn.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::GuardCall {
                    call: "checkPermission".into(),
                }],
                scope: PolicyScope::Function,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
        let irs = lower(split_pos);
        let hits_fn = policy::check_program(&irs, &facts_fn);
        assert_eq!(
            hits_fn.len(),
            1,
            "function scope cannot see the sibling helper: {:?}",
            hits_fn
        );

        let mut facts_mod = FactTable::default();
        facts_mod.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::GuardCall {
                    call: "checkPermission".into(),
                }],
                scope: PolicyScope::Module,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
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
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_banned_insecure_transport".into(),
                when_call: "initConnection".into(),
                require: vec![PolicyRequirement::BannedArgLiteral {
                    slot: 1,
                    values: vec!["false".into(), "insecure".into()],
                }],
                scope: PolicyScope::Function,
                message: "Insecure transport option used".into(),
                severity: "critical".into(),
            },
            Provenance::Learned,
        ));

        // Positive sample: slot 1 is banned literal "false"
        let pos_src = r#"
export function connectClient (host: string) {
  return initConnection(host, false);
}
"#;
        let hits_pos = policy::check_program(&lower(pos_src), &facts);
        assert_eq!(
            hits_pos.len(),
            1,
            "banned arg literal must fire on positive sample"
        );
        assert_eq!(hits_pos[0].rule, "policy_banned_insecure_transport");

        // Negative sample: slot 1 is safe literal "true"
        let neg_src = r#"
export function connectClient (host: string) {
  return initConnection(host, true);
}
"#;
        let hits_neg = policy::check_program(&lower(neg_src), &facts);
        assert!(
            hits_neg.is_empty(),
            "safe arg literal must stay silent on negative sample"
        );
    }

    /// Positive & negative test for PolicyRequirement::RequiredArgLiteral.
    #[test]
    fn policy_required_arg_literal_positive_and_negative() {
        let mut facts = FactTable::default();
        facts.policy_facts.push((
            PolicyFact {
                package: None,
                rule: "policy_require_secure_algorithm".into(),
                when_call: "signToken".into(),
                require: vec![PolicyRequirement::RequiredArgLiteral {
                    slot: 2,
                    values: vec!["RS256".into(), "ES256".into()],
                }],
                scope: PolicyScope::Function,
                message: "Must use approved asymmetric signature algorithm".into(),
                severity: "critical".into(),
            },
            Provenance::Learned,
        ));

        // Positive sample: slot 2 uses unapproved algorithm "HS256"
        let pos_src = r#"
export function generateToken (payload: string, key: string) {
  return signToken(payload, key, "HS256");
}
"#;
        let hits_pos = policy::check_program(&lower(pos_src), &facts);
        assert_eq!(
            hits_pos.len(),
            1,
            "unapproved arg literal must violate required arg policy"
        );
        assert_eq!(hits_pos[0].rule, "policy_require_secure_algorithm");

        // Negative sample: slot 2 uses approved algorithm "RS256"
        let neg_src = r#"
export function generateToken (payload: string, key: string) {
  return signToken(payload, key, "RS256");
}
"#;
        let hits_neg = policy::check_program(&lower(neg_src), &facts);
        assert!(
            hits_neg.is_empty(),
            "approved required literal must stay silent on negative sample"
        );
    }

    /// A presence-only policy (`require` empty) must ALERT whenever the
    /// trigger call occurs: the corpus twins proved the call site itself is
    /// the vulnerability - the negative avoids the call, it does not guard
    /// around it. Regression: rerouting legacy learned checks into the
    /// policy evaluator turned empty-require policies permanently silent.
    /// Also covers package-scoping end-to-end through [`crate::scan::scan`].
    #[test]
    fn presence_only_policy_alarms_on_trigger_and_respects_package_scope() {
        use crate::checks::Provenance as CheckProvenance;
        use crate::scan;
        let pos = concat!(
            "import jwt from 'jsonwebtoken';\n",
            "import type { Request, Response } from 'express';\n",
            "\n",
            "function authenticate(req: Request, res: Response) {\n",
            "  const token = req.headers.authorization?.split(' ')[1];\n",
            "  const payload = jwt.decode(token);\n",
            "  req.user = payload;\n",
            "}\n",
        );
        let neg = concat!(
            "import jwt from 'jsonwebtoken';\n",
            "import type { Request, Response } from 'express';\n",
            "\n",
            "function authenticate(req: Request, res: Response) {\n",
            "  const token = req.headers.authorization?.split(' ')[1];\n",
            "  const payload = jwt.verify(token, process.env.JWT_SECRET);\n",
            "  req.user = payload;\n",
            "}\n",
        );
        let pos_files = vec![(
            "ts_jwt_bypass_positive.ts".to_string(),
            pos.to_string(),
            "ts".to_string(),
        )];
        let neg_files = vec![(
            "ts_jwt_bypass_negative.ts".to_string(),
            neg.to_string(),
            "ts".to_string(),
        )];
        let mk = |package: Option<&str>| {
            let mut facts = FactTable::default();
            facts.policy_facts.push((
                PolicyFact {
                    rule: "policy_decode".into(),
                    when_call: "decode".into(),
                    require: vec![],
                    scope: PolicyScope::Function,
                    message: "probe".into(),
                    severity: "critical".into(),
                    package: package.map(|s| s.to_string()),
                },
                CheckProvenance::Learned,
            ));
            facts
        };

        // Presence-only, unscoped: fires on the positive twin only.
        let hits = policy::check_program(&lower(pos), &mk(None));
        assert_eq!(
            hits.len(),
            1,
            "presence-only policy must alert on the trigger call: {:?}",
            hits
        );
        assert!(policy::check_program(&lower(neg), &mk(None)).is_empty());

        // Package-scoped through the full scan(): fires when the file
        // imports the declared package, silent under an unrelated scope.
        let scan_pos = scan::scan(
            &pos_files,
            &crate::analysis::taint::config::TaintConfig::default(),
            &mk(Some("jsonwebtoken")),
        );
        assert!(
            !scan_pos.checker.is_empty(),
            "scoped presence-only policy must fire on the importing file: {:?}",
            scan_pos.checker
        );
        let scan_miss = scan::scan(
            &pos_files,
            &crate::analysis::taint::config::TaintConfig::default(),
            &mk(Some("unrelated-pkg")),
        );
        assert!(
            scan_miss.checker.is_empty(),
            "scoped policy must stay silent when the package is not imported: {:?}",
            scan_miss.checker
        );
        let scan_neg = scan::scan(
            &neg_files,
            &crate::analysis::taint::config::TaintConfig::default(),
            &mk(Some("jsonwebtoken")),
        );
        assert!(scan_neg.checker.is_empty());
    }
}

/// Keyword-argument policies: a flag's identity, not its position.
///
/// `set_cookie("k", "v", path="/", secure=False)` and
/// `set_cookie("k", "v", secure=False)` put `secure` at different argument
/// positions, so no slot rule is correct for both. These tests pin the
/// named-argument path end to end: lowering records the name, the policy
/// requirement reads it, and the value still lands at its written position.
#[cfg(test)]
mod named_arg_tests {
    use crate::analysis::taint::facts::{
        FactTable, PolicyFact, PolicyRequirement, PolicyScope, Provenance,
    };
    use crate::checks::policy;
    use crate::harness::lower_source;
    use crate::ir::function::{FunctionIR, Instruction};

    fn lower_py(src: &str) -> Vec<&'static FunctionIR> {
        lower_source("t.py", src, "py")
            .expect("python lowering")
            .into_values()
            .map(|ir| -> &'static FunctionIR { Box::leak(Box::new(ir)) })
            .collect()
    }

    fn cookie_policy() -> (PolicyFact, Provenance) {
        (
            PolicyFact {
                rule: "insecure_cookie_flags".into(),
                when_call: "set_cookie".into(),
                require: vec![
                    PolicyRequirement::RequireNamedArgLiteral {
                        name: "secure".into(),
                        values: vec!["true".into()],
                    },
                    PolicyRequirement::RequireNamedArgLiteral {
                        name: "httponly".into(),
                        values: vec!["true".into()],
                    },
                ],
                scope: PolicyScope::Function,
                message: "cookie flags".into(),
                severity: "warning".into(),
                package: None,
            },
            Provenance::Learned,
        )
    }

    fn findings(src: &str) -> Vec<String> {
        let mut facts = FactTable::default();
        facts.policy_facts.push(cookie_policy());
        let irs = lower_py(src);
        policy::check_program(&irs, &facts)
            .into_iter()
            .map(|f| f.rule)
            .collect()
    }

    #[test]
    fn fires_when_a_flag_is_false() {
        let hits = findings("def u():\n    r.set_cookie(\"sid\", \"abc\", secure=False)\n");
        assert_eq!(hits, vec!["insecure_cookie_flags".to_string()]);
    }

    #[test]
    fn silent_when_both_flags_are_true() {
        let hits =
            findings("def u():\n    r.set_cookie(\"sid\", \"abc\", secure=True, httponly=True)\n");
        assert!(hits.is_empty(), "compliant cookie must be silent: {hits:?}");
    }

    /// The regression the IR change exists for: `path="/"` shifts `secure`
    /// to slot 3, so a positional rule would read `True` (httponly) and
    /// stay silent while the cookie is insecure.
    #[test]
    fn fires_when_an_earlier_optional_argument_shifts_the_flag() {
        let hits = findings(
            "def u():\n    r.set_cookie(\"sid\", \"abc\", path=\"/\", secure=False, httponly=True)\n",
        );
        assert_eq!(
            hits,
            vec!["insecure_cookie_flags".to_string()],
            "secure at slot 3 must still be read by name"
        );
    }

    /// A flag the caller never mentions is the violation the rule exists
    /// to catch (defaults are insecure).
    #[test]
    fn missing_flag_is_a_violation() {
        let hits = findings("def u():\n    r.set_cookie(\"sid\", \"abc\")\n");
        assert_eq!(hits, vec!["insecure_cookie_flags".to_string()]);
    }

    /// Literal-only proof: an unresolvable value is not evidence of a
    /// violation (the check may miss `secure=flag`, never invent it).
    #[test]
    fn non_literal_flag_value_is_not_a_proven_violation() {
        let hits =
            findings("def u():\n    r.set_cookie(\"sid\", \"abc\", secure=flag, httponly=True)\n");
        assert!(hits.is_empty(), "unprovable flag must not fire: {hits:?}");
    }

    /// The lowering contract: names are parallel to args, empty for
    /// positional arguments, and the value keeps its written position.
    #[test]
    fn lowering_records_names_parallel_to_args() {
        let irs =
            lower_py("def u():\n    r.set_cookie(\"sid\", \"abc\", path=\"/\", secure=False)\n");
        let mut checked = false;
        for ir in irs {
            for block in ir.blocks.values() {
                for instr in &block.instructions {
                    if let Instruction::CallVirtual {
                        method,
                        args,
                        arg_names,
                        ..
                    } = instr
                        && method == "set_cookie"
                    {
                        assert_eq!(args.len(), 4, "value keeps its written position");
                        assert_eq!(arg_names, &["", "", "path", "secure"]);
                        checked = true;
                    }
                }
            }
        }
        assert!(checked, "set_cookie call not lowered");
    }
}
