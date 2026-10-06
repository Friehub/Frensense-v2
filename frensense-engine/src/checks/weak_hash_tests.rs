// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the non-dataflow checker layer (`graph::checker`).

#[cfg(test)]
pub mod checker_tests {
    use crate::analysis::taint::facts::{FactTable, LearnedFactEntry};
    use crate::checks::check_all;
    use crate::harness::lower_source;

    /// Production-seeded table (spec seed -> default pack -> pack language
    /// sections): the checks read `FactTable` only, so test fixtures must
    /// seed the vocabulary exactly like a production scan
    /// (`seeded_tables`) does.
    fn ts_facts() -> FactTable {
        crate::analysis::taint::facts::seeded_tables(["ts"]).1
    }

    fn check(src: &str) -> Vec<(String, String)> {
        let fns = lower_source("test.ts", src, "ts").expect("lowering failed");
        check_all(fns.values(), &ts_facts())
            .into_iter()
            .map(|f| (f.function, f.rule))
            .collect()
    }

    fn check_with(src: &str, facts: &FactTable) -> Vec<(String, String)> {
        let fns = lower_source("test.ts", src, "ts").expect("lowering failed");
        check_all(fns.values(), facts)
            .into_iter()
            .map(|f| (f.function, f.rule))
            .collect()
    }

    /// The weakPasswordChallenge shape: `crypto.createHash('md5')`.
    #[test]
    fn weak_hash_createhash_md5_fires() {
        let src = r#"
import * as crypto from 'crypto'
export function hashPassword (clearTextPassword: string): string {
  return crypto.createHash('md5').update(clearTextPassword).digest('hex')
}
"#;
        let findings = check(src);
        assert!(
            findings.iter().any(|(_, r)| *r == "weak_hash"),
            "expected weak_hash finding, got {findings:?}"
        );
    }

    /// SHA-256 is acceptable, no weak_hash finding.
    #[test]
    fn strong_hash_sha256_does_not_fire() {
        let src = r#"
import * as crypto from 'crypto'
export function hashPassword (clearTextPassword: string): string {
  return crypto.createHash('sha256').update(clearTextPassword).digest('hex')
}
"#;
        let findings = check(src);
        assert!(
            !findings.iter().any(|(_, r)| *r == "weak_hash"),
            "sha256 must not be flagged, got {findings:?}"
        );
    }

    /// Bare `md5(data)` import style fires.
    #[test]
    fn bare_md5_call_fires() {
        let src = r#"
import { md5 } from 'hash-wasm'
export function legacy (d: string) { return md5(d) }
"#;
        let findings = check(src);
        assert!(
            findings.iter().any(|(_, r)| *r == "weak_hash"),
            "expected weak_hash finding, got {findings:?}"
        );
    }

    /// Insecure algorithm selector accepted by a *verifier*:
    /// `jwt.verify(token, secret, 'none')` - verification-context fires.
    #[test]
    fn jwt_verifier_with_insecure_algorithm_fires() {
        let src = r#"
import * as jwt from 'jsonwebtoken'
export function checkToken (token: string, secret: string) {
  return jwt.verify(token, secret, 'none')
}
"#;
        let findings = check(src);
        assert!(
            findings.iter().any(|(_, r)| *r == "insecure_jwt_algorithm"),
            "jwt.verify with 'none' must fire, got {findings:?}"
        );
    }

    /// Challenge/test harness wrappers that *issue* a token under an
    /// insecure algorithm (`jwtChallenge(id, req, 'none', ...)`) are not
    /// verifiers accepting `none` - no finding.
    #[test]
    fn jwt_issuing_wrapper_is_silent() {
        let src = r#"
export function jwtChallenges (req: any) {
  jwtChallenge('jwtUnsignedChallenge', req, 'none', /x/)
}
"#;
        let findings = check(src);
        assert!(
            !findings.iter().any(|(_, r)| *r == "insecure_jwt_algorithm"),
            "token-issuing wrapper must not fire, got {findings:?}"
        );
    }

    /// A generic digest utility (`const digest = (data) => createHash('md5')`)
    /// with no credential context is not a password-KDF shape - the
    /// selector rule fires only when the enclosing function/parameters name
    /// a credential context (password/secret/token/...). Credential-named
    /// wrappers (`hashPassword`) keep firing (covered by
    /// `weak_hash_createhash_md5_fires`).
    #[test]
    fn createhash_md5_without_credential_context_is_silent() {
        let src = r#"
import * as crypto from 'crypto'
export const digest = (data: string) => crypto.createHash('md5').update(data).digest('hex')
"#;
        let findings = check(src);
        assert!(
            !findings.iter().any(|(_, r)| *r == "weak_hash"),
            "non-credential digest utility must be silent, got {findings:?}"
        );
    }

    /// Clean code produces zero checker findings.
    #[test]
    fn clean_code_is_silent() {
        let src = r#"
export function add (a: number, b: number): number {
  return a + b
}
"#;
        assert!(check(src).is_empty());
    }

    /// Non-security code calling an unrelated `.new()` or `.hash()`-like
    /// method must not fire (the receiver-qualification guard).
    #[test]
    fn generic_hash_method_without_security_context_is_silent() {
        let src = r#"
const mapper = { hash: (s: string) => s }
export function process (data: string) {
  return mapper.hash(data)
}
"#;
        let findings = check(src);
        assert!(
            !findings.iter().any(|(_, r)| *r == "weak_hash_wrapper"),
            "unrelated .hash must not fire, got {findings:?}"
        );
    }

    // ── Composite-literal / spread value-flow regressions ────────────────

    use crate::analysis::taint::facts::seeded_tables;
    use crate::scan::scan;

    fn scan_count(src: &str) -> usize {
        let (config, facts) = seeded_tables(["ts"]);
        let files = vec![("test.ts".to_string(), src.to_string(), "ts".to_string())];
        let result = scan(&files, &config, &facts);
        result
            .findings
            .iter()
            .filter(|f| {
                f.verdict == crate::analysis::taint::engine::BackwardVerdict::Vulnerable
                    && f.alert.is_some()
            })
            .count()
    }

    /// `{ ...req.body, sql: "SELECT 1" }` as a call argument: the spread's
    /// taint must survive the composite literal (previously the object
    /// collapsed to its LAST property value and the taint vanished).
    #[test]
    fn spread_inside_object_arg_propagates() {
        let src = r#"
export function spreadFirst (req: any, pool: any) {
    pool.query({ ...req.body, sql: "SELECT 1" });
}
"#;
        assert_eq!(scan_count(src), 1, "spread taint in object arg lost");
    }

    /// Object literal held in a variable, then passed to a sink, the var
    /// round-trip must not break the flow.
    #[test]
    fn object_literal_via_variable_propagates() {
        let src = r#"
export function varFind (req: any, db: any) {
    const f = { _id: req.body.name };
    db.collection.findOne(f);
}
"#;
        assert_eq!(scan_count(src), 1, "obj-literal taint lost through var");
    }

    /// Spread of a tainted variable directly in the argument list.
    #[test]
    fn spread_tainted_var_propagates() {
        let src = r#"
export function spreadTaintedVar (req: any, pool: any) {
    pool.query("SELECT * FROM t WHERE id = " + req.body.name, { ...req.body });
}
"#;
        assert_eq!(scan_count(src), 1, "spread var taint lost");
    }

    /// `find` (mongoose/mongo shell) must be a known sink, it was only in
    /// the semantic-categories table, which the engine never reads. Uses an
    /// identity payload: finder sinks only report identity-keyed objects.
    #[test]
    fn find_is_a_sink() {
        let src = r#"
export function directFind (req: any, db: any) {
    db.collection.find({ _id: req.body.name });
}
"#;
        assert_eq!(scan_count(src), 1, "find missing from sink table");
    }

    /// Clean composite literals must stay silent (no FP from the merge).
    #[test]
    fn clean_composites_stay_silent() {
        let src = r#"
export function cleanSpread (pool: any, defaults: any) {
    pool.query("SELECT 1", { ...defaults, timeout: 5000 });
}
export function cleanFind (db: any) {
    const filter = { status: "active" };
    db.users.find(filter);
}
"#;
        assert_eq!(scan_count(src), 0, "false positive on clean composite");
    }

    // ── Learned-check facts (.frc-bundle-installed rules) ─────────────────

    fn learned_table(call: &str, rule: &str) -> FactTable {
        let mut t = FactTable::default();
        LearnedFactEntry::Check {
            rule: rule.to_string(),
            call: call.to_string(),
            message: format!("corpus-learned violation: {call}"),
            severity: "warning".to_string(),
            unless_guard: None,
            unless_range_check: None,
        }
        .apply(&mut t);
        t
    }

    /// A learned fact with an inline range-check qualification: fires when
    /// the trigger argument has no literal comparison, stays silent when
    /// it does (`if (d < 0 || d > MAX)`), enforcement without a helper.
    #[test]
    fn learned_check_range_qualification() {
        let mut t = FactTable::default();
        LearnedFactEntry::Check {
            rule: "policy_generateCoupon".into(),
            call: "generateCoupon".into(),
            message: "policy violation".into(),
            severity: "warning".into(),
            unless_guard: None,
            unless_range_check: Some(
                ["<", ">", "<=", ">="]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            ),
        }
        .apply(&mut t);

        let vuln = r#"
export function vulnerableTool (discount: number) {
  return security.generateCoupon(discount)
}
"#;
        assert!(
            check_with(vuln, &t)
                .iter()
                .any(|(_, r)| r == "policy_generateCoupon"),
            "no enforcement anywhere: must fire"
        );

        let enforced = r#"
export function enforcedTool (discount: number) {
  if (discount < 0 || discount > 10) {
    return null
  }
  return security.generateCoupon(discount)
}
"#;
        assert!(
            check_with(enforced, &t).is_empty(),
            "inline literal range check on the arg: must stay silent"
        );

        let flawed = r#"
export function flawedTool (discount: number) {
  if (discount < 0) {
    return security.generateCoupon(discount)
  }
  return null
}
"#;
        assert!(
            check_with(flawed, &t)
                .iter()
                .any(|(_, r)| r == "policy_generateCoupon"),
            "trigger call inside flawed/negative branch is not safely guarded and must fire"
        );
    }

    /// A bundle-installed check fires on the trigger call.
    #[test]
    fn learned_check_fires_on_trigger_call() {
        let facts = learned_table("dangerousApi", "policy_dangerous_api");
        let src = r#"
export function caller (x: any) {
  dangerousApi(x);
}
"#;
        let findings = check_with(src, &facts);
        assert!(
            findings.iter().any(|(_, r)| r == "policy_dangerous_api"),
            "learned check must fire, got {findings:?}"
        );
    }

    /// Receiver-segment matching: `obj.dangerousApi()` fires the rule too.
    #[test]
    fn learned_check_matches_last_segment() {
        let facts = learned_table("dangerousApi", "policy_dangerous_api");
        let src = r#"
export function methodCaller (obj: any) {
  obj.dangerousApi(1);
}
"#;
        let findings = check_with(src, &facts);
        assert!(
            findings.iter().any(|(_, r)| r == "policy_dangerous_api"),
            "learned check must fire via receiver segment, got {findings:?}"
        );
    }

    /// Silence on unrelated calls; empty table means no learned findings.
    #[test]
    fn learned_check_silent_without_fact_or_trigger() {
        let src = r#"
export function cleanCaller (x: any) {
  safeApi(x);
}
"#;
        let facts = learned_table("dangerousApi", "policy_dangerous_api");
        assert!(
            check_with(src, &facts).is_empty(),
            "unrelated call must not fire"
        );
        let src2 = r#"
export function caller (x: any) {
  dangerousApi(x);
}
"#;
        assert!(
            check_with(src2, &FactTable::default()).is_empty(),
            "no bundle = no learned findings"
        );
    }

    /// Merge accumulates distinct learned checks and dedups duplicates.
    #[test]
    fn learned_checks_merge_accumulates_and_dedups() {
        let mut t = FactTable::default();
        t.merge(&learned_table("a", "rule_one"));
        t.merge(&learned_table("b", "rule_two"));
        t.merge(&learned_table("a", "rule_one")); // duplicate
        assert_eq!(t.learned_checks.len(), 2, "dedup on (rule, call)");
    }

    /// End-to-end: scan applies learned checks alongside taint.
    #[test]
    fn learned_check_via_scan() {
        let config = crate::analysis::taint::facts::seeded_tables(["ts"]).0;
        let facts = learned_table("insecureRedirect", "policy_open_redirect");
        let files = vec![(
            "t.ts".to_string(),
            r#"
export function hop (req: any, res: any) {
  res.redirect(insecureRedirect(req.query.to));
}
"#
            .to_string(),
            "ts".to_string(),
        )];
        let result = crate::scan::scan(&files, &config, &facts);
        assert!(
            result
                .checker
                .iter()
                .any(|c| c.rule == "policy_open_redirect"),
            "scan must surface learned checker findings, got {:?}",
            result.checker
        );
    }

    /// Positive & negative tests for learned weak crypto facts.
    #[test]
    fn learned_weak_crypto_with_selector_positive_and_negative() {
        use crate::analysis::taint::facts::WeakCryptoFact;
        let mut facts = FactTable::default();
        facts.weak_crypto_rules.push(WeakCryptoFact {
            rule_id: "learned_weak_cipher_des".into(),
            call: "createCipher".into(),
            selector_slot: Some(0),
            weak_selectors: vec!["des".into(), "rc4".into()],
            severity: "warning".into(),
            message: String::new(),
        });

        // Positive sample: 'des' selected
        let pos_src = r#"
export function encryptData (data: string, key: string) {
  return createCipher('des', key).update(data);
}
"#;
        let pos_findings = check_with(pos_src, &facts);
        assert!(
            pos_findings
                .iter()
                .any(|(_, r)| r == "learned_weak_cipher_des"),
            "expected learned_weak_cipher_des finding on positive sample, got: {pos_findings:?}"
        );

        // Negative sample: 'aes-256-gcm' selected
        let neg_src = r#"
export function encryptData (data: string, key: string) {
  return createCipher('aes-256-gcm', key).update(data);
}
"#;
        let neg_findings = check_with(neg_src, &facts);
        assert!(
            !neg_findings
                .iter()
                .any(|(_, r)| r == "learned_weak_cipher_des"),
            "negative sample with aes-256-gcm must stay silent, got: {neg_findings:?}"
        );
    }

    #[test]
    fn learned_weak_crypto_bare_call_positive_and_negative() {
        use crate::analysis::taint::facts::WeakCryptoFact;
        let mut facts = FactTable::default();
        facts.weak_crypto_rules.push(WeakCryptoFact {
            rule_id: "learned_broken_hash_func".into(),
            call: "brokenCustomHash".into(),
            selector_slot: None,
            weak_selectors: vec![],
            severity: "warning".into(),
            message: String::new(),
        });

        // Positive sample: calls brokenCustomHash
        let pos_src = r#"
export function hashToken (token: string) {
  return brokenCustomHash(token);
}
"#;
        let pos_findings = check_with(pos_src, &facts);
        assert!(
            pos_findings
                .iter()
                .any(|(_, r)| r == "learned_broken_hash_func"),
            "expected finding on positive sample, got: {pos_findings:?}"
        );

        // Negative sample: calls safeCustomHash
        let neg_src = r#"
export function hashToken (token: string) {
  return safeCustomHash(token);
}
"#;
        let neg_findings = check_with(neg_src, &facts);
        assert!(
            neg_findings.is_empty(),
            "negative sample must stay silent, got: {neg_findings:?}"
        );
    }

    /// Phase 2.2: a finding carries the severity declared by the rule that
    /// fired - the spec bootstrap's declared level for spec rules, the
    /// bundle-authored level for learned facts.
    #[test]
    fn findings_carry_rule_declared_severity() {
        use crate::analysis::taint::facts::WeakCryptoFact;
        let src = r#"
import * as crypto from 'crypto'
export function hashPassword (clearTextPassword: string): string {
  return crypto.createHash('md5').update(clearTextPassword).digest('hex')
}
"#;
        let fns = lower_source("test.ts", src, "ts").expect("lowering failed");
        let spec_findings = check_all(fns.values(), &ts_facts());
        let weak = spec_findings
            .iter()
            .find(|f| f.rule == "weak_hash")
            .expect("weak_hash finding expected");
        assert_eq!(
            weak.severity, "warning",
            "spec rule must report its declared severity, got {:?}",
            weak
        );

        let mut facts = ts_facts();
        facts.weak_crypto_rules.push(WeakCryptoFact {
            rule_id: "learned_broken_hash_func".into(),
            call: "brokenCustomHash".into(),
            selector_slot: None,
            weak_selectors: vec![],
            severity: "critical".into(),
            message: "authored observation".into(),
        });
        let pos_src = r#"
export function hashToken (token: string) {
  return brokenCustomHash(token);
}
"#;
        let fns = lower_source("test.ts", pos_src, "ts").expect("lowering failed");
        let learned_findings = check_all(fns.values(), &facts);
        let learned = learned_findings
            .iter()
            .find(|f| f.rule == "learned_broken_hash_func")
            .expect("learned finding expected");
        assert_eq!(
            learned.severity, "critical",
            "learned fact must report its authored severity, got {:?}",
            learned
        );
    }
}
