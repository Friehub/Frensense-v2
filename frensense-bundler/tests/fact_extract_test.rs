// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use frensense_bundler::builder::build_facts_bundle;
use frensense_bundler::extract::alerts;
use frensense_bundler::fact_extract::{
    extract_facts_with_tables, group_families, Family, FamilyMetadata,
};
use frensense_bundler::format::load_bundle;
use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{
    fact_table_from_entries, fact_table_from_spec, FactTable, LearnedFactEntry, PolicyRequirement,
};

fn config() -> TaintConfig {
    TaintConfig {
        sources: ["req.body", "req.query"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        sinks: ["query", "execute", "eval"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        sanitizers: ["escapeHtml"].iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn test_group_families_from_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("fam_x_positive.ts"), "const a = 1;").unwrap();
    std::fs::write(dir.path().join("fam_x_negative.ts"), "const a = 2;").unwrap();
    std::fs::write(dir.path().join("fam_x_negative2.ts"), "const a = 3;").unwrap();
    std::fs::write(dir.path().join("unrelated.ts"), "const b = 4;").unwrap();
    let fams = group_families(dir.path()).unwrap();
    assert_eq!(fams.len(), 1);
    assert_eq!(fams[0].id, "fam_x");
    assert_eq!(fams[0].positives.len(), 1);
    assert_eq!(fams[0].negatives.len(), 2);
}

#[test]
fn test_extract_sanitizer_fact_from_healthy_pair() {
    // Positive: tainted value flows straight into a sink (alerts at baseline).
    // Negative: same flow but guarded by a `.test()` allowlist, engine
    // doesn't know `test` yet → negative alerts (FP). The family proposes
    // `test` as a guard sanitizer; the replay gate verifies the family
    // separates with it and the fact is published.
    let pos = r#"
import express from "express";
const router = express.Router();
router.post("/p", (req: any, res: any) => {
    const id = req.body.id;
    eval(id);
    res.json({});
});
export default router;
"#;
    let neg = r#"
import express from "express";
const router = express.Router();
const SAFE = /^[a-z0-9]+$/;
router.post("/p", (req: any, res: any) => {
    const id = req.body.id;
    if (SAFE.test(id)) {
        eval(id);
    }
    res.json({});
});
export default router;
"#;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("fam_guard_positive.ts"), pos).unwrap();
    std::fs::write(dir.path().join("fam_guard_negative.ts"), neg).unwrap();
    let fams = group_families(dir.path()).unwrap();

    let cfg = config();
    let builtin = FactTable::from_config(&cfg);

    // Baseline: positive alerts, but negative ALSO alerts (unknown sanitizer).
    let base = frensense_engine::scan::scan(&fams[0].positives, &cfg, &builtin);
    assert!(alerts(&base), "positive must alert at baseline");
    let base_neg = frensense_engine::scan::scan(&fams[0].negatives, &cfg, &builtin);
    assert!(
        alerts(&base_neg),
        "negative alerts at baseline (test unknown), this is the FP the fact should fix"
    );

    let (learned, published) = extract_facts_with_tables(&fams, &cfg, &builtin);
    let has_test = published.iter().any(
        |f| matches!(&f.entry, LearnedFactEntry::Sanitizer { call, guard_style: true, .. } if call == "test"),
    );
    assert!(
        has_test,
        "expected a `test` guard fact; published: {:?}",
        published.iter().map(|f| &f.entry).collect::<Vec<_>>()
    );

    // The learned table must now separate the family.
    let after = frensense_engine::scan::scan(&fams[0].negatives, &cfg, &learned);
    assert!(
        !alerts(&after),
        "negative must be clean with the learned fact; findings: {:?}",
        after.findings
    );
}

#[test]
fn test_extract_memory_contract_fact_from_positive_and_negative_pair() {
    // 1. Training Corpus:
    // Defines custom wrapper `my_free` in both positive and negative variants.
    // The positive sample exhibits UAF, the negative sample is safe.
    let corpus_pos = r#"
#include <stdlib.h>
void my_free(char *p) {
    free(p);
}
void caller() {
    char *p = malloc(16);
    my_free(p);
    p[0] = 1;
}
"#;
    let corpus_neg = r#"
#include <stdlib.h>
void my_free(char *p) {
    free(p);
}
void caller() {
    char *p = malloc(16);
    my_free(p);
    p = NULL;
}
"#;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("cwe416_uaf_positive.c"), corpus_pos).unwrap();
    std::fs::write(dir.path().join("cwe416_uaf_negative.c"), corpus_neg).unwrap();
    let fams = group_families(dir.path()).unwrap();
    assert_eq!(fams.len(), 1);

    let cfg = config();
    // Production extraction runs under the family's language spec tables
    // (`extract_facts`); mirror that here so the registry carries the C
    // memory vocabulary the fixpoint needs to recognise `free` as consuming.
    let builtin = {
        let spec = frensense_lang::spec_for_ext("c").expect("c spec");
        frensense_engine::analysis::taint::facts::fact_table_from_spec(spec)
    };

    // 2. Fact Extraction:
    // Bundler extracts memory contract from corpus pairs, replay-gates it,
    // and publishes it as a LearnedFactEntry::MemoryContract.
    let (learned, published) = extract_facts_with_tables(&fams, &cfg, &builtin);
    let has_my_free = published.iter().any(|f| {
        matches!(&f.entry, LearnedFactEntry::MemoryContract { name, consumes_params, .. }
            if name == "my_free" && consumes_params == &[0])
    });
    assert!(
        has_my_free,
        "expected my_free MemoryContract fact to be learned and published from the corpus pair; published: {:?}",
        published.iter().map(|f| &f.entry).collect::<Vec<_>>()
    );

    // 3. Consumer project scanning without the wrapper source code (e.g. extern my_free):
    // Positive consumer sample: calls external my_free(p), then uses p[0] (UAF).
    let consumer_pos = vec![(
        "app_pos.c".to_string(),
        r#"
#include <stdlib.h>
extern void my_free(char *p);
void test_app() {
    char *p = malloc(16);
    my_free(p);
    p[0] = 1;
}
"#
        .to_string(),
        "c".to_string(),
    )];

    // Negative consumer sample: calls external my_free(p) safely without subsequent access.
    let consumer_neg = vec![(
        "app_neg.c".to_string(),
        r#"
#include <stdlib.h>
extern void my_free(char *p);
void test_app() {
    char *p = malloc(16);
    p[0] = 1;
    my_free(p);
}
"#
        .to_string(),
        "c".to_string(),
    )];

    // At baseline (without learned facts), the engine doesn't know external
    // `my_free`, so no use-after-free can be proven. The ownership model may
    // still report `memory_leak` here (unknown callees consume nothing by
    // default, leak.rs): that finding is orthogonal to the contract this
    // test teaches - the learned `consumes_params` is what unlocks the UAF.
    let baseline_pos = frensense_engine::scan::scan(&consumer_pos, &cfg, &builtin);
    let baseline_uaf = baseline_pos
        .checker
        .iter()
        .any(|c| c.rule == "use_after_free");
    assert!(
        !baseline_uaf,
        "consumer positive must NOT report use_after_free at baseline because external my_free is unknown; findings: {:?}",
        baseline_pos.checker
    );

    // With learned facts (from the bundle), the engine knows `my_free` consumes param 0:
    // Positive consumer sample ALERTS on use_after_free. The consumer CLI scans
    // under spec-seeded tables merged with the bundle - mirror that here.
    let scan_facts = {
        let spec = frensense_lang::spec_for_ext("c").expect("c spec");
        let mut t = fact_table_from_spec(spec);
        t.merge(&learned);
        t
    };
    let scan_pos = frensense_engine::scan::scan(&consumer_pos, &cfg, &scan_facts);
    assert!(
        alerts(&scan_pos),
        "consumer positive sample MUST alert on use_after_free with learned contract; findings: {:?}",
        scan_pos.checker
    );

    // Negative consumer sample remains completely SILENT.
    let scan_neg = frensense_engine::scan::scan(&consumer_neg, &cfg, &scan_facts);
    assert!(
        !alerts(&scan_neg),
        "consumer negative sample MUST stay silent with learned contract; findings: {:?}",
        scan_neg.checker
    );
}

#[test]
fn test_learn_arg_literal_policy_from_corpus() {
    let cfg = TaintConfig::default();
    let builtin = FactTable::default();

    // 1. Training corpus family with positive and negative variants
    let family = Family {
        id: "tls_verification_policy".to_string(),
        positives: vec![(
            "tls_pos.ts".to_string(),
            r#"
export function createSession(host: string) {
    return configureTls(host, "insecure");
}
"#
            .to_string(),
            "ts".to_string(),
        )],
        negatives: vec![(
            "tls_neg.ts".to_string(),
            r#"
export function createSession(host: string) {
    return configureTls(host, "secure");
}
"#
            .to_string(),
            "ts".to_string(),
        )],
        declared_check_call: None,
        metadata: FamilyMetadata::default(),
    };

    // 2. Extract facts via the bundler replay gate:
    let (learned, published) = extract_facts_with_tables(&[family], &cfg, &builtin);
    assert!(
        !published.is_empty(),
        "must publish learned facts from separating variants; published: {:?}",
        published.iter().map(|f| &f.entry).collect::<Vec<_>>()
    );

    // 3. Test on consumer project with positive (vulnerable) and negative (safe) samples:
    let consumer_pos = vec![(
        "app_pos.ts".to_string(),
        r#"
export function connect() {
    return configureTls("api.internal", "insecure");
}
"#
        .to_string(),
        "ts".to_string(),
    )];

    let consumer_neg = vec![(
        "app_neg.ts".to_string(),
        r#"
export function connect() {
    return configureTls("api.internal", "secure");
}
"#
        .to_string(),
        "ts".to_string(),
    )];

    // At baseline: does not alert
    let baseline_res = frensense_engine::scan::scan(&consumer_pos, &cfg, &builtin);
    assert!(!alerts(&baseline_res));

    // With learned bundle facts:
    // Positive sample must alert
    let scan_pos = frensense_engine::scan::scan(&consumer_pos, &cfg, &learned);
    assert!(
        alerts(&scan_pos),
        "consumer positive MUST alert with learned policy: {:?}",
        scan_pos.checker
    );

    // Negative sample must stay completely silent
    let scan_neg = frensense_engine::scan::scan(&consumer_neg, &cfg, &learned);
    assert!(
        !alerts(&scan_neg),
        "consumer negative MUST stay silent: {:?}",
        scan_neg.checker
    );
}

/// End-to-end verification that the engine is teachable via a `.frc` bundle
/// for a security-policy bug (CWE-862: Missing Authorization).
///
/// Training: two Python files teach the rule
///   "calling `delete_user_account` without `verify_admin_permission` is a violation".
/// Expected outcomes:
///   - No bundle: scanner sees the positive file and produces 0 findings
///     (the engine has no prior knowledge of this custom API).
///   - With bundle: scanner fires on the unguarded positive.
///   - With bundle: scanner stays silent on the guarded negative.
#[test]
fn test_security_policy_frc_roundtrip() {
    let dir = tempfile::tempdir().unwrap();

    // Training corpus
    std::fs::write(
        dir.path().join("delete_account_positive.py"),
        concat!(
            "# check-call: delete_user_account\n",
            "def handle(uid):\n",
            "    delete_user_account(uid)\n",
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("delete_account_negative.py"),
        concat!(
            "def handle(uid):\n",
            "    if not verify_admin_permission(uid):\n",
            "        raise Exception('denied')\n",
            "    delete_user_account(uid)\n",
        ),
    )
    .unwrap();

    // Build the .frc bundle from the corpus
    let cfg = TaintConfig::default();
    let builtin = FactTable::default();
    let (bundle_bytes, published) =
        build_facts_bundle(dir.path()).expect("bundle build must not fail");

    // At least one Check or Policy fact must have been published
    let has_policy_fact = published.iter().any(|f| match &f.entry {
        LearnedFactEntry::Check {
            call, unless_guard, ..
        } => {
            call.ends_with("delete_user_account")
                && unless_guard
                    .as_deref()
                    .map(|g| g.contains("verify_admin_permission"))
                    .unwrap_or(false)
        }
        LearnedFactEntry::Policy {
            when_call, require, ..
        } => {
            when_call.ends_with("delete_user_account")
                && require.iter().any(|r| {
                    matches!(r, PolicyRequirement::GuardCall { call }
                        if call.contains("verify_admin_permission"))
                })
        }
        _ => false,
    });
    assert!(
        has_policy_fact,
        "bundler must publish a GuardCall policy for delete_user_account; published: {:#?}",
        published.iter().map(|f| &f.entry).collect::<Vec<_>>()
    );

    // Round-trip: load the bundle bytes and hydrate a FactTable
    let loaded = load_bundle(&bundle_bytes).expect("bundle must deserialize");
    let learned_facts = fact_table_from_entries(&loaded.learned_facts);

    // Phase 2.3: the family's advisory pattern carries the join keys of the
    // facts it published (checker rule ids / sink names).
    assert!(
        loaded.patterns.iter().any(|p| {
            p.id == "delete_account"
                && !p.rules.is_empty()
                && p.rules.iter().any(|r| r.contains("delete_user_account"))
        }),
        "pattern must join to the published check/policy rule, patterns: {:#?}",
        loaded.patterns
    );

    // Scanner test fixtures
    let positive_file = vec![(
        "app_positive.py".to_string(),
        concat!(
            "def route_handler(user_id):\n",
            "    delete_user_account(user_id)\n",
        )
        .to_string(),
        "py".to_string(),
    )];

    let negative_file = vec![(
        "app_negative.py".to_string(),
        concat!(
            "def route_handler(user_id):\n",
            "    if not verify_admin_permission(user_id):\n",
            "        raise PermissionError('forbidden')\n",
            "    delete_user_account(user_id)\n",
        )
        .to_string(),
        "py".to_string(),
    )];

    // Without bundle: engine is blind to this custom API -- 0 findings expected
    let baseline = frensense_engine::scan::scan(&positive_file, &cfg, &builtin);
    assert!(
        !alerts(&baseline),
        "no findings expected without bundle (engine has no prior knowledge): {:?}",
        baseline.checker
    );

    // With bundle: positive must alert
    let with_bundle_pos = frensense_engine::scan::scan(&positive_file, &cfg, &learned_facts);
    assert!(
        alerts(&with_bundle_pos),
        "unguarded positive MUST alert after engine is taught the rule; checker: {:?}",
        with_bundle_pos.checker
    );

    // With bundle: negative must stay silent
    let with_bundle_neg = frensense_engine::scan::scan(&negative_file, &cfg, &learned_facts);
    assert!(
        !alerts(&with_bundle_neg),
        "guarded negative MUST stay silent after engine is taught the rule; checker: {:?}",
        with_bundle_neg.checker
    );
}

#[test]
fn test_learn_guard_bypass_containment_from_corpus() {
    let cfg = TaintConfig::default();
    let builtin = FactTable::default();

    // 1. Training corpus family for custom containment callee
    let family = Family {
        id: "url_allowlist_bypass".to_string(),
        positives: vec![(
            "redirect_pos.ts".to_string(),
            r#"
export function isAllowedUrl(targetUrl: string, allowedHost: string) {
    return targetUrl.fuzzyMatch(allowedHost);
}
"#
            .to_string(),
            "ts".to_string(),
        )],
        negatives: vec![(
            "redirect_neg.ts".to_string(),
            r#"
export function isAllowedUrl(targetUrl: string, allowedHost: string) {
    return parseDomain(targetUrl) === allowedHost;
}
"#
            .to_string(),
            "ts".to_string(),
        )],
        declared_check_call: None,
        metadata: FamilyMetadata::default(),
    };

    // 2. Extract facts via the bundler replay gate:
    let (learned, published) = extract_facts_with_tables(&[family], &cfg, &builtin);
    assert!(
        !published.is_empty(),
        "must publish learned facts; published: {:?}",
        published.iter().map(|f| &f.entry).collect::<Vec<_>>()
    );

    // 3. Test on consumer project:
    let consumer_pos = vec![(
        "client_pos.ts".to_string(),
        r#"
export function validateRedirect(url: string) {
    return url.fuzzyMatch("https://good.com");
}
"#
        .to_string(),
        "ts".to_string(),
    )];

    let consumer_neg = vec![(
        "client_neg.ts".to_string(),
        r#"
export function validateRedirect(url: string) {
    return getHost(url) === "https://good.com";
}
"#
        .to_string(),
        "ts".to_string(),
    )];

    // With learned bundle facts:
    let scan_pos = frensense_engine::scan::scan(&consumer_pos, &cfg, &learned);
    assert!(
        alerts(&scan_pos),
        "consumer positive with fuzzyMatch MUST alert on guard bypass: {:?}",
        scan_pos.checker
    );

    let scan_neg = frensense_engine::scan::scan(&consumer_neg, &cfg, &learned);
    assert!(
        !alerts(&scan_neg),
        "consumer negative MUST stay silent: {:?}",
        scan_neg.checker
    );
}
