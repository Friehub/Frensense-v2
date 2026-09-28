// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use frensense_bundler::fact_extract::{extract_facts, group_families, Family, FamilyMetadata};
use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{FactTable, LearnedFactEntry};

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
    assert!(base.has_alert(), "positive must alert at baseline");
    let base_neg = frensense_engine::scan::scan(&fams[0].negatives, &cfg, &builtin);
    assert!(
        base_neg.has_alert(),
        "negative alerts at baseline (test unknown), this is the FP the fact should fix"
    );

    let (learned, published) = extract_facts(&fams, &cfg, &builtin);
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
        !after.has_alert(),
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
    let builtin = FactTable::default();

    // 2. Fact Extraction:
    // Bundler extracts memory contract from corpus pairs, replay-gates it,
    // and publishes it as a LearnedFactEntry::MemoryContract.
    let (learned, published) = extract_facts(&fams, &cfg, &builtin);
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

    // At baseline (without learned facts), the engine doesn't know external `my_free`:
    let baseline_pos = frensense_engine::scan::scan(&consumer_pos, &cfg, &builtin);
    assert!(
        !baseline_pos.has_alert(),
        "consumer positive does NOT alert at baseline because external my_free is unknown"
    );

    // With learned facts (from the bundle), the engine knows `my_free` consumes param 0:
    // Positive consumer sample ALERTS on use_after_free.
    let scan_pos = frensense_engine::scan::scan(&consumer_pos, &cfg, &learned);
    assert!(
        scan_pos.has_alert(),
        "consumer positive sample MUST alert on use_after_free with learned contract; findings: {:?}",
        scan_pos.checker
    );

    // Negative consumer sample remains completely SILENT.
    let scan_neg = frensense_engine::scan::scan(&consumer_neg, &cfg, &learned);
    assert!(
        !scan_neg.has_alert(),
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
    let (learned, published) = extract_facts(&[family], &cfg, &builtin);
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
    assert!(!baseline_res.has_alert());

    // With learned bundle facts:
    // Positive sample must alert
    let scan_pos = frensense_engine::scan::scan(&consumer_pos, &cfg, &learned);
    assert!(
        scan_pos.has_alert(),
        "consumer positive MUST alert with learned policy: {:?}",
        scan_pos.checker
    );

    // Negative sample must stay completely silent
    let scan_neg = frensense_engine::scan::scan(&consumer_neg, &cfg, &learned);
    assert!(
        !scan_neg.has_alert(),
        "consumer negative MUST stay silent: {:?}",
        scan_neg.checker
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
    let (learned, published) = extract_facts(&[family], &cfg, &builtin);
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
        scan_pos.has_alert(),
        "consumer positive with fuzzyMatch MUST alert on guard bypass: {:?}",
        scan_pos.checker
    );

    let scan_neg = frensense_engine::scan::scan(&consumer_neg, &cfg, &learned);
    assert!(
        !scan_neg.has_alert(),
        "consumer negative MUST stay silent: {:?}",
        scan_neg.checker
    );
}


