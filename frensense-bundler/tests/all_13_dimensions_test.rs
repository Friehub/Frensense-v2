// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Verification test suite for all 13 learnable security dimensions
//! documented in the Frensense architecture and blog post:
//!
//! 1. Dangerous Sinks (`LearnedFactEntry::Sink`)
//! 2. Taint Sources (`LearnedFactEntry::Source`)
//! 3. Sanitizers (`LearnedFactEntry::Sanitizer`)
//! 4. Data Propagators (`LearnedFactEntry::Propagator`)
//! 5. Security Policies (`LearnedFactEntry::Policy`)
//! 6. Structural Checks (`LearnedFactEntry::Check`)
//! 7. Memory Contracts (`LearnedFactEntry::MemoryContract`)
//! 8. Cryptographic Rules (`LearnedFactEntry::WeakCrypto`)
//! 9. Authorization Guards (`LearnedFactEntry::GuardBypass`)
//! 10. Schema Validation (`LearnedFactEntry::SchemaPolicy`)
//! 11. Grammar Syntax (`LearnedFactEntry::GrammarRole`)
//! 12. Grammar Features (`LearnedFactEntry::GrammarFeature`)
//! 13. IDOR & Multi-Tenancy (`LearnedFactEntry::IdorFinderSink`, `LearnedFactEntry::IdorKey`)

use std::collections::BTreeSet;

use frensense_bundler::extract::alerts;
use frensense_bundler::format::{load_bundle, write_bundle, BundlePayload};
use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::engine::FindingClass;
use frensense_engine::analysis::taint::facts::{
    fact_table_from_entries, FactTable, GrammarFeature, GuardBypassFact, LearnedFactEntry,
    PolicyRequirement, PolicyScope, SchemaPolicyFact, TeachableNodeRole, WeakCryptoFact,
};
use frensense_engine::checks::memory_summary::CapacitySpec;
use frensense_engine::checks::Provenance;
use frensense_engine::scan::scan;

fn make_bundle(facts: Vec<LearnedFactEntry>) -> FactTable {
    let payload = BundlePayload {
        patterns: vec![],
        learned_facts: facts,
    };
    let bytes = write_bundle(&payload, 0).expect("write bundle");
    let loaded = load_bundle(&bytes).expect("load bundle");
    fact_table_from_entries(&loaded.learned_facts)
}

// ── Dimension 1: Dangerous Sinks ──────────────────────────────────────────
#[test]
fn test_dim_01_dangerous_sinks_per_slot_safety() {
    let mut dangerous_args = BTreeSet::new();
    dangerous_args.insert(0); // Only argument 0 is SQL/command string; argument 1 is safe parameter

    let facts = make_bundle(vec![LearnedFactEntry::Sink {
        call: "execute_db".into(),
        dangerous_args,
        binding_args_safe: true,
    }]);

    let cfg = TaintConfig {
        sources: ["req.body".into()].into_iter().collect(),
        sinks: ["execute_db".into()].into_iter().collect(),
        sanitizers: Default::default(),
    };

    // Positive: untrusted input in dangerous slot 0 -> ALERTS
    let pos_file = vec![(
        "app_pos.ts".into(),
        "function handle(req: any) { execute_db(req.body, ['safe']); }".into(),
        "ts".into(),
    )];
    let res_pos = scan(&pos_file, &cfg, &facts);
    assert!(
        alerts(&res_pos),
        "untrusted input in slot 0 must trigger an alert"
    );

    // Negative: untrusted input in safe parameter binding slot 1 -> SILENT
    let neg_file = vec![(
        "app_neg.ts".into(),
        "function handle(req: any) { execute_db('SELECT * WHERE id = ?', [req.body]); }".into(),
        "ts".into(),
    )];
    let res_neg = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&res_neg),
        "untrusted input in safe binding slot 1 must stay silent: {:?}",
        res_neg.findings
    );
}

// ── Dimension 2: Taint Sources ────────────────────────────────────────────
#[test]
fn test_dim_02_taint_sources_custom_rpc() {
    let facts = make_bundle(vec![LearnedFactEntry::Source {
        pattern: "fetch_untrusted_event".into(),
    }]);

    let cfg = TaintConfig {
        sources: Default::default(), // No built-in sources
        sinks: ["sink_exec".into()].into_iter().collect(),
        sanitizers: Default::default(),
    };

    let files = vec![(
        "app.py".into(),
        concat!(
            "def process_job():\n",
            "    data = fetch_untrusted_event()\n",
            "    sink_exec(data)\n",
        )
        .into(),
        "py".into(),
    )];

    // Baseline without learned source: blind to custom RPC -> SILENT
    let baseline = scan(&files, &cfg, &FactTable::default());
    assert!(
        !alerts(&baseline),
        "baseline must not alert without learned source"
    );

    // With learned source: ALERTS
    let taught = scan(&files, &cfg, &facts);
    assert!(
        alerts(&taught),
        "scanner must alert when taint flows from taught source to sink"
    );
}

// ── Dimension 3: Sanitizers ───────────────────────────────────────────────
#[test]
fn test_dim_03_sanitizers_custom_cleanse() {
    let facts = make_bundle(vec![LearnedFactEntry::Sanitizer {
        call: "cleanse_input".into(),
        kind: "generic".into(),
        guard_style: false,
    }]);

    let cfg = TaintConfig {
        sources: ["req.body".into()].into_iter().collect(),
        sinks: ["query".into()].into_iter().collect(),
        sanitizers: ["cleanse_input".into()].into_iter().collect(),
    };

    // Positive: directly reaching sink without sanitizer -> ALERTS
    let pos_file = vec![(
        "pos.js".into(),
        "function run(req) { query(req.body); }".into(),
        "js".into(),
    )];
    let pos_res = scan(&pos_file, &cfg, &facts);
    assert!(alerts(&pos_res), "unsanitized flow must alert");

    // Negative: sanitized flow -> SILENT
    let neg_file = vec![(
        "neg.js".into(),
        "function run(req) { let clean = cleanse_input(req.body); query(clean); }".into(),
        "js".into(),
    )];
    let neg_res = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&neg_res),
        "flow through learned sanitizer must stay silent: {:?}",
        neg_res.findings
    );
}

// ── Dimension 4: Data Propagators ─────────────────────────────────────────
#[test]
fn test_dim_04_data_propagators_custom_transform() {
    // Only argument 0 propagates taint; argument 1 does not
    let facts = make_bundle(vec![LearnedFactEntry::Propagator {
        call: "custom_transform".into(),
        input_args: vec![0],
        preserves_taint: true,
    }]);

    let cfg = TaintConfig {
        sources: ["req.body".into()].into_iter().collect(),
        sinks: ["eval_sink".into()].into_iter().collect(),
        sanitizers: Default::default(),
    };

    // Positive: untrusted input passed to slot 0 -> propagates to eval_sink -> ALERTS
    let pos_file = vec![(
        "pos.js".into(),
        "function run(req) { let out = custom_transform(req.body, 'safe_context'); eval_sink(out); }".into(),
        "js".into(),
    )];
    let pos_res = scan(&pos_file, &cfg, &facts);
    assert!(
        alerts(&pos_res),
        "taint passed through propagating slot 0 must alert"
    );

    // Negative: untrusted input passed to non-propagating slot 1 -> SILENT
    let neg_file = vec![(
        "neg.js".into(),
        "function run(req) { let out = custom_transform('safe_template', req.body); eval_sink(out); }".into(),
        "js".into(),
    )];
    let neg_res = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&neg_res),
        "taint passed to non-propagating slot 1 must stay silent: {:?}",
        neg_res.findings
    );
}

// ── Dimension 5: Security Policies ────────────────────────────────────────
#[test]
fn test_dim_05_security_policies_guard_call() {
    let facts = make_bundle(vec![LearnedFactEntry::Policy {
        rule: "policy_delete_user_account".into(),
        when_call: "delete_user_account".into(),
        require: vec![PolicyRequirement::GuardCall {
            call: "verify_admin_permission".into(),
        }],
        scope: PolicyScope::Function,
        message: "Missing authorization guard on privileged deletion".into(),
        severity: "High".into(),
    }]);

    let cfg = TaintConfig::default();

    // Positive: unguarded privileged action -> ALERTS
    let pos_file = vec![(
        "pos.py".into(),
        "def run(uid):\n    delete_user_account(uid)\n".into(),
        "py".into(),
    )];
    let pos_res = scan(&pos_file, &cfg, &facts);
    assert!(alerts(&pos_res), "unguarded action must alert");
    assert_eq!(pos_res.checker[0].rule, "policy_delete_user_account");

    // Negative: guarded action -> SILENT
    let neg_file = vec![(
        "neg.py".into(),
        "def run(uid):\n    if not verify_admin_permission(uid):\n        return\n    delete_user_account(uid)\n".into(),
        "py".into(),
    )];
    let neg_res = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&neg_res),
        "guarded action must stay silent: {:?}",
        neg_res.checker
    );
}

// ── Dimension 6: Structural Checks ────────────────────────────────────────
#[test]
fn test_dim_06_structural_checks_range_bound() {
    let facts = make_bundle(vec![LearnedFactEntry::Check {
        rule: "check_allocate_buffer_range".into(),
        call: "allocate_buffer".into(),
        message: "allocate_buffer requires bounds check".into(),
        severity: "Warning".into(),
        unless_guard: None,
        unless_range_check: Some(vec!["<".into(), "<=".into()]),
    }]);

    let cfg = TaintConfig::default();

    // Positive: call without range check -> ALERTS
    let pos_file = vec![(
        "pos.c".into(),
        "void run(int sz) { allocate_buffer(sz); }".into(),
        "c".into(),
    )];
    let pos_res = scan(&pos_file, &cfg, &facts);
    assert!(
        alerts(&pos_res),
        "allocate_buffer without range check must alert"
    );

    // Negative: call with inline `< 1024` comparison -> SILENT
    let neg_file = vec![(
        "neg.c".into(),
        "void run(int sz) { if (sz < 1024) { allocate_buffer(sz); } }".into(),
        "c".into(),
    )];
    let neg_res = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&neg_res),
        "allocate_buffer with range check must stay silent: {:?}",
        neg_res.checker
    );
}

// ── Dimension 7: Memory Contracts ─────────────────────────────────────────
#[test]
fn test_dim_07_memory_contracts_custom_alloc_free() {
    let facts = make_bundle(vec![
        LearnedFactEntry::MemoryContract {
            name: "custom_arena_free".into(),
            returns_fresh: false,
            return_capacity: CapacitySpec::Unknown,
            consumes_params: vec![0],
        },
        LearnedFactEntry::Deallocator {
            name: "custom_arena_free".into(),
        },
    ]);

    let cfg = TaintConfig::default();

    // Positive: use after free -> ALERTS
    let pos_file = vec![(
        "pos.c".into(),
        concat!(
            "#include <stdlib.h>\n",
            "extern void custom_arena_free(char *p);\n",
            "void test() {\n",
            "    char *p = malloc(16);\n",
            "    custom_arena_free(p);\n",
            "    p[0] = 1;\n", // UAF
            "}\n",
        )
        .into(),
        "c".into(),
    )];
    let pos_res = scan(&pos_file, &cfg, &facts);
    assert!(
        alerts(&pos_res),
        "use-after-free with custom deallocator must alert"
    );

    // Negative: freed without reuse -> SILENT
    let neg_file = vec![(
        "neg.c".into(),
        concat!(
            "#include <stdlib.h>\n",
            "extern void custom_arena_free(char *p);\n",
            "void test() {\n",
            "    char *p = malloc(16);\n",
            "    p[0] = 1;\n",
            "    custom_arena_free(p);\n",
            "}\n",
        )
        .into(),
        "c".into(),
    )];
    let neg_res = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&neg_res),
        "safe deallocation must stay silent: {:?}",
        neg_res.checker
    );
}

// ── Dimension 8: Cryptographic Rules ──────────────────────────────────────
#[test]
fn test_dim_08_cryptographic_rules_weak_cipher() {
    let facts = make_bundle(vec![LearnedFactEntry::WeakCrypto(WeakCryptoFact {
        rule_id: "weak_crypto_custom".into(),
        call: "initCustomCipher".into(),
        selector_slot: Some(0),
        weak_selectors: vec!["des".into(), "rc4".into()],
    })]);

    let cfg = TaintConfig::default();

    // Baseline: without bundle, unknown API does NOT alert
    let pos_file = vec![(
        "pos.js".into(),
        "function setup(data) { return initCustomCipher('des'); }".into(),
        "js".into(),
    )];
    let baseline = scan(&pos_file, &cfg, &FactTable::default());
    assert!(
        !alerts(&baseline),
        "baseline must stay silent on unknown cipher API"
    );

    // Positive: uses banned 'des' with learned bundle -> ALERTS
    let pos_res = scan(&pos_file, &cfg, &facts);
    assert!(
        alerts(&pos_res),
        "banned cryptographic primitive must alert"
    );
    assert_eq!(pos_res.checker[0].rule, "weak_crypto_custom");
    assert_eq!(pos_res.checker[0].provenance, Provenance::Learned);

    // Negative: uses secure 'aes256' -> SILENT
    let neg_file = vec![(
        "neg.js".into(),
        "function setup(data) { return initCustomCipher('aes256'); }".into(),
        "js".into(),
    )];
    let neg_res = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&neg_res),
        "secure cryptographic primitive must stay silent: {:?}",
        neg_res.checker
    );
}

// ── Dimension 9: Authorization Guards ─────────────────────────────────────
#[test]
fn test_dim_09_authorization_guards_containment_bypass() {
    let facts = make_bundle(vec![
        LearnedFactEntry::GuardBypass(GuardBypassFact {
            containment_callees: vec!["customSubstrMatch".into()],
            credential_sinks: vec![],
            credential_params: vec![],
        }),
        LearnedFactEntry::GuardDenylistPattern {
            pattern: "/internal/".into(),
        },
    ]);

    let cfg = TaintConfig::default();

    // Positive: allowlist validation by substring containment -> ALERTS
    let pos_file = vec![(
        "pos.ts".into(),
        concat!(
            "export const isRedirectAllowed = (url: string) => {\n",
            "    return url.customSubstrMatch('https://allowed.com');\n",
            "}\n",
        )
        .into(),
        "ts".into(),
    )];
    let pos_res = scan(&pos_file, &cfg, &facts);
    assert!(
        alerts(&pos_res),
        "substring allowlist containment guard must alert"
    );
    assert_eq!(pos_res.checker[0].rule, "substring_allowlist_guard");

    // Negative: exact origin comparison -> SILENT
    let neg_file = vec![(
        "neg.ts".into(),
        concat!(
            "export const isRedirectAllowed = (url: string) => {\n",
            "    return parseOrigin(url) === 'https://allowed.com';\n",
            "}\n",
        )
        .into(),
        "ts".into(),
    )];
    let neg_res = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&neg_res),
        "exact origin check must stay silent: {:?}",
        neg_res.checker
    );
}

// ── Dimension 10: Schema Validation ───────────────────────────────────────
#[test]
fn test_dim_10_schema_validation_custom_enforcer() {
    let facts = make_bundle(vec![LearnedFactEntry::SchemaPolicy(SchemaPolicyFact {
        builders: vec!["customQuantity".into()],
        enforcers: vec!["customClamp".into()],
        bound_keywords: vec!["limit".into()],
    })]);

    let cfg = TaintConfig::default();

    // Positive: schema declares bound in prose without enforcement -> ALERTS
    let pos_file = vec![(
        "pos.ts".into(),
        concat!(
            "import { z } from 'zod';\n",
            "export const schema = {\n",
            "    count: builder.customQuantity().describe('limit 20')\n",
            "};\n",
        )
        .into(),
        "ts".into(),
    )];
    let pos_res = scan(&pos_file, &cfg, &facts);
    assert!(
        alerts(&pos_res),
        "unenforced schema bound must alert under learned SchemaPolicy"
    );
    assert_eq!(pos_res.checker[0].rule, "unbounded_number_schema");

    // Negative: schema uses learned customClamp enforcer -> SILENT
    let neg_file = vec![(
        "neg.ts".into(),
        concat!(
            "import { z } from 'zod';\n",
            "export const schema = {\n",
            "    count: builder.customQuantity().customClamp(20).describe('limit 20')\n",
            "};\n",
        )
        .into(),
        "ts".into(),
    )];
    let neg_res = scan(&neg_file, &cfg, &facts);
    assert!(
        !alerts(&neg_res),
        "enforced schema bound must stay silent: {:?}",
        neg_res.checker
    );
}

// ── Dimension 11: Grammar Syntax ──────────────────────────────────────────
#[test]
fn test_dim_11_grammar_syntax_role_mapping() {
    let facts = make_bundle(vec![
        LearnedFactEntry::GrammarRole {
            language: "javascript".into(),
            node_kind: "custom_iteration_statement".into(),
            role: TeachableNodeRole::Loop,
        },
        LearnedFactEntry::GrammarRole {
            language: "python".into(),
            node_kind: "yield_expression".into(),
            role: TeachableNodeRole::Return,
        },
    ]);

    assert_eq!(
        facts.get_grammar_role("javascript", "custom_iteration_statement"),
        Some(&frensense_lang::NodeRole::Loop)
    );
    assert_eq!(
        facts.get_grammar_role("python", "yield_expression"),
        Some(&frensense_lang::NodeRole::Return)
    );
    assert_eq!(facts.get_grammar_role("javascript", "unknown_node"), None);
}

// ── Dimension 12: Grammar Features ────────────────────────────────────────
#[test]
fn test_dim_12_grammar_features_template_strings() {
    let facts = make_bundle(vec![
        LearnedFactEntry::GrammarFeature {
            language: "javascript".into(),
            node_kind: "template_string".into(),
            feature: GrammarFeature::TemplateString,
        },
        LearnedFactEntry::GrammarFeature {
            language: "javascript".into(),
            node_kind: "as_expression".into(),
            feature: GrammarFeature::Cast,
        },
    ]);

    assert_eq!(
        facts.has_grammar_feature(
            "javascript",
            "template_string",
            GrammarFeature::TemplateString
        ),
        Some(true)
    );
    assert_eq!(
        facts.has_grammar_feature("javascript", "as_expression", GrammarFeature::Cast),
        Some(true)
    );
    assert_eq!(
        facts.has_grammar_feature("javascript", "template_string", GrammarFeature::Cast),
        None
    );
}

// ── Dimension 13: IDOR & Multi-Tenancy ─────────────────────────────────────
#[test]
fn test_dim_13_idor_finder_sinks_and_tenant_keys() {
    let facts = make_bundle(vec![
        LearnedFactEntry::IdorFinderSink {
            call: "findCompanyRecord".into(),
            keys: vec!["organization_id".into(), "tenant_id".into()],
        },
        LearnedFactEntry::IdorKey {
            key: "workspace_id".into(),
        },
    ]);

    let cfg = TaintConfig {
        sources: ["req.body".into()].into_iter().collect(),
        sinks: ["findCompanyRecord".into()].into_iter().collect(),
        sanitizers: Default::default(),
    };

    // Positive: untrusted data flows into query object field with IDOR key -> ALERTS with IDOR classification
    let pos_file = vec![(
        "app.js".into(),
        concat!(
            "function getRecord(req) {\n",
            "    const query = { tenant_id: req.body };\n",
            "    findCompanyRecord(query);\n",
            "}\n",
        )
        .into(),
        "js".into(),
    )];

    let res = scan(&pos_file, &cfg, &facts);
    assert!(alerts(&res), "IDOR query object must alert");
    assert!(
        res.findings
            .iter()
            .any(|f| f.finding_class == FindingClass::Idor),
        "finding must be classified as FindingClass::Idor; got: {:?}",
        res.findings
            .iter()
            .map(|f| (&f.finding_class, &f.alert))
            .collect::<Vec<_>>()
    );
}
