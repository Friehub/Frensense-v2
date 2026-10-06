// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

use crate::analysis::taint::config::TaintConfig;

fn cfg() -> TaintConfig {
    TaintConfig {
        sources: ["req.body".to_string()].into_iter().collect(),
        sinks: ["query".to_string(), "exec".to_string()]
            .into_iter()
            .collect(),
        sanitizers: ["escapeHtml".to_string()].into_iter().collect(),
    }
}

#[test]
fn test_fact_table_defaults_all_args_dangerous() {
    let t = FactTable::from_config(&cfg());
    let sig = t.sink_signature("query").unwrap();
    assert!(sig.is_dangerous(0));
    assert!(sig.is_dangerous(1));
    assert!(sig.is_dangerous(9));
}

#[test]
fn test_parameterized_query_signature() {
    let mut t = FactTable::from_config(&cfg());
    let mut sig = SinkSignature::with_args("query", &[0]);
    sig.binding_args_safe = true;
    t.sink_signatures.insert("query".into(), sig);

    let s = t.sink_signature("query").unwrap();
    assert!(s.is_dangerous(0), "sql template slot is dangerous");
    assert!(
        !s.is_dangerous(1),
        "params array slot is the safe binding channel"
    );
    assert!(s.is_binding(1));
}

#[test]
fn test_merge_learns_over_builtins() {
    let mut t = FactTable::from_config(&cfg());
    assert!(t.sink_signature("query").unwrap().is_dangerous(1));

    let mut learned = FactTable::default();
    let mut sig = SinkSignature::with_args("query", &[0]);
    sig.binding_args_safe = true;
    learned.sink_signatures.insert("query".into(), sig);
    t.merge(&learned);

    assert!(!t.sink_signature("query").unwrap().is_dangerous(1));
}

#[test]
fn test_sanitizer_fact_lookup() {
    let t = FactTable::from_config(&cfg());
    let f = t.sanitizer_fact("escapeHtml").unwrap();
    assert_eq!(f.kind, "encode");
    assert!(t.sanitizer_fact("exec").is_none());
}

#[test]
fn test_verb_sink_receiver_aware() {
    // The JS spec carries dotted client sinks (got.get, axios.post, ...);
    // their bare verb segments must be receiver-aware, not blanket sinks.
    let t = seeded_tables(["ts"]).1;

    assert!(
        t.verb_sinks.contains("get"),
        "dotted got.get registers verb"
    );
    assert!(t.client_roots.contains("got"), "client root from got.get");

    // Known client root: real SSRF channel, sink.
    assert!(t.is_sink_call("get", Some("got")));
    // Arbitrary Map/receiver root: accessor, NOT a sink.
    assert!(!t.is_sink_call("get", Some("authenticatedUsers")));
    // Non-verb sinks match by name regardless of receiver.
    assert!(t.is_sink_call("findOne", Some("anything")));
}

#[test]
fn test_verb_sink_merge_accumulates() {
    let base = seeded_tables(["ts"]).1;
    let mut merged = FactTable::default();
    merged.merge(&base);
    assert!(merged.verb_sinks.contains("post"));
    assert!(merged.client_roots.contains("axios"));
}

#[test]
fn test_last_segment_role_collision_bare_wins() {
    // `decode` (JwtUnsafeDecode) and `msgpack.decode` (UnsafeDeserialize)
    // share a last segment with different roles. The bare entry must keep
    // Validation; a dotted sibling must never silently re-role it.
    let t = seeded_tables(["ts"]).1;
    let sig = t.sink_signature("decode").expect("decode registered");
    assert_eq!(sig.role, crate::analysis::taint::role::SinkRole::Validation);
    // The dotted entry keeps its own role under its full-path key.
    let msgpack = t
        .sink_signature("msgpack.decode")
        .expect("msgpack.decode registered");
    assert_eq!(
        msgpack.role,
        crate::analysis::taint::role::SinkRole::Execution
    );
}

#[test]
fn test_per_slot_signature_inherits_label_role() {
    // Per-slot entries (JS_SINK_SIGNATURES) carry no label of their own;
    // they must inherit the role of the same call's all-args entry.
    let t = seeded_tables(["ts"]).1;
    let query = t.sink_signature("query").expect("query registered");
    assert_eq!(
        query.role,
        crate::analysis::taint::role::SinkRole::Execution
    );
    assert!(
        query.binding_args_safe,
        "parameterized query keeps binding safety"
    );
    let fetch = t.sink_signature("fetch").expect("bare fetch registered");
    assert_eq!(fetch.role, crate::analysis::taint::role::SinkRole::Resource);
}

#[test]
fn test_rust_fetch_single_label() {
    // The Rust spec once declared `fetch` twice (SqlInjection + Ssrf);
    // insertion-order races decided its role. Exactly one label wins now.
    let t = seeded_tables(["rs"]).1;
    let fetch = t.sink_signature("fetch").expect("fetch registered");
    assert_eq!(
        fetch.role,
        crate::analysis::taint::role::SinkRole::Execution
    );
}

#[test]
fn test_receiver_role_disambiguates_dotted_vs_bare() {
    // The JS spec declares dotted KVNamespace.put (StorageWrite) whose
    // last segment collides with the bare HTTP-verb space, and
    // `res.send` (XssReflected) colliding with `Queue.send` (Ssrf).
    // A receiver root matching the dotted entry's declared root must
    // flip the role; an unmatched receiver keeps the bare entry's.
    let t = seeded_tables(["ts"]).1;

    // res.send: receiver `res` matches the dotted root -> XssReflected -> Xss.
    let res_send = t.role_for_call("send", Some("res"));
    assert_eq!(
        res_send,
        Some(crate::analysis::taint::role::SinkRole::Xss),
        "res.send resolves via dotted XssReflected entry"
    );
    // queue.send: receiver `queue` does NOT match `res`'s root, but
    // Queue.send is its own dotted entry with root `Queue` -> Ssrf.
    let queue_send = t.role_for_call("send", Some("Queue"));
    assert_eq!(
        queue_send,
        Some(crate::analysis::taint::role::SinkRole::Resource),
        "Queue.send resolves via dotted Ssrf entry"
    );
    // Unresolvable receiver: falls back to the bare last-segment entry.
    let bare = t.role_for_call("send", None);
    assert!(bare.is_some(), "bare send still a sink");
}

#[test]
fn test_receiver_roles_survive_merge() {
    let base = seeded_tables(["ts"]).1;
    let mut merged = FactTable::default();
    merged.merge(&base);
    let role = merged.role_for_call("put", Some("KVNamespace"));
    assert_eq!(
        role,
        Some(crate::analysis::taint::role::SinkRole::Storage),
        "KVNamespace.put role survives FactTable::merge"
    );
}

#[test]
fn signature_only_sinks_carry_spec_labels() {
    // Sinks declared only in JS_SINK_SIGNATURES used to silently fall back
    // to SinkRole::Other (config.rs inherits the label from the all-args
    // entry, which did not exist for them): `destroy` reported as "other"
    // instead of its query class, pg-promise verbs as "other" instead of
    // SQL. Every sink must resolve a real label.
    let t = seeded_tables(["ts"]).1;
    for call in ["destroy", "findByIdAndUpdate", "findByIdAndDelete"] {
        let sig = t
            .sink_signature(call)
            .unwrap_or_else(|| panic!("{call} must be a sink"));
        assert_eq!(
            sig.role,
            crate::analysis::taint::role::SinkRole::Execution,
            "{call} must carry its NoSqlInjection label, got {:?}",
            sig.role
        );
    }
    for call in ["one", "none"] {
        let sig = t
            .sink_signature(call)
            .unwrap_or_else(|| panic!("{call} must be a sink"));
        assert_eq!(
            sig.role,
            crate::analysis::taint::role::SinkRole::Execution,
            "{call} must carry its SqlInjection label, got {:?}",
            sig.role
        );
    }
}

#[test]
fn generic_promise_verbs_are_not_sinks() {
    // Bare sqlite/pg-promise verb entries (`all`, `any`) matched
    // `Promise.all(...)`/`Promise.any(...)` - ubiquitous, benign JS - as
    // sinks (juice-shop: restoreOverwrittenFilesWithOriginals.ts:26).
    // Until the spec grows an ambiguous-verb + receiver-root vocabulary,
    // these names must not be sinks at all.
    let t = seeded_tables(["ts"]).1;
    assert!(
        !t.is_sink_call("all", Some("Promise")),
        "Promise.all must not be a sink"
    );
    assert!(
        !t.is_sink_call("any", Some("Promise")),
        "Promise.any must not be a sink"
    );
    assert!(
        !t.is_sink_call("all", None),
        "unambiguous bare 'all' stays out of the sink set"
    );
}

#[test]
fn spec_drives_idor_vocabulary() {
    // IDOR finder vocabulary is spec-owned (frensense-lang
    // `known_idor_sinks`), not engine built-ins: the spec says which calls
    // take identity payloads and which top-level keys mark one. Clause
    // wrappers (`where`) are NOT identity keys - a where-wrapped leaf value
    // is a parameterized filter, structurally unprovable as an
    // access-control violation (zero-FP).
    let t = seeded_tables(["ts"]).1;
    for call in [
        "findOne",
        "find",
        "findAll",
        "findOneAndUpdate",
        "findByIdAndUpdate",
        "destroy",
        "count",
        "update",
    ] {
        assert!(
            t.is_idor_finder_sink(call),
            "{call} must be an IDOR finder sink"
        );
    }
    assert!(!t.is_idor_finder_sink("query"));
    assert!(!t.is_idor_finder_sink("eval"));

    for key in ["_id", "id", "owner", "userId", "user"] {
        assert!(t.is_idor_key(key), "{key} must be an identity key");
    }
    assert!(
        !t.is_idor_key("where"),
        "'where' is a clause wrapper, not an identity key"
    );

    let sig = t
        .sink_signature("findOne")
        .expect("findOne must have a signature");
    assert!(
        sig.idor_keys.contains(&"_id".to_string()),
        "findOne signature carries the identity keys"
    );
    assert!(
        !sig.idor_keys.iter().any(|k| k == "where"),
        "findOne signature must not treat 'where' as identity"
    );
    let query = t
        .sink_signature("query")
        .expect("query must have a signature");
    assert!(
        query.idor_keys.is_empty(),
        "non-finder sinks carry no identity gate"
    );
}

#[test]
fn spec_drives_policy_vocabulary() {
    // Guard/credential/schema/URL/weak-crypto policy vocabulary ships in
    // the default pack (Phase 6.1: the lang `known_*` seeds are gone) and
    // is installed by the production seeding order (`seeded_tables`).
    let t = seeded_tables(["ts"]).1;

    for callee in ["includes", "indexOf", "contains"] {
        assert!(
            t.containment_callees.contains_key(callee),
            "{callee} must be a containment callee"
        );
    }
    for sink in ["hash", "hashPassword", "setPassword"] {
        assert!(
            t.credential_sinks.contains_key(sink),
            "{sink} must be a credential sink"
        );
    }
    assert!(t.credential_params.contains_key("password"));
    for builder in ["number", "int", "float", "bigint"] {
        assert!(
            t.schema_builders.contains_key(builder),
            "{builder} must be a schema builder"
        );
    }
    assert!(t.schema_enforcers.contains("max"));
    assert!(t.schema_keywords.contains_key("maximum"));
    assert!(t.url_param_hints.contains("url"));
    assert!(t.url_arg_hints.contains("allowed"));
    assert!(t.url_literal_hints.contains("http"));
    assert!(t.security_context_hints.contains("security"));

    assert!(
        t.weak_hash_rules
            .iter()
            .any(|r| r.selector_calls.iter().any(|c| c == "createHash")),
        "weak-hash rules must include the createHash selector rule"
    );
    assert!(
        t.key_size_rules
            .iter()
            .any(|r| r.call == "generateKeyPair" && r.min_bits == 2048),
        "key-size rules must include the RSA floor"
    );
    assert!(!t.insecure_config_selectors.is_empty());
    assert!(t.suspicious_hash_wrappers.contains("hashPassword"));

    // The pack provides the whole vocabulary the checks union at
    // evaluation time (rank-tied with the spec seed: nothing else seeds
    // these fields anymore).
    assert!(t.containment_callees.contains_key("includes"));
    assert!(t.weak_hash_rules.len() >= 2);
}

/// Phase 2.3: finding identities the bundle advisory join
/// (`BundlePattern::rules`) relies on.
#[test]
fn finding_identities_cover_joinable_entries() {
    assert_eq!(
        LearnedFactEntry::Sink {
            call: "query".to_string(),
            dangerous_args: Default::default(),
            binding_args_safe: false,
        }
        .finding_identities(),
        vec!["query"]
    );
    assert_eq!(
        LearnedFactEntry::Policy {
            rule: "policy_checkout".to_string(),
            when_call: "checkout".to_string(),
            require: vec![],
            scope: PolicyScope::Function,
            message: String::new(),
            severity: String::new(),
        }
        .finding_identities(),
        vec!["policy_checkout"]
    );
    // Entries whose findings use engine-internal rule ids contribute none.
    assert!(
        LearnedFactEntry::Allocator {
            name: "my_alloc".to_string()
        }
        .finding_identities()
        .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Phase 5.3: provenance-ordered merge (Spec < Authored < Learned)
// ---------------------------------------------------------------------------

fn check(rule: &str, call: &str, msg: &str) -> LearnedCheckFact {
    LearnedCheckFact {
        rule: rule.into(),
        call: call.into(),
        message: msg.into(),
        severity: "warning".into(),
        unless_guard: None,
        unless_range_check: None,
    }
}

fn policy(rule: &str, when: &str, msg: &str) -> PolicyFact {
    PolicyFact {
        rule: rule.into(),
        when_call: when.into(),
        require: vec![],
        scope: PolicyScope::Function,
        message: msg.into(),
        severity: "warning".into(),
    }
}

fn iorule(rule: &str, msg: &str) -> IntegerOverflowRule {
    IntegerOverflowRule {
        rule_id: rule.into(),
        wrap_threshold: u64::MAX as u128,
        severity: "warning".into(),
        message: msg.into(),
    }
}

/// Acceptance (Phase 5.3): merging in either direction yields the same
/// higher-ranked (Learned) entry for every provenance-tracked table - the
/// result no longer depends on which table was seeded first.
#[test]
fn provenance_ordered_merge_is_order_independent() {
    let mut spec_side = FactTable::default();
    spec_side
        .learned_checks
        .push((check("r1", "f", "spec"), Provenance::Spec));
    spec_side
        .policy_facts
        .push((policy("p1", "g", "spec"), Provenance::Spec));
    spec_side
        .integer_overflow_rules
        .push((iorule("io1", "spec"), Provenance::Spec));
    spec_side
        .containment_callees
        .insert("f".into(), Provenance::Spec);

    let mut learned_side = FactTable::default();
    learned_side
        .learned_checks
        .push((check("r1", "f", "learned"), Provenance::Learned));
    learned_side
        .policy_facts
        .push((policy("p1", "g", "learned"), Provenance::Learned));
    learned_side
        .integer_overflow_rules
        .push((iorule("io1", "learned"), Provenance::Learned));
    learned_side
        .containment_callees
        .insert("f".into(), Provenance::Learned);

    let mut a = spec_side.clone();
    a.merge(&learned_side);
    let mut b = learned_side.clone();
    b.merge(&spec_side);

    for t in [&a, &b] {
        assert_eq!(t.learned_checks.len(), 1);
        assert_eq!(t.learned_checks[0].0.message, "learned");
        assert_eq!(t.learned_checks[0].1, Provenance::Learned);
        assert_eq!(t.policy_facts.len(), 1);
        assert_eq!(t.policy_facts[0].0.message, "learned");
        assert_eq!(t.policy_facts[0].1, Provenance::Learned);
        assert_eq!(t.integer_overflow_rules.len(), 1);
        assert_eq!(t.integer_overflow_rules[0].0.message, "learned");
        assert_eq!(t.integer_overflow_rules[0].1, Provenance::Learned);
        assert_eq!(t.containment_callees.get("f"), Some(&Provenance::Learned));
    }
}

/// Acceptance (Phase 5.3): a lower-ranked incoming entry never overrides a
/// higher-ranked existing one (today's first-wins never overrode either -
/// the rank rule generalizes it to be tier-aware).
#[test]
fn lower_ranked_incoming_never_overrides() {
    let mut learned = FactTable::default();
    learned
        .learned_checks
        .push((check("r1", "f", "learned"), Provenance::Learned));
    learned
        .policy_facts
        .push((policy("p1", "g", "learned"), Provenance::Learned));
    learned
        .integer_overflow_rules
        .push((iorule("io1", "learned"), Provenance::Learned));
    learned
        .containment_callees
        .insert("f".into(), Provenance::Learned);

    let mut spec = FactTable::default();
    spec.learned_checks
        .push((check("r1", "f", "spec"), Provenance::Spec));
    spec.policy_facts
        .push((policy("p1", "g", "spec"), Provenance::Spec));
    spec.integer_overflow_rules
        .push((iorule("io1", "spec"), Provenance::Spec));
    spec.containment_callees
        .insert("f".into(), Provenance::Spec);

    learned.merge(&spec);
    assert_eq!(learned.learned_checks[0].0.message, "learned");
    assert_eq!(learned.policy_facts[0].0.message, "learned");
    assert_eq!(learned.integer_overflow_rules[0].0.message, "learned");
    assert_eq!(
        learned.containment_callees.get("f"),
        Some(&Provenance::Learned)
    );
}

/// Acceptance (Phase 5.3): equal-rank collisions keep the existing entry,
/// so re-merging the same bundle (or two bundles at one tier) is a no-op.
#[test]
fn equal_provenance_tie_keeps_existing_entry() {
    let mut first = FactTable::default();
    first
        .learned_checks
        .push((check("r1", "f", "first"), Provenance::Learned));
    first
        .policy_facts
        .push((policy("p1", "g", "first"), Provenance::Learned));

    let mut second = FactTable::default();
    second
        .learned_checks
        .push((check("r1", "f", "second"), Provenance::Learned));
    second
        .policy_facts
        .push((policy("p1", "g", "second"), Provenance::Learned));

    first.merge(&second);
    assert_eq!(first.learned_checks.len(), 1);
    assert_eq!(first.learned_checks[0].0.message, "first");
    assert_eq!(first.policy_facts.len(), 1);
    assert_eq!(first.policy_facts[0].0.message, "first");
}
