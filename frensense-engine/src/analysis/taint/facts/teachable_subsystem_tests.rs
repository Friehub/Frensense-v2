// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

use crate::checks::memory_summary::MemorySummaryRegistry;

#[test]
fn test_teachable_allocator_and_deallocator() {
    // Memory vocabulary is pack/bundle-owned (Phase 6.1): the default
    // pack seeds the fact table after the structural spec seed; there is
    // no implicit bootstrap fallback.
    let spec = frensense_lang::spec_for_ext("c").expect("c spec");
    let mut seeded = crate::analysis::taint::facts::fact_table_from_spec(spec);
    seeded.merge(&crate::analysis::taint::facts::default_pack_table());
    let seeded_reg = MemorySummaryRegistry::from_facts(&seeded);
    assert!(seeded_reg.returns_fresh("malloc"));
    assert!(seeded_reg.returns_fresh("calloc"));
    assert_eq!(seeded_reg.consumes_params("free"), &[0]);
    assert!(!seeded_reg.returns_fresh("custom_arena_alloc"));

    // A bare table carries no vocabulary at all - seeding is the caller's
    // job (`fact_table_from_spec`, exactly like a production scan).
    let bare_reg = MemorySummaryRegistry::from_facts(&FactTable::default());
    assert!(!bare_reg.returns_fresh("malloc"));
    assert!(bare_reg.consumes_params("free").is_empty());

    // Learn custom primitives from a bundle over the spec-seeded table
    // (production merge order: spec first, bundle facts on top).
    let mut table = crate::analysis::taint::facts::fact_table_from_spec(
        frensense_lang::spec_for_ext("c").expect("c spec"),
    );
    table.merge(&crate::analysis::taint::facts::default_pack_table());
    let alloc_fact = LearnedFactEntry::Allocator {
        name: "custom_arena_alloc".into(),
    };
    let dealloc_fact = LearnedFactEntry::Deallocator {
        name: "custom_arena_free".into(),
    };
    alloc_fact.apply(&mut table);
    dealloc_fact.apply(&mut table);

    // MemorySummaryRegistry consumes dynamic facts seamlessly
    let reg = MemorySummaryRegistry::from_facts(&table);
    assert!(reg.returns_fresh("custom_arena_alloc"));
    assert_eq!(reg.consumes_params("custom_arena_free"), &[0]);
    // Spec vocabulary intact alongside learned facts.
    assert!(reg.returns_fresh("malloc"));
    assert_eq!(reg.consumes_params("free"), &[0]);
}

#[test]
fn test_teachable_idor_finder_sinks_and_keys() {
    // The engine carries no built-in IDOR vocabulary: which calls are
    // finder sinks and which keys are identity keys comes from the spec
    // (`known_idor_sinks`) or a learned bundle.
    let mut table = FactTable::default();
    assert!(!table.is_idor_finder_sink("find"));
    assert!(!table.is_idor_finder_sink("findOne"));
    assert!(!table.is_idor_key("id"));
    assert!(!table.is_idor_key("where"));

    let spec = frensense_lang::spec_for_ext("ts").expect("ts spec");
    let t = crate::analysis::taint::facts::fact_table_from_spec(spec);
    assert!(t.is_idor_finder_sink("find"));
    assert!(t.is_idor_finder_sink("findOne"));
    assert!(t.is_idor_key("id"));
    assert!(t.is_idor_key("_id"));
    assert!(!t.is_idor_key("where"), "clause wrapper is not identity");

    // Learn custom IDOR sink and keys
    let fact = LearnedFactEntry::IdorFinderSink {
        call: "findCompanyRecord".into(),
        keys: vec!["organization_id".into(), "tenant_id".into()],
    };
    fact.apply(&mut table);

    assert!(table.is_idor_finder_sink("findCompanyRecord"));
    assert!(table.is_idor_key("organization_id"));
    assert!(table.is_idor_key("tenant_id"));
    assert!(!table.is_idor_key("id"), "learned table gains no built-ins");
}

#[test]
fn test_teachable_propagator_rules() {
    let mut table = FactTable::default();
    assert_eq!(table.propagator_input_args("custom_transform"), None);

    let fact = LearnedFactEntry::Propagator {
        call: "custom_transform".into(),
        input_args: vec![0, 2],
        preserves_taint: true,
    };
    fact.apply(&mut table);

    assert_eq!(
        table.propagator_input_args("custom_transform"),
        Some(&[0, 2][..])
    );
    assert_eq!(
        table.propagator_input_args("mod.custom_transform"),
        Some(&[0, 2][..])
    );
}

#[test]
fn test_teachable_guard_denylist_patterns() {
    // Patterns are spec/bundle vocabulary: no built-in default in the
    // engine's empty table, the spec seeds them (path-traversal marker).
    let mut table = FactTable::default();
    assert!(!table.is_guard_denylist("../etc/shadow"));

    let spec = frensense_lang::spec_for_ext("ts").expect("ts spec");
    let seeded = crate::analysis::taint::facts::fact_table_from_spec(spec);
    assert!(seeded.is_guard_denylist("../etc/shadow"));
    assert!(!seeded.is_guard_denylist("/private/vault"));

    let fact = LearnedFactEntry::GuardDenylistPattern {
        pattern: "/private/vault".into(),
    };
    fact.apply(&mut table);

    assert!(table.is_guard_denylist("/private/vault"));
    assert!(
        !table.is_guard_denylist("../etc/shadow"),
        "learned table gains no spec built-ins"
    );
}

#[test]
#[cfg(feature = "serialize")]
fn test_bincode_roundtrip_all_new_variants() {
    let facts = vec![
        LearnedFactEntry::Allocator {
            name: "arena_alloc".into(),
        },
        LearnedFactEntry::Deallocator {
            name: "arena_free".into(),
        },
        LearnedFactEntry::IdorFinderSink {
            call: "query_repo".into(),
            keys: vec!["workspace_id".into()],
        },
        LearnedFactEntry::IdorKey {
            key: "team_id".into(),
        },
        LearnedFactEntry::Propagator {
            call: "format_str".into(),
            input_args: vec![0, 1],
            preserves_taint: true,
        },
        LearnedFactEntry::GuardDenylistPattern {
            pattern: ".env".into(),
        },
    ];

    let bytes = bincode::serialize(&facts).expect("serialization succeeds");
    let decoded: Vec<LearnedFactEntry> =
        bincode::deserialize(&bytes).expect("deserialization succeeds");
    assert_eq!(facts, decoded);
}
