// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! The embedded default pack (Phase 5.2 / decision D1, extended in Phase 6).
//!
//! `frensense-lang`'s bootstrap policy tables re-shipped as a `.frc`
//! bundle, embedded in the bundler and merged between the spec seed and
//! the consumer bundle (seeding order: spec -> default pack -> consumer,
//! last-wins). Both consumers - the bundler gate's per-family tables and
//! the CLI scan runner - merge it with [`Provenance::Spec`], so consumer
//! bundle facts still win and provenance reporting stays truthful.
//!
//! Coverage: the full bootstrap policy cluster (guard/schema
//! vocabularies, hint vocabularies, integer-overflow, weak-hash,
//! insecure-config, key-size and suspicious-wrapper rules), memory
//! contracts, and the buffer builtin vocabulary - everything the
//! spec-seeded `known_*` methods provided for these tables, so Phase 6
//! can delete them from `frensense-lang` without changing a check
//! verdict.

use frensense_engine::analysis::taint::facts::{
    GuardBypassFact, HintKind, LearnedFactEntry, SchemaPolicyFact,
};
use frensense_engine::checks::memory_summary::CapacitySpec;
use frensense_lang::memory::{
    bootstrap_buffer_builtins, bootstrap_memory_functions, AllocCapacity,
};
use frensense_lang::policy::{
    bootstrap_auth_guard_hints, bootstrap_containment_callees, bootstrap_credential_context_hints,
    bootstrap_credential_params, bootstrap_credential_sinks, bootstrap_insecure_config_selectors,
    bootstrap_integer_overflow_rules, bootstrap_jwt_algorithm_hints, bootstrap_key_size_rules,
    bootstrap_schema_builders, bootstrap_schema_enforcers, bootstrap_schema_keywords,
    bootstrap_security_context_hints, bootstrap_suspicious_hash_wrappers, bootstrap_url_arg_hints,
    bootstrap_url_literal_hints, bootstrap_url_param_hints, bootstrap_weak_hash_rules,
};
use std::sync::OnceLock;

use super::{load_bundle, write_bundle, BundlePayloadV5, LoadedBundle};

fn owned(vals: &[&str]) -> Vec<String> {
    vals.iter().map(|s| (*s).to_string()).collect()
}

/// The default pack's entries, generated from lang's bootstrap tables.
/// Deterministic (static iteration order) so the committed asset and the
/// drift test agree byte-for-byte.
pub fn default_pack_entries() -> Vec<LearnedFactEntry> {
    let mut entries = vec![
        LearnedFactEntry::GuardBypass(GuardBypassFact {
            containment_callees: owned(bootstrap_containment_callees()),
            credential_sinks: owned(bootstrap_credential_sinks()),
            credential_params: owned(bootstrap_credential_params()),
        }),
        LearnedFactEntry::SchemaPolicy(SchemaPolicyFact {
            builders: owned(bootstrap_schema_builders()),
            enforcers: owned(bootstrap_schema_enforcers()),
            bound_keywords: owned(bootstrap_schema_keywords()),
        }),
        LearnedFactEntry::SuspiciousHashWrappers {
            calls: owned(bootstrap_suspicious_hash_wrappers()),
        },
    ];
    // Hint vocabularies: one entry per table, kind-keyed.
    for (kind, hints) in [
        (HintKind::UrlParam, bootstrap_url_param_hints()),
        (HintKind::UrlArg, bootstrap_url_arg_hints()),
        (HintKind::UrlLiteral, bootstrap_url_literal_hints()),
        (
            HintKind::SecurityContext,
            bootstrap_security_context_hints(),
        ),
        (HintKind::AuthGuard, bootstrap_auth_guard_hints()),
        (HintKind::JwtAlgorithm, bootstrap_jwt_algorithm_hints()),
        (
            HintKind::CredentialContext,
            bootstrap_credential_context_hints(),
        ),
    ] {
        entries.push(LearnedFactEntry::Hints {
            kind,
            values: owned(hints),
        });
    }
    // Rule tables: weak hash, insecure config, key size.
    for rule in bootstrap_weak_hash_rules().iter() {
        entries.push(LearnedFactEntry::WeakPrimitiveRule {
            rule_id: rule.rule_id.clone(),
            selector_calls: rule.selector_calls.clone(),
            bare_calls: rule.bare_calls.clone(),
            selector_slot: rule.selector_slot,
            weak_selectors: rule.weak_selectors.clone(),
            requires_credential_context: rule.requires_credential_context,
            severity: rule.severity.clone(),
            message: rule.message.clone(),
        });
    }
    for rule in bootstrap_insecure_config_selectors().iter() {
        entries.push(LearnedFactEntry::InsecureConfigRule {
            prefix: rule.prefix.clone(),
            selectors: rule.selectors.clone(),
            rule_id: rule.rule_id.clone(),
            severity: rule.severity.clone(),
            message: rule.message.clone(),
        });
    }
    for rule in bootstrap_key_size_rules().iter() {
        entries.push(LearnedFactEntry::KeySizeRule {
            rule_id: rule.rule_id.clone(),
            call: rule.call.clone(),
            slot: rule.slot,
            min_bits: rule.min_bits,
            kind: rule.kind.clone(),
            severity: rule.severity.clone(),
            message: rule.message.clone(),
        });
    }
    for rule in bootstrap_integer_overflow_rules().iter() {
        entries.push(LearnedFactEntry::IntegerOverflowRule {
            rule: rule.rule_id.clone(),
            wrap_threshold: rule.wrap_threshold,
            severity: rule.severity.clone(),
            message: rule.message.clone(),
        });
    }
    // Buffer builtins: the spatial checker's dest/src/len vocabulary.
    for b in bootstrap_buffer_builtins().iter() {
        entries.push(LearnedFactEntry::BufferBuiltin {
            name: b.name.clone(),
            dst_arg: b.dst_arg,
            src_arg: b.src_arg,
            len_arg: b.len_arg,
        });
    }
    // Same capacity mapping as `MemorySummaryRegistry::from_vocabulary`, so
    // the contract entries produce identical summaries when layered over
    // the spec-seeded vocabulary.
    for f in bootstrap_memory_functions().iter() {
        entries.push(LearnedFactEntry::MemoryContract {
            name: f.name.to_string(),
            returns_fresh: f.returns_fresh,
            return_capacity: match f.capacity {
                AllocCapacity::Unknown => CapacitySpec::Unknown,
                AllocCapacity::Param(n) => CapacitySpec::Param(n),
                AllocCapacity::ParamProduct(a, b) => CapacitySpec::ParamProduct(a, b),
            },
            consumes_params: f.consumes_params.to_vec(),
        });
    }
    entries
}

/// Serialize [`default_pack_entries`] into the `.frc` envelope (v5, zero
/// patterns, empty `policy_pack`). Used by the drift/regeneration tests;
/// production reads the committed asset via [`default_bundle_bytes`].
pub fn build_default_bundle() -> Vec<u8> {
    let payload = BundlePayloadV5 {
        patterns: Vec::new(),
        learned_facts: default_pack_entries(),
        policy_pack: Vec::new(),
    };
    write_bundle(&payload, 0).unwrap_or_else(|e| panic!("default pack serialization failed: {e}"))
}

/// Bytes of the committed `assets/frensense-default.frc`.
pub fn default_bundle_bytes() -> &'static [u8] {
    include_bytes!("../../assets/frensense-default.frc")
}

/// The embedded default pack, parsed once. Panics only if the committed
/// asset is stale or corrupt - the drift test in this module keeps that
/// from reaching a release.
pub fn default_pack() -> &'static LoadedBundle {
    static PACK: OnceLock<LoadedBundle> = OnceLock::new();
    PACK.get_or_init(|| {
        load_bundle(default_bundle_bytes())
            .unwrap_or_else(|e| panic!("embedded default pack failed to load: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use frensense_engine::analysis::taint::facts::{
        fact_table_from_entries, fact_table_from_entries_with, tables_from_exts, FactTable,
        Provenance,
    };
    use frensense_engine::checks::memory_summary::MemorySummaryRegistry;

    /// The committed asset must be exactly what the generator produces.
    /// On failure run:
    /// `cargo test -p frensense-bundler regenerate_default_pack_asset -- --ignored`
    #[test]
    fn committed_asset_matches_generated_bytes() {
        assert_eq!(
            build_default_bundle(),
            default_bundle_bytes(),
            "assets/frensense-default.frc is out of date; run regenerate_default_pack_asset"
        );
    }

    /// Regenerate the committed asset from the current bootstrap tables.
    #[test]
    #[ignore = "writes the committed asset; run explicitly when tables change"]
    fn regenerate_default_pack_asset() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("assets")
            .join("frensense-default.frc");
        std::fs::create_dir_all(path.parent().expect("asset dir")).expect("create asset dir");
        std::fs::write(&path, build_default_bundle()).expect("write asset");
    }

    #[test]
    fn default_pack_round_trips_with_expected_entries() {
        let pack = default_pack();
        assert!(pack.patterns.is_empty());
        assert!(pack.policy_pack.is_empty());
        assert!(!pack.learned_facts.is_empty());
        let has = |pred: fn(&LearnedFactEntry) -> bool| pack.learned_facts.iter().any(pred);
        assert!(has(|e| matches!(e, LearnedFactEntry::GuardBypass(_))));
        assert!(has(|e| matches!(e, LearnedFactEntry::SchemaPolicy(_))));
        assert!(has(|e| matches!(
            e,
            LearnedFactEntry::IntegerOverflowRule { .. }
        )));
        assert!(has(|e| matches!(
            e,
            LearnedFactEntry::MemoryContract { .. }
        )));
        assert!(has(|e| matches!(e, LearnedFactEntry::Hints { .. })));
        assert!(has(|e| matches!(
            e,
            LearnedFactEntry::WeakPrimitiveRule { .. }
        )));
        assert!(has(|e| matches!(
            e,
            LearnedFactEntry::InsecureConfigRule { .. }
        )));
        assert!(has(|e| matches!(e, LearnedFactEntry::KeySizeRule { .. })));
        assert!(has(|e| matches!(
            e,
            LearnedFactEntry::SuspiciousHashWrappers { .. }
        )));
        assert!(has(|e| matches!(e, LearnedFactEntry::BufferBuiltin { .. })));
    }

    #[test]
    fn pack_entries_apply_with_spec_provenance() {
        let spec = fact_table_from_entries_with(&default_pack_entries(), Provenance::Spec);
        assert!(spec
            .containment_callees
            .values()
            .all(|p| *p == Provenance::Spec));
        assert!(spec
            .schema_builders
            .values()
            .all(|p| *p == Provenance::Spec));
        assert!(spec
            .integer_overflow_rules
            .iter()
            .all(|(_, p)| *p == Provenance::Spec));

        let learned = fact_table_from_entries(&default_pack_entries());
        assert!(learned
            .containment_callees
            .values()
            .all(|p| *p == Provenance::Learned));
        assert!(learned
            .integer_overflow_rules
            .iter()
            .all(|(_, p)| *p == Provenance::Learned));
    }

    fn io_ids(t: &FactTable) -> Vec<(String, u128, Provenance)> {
        t.integer_overflow_rules
            .iter()
            .map(|(r, p)| (r.rule_id.clone(), r.wrap_threshold, *p))
            .collect()
    }

    /// Merging the pack over the spec seed must not change any value the
    /// checks read (today's tables are the same knowledge by construction).
    #[test]
    fn default_pack_merge_is_value_neutral_over_spec_seed() {
        for ext in ["ts", "tsx", "js", "py", "go", "rs"] {
            let (_, spec) = tables_from_exts([ext]);
            let (_, mut with_pack) = tables_from_exts([ext]);
            with_pack.merge(&fact_table_from_entries_with(
                default_pack().learned_facts.as_slice(),
                Provenance::Spec,
            ));

            assert_eq!(
                spec.containment_callees, with_pack.containment_callees,
                "containment_callees drifted for {ext}"
            );
            assert_eq!(
                spec.credential_sinks, with_pack.credential_sinks,
                "credential_sinks drifted for {ext}"
            );
            assert_eq!(
                spec.credential_params, with_pack.credential_params,
                "credential_params drifted for {ext}"
            );
            assert_eq!(
                spec.schema_builders, with_pack.schema_builders,
                "schema_builders drifted for {ext}"
            );
            assert_eq!(
                spec.schema_keywords, with_pack.schema_keywords,
                "schema_keywords drifted for {ext}"
            );
            assert_eq!(
                spec.schema_enforcers, with_pack.schema_enforcers,
                "schema_enforcers drifted for {ext}"
            );
            assert_eq!(
                io_ids(&spec),
                io_ids(&with_pack),
                "IO rules drifted for {ext}"
            );
            assert_eq!(
                spec.url_param_hints, with_pack.url_param_hints,
                "url_param_hints drifted for {ext}"
            );
            assert_eq!(
                spec.url_arg_hints, with_pack.url_arg_hints,
                "url_arg_hints drifted for {ext}"
            );
            assert_eq!(
                spec.url_literal_hints, with_pack.url_literal_hints,
                "url_literal_hints drifted for {ext}"
            );
            assert_eq!(
                spec.security_context_hints, with_pack.security_context_hints,
                "security_context_hints drifted for {ext}"
            );
            assert_eq!(
                spec.auth_guard_hints, with_pack.auth_guard_hints,
                "auth_guard_hints drifted for {ext}"
            );
            assert_eq!(
                spec.jwt_algorithm_hints, with_pack.jwt_algorithm_hints,
                "jwt_algorithm_hints drifted for {ext}"
            );
            assert_eq!(
                spec.credential_context_hints, with_pack.credential_context_hints,
                "credential_context_hints drifted for {ext}"
            );
            assert_eq!(
                spec.weak_hash_rules, with_pack.weak_hash_rules,
                "weak_hash_rules drifted for {ext}"
            );
            assert_eq!(
                spec.insecure_config_selectors, with_pack.insecure_config_selectors,
                "insecure_config_selectors drifted for {ext}"
            );
            assert_eq!(
                spec.key_size_rules, with_pack.key_size_rules,
                "key_size_rules drifted for {ext}"
            );
            assert_eq!(
                spec.suspicious_hash_wrappers, with_pack.suspicious_hash_wrappers,
                "suspicious_hash_wrappers drifted for {ext}"
            );
            assert_eq!(
                spec.buffer_builtins, with_pack.buffer_builtins,
                "buffer_builtins drifted for {ext}"
            );
            assert_eq!(
                MemorySummaryRegistry::from_facts(&spec).summaries,
                MemorySummaryRegistry::from_facts(&with_pack).summaries,
                "memory summaries drifted for {ext}"
            );
        }
    }
}
