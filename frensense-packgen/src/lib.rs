// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! The default-pack generator (Phase 6.3a).
//!
//! Owns the vocabularies the committed `assets/frensense-default.frc` is
//! built from: the language-agnostic bootstrap tables ([`data`], moved
//! here from the bundler) and the per-language provider vocabularies
//! ([`vocab`], moved here from `frensense-lang` in 6.3b-6.3d, together
//! with the vocabulary types and derivations in [`role_map`]). The
//! bundler embeds the committed asset via `include_bytes!` and only
//! parses it; this crate is its sole generator, and `packgen --check`
//! (plus the drift test here) keeps the asset from going stale.
//!
//! The pack is now the sole source of provider vocabulary: emission is
//! fully static, and `frensense-lang` keeps only mechanism (grammar,
//! node classification, the severity ladder/tag). Scan-time readers
//! (e.g. the lowering harness's route detection) get their vocabulary
//! from the installed [`FactTable`] sections, never from lang.
//!
//! Emission order is the install order `apply_language_entries` expects
//! and must never change without regenerating the asset: the
//! language-agnostic entries first, then one language-keyed section per
//! registered spec, sorted by language name for byte-determinism.

mod data;
mod role_map;
mod vocab;

use frensense_bundler::format::{write_bundle, BundlePayloadV5};
use frensense_engine::analysis::taint::facts::{
    AllocCapacity, GuardBypassFact, HintKind, LearnedFactEntry, SchemaPolicyFact,
};
use frensense_engine::checks::memory_summary::CapacitySpec;

fn owned(vals: &[&str]) -> Vec<String> {
    vals.iter().map(|s| (*s).to_string()).collect()
}

/// The default pack's entries, generated from lang's bootstrap tables.
/// Deterministic (static iteration order) so the committed asset and the
/// drift test agree byte-for-byte.
pub fn default_pack_entries() -> Vec<LearnedFactEntry> {
    let mut entries = vec![
        LearnedFactEntry::GuardBypass(GuardBypassFact {
            containment_callees: owned(data::BOOTSTRAP_CONTAINMENT_CALLEES),
            credential_sinks: owned(data::BOOTSTRAP_CREDENTIAL_SINKS),
            credential_params: owned(data::BOOTSTRAP_CREDENTIAL_PARAMS),
        }),
        LearnedFactEntry::SchemaPolicy(SchemaPolicyFact {
            builders: owned(data::BOOTSTRAP_SCHEMA_BUILDERS),
            enforcers: owned(data::BOOTSTRAP_SCHEMA_ENFORCERS),
            bound_keywords: owned(data::BOOTSTRAP_SCHEMA_KEYWORDS),
        }),
        LearnedFactEntry::SuspiciousHashWrappers {
            calls: owned(data::BOOTSTRAP_SUSPICIOUS_HASH_WRAPPERS),
        },
    ];
    // Hint vocabularies: one entry per table, kind-keyed.
    for (kind, hints) in [
        (HintKind::UrlParam, data::BOOTSTRAP_URL_PARAM_HINTS),
        (HintKind::UrlArg, data::BOOTSTRAP_URL_ARG_HINTS),
        (HintKind::UrlLiteral, data::BOOTSTRAP_URL_LITERAL_HINTS),
        (
            HintKind::SecurityContext,
            data::BOOTSTRAP_SECURITY_CONTEXT_HINTS,
        ),
        (HintKind::AuthGuard, data::BOOTSTRAP_AUTH_GUARD_HINTS),
        (HintKind::JwtAlgorithm, data::BOOTSTRAP_JWT_ALGORITHM_HINTS),
        (
            HintKind::CredentialContext,
            data::BOOTSTRAP_CREDENTIAL_CONTEXT_HINTS,
        ),
    ] {
        entries.push(LearnedFactEntry::Hints {
            kind,
            values: owned(hints),
        });
    }
    // Rule tables: weak hash, insecure config, key size.
    for rule in data::BOOTSTRAP_WEAK_HASH_RULES.iter() {
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
    for rule in data::BOOTSTRAP_INSECURE_CONFIG_SELECTORS.iter() {
        entries.push(LearnedFactEntry::InsecureConfigRule {
            prefix: rule.prefix.clone(),
            selectors: rule.selectors.clone(),
            rule_id: rule.rule_id.clone(),
            severity: rule.severity.clone(),
            message: rule.message.clone(),
        });
    }
    for rule in data::BOOTSTRAP_KEY_SIZE_RULES.iter() {
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
    for rule in data::BOOTSTRAP_INTEGER_OVERFLOW_RULES.iter() {
        entries.push(LearnedFactEntry::IntegerOverflowRule {
            rule: rule.rule_id.clone(),
            wrap_threshold: rule.wrap_threshold,
            severity: rule.severity.clone(),
            message: rule.message.clone(),
        });
    }
    // Buffer builtins: the spatial checker's dest/src/len vocabulary.
    for b in data::BOOTSTRAP_BUFFER_BUILTINS.iter() {
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
    for f in data::BOOTSTRAP_MEMORY_FUNCS.iter() {
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
    // Phase 6.5: the seven structural vocabularies, formerly the bare
    // spec seed's only content (guard denylist via the per-pattern
    // variant bundles already use, the rest one entry per table).
    for pattern in data::BOOTSTRAP_GUARD_DENYLIST {
        entries.push(LearnedFactEntry::GuardDenylistPattern {
            pattern: (*pattern).to_string(),
        });
    }
    entries.push(LearnedFactEntry::StackAllocators {
        values: owned(data::BOOTSTRAP_STACK_ALLOCATORS),
    });
    entries.push(LearnedFactEntry::CollectionConstructors {
        values: owned(data::BOOTSTRAP_COLLECTION_CONSTRUCTORS),
    });
    entries.push(LearnedFactEntry::SchemaDescribeMethods {
        values: owned(data::BOOTSTRAP_SCHEMA_DESCRIBE_METHODS),
    });
    entries.push(LearnedFactEntry::NullTokens {
        values: owned(data::BOOTSTRAP_NULL_TOKENS),
    });
    entries.push(LearnedFactEntry::SessionAccessors {
        values: owned(data::BOOTSTRAP_SESSION_ACCESSORS),
    });
    entries.push(LearnedFactEntry::ReceiverParams {
        values: owned(data::BOOTSTRAP_RECEIVER_PARAMS),
    });
    // Phase 6.2: one language-keyed section per language, installed by
    // `apply_language_entries` filtered to the scan's languages (the
    // language-agnostic variants above stay shared). Sorted by language
    // name for byte-determinism. Phase 6.3c: every language emits from
    // the generator's static vocabulary; 6.3d deleted lang's provider
    // bodies, so this static path is the only path.
    for v in vocab::all_vocab() {
        entries.extend(vocab::entries_for_static(v));
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

/// [`default_pack_entries`] encoded alone as raw bytes.
///
/// Engine tests use this to merge the real pack across the
/// engine<->bundler dev-dependency cycle: only `Vec<u8>` crosses the
/// cycle, never engine-typed values (which would hit duplicate crate
/// units), and the engine decodes with its own `LearnedFactEntry` serde
/// impls from the same source (Phase 6.1).
pub fn default_pack_entry_bytes() -> Vec<u8> {
    bincode::serialize(&default_pack_entries())
        .unwrap_or_else(|e| panic!("default pack entries serialization failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use frensense_bundler::format::{default_bundle_bytes, default_pack};
    use frensense_engine::analysis::taint::config::TaintConfig;
    use frensense_engine::analysis::taint::facts::{
        apply_language_entries, fact_table_from_entries, fact_table_from_entries_with,
        tables_from_exts, FactTable, LearnedFactEntry, Provenance,
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
            LearnedFactEntry::LanguageAmbiguousVerbs { .. }
        )));
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

    /// Phase 6.1: the spec seed for these tables was deleted, so the
    /// default pack is their sole source. For every extension the bare
    /// spec seed must contribute nothing, and merging the pack must
    /// reproduce the pack's own tables exactly (family-independent
    /// vocabulary).
    #[test]
    fn default_pack_is_the_sole_source_of_the_vacated_tables() {
        let pack =
            fact_table_from_entries_with(default_pack().learned_facts.as_slice(), Provenance::Spec);
        for ext in ["ts", "tsx", "js", "py", "go", "rs"] {
            let (_, spec) = tables_from_exts([ext]);
            let (_, mut with_pack) = tables_from_exts([ext]);
            with_pack.merge(&pack);

            assert!(
                spec.containment_callees.is_empty(),
                "spec still seeds containment_callees for {ext}"
            );
            assert!(
                spec.credential_sinks.is_empty(),
                "spec still seeds credential_sinks for {ext}"
            );
            assert!(
                spec.credential_params.is_empty(),
                "spec still seeds credential_params for {ext}"
            );
            assert!(
                spec.schema_builders.is_empty(),
                "spec still seeds schema_builders for {ext}"
            );
            assert!(
                spec.schema_keywords.is_empty(),
                "spec still seeds schema_keywords for {ext}"
            );
            assert!(
                spec.schema_enforcers.is_empty(),
                "spec still seeds schema_enforcers for {ext}"
            );
            assert!(
                spec.integer_overflow_rules.is_empty(),
                "spec still seeds IO rules for {ext}"
            );
            assert!(
                spec.url_param_hints.is_empty(),
                "spec still seeds url_param_hints for {ext}"
            );
            assert!(
                spec.url_arg_hints.is_empty(),
                "spec still seeds url_arg_hints for {ext}"
            );
            assert!(
                spec.url_literal_hints.is_empty(),
                "spec still seeds url_literal_hints for {ext}"
            );
            assert!(
                spec.security_context_hints.is_empty(),
                "spec still seeds security_context_hints for {ext}"
            );
            assert!(
                spec.auth_guard_hints.is_empty(),
                "spec still seeds auth_guard_hints for {ext}"
            );
            assert!(
                spec.jwt_algorithm_hints.is_empty(),
                "spec still seeds jwt_algorithm_hints for {ext}"
            );
            assert!(
                spec.credential_context_hints.is_empty(),
                "spec still seeds credential_context_hints for {ext}"
            );
            assert!(
                spec.weak_hash_rules.is_empty(),
                "spec still seeds weak_hash_rules for {ext}"
            );
            assert!(
                spec.insecure_config_selectors.is_empty(),
                "spec still seeds insecure_config_selectors for {ext}"
            );
            assert!(
                spec.key_size_rules.is_empty(),
                "spec still seeds key_size_rules for {ext}"
            );
            assert!(
                spec.suspicious_hash_wrappers.is_empty(),
                "spec still seeds suspicious_hash_wrappers for {ext}"
            );
            assert!(
                spec.memory_functions.is_empty(),
                "spec still seeds memory_functions for {ext}"
            );
            assert!(
                spec.buffer_builtins.is_empty(),
                "spec still seeds buffer_builtins for {ext}"
            );
            // Phase 6.5: the seven structural vocabularies moved from the
            // spec seed into the pack - the bare seed now carries no data
            // at all.
            assert!(
                spec.guard_denylist_patterns.is_empty(),
                "spec still seeds guard_denylist_patterns for {ext}"
            );
            assert!(
                spec.stack_allocators.is_empty(),
                "spec still seeds stack_allocators for {ext}"
            );
            assert!(
                spec.collection_constructors.is_empty(),
                "spec still seeds collection_constructors for {ext}"
            );
            assert!(
                spec.schema_describe_methods.is_empty(),
                "spec still seeds schema_describe_methods for {ext}"
            );
            assert!(
                spec.null_tokens.is_empty(),
                "spec still seeds null_tokens for {ext}"
            );
            assert!(
                spec.session_accessors.is_empty(),
                "spec still seeds session_accessors for {ext}"
            );
            assert!(
                spec.receiver_params.is_empty(),
                "spec still seeds receiver_params for {ext}"
            );

            assert_eq!(
                with_pack.containment_callees, pack.containment_callees,
                "containment_callees drifted for {ext}"
            );
            assert_eq!(
                with_pack.credential_sinks, pack.credential_sinks,
                "credential_sinks drifted for {ext}"
            );
            assert_eq!(
                with_pack.credential_params, pack.credential_params,
                "credential_params drifted for {ext}"
            );
            assert_eq!(
                with_pack.schema_builders, pack.schema_builders,
                "schema_builders drifted for {ext}"
            );
            assert_eq!(
                with_pack.schema_keywords, pack.schema_keywords,
                "schema_keywords drifted for {ext}"
            );
            assert_eq!(
                with_pack.schema_enforcers, pack.schema_enforcers,
                "schema_enforcers drifted for {ext}"
            );
            assert_eq!(
                io_ids(&with_pack),
                io_ids(&pack),
                "IO rules drifted for {ext}"
            );
            assert_eq!(
                with_pack.url_param_hints, pack.url_param_hints,
                "url_param_hints drifted for {ext}"
            );
            assert_eq!(
                with_pack.url_arg_hints, pack.url_arg_hints,
                "url_arg_hints drifted for {ext}"
            );
            assert_eq!(
                with_pack.url_literal_hints, pack.url_literal_hints,
                "url_literal_hints drifted for {ext}"
            );
            assert_eq!(
                with_pack.security_context_hints, pack.security_context_hints,
                "security_context_hints drifted for {ext}"
            );
            assert_eq!(
                with_pack.auth_guard_hints, pack.auth_guard_hints,
                "auth_guard_hints drifted for {ext}"
            );
            assert_eq!(
                with_pack.jwt_algorithm_hints, pack.jwt_algorithm_hints,
                "jwt_algorithm_hints drifted for {ext}"
            );
            assert_eq!(
                with_pack.credential_context_hints, pack.credential_context_hints,
                "credential_context_hints drifted for {ext}"
            );
            assert_eq!(
                with_pack.weak_hash_rules, pack.weak_hash_rules,
                "weak_hash_rules drifted for {ext}"
            );
            assert_eq!(
                with_pack.insecure_config_selectors, pack.insecure_config_selectors,
                "insecure_config_selectors drifted for {ext}"
            );
            assert_eq!(
                with_pack.key_size_rules, pack.key_size_rules,
                "key_size_rules drifted for {ext}"
            );
            assert_eq!(
                with_pack.suspicious_hash_wrappers, pack.suspicious_hash_wrappers,
                "suspicious_hash_wrappers drifted for {ext}"
            );
            assert_eq!(
                with_pack.buffer_builtins, pack.buffer_builtins,
                "buffer_builtins drifted for {ext}"
            );
            assert_eq!(
                with_pack.memory_functions, pack.memory_functions,
                "memory_functions drifted for {ext}"
            );
            assert_eq!(
                with_pack.guard_denylist_patterns, pack.guard_denylist_patterns,
                "guard_denylist_patterns drifted for {ext}"
            );
            assert_eq!(
                with_pack.stack_allocators, pack.stack_allocators,
                "stack_allocators drifted for {ext}"
            );
            assert_eq!(
                with_pack.collection_constructors, pack.collection_constructors,
                "collection_constructors drifted for {ext}"
            );
            assert_eq!(
                with_pack.schema_describe_methods, pack.schema_describe_methods,
                "schema_describe_methods drifted for {ext}"
            );
            assert_eq!(
                with_pack.null_tokens, pack.null_tokens,
                "null_tokens drifted for {ext}"
            );
            assert_eq!(
                with_pack.session_accessors, pack.session_accessors,
                "session_accessors drifted for {ext}"
            );
            assert_eq!(
                with_pack.receiver_params, pack.receiver_params,
                "receiver_params drifted for {ext}"
            );
            assert_eq!(
                MemorySummaryRegistry::from_facts(&with_pack).summaries,
                MemorySummaryRegistry::from_facts(&pack).summaries,
                "memory summaries drifted for {ext}"
            );
        }
    }

    /// Phase 6.2d/6.3d/6.5 sole-source contract: lang no longer declares
    /// any provider or structural knowledge (those trait methods are
    /// deleted), so the generator's static vocabularies are the only
    /// source. For every vocabulary the bare [`tables_from_exts`] seed
    /// yields empty source/sink/sanitizer sets and empty provider tables,
    /// and installing that vocabulary's pack sections via
    /// [`apply_language_entries`] is what populates all of them - with
    /// exactly the static values the vocabulary declares (the structural
    /// tables are covered by [`default_pack_is_the_sole_source_of_the_vacated_tables`]).
    #[test]
    fn language_pack_entries_are_the_sole_source_of_provider_knowledge() {
        use crate::role_map::sink_role_for_label;

        // One canonical extension per language key (the bare seed is
        // empty since Phase 6.5; the extension only names the language's
        // spec the pack sections are keyed by).
        fn ext_for(language: &str) -> &str {
            match language {
                "typescript" => "ts",
                "javascript" => "js",
                "python" => "py",
                "rust" => "rs",
                other => other, // c, go
            }
        }

        for v in vocab::all_vocab() {
            let lang = v.language;

            // 1. Bare spec seed: nothing provider-shaped.
            let (bare_config, bare_facts) = tables_from_exts([ext_for(lang)]);
            assert!(
                bare_config.sources.is_empty(),
                "spec seeds sources for {lang}"
            );
            assert!(bare_config.sinks.is_empty(), "spec seeds sinks for {lang}");
            assert!(
                bare_config.sanitizers.is_empty(),
                "spec seeds sanitizers for {lang}"
            );
            assert!(
                bare_facts.sink_signatures.is_empty(),
                "spec seeds sink_signatures for {lang}"
            );
            assert!(
                bare_facts.receiver_roles.is_empty(),
                "spec seeds receiver_roles for {lang}"
            );
            assert!(
                bare_facts.verb_sinks.is_empty(),
                "spec seeds verb_sinks for {lang}"
            );
            assert!(
                bare_facts.client_roots.is_empty(),
                "spec seeds client_roots for {lang}"
            );
            assert!(
                bare_facts.idor_finder_sinks.is_empty(),
                "spec seeds idor_finder_sinks for {lang}"
            );
            assert!(
                bare_facts.idor_keys.is_empty(),
                "spec seeds idor_keys for {lang}"
            );
            assert!(
                bare_facts.session_roots.is_empty(),
                "spec seeds session_roots for {lang}"
            );
            assert!(
                bare_facts.sanitizer_facts.is_empty(),
                "spec seeds sanitizer_facts for {lang}"
            );
            assert!(
                bare_facts.propagators.is_empty(),
                "spec seeds propagators for {lang}"
            );
            assert!(
                bare_facts.propagator_blocks_receiver.is_empty(),
                "spec seeds propagator_blocks_receiver for {lang}"
            );
            assert!(
                bare_facts.route_patterns.is_empty(),
                "spec seeds route_patterns for {lang}"
            );

            // 2. Installing this vocabulary's pack sections is the only
            //    source, and it lands exactly the static values.
            let entries = vocab::entries_for_static(v);
            let mut config = TaintConfig::default();
            let mut facts = FactTable::default();
            apply_language_entries(&mut config, &mut facts, &entries, &[lang]);

            let expected_sources: std::collections::BTreeSet<String> = v
                .source_patterns
                .iter()
                .chain(v.request_param_names.iter())
                .map(|p| (*p).to_string())
                .collect();
            let actual_sources: std::collections::BTreeSet<String> =
                config.sources.iter().cloned().collect();
            assert_eq!(
                actual_sources, expected_sources,
                "sources differ for {lang}"
            );

            let expected_sinks: std::collections::BTreeSet<String> = v
                .sink_names
                .iter()
                .map(|(call, _)| call.rsplit('.').next().unwrap_or(call).to_string())
                .collect();
            let actual_sinks: std::collections::BTreeSet<String> =
                config.sinks.iter().cloned().collect();
            assert_eq!(actual_sinks, expected_sinks, "sinks differ for {lang}");

            let expected_sanitizers: std::collections::BTreeSet<String> =
                v.sanitizer_names.iter().map(|s| (*s).to_string()).collect();
            let actual_sanitizers: std::collections::BTreeSet<String> =
                config.sanitizers.iter().cloned().collect();
            assert_eq!(
                actual_sanitizers, expected_sanitizers,
                "sanitizers differ for {lang}"
            );

            assert!(
                !facts.sink_signatures.is_empty(),
                "pack install must populate sink_signatures for {lang}"
            );
            assert!(
                !facts.sanitizer_facts.is_empty(),
                "pack install must populate sanitizer_facts for {lang}"
            );

            // 3. Spot-check the sink signatures the pack installed: every
            //    vocabulary sink name resolves under its full path with
            //    the mapped role, every per-slot rule keeps its slots, and
            //    the last segment resolves to some signature (bare-wins
            //    rule: a dotted entry's last segment may carry a different
            //    role when a bare entry owns the shared name).
            for (call, label) in v.sink_names {
                let last = call.rsplit('.').next().unwrap_or(call);
                let sig = facts
                    .sink_signature(call)
                    .unwrap_or_else(|| panic!("{call} must be a sink for {lang}"));
                assert_eq!(
                    sig.role,
                    sink_role_for_label(*label),
                    "role for {call} ({lang})"
                );
                assert!(
                    facts.sink_signature(last).is_some(),
                    "last-segment alias for {call} ({lang}) must resolve"
                );
            }
            for (call, slots, binding_safe) in v.sink_signatures {
                let sig = facts
                    .sink_signature(call)
                    .unwrap_or_else(|| panic!("{call} must have a signature for {lang}"));
                let expected_slots: std::collections::BTreeSet<usize> =
                    slots.iter().copied().collect();
                let actual_slots: std::collections::BTreeSet<usize> =
                    sig.dangerous_args.iter().copied().collect();
                assert_eq!(
                    actual_slots, expected_slots,
                    "dangerous args for {call} ({lang})"
                );
                assert_eq!(
                    sig.binding_args_safe, *binding_safe,
                    "binding safety for {call} ({lang})"
                );
            }
            for (call, keys) in v.idor_sinks {
                assert!(
                    facts.is_idor_finder_sink(call),
                    "{call} must be an IDOR finder sink for {lang}"
                );
                for key in keys.iter() {
                    assert!(
                        facts.is_idor_key(key),
                        "{key} must be an identity key for {lang}"
                    );
                }
            }
            for root in v.session_roots {
                assert!(
                    facts.session_roots.contains(*root),
                    "{root} must be a session root for {lang}"
                );
            }
            for prop in v.propagators {
                assert!(
                    facts.propagators.contains_key(prop.call),
                    "{} must be a propagator for {lang}",
                    prop.call
                );
            }

            // Route patterns: the pack must carry exactly what the
            // vocabulary declares, keyed by language name.
            let expected: Vec<String> = v.route_patterns.iter().map(|p| (*p).to_string()).collect();
            let actual = facts.route_patterns.get(lang).cloned().unwrap_or_default();
            assert_eq!(actual, expected, "route_patterns differ for {lang}");

            // Ambiguous verbs (Phase 6.6): this language's pack-declared
            // verb list arms receiver gating while its dotted sink
            // entries install - `verb_sinks` and `client_roots` must hold
            // exactly the dotted sinks whose last segment is one of them
            // (the bare spec seed stays empty; step 1 asserted that).
            let expected_verbs: std::collections::BTreeSet<String> = v
                .sink_names
                .iter()
                .filter(|(call, _)| {
                    let last = call.rsplit('.').next().unwrap_or(call);
                    last != *call && v.ambiguous_verbs.contains(&last)
                })
                .map(|(call, _)| call.rsplit('.').next().unwrap_or(call).to_string())
                .collect();
            let expected_roots: std::collections::BTreeSet<String> = v
                .sink_names
                .iter()
                .filter(|(call, _)| {
                    let last = call.rsplit('.').next().unwrap_or(call);
                    last != *call && v.ambiguous_verbs.contains(&last)
                })
                .map(|(call, _)| call.split('.').next().unwrap_or(call).to_string())
                .collect();
            let actual_verbs: std::collections::BTreeSet<String> =
                facts.verb_sinks.iter().cloned().collect();
            let actual_roots: std::collections::BTreeSet<String> =
                facts.client_roots.iter().cloned().collect();
            assert_eq!(actual_verbs, expected_verbs, "verb_sinks differ for {lang}");
            assert_eq!(
                actual_roots, expected_roots,
                "client_roots differ for {lang}"
            );
        }
    }
}
