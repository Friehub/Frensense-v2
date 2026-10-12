// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Bundle payload types.
//!
//! A `.frc` bundle is two things: per-family advisory metadata
//! ([`BundlePattern`]) and the machine-consumable knowledge
//! (`learned_facts`, replay-verified sink/sanitizer facts the engine
//! merges into its fact table).

use frensense_engine::analysis::taint::facts::{AuthoredPolicyEntry, LearnedFactEntry};

use super::frc::{read_bundle_parts, BundleHeader};

/// Per-family advisory metadata.
///
/// The facts pipeline writes one pattern per corpus family
/// carrying the human-facing advisory fields (CWE, CVSS, OWASP, severity).
/// Flow knowledge is NOT here, it is in `learned_facts`, which the engine
/// consumes.
///
/// `rules` is the join back to scanner output: the finding identities
/// (checker rule ids, learned sink names) published from the family, so
/// the consumer's advisory path can attach this metadata to the findings
/// the family's facts cause. v4 bundles predate the join and load with
/// an empty list.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BundlePattern {
    pub id: String,
    #[serde(default)]
    pub observation: Option<String>,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub improvement: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub cvss: Option<f32>,
    #[serde(default)]
    pub owasp: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    /// Finding identities this family's advisory applies to (see the type
    /// docs); filled by the builder from the family's published facts.
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Bundle {
    pub header: BundleHeader,
    pub patterns: Vec<BundlePattern>,
}

/// The v4 payload shape: patterns plus learned facts, no `policy_pack`.
/// Read-only since v5 - kept so v4 bundles keep loading through the
/// version-branched load in [`load_bundle`].
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct V4Payload {
    pub patterns: Vec<V4Pattern>,
    #[serde(default)]
    pub learned_facts: Vec<LearnedFactEntryV5>,
}

/// The v4 per-family advisory shape, frozen: bincode is positional, so
/// widening [`BundlePattern`] (the `rules` join) must not touch bytes
/// v4 bundles already shipped with.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct V4Pattern {
    id: String,
    observation: Option<String>,
    impact: Option<String>,
    improvement: Option<String>,
    cwe: Option<String>,
    cvss: Option<f32>,
    owasp: Option<String>,
    severity: Option<String>,
}

impl From<V4Pattern> for BundlePattern {
    fn from(p: V4Pattern) -> Self {
        BundlePattern {
            id: p.id,
            observation: p.observation,
            impact: p.impact,
            improvement: p.improvement,
            cwe: p.cwe,
            cvss: p.cvss,
            owasp: p.owasp,
            severity: p.severity,
            rules: Vec::new(),
        }
    }
}

/// Frozen v5 layout of `LearnedFactEntry` for deserializing v4 and v5 bundles.
/// Bincode is positional and non-self-describing; adding fields like `package`
/// to `LearnedFactEntry` requires freezing this structure for backwards compatibility.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum LearnedFactEntryV5 {
    Source {
        pattern: String,
    },
    Sink {
        call: String,
        dangerous_args: std::collections::BTreeSet<usize>,
        binding_args_safe: bool,
    },
    Sanitizer {
        call: String,
        kind: String,
        guard_style: bool,
    },
    Policy {
        rule: String,
        when_call: String,
        #[serde(default)]
        require: Vec<frensense_engine::analysis::taint::facts::PolicyRequirement>,
        #[serde(default)]
        scope: frensense_engine::analysis::taint::facts::PolicyScope,
        message: String,
        severity: String,
    },
    Check {
        rule: String,
        call: String,
        message: String,
        severity: String,
        #[serde(default)]
        unless_guard: Option<String>,
        #[serde(default)]
        unless_range_check: Option<Vec<String>>,
    },
    MemoryContract {
        name: String,
        returns_fresh: bool,
        return_capacity: frensense_engine::checks::memory_summary::CapacitySpec,
        consumes_params: Vec<usize>,
    },
    WeakCrypto(frensense_engine::analysis::taint::facts::WeakCryptoFact),
    GuardBypass(frensense_engine::analysis::taint::facts::GuardBypassFact),
    SchemaPolicy(frensense_engine::analysis::taint::facts::SchemaPolicyFact),
    GrammarRole {
        language: String,
        node_kind: String,
        role: frensense_engine::analysis::taint::facts::TeachableNodeRole,
    },
    GrammarFeature {
        language: String,
        node_kind: String,
        feature: frensense_engine::analysis::taint::facts::GrammarFeature,
    },
    Allocator {
        name: String,
    },
    Deallocator {
        name: String,
    },
    IdorFinderSink {
        call: String,
        keys: Vec<String>,
    },
    IdorKey {
        key: String,
    },
    Propagator {
        call: String,
        input_args: Vec<usize>,
        preserves_taint: bool,
    },
    GuardDenylistPattern {
        pattern: String,
    },
    IntegerOverflowRule {
        rule: String,
        wrap_threshold: u128,
        severity: String,
        message: String,
    },
    Hints {
        kind: frensense_engine::analysis::taint::facts::HintKind,
        values: Vec<String>,
    },
    WeakPrimitiveRule {
        rule_id: String,
        selector_calls: Vec<String>,
        bare_calls: Vec<String>,
        selector_slot: usize,
        weak_selectors: Vec<String>,
        requires_credential_context: bool,
        severity: String,
        message: String,
    },
    InsecureConfigRule {
        prefix: String,
        selectors: Vec<String>,
        rule_id: String,
        severity: String,
        message: String,
    },
    KeySizeRule {
        rule_id: String,
        call: String,
        slot: usize,
        min_bits: i64,
        kind: String,
        severity: String,
        message: String,
    },
    SuspiciousHashWrappers {
        calls: Vec<String>,
    },
    BufferBuiltin {
        name: String,
        dst_arg: Option<usize>,
        src_arg: Option<usize>,
        len_arg: usize,
    },
    LanguageSink {
        language: String,
        call: String,
        role: String,
    },
    LanguageSinkSlots {
        language: String,
        call: String,
        dangerous_args: std::collections::BTreeSet<usize>,
        binding_args_safe: bool,
    },
    LanguageIdorSink {
        language: String,
        call: String,
        keys: Vec<String>,
    },
    LanguageSource {
        language: String,
        pattern: String,
    },
    LanguageSanitizer {
        language: String,
        call: String,
        kind: String,
        guard_style: bool,
    },
    LanguagePropagator {
        language: String,
        call: String,
        tainted_arg: Option<usize>,
        tainted_receiver: bool,
    },
    LanguageSessionRoot {
        language: String,
        root: String,
    },
    LanguageRoutePattern {
        language: String,
        pattern: String,
    },
    StackAllocators {
        values: Vec<String>,
    },
    CollectionConstructors {
        values: Vec<String>,
    },
    SchemaDescribeMethods {
        values: Vec<String>,
    },
    NullTokens {
        values: Vec<String>,
    },
    SessionAccessors {
        values: Vec<String>,
    },
    ReceiverParams {
        values: Vec<String>,
    },
    LanguageAmbiguousVerbs {
        language: String,
        values: Vec<String>,
    },
}

impl From<LearnedFactEntryV5> for LearnedFactEntry {
    fn from(v: LearnedFactEntryV5) -> Self {
        match v {
            LearnedFactEntryV5::Source { pattern } => LearnedFactEntry::Source {
                pattern,
                package: None,
            },
            LearnedFactEntryV5::Sink {
                call,
                dangerous_args,
                binding_args_safe,
            } => LearnedFactEntry::Sink {
                call,
                package: None,
                dangerous_args,
                binding_args_safe,
            },
            LearnedFactEntryV5::Sanitizer {
                call,
                kind,
                guard_style,
            } => LearnedFactEntry::Sanitizer {
                call,
                package: None,
                kind,
                guard_style,
            },
            LearnedFactEntryV5::Policy {
                rule,
                when_call,
                require,
                scope,
                message,
                severity,
            } => LearnedFactEntry::Policy {
                rule,
                when_call,
                require,
                scope,
                message,
                severity,
            },
            LearnedFactEntryV5::Check {
                rule,
                call,
                message,
                severity,
                unless_guard,
                unless_range_check,
            } => LearnedFactEntry::Check {
                rule,
                call,
                message,
                severity,
                unless_guard,
                unless_range_check,
            },
            LearnedFactEntryV5::MemoryContract {
                name,
                returns_fresh,
                return_capacity,
                consumes_params,
            } => LearnedFactEntry::MemoryContract {
                name,
                returns_fresh,
                return_capacity,
                consumes_params,
            },
            LearnedFactEntryV5::WeakCrypto(f) => LearnedFactEntry::WeakCrypto(f),
            LearnedFactEntryV5::GuardBypass(f) => LearnedFactEntry::GuardBypass(f),
            LearnedFactEntryV5::SchemaPolicy(f) => LearnedFactEntry::SchemaPolicy(f),
            LearnedFactEntryV5::GrammarRole {
                language,
                node_kind,
                role,
            } => LearnedFactEntry::GrammarRole {
                language,
                node_kind,
                role,
            },
            LearnedFactEntryV5::GrammarFeature {
                language,
                node_kind,
                feature,
            } => LearnedFactEntry::GrammarFeature {
                language,
                node_kind,
                feature,
            },
            LearnedFactEntryV5::Allocator { name } => LearnedFactEntry::Allocator { name },
            LearnedFactEntryV5::Deallocator { name } => LearnedFactEntry::Deallocator { name },
            LearnedFactEntryV5::IdorFinderSink { call, keys } => {
                LearnedFactEntry::IdorFinderSink { call, keys }
            }
            LearnedFactEntryV5::IdorKey { key } => LearnedFactEntry::IdorKey { key },
            LearnedFactEntryV5::Propagator {
                call,
                input_args,
                preserves_taint,
            } => LearnedFactEntry::Propagator {
                call,
                input_args,
                preserves_taint,
            },
            LearnedFactEntryV5::GuardDenylistPattern { pattern } => {
                LearnedFactEntry::GuardDenylistPattern { pattern }
            }
            LearnedFactEntryV5::IntegerOverflowRule {
                rule,
                wrap_threshold,
                severity,
                message,
            } => LearnedFactEntry::IntegerOverflowRule {
                rule,
                wrap_threshold,
                severity,
                message,
            },
            LearnedFactEntryV5::Hints { kind, values } => LearnedFactEntry::Hints { kind, values },
            LearnedFactEntryV5::WeakPrimitiveRule {
                rule_id,
                selector_calls,
                bare_calls,
                selector_slot,
                weak_selectors,
                requires_credential_context,
                severity,
                message,
            } => LearnedFactEntry::WeakPrimitiveRule {
                rule_id,
                selector_calls,
                bare_calls,
                selector_slot,
                weak_selectors,
                requires_credential_context,
                severity,
                message,
            },
            LearnedFactEntryV5::InsecureConfigRule {
                prefix,
                selectors,
                rule_id,
                severity,
                message,
            } => LearnedFactEntry::InsecureConfigRule {
                prefix,
                selectors,
                rule_id,
                severity,
                message,
            },
            LearnedFactEntryV5::KeySizeRule {
                rule_id,
                call,
                slot,
                min_bits,
                kind,
                severity,
                message,
            } => LearnedFactEntry::KeySizeRule {
                rule_id,
                call,
                slot,
                min_bits,
                kind,
                severity,
                message,
            },
            LearnedFactEntryV5::SuspiciousHashWrappers { calls } => {
                LearnedFactEntry::SuspiciousHashWrappers { calls }
            }
            LearnedFactEntryV5::BufferBuiltin {
                name,
                dst_arg,
                src_arg,
                len_arg,
            } => LearnedFactEntry::BufferBuiltin {
                name,
                dst_arg,
                src_arg,
                len_arg,
            },
            LearnedFactEntryV5::LanguageSink {
                language,
                call,
                role,
            } => LearnedFactEntry::LanguageSink {
                language,
                call,
                role,
            },
            LearnedFactEntryV5::LanguageSinkSlots {
                language,
                call,
                dangerous_args,
                binding_args_safe,
            } => LearnedFactEntry::LanguageSinkSlots {
                language,
                call,
                package: None,
                dangerous_args,
                binding_args_safe,
            },
            LearnedFactEntryV5::LanguageIdorSink {
                language,
                call,
                keys,
            } => LearnedFactEntry::LanguageIdorSink {
                language,
                call,
                keys,
            },
            LearnedFactEntryV5::LanguageSource { language, pattern } => {
                LearnedFactEntry::LanguageSource {
                    language,
                    pattern,
                    package: None,
                }
            }
            LearnedFactEntryV5::LanguageSanitizer {
                language,
                call,
                kind,
                guard_style,
            } => LearnedFactEntry::LanguageSanitizer {
                language,
                call,
                package: None,
                kind,
                guard_style,
            },
            LearnedFactEntryV5::LanguagePropagator {
                language,
                call,
                tainted_arg,
                tainted_receiver,
            } => LearnedFactEntry::LanguagePropagator {
                language,
                call,
                tainted_arg,
                tainted_receiver,
            },
            LearnedFactEntryV5::LanguageSessionRoot { language, root } => {
                LearnedFactEntry::LanguageSessionRoot { language, root }
            }
            LearnedFactEntryV5::LanguageRoutePattern { language, pattern } => {
                LearnedFactEntry::LanguageRoutePattern { language, pattern }
            }
            LearnedFactEntryV5::StackAllocators { values } => {
                LearnedFactEntry::StackAllocators { values }
            }
            LearnedFactEntryV5::CollectionConstructors { values } => {
                LearnedFactEntry::CollectionConstructors { values }
            }
            LearnedFactEntryV5::SchemaDescribeMethods { values } => {
                LearnedFactEntry::SchemaDescribeMethods { values }
            }
            LearnedFactEntryV5::NullTokens { values } => LearnedFactEntry::NullTokens { values },
            LearnedFactEntryV5::SessionAccessors { values } => {
                LearnedFactEntry::SessionAccessors { values }
            }
            LearnedFactEntryV5::ReceiverParams { values } => {
                LearnedFactEntry::ReceiverParams { values }
            }
            LearnedFactEntryV5::LanguageAmbiguousVerbs { language, values } => {
                LearnedFactEntry::LanguageAmbiguousVerbs { language, values }
            }
        }
    }
}

/// The v5 payload: learned facts plus the authored-policy section.
/// Kept frozen with [`LearnedFactEntryV5`] so v5 bundles keep loading cleanly.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BundlePayloadV5 {
    pub patterns: Vec<BundlePattern>,
    #[serde(default)]
    pub learned_facts: Vec<LearnedFactEntryV5>,
    #[serde(default)]
    pub policy_pack: Vec<AuthoredPolicyEntry>,
}

/// The modern v6 payload: supports package-qualified provenance facts
/// in [`LearnedFactEntry`] for multi-framework disambiguation without FP explosions.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BundlePayloadV6 {
    pub patterns: Vec<BundlePattern>,
    #[serde(default)]
    pub learned_facts: Vec<LearnedFactEntry>,
    #[serde(default)]
    pub policy_pack: Vec<AuthoredPolicyEntry>,
}

/// Alias for the latest bundle payload.
pub type BundlePayload = BundlePayloadV6;

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub header: BundleHeader,
    pub patterns: Vec<BundlePattern>,
    /// Learned facts from §9 (empty for legacy bundles).
    pub learned_facts: Vec<LearnedFactEntry>,
    /// Authored policy entries (empty for v4 and legacy bundles).
    pub policy_pack: Vec<AuthoredPolicyEntry>,
}

pub fn load_bundle(bytes: &[u8]) -> Result<LoadedBundle, String> {
    let (header, payload_bytes) =
        read_bundle_parts(bytes).map_err(|e| format!("Failed to deserialize bundle: {}", e))?;

    // Version-branched payload load: bincode is positional and non-self-describing.
    // - >= 6: v6 payload with package-scoped LearnedFactEntry
    // - == 5: frozen v5 payload with LearnedFactEntryV5 converted to modern entries
    // - == 4: frozen v4 payload with V4Pattern and LearnedFactEntryV5 converted to modern entries
    // - < 4: legacy pattern vector
    let (patterns, learned_facts, policy_pack) = if header.version >= 6 {
        let payload: BundlePayloadV6 = bincode::deserialize(payload_bytes)
            .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;
        (payload.patterns, payload.learned_facts, payload.policy_pack)
    } else if header.version == 5 {
        let payload: BundlePayloadV5 = bincode::deserialize(payload_bytes)
            .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;
        (
            payload.patterns,
            payload
                .learned_facts
                .into_iter()
                .map(LearnedFactEntry::from)
                .collect(),
            payload.policy_pack,
        )
    } else {
        match bincode::deserialize::<V4Payload>(payload_bytes) {
            Ok(payload) => (
                payload
                    .patterns
                    .into_iter()
                    .map(BundlePattern::from)
                    .collect(),
                payload
                    .learned_facts
                    .into_iter()
                    .map(LearnedFactEntry::from)
                    .collect(),
                Vec::new(),
            ),
            Err(e) => match bincode::deserialize::<Vec<LegacyPattern>>(payload_bytes) {
                Ok(_) => {
                    tracing::warn!(
                        "legacy fingerprint bundle loaded (version {}); no facts available",
                        header.version
                    );
                    (Vec::new(), Vec::new(), Vec::new())
                }
                Err(_) => return Err(format!("Failed to deserialize bundle: {}", e)),
            },
        }
    };

    if patterns.len() < header.pattern_count as usize {
        tracing::warn!(
            "bundle pattern count mismatch (expected {}, loaded {})",
            header.pattern_count,
            patterns.len()
        );
    }

    Ok(LoadedBundle {
        header,
        patterns,
        learned_facts,
        policy_pack,
    })
}

/// Legacy bundles serialized a bare pattern vector with fingerprint
/// payloads. We accept the envelope but discard the shape data.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct LegacyPattern {
    #[serde(default)]
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{write_bundle, BundleHeader, BUNDLE_MAGIC};
    use frensense_engine::analysis::taint::facts::{PolicyFact, PolicyScope};

    /// Hand-craft an `.frc` envelope around `payload` at a chosen version.
    fn raw_bundle(version: u32, payload: &[u8]) -> Vec<u8> {
        let header = BundleHeader {
            magic: *BUNDLE_MAGIC,
            version,
            pattern_count: 0,
            checksum: *blake3::hash(payload).as_bytes(),
        };
        let header_bytes = bincode::serialize(&header).expect("header serializes");
        let mut bytes = (header_bytes.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn test_bundle_version_check() {
        let bytes = vec![b'F', b'R', b'C', b'1'];
        assert!(load_bundle(&bytes).is_err());
    }

    /// v4 bundles keep loading, with no policy_pack and
    /// no `rules` join (the field postdates the v4 shape).
    #[test]
    fn v4_bundle_loads_with_empty_policy_pack() {
        let payload = bincode::serialize(&V4Payload {
            patterns: vec![V4Pattern {
                id: "family-a".to_string(),
                observation: None,
                impact: None,
                improvement: None,
                cwe: None,
                cvss: None,
                owasp: None,
                severity: None,
            }],
            learned_facts: vec![],
        })
        .expect("v4 payload serializes");
        let bytes = raw_bundle(4, &payload);
        let loaded = load_bundle(&bytes).expect("v4 bundle loads");
        assert_eq!(loaded.patterns.len(), 1);
        assert_eq!(loaded.patterns[0].id, "family-a");
        assert!(
            loaded.patterns[0].rules.is_empty(),
            "v4 bundles predate the rules join"
        );
        assert!(loaded.learned_facts.is_empty());
        assert!(loaded.policy_pack.is_empty());
    }

    /// v5 bundle loading backward compatibility.
    #[test]
    fn v5_bundle_loads_and_converts_cleanly() {
        let payload = bincode::serialize(&BundlePayloadV5 {
            patterns: vec![],
            learned_facts: vec![LearnedFactEntryV5::Sink {
                call: "query".to_string(),
                dangerous_args: std::collections::BTreeSet::new(),
                binding_args_safe: false,
            }],
            policy_pack: vec![AuthoredPolicyEntry::Policy(PolicyFact {
                rule: "authored_guard_rule".to_string(),
                when_call: "checkout".to_string(),
                require: vec![],
                scope: PolicyScope::Function,
                message: "author-declared advisory".to_string(),
                severity: "critical".to_string(),
                package: None,
            })],
        })
        .expect("v5 payload serializes");
        let bytes = raw_bundle(5, &payload);
        let loaded = load_bundle(&bytes).expect("v5 bundle loads");
        assert_eq!(loaded.policy_pack.len(), 1);
        assert_eq!(loaded.learned_facts.len(), 1);
        let LearnedFactEntry::Sink { call, package, .. } = &loaded.learned_facts[0] else {
            panic!("expected Sink entry: {:?}", loaded.learned_facts);
        };
        assert_eq!(call, "query");
        assert_eq!(*package, None, "v5 facts convert with package: None");
    }

    /// v6 round-trip preserves package metadata and policy pack.
    #[test]
    fn v6_round_trip_preserves_package_and_policy_pack() {
        let payload = BundlePayloadV6 {
            patterns: vec![],
            learned_facts: vec![LearnedFactEntry::Sink {
                call: "query".to_string(),
                package: Some("pg".to_string()),
                dangerous_args: std::collections::BTreeSet::new(),
                binding_args_safe: true,
            }],
            policy_pack: vec![AuthoredPolicyEntry::Policy(PolicyFact {
                rule: "authored_guard_rule".to_string(),
                when_call: "checkout".to_string(),
                require: vec![],
                scope: PolicyScope::Function,
                message: "author-declared advisory".to_string(),
                severity: "critical".to_string(),
                package: Some("checkout-lib".to_string()),
            })],
        };
        let bytes = write_bundle(&payload, 0).expect("v6 write");
        let loaded = load_bundle(&bytes).expect("v6 bundle loads");
        assert_eq!(loaded.header.version, 6);
        assert_eq!(loaded.learned_facts.len(), 1);
        let LearnedFactEntry::Sink {
            call,
            package,
            binding_args_safe,
            ..
        } = &loaded.learned_facts[0]
        else {
            panic!("expected Sink entry: {:?}", loaded.learned_facts);
        };
        assert_eq!(call, "query");
        assert_eq!(*package, Some("pg".to_string()));
        assert!(*binding_args_safe);
        assert_eq!(loaded.policy_pack.len(), 1);
    }

    /// The envelope gate rejects newer-than-known bundle versions with a clean error.
    #[test]
    fn newer_bundle_version_rejected_with_clean_error() {
        let payload = bincode::serialize(&BundlePayloadV6 {
            patterns: vec![],
            learned_facts: vec![],
            policy_pack: vec![],
        })
        .expect("v6 payload serializes");
        let bytes = raw_bundle(crate::format::BUNDLE_VERSION + 1, &payload);
        let err = load_bundle(&bytes).expect_err("newer version must fail");
        assert!(err.contains("Unsupported bundle version"), "{err}");
        assert!(
            err.contains(&format!(
                "engine supports {}",
                crate::format::BUNDLE_VERSION
            )),
            "{err}"
        );
    }
}
