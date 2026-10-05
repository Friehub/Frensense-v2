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
/// The facts pipeline (`--facts`) writes one pattern per corpus family
/// carrying the human-facing advisory fields (CWE, CVSS, OWASP, severity).
/// Flow knowledge is NOT here, it is in `learned_facts`, which the engine
/// consumes.
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
    pub patterns: Vec<BundlePattern>,
    #[serde(default)]
    pub learned_facts: Vec<LearnedFactEntry>,
}

/// The v5 payload: learned facts plus the authored-policy section. Each
/// section's presence marks its entries' provenance (learned_facts ->
/// Learned, policy_pack -> Authored).
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct BundlePayloadV5 {
    pub patterns: Vec<BundlePattern>,
    /// Learned facts (§9): sink signatures + sanitizer facts extracted from
    /// positive/negative pairs, replay-verified at bundle build time.
    #[serde(default)]
    pub learned_facts: Vec<LearnedFactEntry>,
    /// Hand-authored `policy.toml` rules (D2); empty until a bundle is
    /// built with `--policy`.
    #[serde(default)]
    pub policy_pack: Vec<AuthoredPolicyEntry>,
}

#[derive(Debug)]
pub struct LoadedBundle {
    pub patterns: Vec<BundlePattern>,
    /// Learned facts from §9 (empty for legacy bundles).
    pub learned_facts: Vec<LearnedFactEntry>,
    /// Authored policy entries (empty for v4 and legacy bundles).
    pub policy_pack: Vec<AuthoredPolicyEntry>,
}

pub fn load_bundle(bytes: &[u8]) -> Result<LoadedBundle, String> {
    let (header, payload_bytes) =
        read_bundle_parts(bytes).map_err(|e| format!("Failed to deserialize bundle: {}", e))?;

    // Version-branched payload load: bincode is positional, so v5's new
    // `policy_pack` section needs its own shape. The envelope gate above
    // already rejected newer-than-known bundles; for older ones the v4
    // shape (then the bare legacy pattern vector) applies.
    let (patterns, learned_facts, policy_pack) = if header.version >= 5 {
        let payload: BundlePayloadV5 = bincode::deserialize(payload_bytes)
            .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;
        (payload.patterns, payload.learned_facts, payload.policy_pack)
    } else {
        match bincode::deserialize::<V4Payload>(payload_bytes) {
            Ok(payload) => (payload.patterns, payload.learned_facts, Vec::new()),
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

    /// Phase 2 accept: v4 bundles keep loading, with no policy_pack.
    #[test]
    fn v4_bundle_loads_with_empty_policy_pack() {
        let payload = bincode::serialize(&V4Payload {
            patterns: vec![BundlePattern {
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
        assert!(loaded.learned_facts.is_empty());
        assert!(loaded.policy_pack.is_empty());
    }

    /// Phase 2 accept: v5 write -> read round-trips the policy_pack.
    #[test]
    fn v5_round_trip_preserves_policy_pack() {
        let payload = BundlePayloadV5 {
            patterns: vec![],
            learned_facts: vec![],
            policy_pack: vec![AuthoredPolicyEntry::Policy(PolicyFact {
                rule: "authored_guard_rule".to_string(),
                when_call: "checkout".to_string(),
                require: vec![],
                scope: PolicyScope::Function,
                message: "author-declared advisory".to_string(),
                severity: "critical".to_string(),
            })],
        };
        let bytes = write_bundle(&payload, 0).expect("v5 write");
        let loaded = load_bundle(&bytes).expect("v5 bundle loads");
        assert_eq!(loaded.policy_pack.len(), 1);
        let AuthoredPolicyEntry::Policy(fact) = &loaded.policy_pack[0] else {
            panic!("expected Policy entry: {:?}", loaded.policy_pack);
        };
        assert_eq!(fact.rule, "authored_guard_rule");
        assert_eq!(fact.severity, "critical");
        assert_eq!(fact.message, "author-declared advisory");
    }

    /// The envelope gate that made old (v4) readers reject v5 bundles:
    /// newer-than-known versions fail with a clean version error before
    /// any payload parsing.
    #[test]
    fn newer_bundle_version_rejected_with_clean_error() {
        let payload = bincode::serialize(&BundlePayloadV5 {
            patterns: vec![],
            learned_facts: vec![],
            policy_pack: vec![],
        })
        .expect("v5 payload serializes");
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
