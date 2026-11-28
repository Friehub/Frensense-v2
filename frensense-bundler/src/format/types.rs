// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Bundle payload types.
//!
//! A `.frc` bundle is two things: per-family advisory metadata
//! ([`BundlePattern`]) and the machine-consumable knowledge
//! (`learned_facts`, replay-verified sink/sanitizer facts the engine
//! merges into its fact table).

use frensense_engine::analysis::taint::facts::{AuthoredPolicyEntry, LearnedFactEntry};

use super::frc::{read_bundle_parts, BundleHeader, BundleTrust};

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

use super::legacy::LearnedFactEntryV5;

/// The v5 payload: learned facts plus the authored-policy section.
/// Kept frozen with `LearnedFactEntryV5` so v5 bundles keep loading cleanly.
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

/// Class scope published for a sanitizer fact with the same `(call,
/// package)` in the same payload.
///
/// v8 moved this out of `LearnedFactEntry::Sanitizer` and out of the engine's
/// `SanitizerFact`, whose published shape must not change: the fact stays a
/// plain sanitizer, and the consumer applies the scope with
/// [`frensense_engine::analysis::taint::facts::FactTable::scope_sanitizer`].
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SanitizerScope {
    /// Sanitizing call name the scope applies to.
    pub call: String,
    /// Package qualification the scope applies to (`None` = unscoped).
    pub package: Option<String>,
    /// Vulnerability classes the sanitizer defeats (`*` = wildcard).
    pub classes: Vec<String>,
    /// Corpus family that taught the sanitizer, for suppression provenance.
    pub family: Option<String>,
}

impl SanitizerScope {
    /// A class scope for one sanitizer fact. `classes` may be empty (a bundle
    /// that ships a sanitizer with no scope is withheld on load).
    #[must_use]
    pub fn new(
        call: String,
        package: Option<String>,
        classes: Vec<String>,
        family: Option<String>,
    ) -> Self {
        Self {
            call,
            package,
            classes,
            family,
        }
    }
}

/// Reporting metadata published for a policy fact with the same `rule` in the
/// same payload: its precision tier and lifecycle state.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyMeta {
    /// Rule id of the policy this decorates.
    pub rule: String,
    /// Reporting tier (`stable`, `beta`, `hygiene`, `experimental`).
    pub tier: String,
    /// Lifecycle: `active` (default), `deprecated` or `removed`.
    pub status: String,
}

/// The v8 payload: v6 facts plus the metadata tables that the engine's
/// published fact types cannot carry.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BundlePayloadV8 {
    pub patterns: Vec<BundlePattern>,
    #[serde(default)]
    pub learned_facts: Vec<LearnedFactEntry>,
    #[serde(default)]
    pub policy_pack: Vec<AuthoredPolicyEntry>,
    /// Class scope for sanitizer facts in `learned_facts`.
    #[serde(default)]
    pub sanitizer_scopes: Vec<SanitizerScope>,
    /// Tier/lifecycle for policy facts in `learned_facts`.
    #[serde(default)]
    pub policy_meta: Vec<PolicyMeta>,
}

/// Argument slots published for a sanitizer fact with the same `(call,
/// package)` in the same payload (v9+).
///
/// [`frensense_engine::analysis::taint::facts::SanitizerFact::sanitizes_args`]
/// is a published engine field that no fact variant carries, so - exactly like
/// the class scope - it rides in a payload side table and the consumer applies
/// it with `FactTable::scope_sanitizer_with_args`. No entry (or an empty
/// `args`) is the legacy "all arguments" reading.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SanitizerArgScope {
    /// Sanitizing call name the slots apply to.
    pub call: String,
    /// Package qualification the slots apply to (`None` = unscoped).
    pub package: Option<String>,
    /// Argument slots the call validates, in declaration order.
    pub args: Vec<usize>,
}

/// The v9 payload: v8 plus the argument-slot table for sanitizer facts.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct BundlePayloadV9 {
    pub patterns: Vec<BundlePattern>,
    #[serde(default)]
    pub learned_facts: Vec<LearnedFactEntry>,
    #[serde(default)]
    pub policy_pack: Vec<AuthoredPolicyEntry>,
    #[serde(default)]
    pub sanitizer_scopes: Vec<SanitizerScope>,
    #[serde(default)]
    pub policy_meta: Vec<PolicyMeta>,
    /// Argument slots validated by the sanitizer facts in `learned_facts`.
    #[serde(default)]
    pub sanitizer_args: Vec<SanitizerArgScope>,
}

/// Base kinds a store sink may fire on (v10+).
///
/// `SinkSignature::base_kinds` is an engine field no entry variant carries, so
/// - like the sanitizer class scope - it rides in a payload side table keyed by
/// `(call, package)`. No entry (or empty `kinds`) is the legacy any-receiver
/// reading. The consumer applies it with
/// [`FactTable::qualify_sink_base_kinds`](frensense_engine::analysis::taint::facts::FactTable::qualify_sink_base_kinds).
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SinkBaseKindScope {
    /// Store sink field name (`innerHTML`).
    pub call: String,
    /// Package qualification the kinds apply to (`None` = unscoped).
    pub package: Option<String>,
    /// Calls (or declared type names) a receiver must come from.
    pub kinds: Vec<String>,
}

impl SinkBaseKindScope {
    /// Build one hint. The struct is `non_exhaustive` so a later payload can
    /// add a field without breaking authors.
    #[must_use]
    pub fn new(call: impl Into<String>, package: Option<String>, kinds: Vec<String>) -> Self {
        Self {
            call: call.into(),
            package,
            kinds,
        }
    }
}

/// The v10 payload: v9 plus the store-sink base-kind table.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[non_exhaustive]
pub struct BundlePayloadV10 {
    pub patterns: Vec<BundlePattern>,
    #[serde(default)]
    pub learned_facts: Vec<LearnedFactEntry>,
    #[serde(default)]
    pub policy_pack: Vec<AuthoredPolicyEntry>,
    #[serde(default)]
    pub sanitizer_scopes: Vec<SanitizerScope>,
    #[serde(default)]
    pub policy_meta: Vec<PolicyMeta>,
    #[serde(default)]
    pub sanitizer_args: Vec<SanitizerArgScope>,
    /// Base kinds for store sinks in `learned_facts`.
    #[serde(default)]
    pub sink_base_kinds: Vec<SinkBaseKindScope>,
}

impl BundlePayloadV10 {
    /// Build a payload. `#[non_exhaustive]` keeps later versions free to add a
    /// table without breaking authors; this constructor is the authoring API.
    #[must_use]
    pub fn new(
        patterns: Vec<BundlePattern>,
        learned_facts: Vec<LearnedFactEntry>,
        policy_pack: Vec<AuthoredPolicyEntry>,
        sanitizer_scopes: Vec<SanitizerScope>,
        policy_meta: Vec<PolicyMeta>,
        sanitizer_args: Vec<SanitizerArgScope>,
        sink_base_kinds: Vec<SinkBaseKindScope>,
    ) -> Self {
        Self {
            patterns,
            learned_facts,
            policy_pack,
            sanitizer_scopes,
            policy_meta,
            sanitizer_args,
            sink_base_kinds,
        }
    }
}

/// Alias for the latest bundle payload.
pub type BundlePayload = BundlePayloadV10;

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub header: BundleHeader,
    pub patterns: Vec<BundlePattern>,
    /// Learned facts from §9 (empty for legacy bundles).
    pub learned_facts: Vec<LearnedFactEntry>,
    /// Authored policy entries (empty for v4 and legacy bundles).
    pub policy_pack: Vec<AuthoredPolicyEntry>,
    /// Sanitizer class scopes (empty before v8).
    pub sanitizer_scopes: Vec<SanitizerScope>,
    /// Policy tier/lifecycle metadata (empty before v8).
    pub policy_meta: Vec<PolicyMeta>,
    /// Sanitizer argument-slot scopes (empty before v9).
    pub sanitizer_args: Vec<SanitizerArgScope>,
    /// Store-sink base kinds (empty before v10).
    pub sink_base_kinds: Vec<SinkBaseKindScope>,
}

/// One sanitizer fact's published qualification, resolved for install.
///
/// The class scope and the argument-slot scope live in separate payload
/// tables keyed by `(call, package)`; this view joins them once so a consumer
/// applies both with one call and cannot apply half of a fact.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct EffectiveSanitizerScope<'a> {
    /// Sanitizing call name.
    pub call: &'a str,
    /// Package qualification (`None` = unscoped).
    pub package: Option<&'a str>,
    /// Classes the fact was proven to defeat (empty = legacy universal).
    pub classes: &'a [String],
    /// Argument slots the fact validates (empty = all arguments).
    pub args: &'a [usize],
    /// Teaching family, for suppression provenance.
    pub family: Option<&'a str>,
}

impl LoadedBundle {
    /// How many sanitizer facts this bundle carries that its trust tier does
    /// not let it apply.
    ///
    /// A bundle built before class scopes existed (v7) carries sanitizers
    /// with no scope, and a custom bundle may not ship them at all. They are
    /// withheld, which keeps findings visible, but a user whose false
    /// positives came back needs to be told why.
    #[must_use]
    pub fn withheld_sanitizers(&self) -> usize {
        let is_san = |e: &LearnedFactEntry| {
            matches!(
                e,
                LearnedFactEntry::Sanitizer { .. } | LearnedFactEntry::LanguageSanitizer { .. }
            )
        };
        let carried = self.learned_facts.iter().filter(|e| is_san(e)).count();
        let applied = self
            .effective_learned_facts()
            .iter()
            .filter(|e| is_san(e))
            .count();
        carried.saturating_sub(applied)
    }

    /// One-line explanation for [`Self::withheld_sanitizers`], or `None` when
    /// nothing is withheld.
    #[must_use]
    pub fn withheld_sanitizers_notice(&self) -> Option<String> {
        let n = self.withheld_sanitizers();
        if n == 0 {
            return None;
        }
        let why = if self.header.version < 8 {
            format!(
                "this v{} bundle predates class scopes, so its sanitizers have no class to be limited to",
                self.header.version
            )
        } else {
            "a bundle of this trust tier may only ship sanitizers scoped to a class and a package"
                .to_string()
        };
        Some(format!(
            "{n} sanitizer fact(s) in this bundle were not applied: {why}. Findings they would have silenced are reported; rebuild the bundle with `frensense bundle` to restore them."
        ))
    }

    /// The facts this bundle's trust tier actually permits it to ship.
    ///
    /// Custom bundles are additive-only: sinks, sources and policies, no
    /// sanitizers. Community bundles may ship a sanitizer only when it is
    /// both class-scoped and name-scoped (package/receiver). Certified
    /// bundles ship everything. This is the single filtering point every
    /// consumer must use; reading `learned_facts` directly would re-open the
    /// cross-class blind spot the tier exists to close.
    #[must_use]
    pub fn effective_learned_facts(&self) -> Vec<LearnedFactEntry> {
        let trust = self.header.trust;
        let mut out = Vec::with_capacity(self.learned_facts.len());
        for entry in &self.learned_facts {
            match entry {
                LearnedFactEntry::Sanitizer { call, package, .. }
                | LearnedFactEntry::LanguageSanitizer { call, package, .. } => {
                    let classes = self
                        .sanitizer_scopes
                        .iter()
                        .find(|s| &s.call == call && &s.package == package)
                        .map(|s| s.classes.as_slice())
                        .unwrap_or(&[]);
                    if trust.may_ship_sanitizer(classes, package.as_deref()) {
                        out.push(entry.clone());
                    }
                }
                LearnedFactEntry::Policy { rule, .. }
                | LearnedFactEntry::PolicyScoped { rule, .. } => {
                    // Lifecycle rides in the payload's `policy_meta` table:
                    // `removed` drops the rule, while `deprecated` still loads
                    // (a pinned bundle keeps its behaviour) but is announced
                    // and demoted to Info so the default severity floor hides
                    // it.
                    let status = self
                        .policy_meta
                        .iter()
                        .find(|m| &m.rule == rule)
                        .map(|m| m.status.as_str())
                        .unwrap_or("");
                    if status.eq_ignore_ascii_case("removed") {
                        continue;
                    }
                    let mut kept = entry.clone();
                    if status.eq_ignore_ascii_case("deprecated") {
                        match &mut kept {
                            LearnedFactEntry::Policy {
                                message, severity, ..
                            }
                            | LearnedFactEntry::PolicyScoped {
                                message, severity, ..
                            } => {
                                *message = format!("[deprecated] {message}");
                                *severity = "info".to_string();
                            }
                            _ => {}
                        }
                    }
                    out.push(kept);
                }
                _ => out.push(entry.clone()),
            }
        }
        out
    }

    /// The sanitizer qualifications this bundle's trust tier permits it to
    /// ship: class scope joined with the argument-slot scope.
    ///
    /// One entry per sanitizer fact that survived
    /// [`Self::effective_learned_facts`]. A consumer installs the fact from
    /// the entry list, then applies the qualification with
    /// `FactTable::scope_sanitizer_with_args`.
    #[must_use]
    pub fn effective_sanitizer_scopes(&self) -> Vec<EffectiveSanitizerScope<'_>> {
        self.sanitizer_scopes
            .iter()
            .filter(|scope| {
                self.header
                    .trust
                    .may_ship_sanitizer(&scope.classes, scope.package.as_deref())
                    && self.learned_facts.iter().any(|entry| {
                        matches!(
                            entry,
                            LearnedFactEntry::Sanitizer { call, package, .. }
                                | LearnedFactEntry::LanguageSanitizer { call, package, .. }
                                if call == &scope.call && package == &scope.package
                        )
                    })
            })
            .map(|scope| EffectiveSanitizerScope {
                call: &scope.call,
                package: scope.package.as_deref(),
                classes: &scope.classes,
                args: self
                    .sanitizer_args
                    .iter()
                    .find(|a| a.call == scope.call && a.package == scope.package)
                    .map_or(&[], |a| a.args.as_slice()),
                family: scope.family.as_deref(),
            })
            .collect()
    }

    /// Reporting tier this bundle declares for `rule`, already capped by the
    /// bundle's trust tier. `None` means the consumer's rule registry decides
    /// (a certified bundle declared nothing).
    #[must_use]
    pub fn policy_tier(&self, rule: &str) -> Option<&str> {
        if let Some(meta) = self.policy_meta.iter().find(|m| m.rule == rule) {
            if meta.status.eq_ignore_ascii_case("removed") {
                return None;
            }
            if !meta.tier.is_empty() {
                // Tier cap: only certified bundles may ship default-on Stable
                // policies; community and custom bundles are capped at
                // Hygiene so they cannot add noisy default-on findings.
                return Some(if self.header.trust.may_ship_policy_tier(&meta.tier) {
                    meta.tier.as_str()
                } else {
                    "hygiene"
                });
            }
        }
        // No declared tier: the registry default is Stable, which only a
        // certified bundle may ship.
        match self.header.trust {
            BundleTrust::Certified => None,
            _ => Some("hygiene"),
        }
    }
}

/// One decoded payload, whichever envelope version it came from.
struct PayloadParts {
    patterns: Vec<BundlePattern>,
    learned_facts: Vec<LearnedFactEntry>,
    policy_pack: Vec<AuthoredPolicyEntry>,
    sanitizer_scopes: Vec<SanitizerScope>,
    policy_meta: Vec<PolicyMeta>,
    sanitizer_args: Vec<SanitizerArgScope>,
    sink_base_kinds: Vec<SinkBaseKindScope>,
}

/// Decode a payload by envelope version: bincode is positional and
/// non-self-describing, so each version has its own frozen struct and every
/// newer field is defaulted for older bundles.
fn decode_payload(version: u32, payload_bytes: &[u8]) -> Result<PayloadParts, String> {
    // Version-branched payload load: bincode is positional and non-self-describing.
    // - >= 6: v6 payload with package-scoped LearnedFactEntry
    // - == 5: frozen v5 payload with LearnedFactEntryV5 converted to modern entries
    // - == 4: frozen v4 payload with V4Pattern and LearnedFactEntryV5 converted to modern entries
    // - < 4: legacy pattern vector
    let (
        patterns,
        learned_facts,
        policy_pack,
        sanitizer_scopes,
        policy_meta,
        sanitizer_args,
        sink_base_kinds,
    ) = if version >= 10 {
        let payload: BundlePayloadV10 = bincode::deserialize(payload_bytes)
            .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;
        (
            payload.patterns,
            payload.learned_facts,
            payload.policy_pack,
            payload.sanitizer_scopes,
            payload.policy_meta,
            payload.sanitizer_args,
            payload.sink_base_kinds,
        )
    } else if version >= 9 {
        let payload: BundlePayloadV9 = bincode::deserialize(payload_bytes)
            .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;
        (
            payload.patterns,
            payload.learned_facts,
            payload.policy_pack,
            payload.sanitizer_scopes,
            payload.policy_meta,
            payload.sanitizer_args,
            Vec::new(),
        )
    } else if version >= 8 {
        let payload: BundlePayloadV8 = bincode::deserialize(payload_bytes)
            .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;
        (
            payload.patterns,
            payload.learned_facts,
            payload.policy_pack,
            payload.sanitizer_scopes,
            payload.policy_meta,
            Vec::new(),
            Vec::new(),
        )
    } else if version >= 6 {
        let payload: BundlePayloadV6 = bincode::deserialize(payload_bytes)
            .map_err(|e| format!("Failed to deserialize bundle: {}", e))?;
        (
            payload.patterns,
            payload.learned_facts,
            payload.policy_pack,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    } else if version == 5 {
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
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
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
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Err(e) => match bincode::deserialize::<Vec<LegacyPattern>>(payload_bytes) {
                Ok(_) => {
                    tracing::warn!(
                        "legacy fingerprint bundle loaded (version {}); no facts available",
                        version
                    );
                    (
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                    )
                }
                Err(_) => return Err(format!("Failed to deserialize bundle: {}", e)),
            },
        }
    };

    Ok(PayloadParts {
        patterns,
        learned_facts,
        policy_pack,
        sanitizer_scopes,
        policy_meta,
        sanitizer_args,
        sink_base_kinds,
    })
}

pub fn load_bundle(bytes: &[u8]) -> Result<LoadedBundle, String> {
    let (header, payload_bytes) =
        read_bundle_parts(bytes).map_err(|e| format!("Failed to deserialize bundle: {}", e))?;

    let parts = decode_payload(header.version, payload_bytes)?;
    let patterns = parts.patterns;
    let learned_facts = parts.learned_facts;
    let policy_pack = parts.policy_pack;
    let sanitizer_scopes = parts.sanitizer_scopes;
    let policy_meta = parts.policy_meta;
    let sanitizer_args = parts.sanitizer_args;
    let sink_base_kinds = parts.sink_base_kinds;

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
        sanitizer_scopes,
        policy_meta,
        sanitizer_args,
        sink_base_kinds,
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
    ///
    /// The header shape follows the version (4 fields at v6, 7 at v7) so the
    /// *reader's* branching is what the test exercises, and the version field
    /// is then patched so a `BUNDLE_VERSION + 1` envelope really is newer than
    /// anything this build knows.
    fn raw_bundle(version: u32, payload: &[u8]) -> Vec<u8> {
        if version < crate::format::BUNDLE_VERSION {
            return crate::format::frc::write_legacy_envelope(version, payload);
        }
        let mut header = BundleHeader::current(0, *blake3::hash(payload).as_bytes());
        // Stamp the *requested* version, not the current one. When the caller
        // asks for "newer than this engine knows", `current()` would stamp
        // `BUNDLE_VERSION` and the gate would never fire.
        header.version = version;
        assert_eq!(header.magic, *BUNDLE_MAGIC);
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

    /// A payload round-trip preserves package metadata and policy pack.
    #[test]
    fn payload_round_trip_preserves_package_and_policy_pack() {
        let payload = BundlePayload {
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
            sanitizer_scopes: Vec::new(),
            policy_meta: Vec::new(),
            sanitizer_args: Vec::new(),
            sink_base_kinds: vec![SinkBaseKindScope::new(
                "innerHTML",
                None,
                vec!["querySelector".to_string()],
            )],
        };
        // `write_bundle` always stamps the current envelope version, so the
        // payload must be the current layout.
        let bytes = write_bundle(&payload, 0).expect("write");
        let loaded = load_bundle(&bytes).expect("bundle loads");
        assert_eq!(loaded.header.version, crate::format::BUNDLE_VERSION);
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
        // The base-kind hint rides in its own table (v10+) because no entry
        // variant carries the engine's `SinkSignature::base_kinds`.
        assert_eq!(loaded.sink_base_kinds.len(), 1);
        assert_eq!(loaded.sink_base_kinds[0].call, "innerHTML");
        assert_eq!(
            loaded.sink_base_kinds[0].kinds,
            ["querySelector".to_string()]
        );
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
                "this engine supports up to {}",
                crate::format::BUNDLE_VERSION
            )),
            "{err}"
        );
    }

    fn scope(call: &str) -> SanitizerScope {
        SanitizerScope {
            call: call.to_string(),
            package: None,
            classes: vec!["inj.sql".to_string()],
            family: Some("family-a".to_string()),
        }
    }

    fn sanitizer(call: &str) -> LearnedFactEntry {
        LearnedFactEntry::Sanitizer {
            call: call.to_string(),
            package: None,
            kind: "allowlist".to_string(),
            guard_style: true,
        }
    }

    /// A v8 payload still loads: it predates the argument-slot table, so the
    /// scope resolves with the legacy "all arguments" reading rather than
    /// being dropped (a dropped scope would re-open cross-class cutting).
    #[test]
    fn v8_bundle_loads_without_argument_slots() {
        let payload = bincode::serialize(&BundlePayloadV8 {
            patterns: vec![],
            learned_facts: vec![sanitizer("check")],
            policy_pack: vec![],
            sanitizer_scopes: vec![scope("check")],
            policy_meta: vec![],
        })
        .expect("v8 payload serializes");
        let mut header = BundleHeader::current(0, *blake3::hash(&payload).as_bytes());
        header.version = 8;
        let header_bytes = bincode::serialize(&header).expect("header serializes");
        let mut bytes = (header_bytes.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&header_bytes);
        bytes.extend_from_slice(&payload);

        let loaded = load_bundle(&bytes).expect("v8 bundle loads");
        assert_eq!(loaded.header.version, 8);
        assert!(loaded.sanitizer_args.is_empty());
        let scopes = loaded.effective_sanitizer_scopes();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].call, "check");
        assert_eq!(scopes[0].classes.to_vec(), vec!["inj.sql".to_string()]);
        assert!(scopes[0].args.is_empty(), "v8 bundles carry no slots");
    }

    /// The v9 payload round-trips the argument-slot table, and the scope view
    /// joins it with the class scope.
    #[test]
    fn v9_round_trip_preserves_sanitizer_args() {
        let payload = BundlePayload {
            patterns: vec![],
            learned_facts: vec![sanitizer("check")],
            policy_pack: vec![],
            sanitizer_scopes: vec![scope("check")],
            policy_meta: vec![],
            sanitizer_args: vec![SanitizerArgScope {
                call: "check".to_string(),
                package: None,
                args: vec![1],
            }],
            sink_base_kinds: Vec::new(),
        };
        let bytes = write_bundle(&payload, 0).expect("write");
        let loaded = load_bundle(&bytes).expect("bundle loads");
        assert_eq!(loaded.header.version, crate::format::BUNDLE_VERSION);
        let scopes = loaded.effective_sanitizer_scopes();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].args.to_vec(), vec![1usize]);
        assert_eq!(scopes[0].classes.to_vec(), vec!["inj.sql".to_string()]);
        assert_eq!(scopes[0].family, Some("family-a"));
    }
}
