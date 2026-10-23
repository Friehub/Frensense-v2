// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//! Machine-readable build identity: one JSON object that answers "which
//! engine, which fact vocabulary, which default pack, which schemas" for
//! every artifact this binary produces.
//!
//! `frensense --version --json` prints it; the release workflow asserts on
//! it (so a published crate is never built from the wrong tree or the wrong
//! pack); and the report producers embed its stable parts as a `producer`
//! block so any finding can be traced back to the exact engine that emitted
//! it.
//!
//! This is Phase 6.0 of the roadmap: the single identity surface that the
//! bundle-format (6.1) and report-schema (6.2) contracts hang off.

use serde_json::{Value, json};

/// Schema version of the identity object itself. Bumped when a key is
/// renamed, removed, or changes type - consumers parse this to know whether
/// they can trust the shape.
pub const IDENTITY_SCHEMA_VERSION: u32 = 1;

/// The identity object for this build.
///
/// Cheap to construct (the default pack is parsed once and cached); safe to
/// call from `--version`, CI assertions, and report producers alike.
#[must_use]
pub fn identity() -> Value {
    let pack = frensense_bundler::format::default_pack();
    json!({
        "schema_version": IDENTITY_SCHEMA_VERSION,
        "name": "frensense",
        "version": crate::FRENSENSE_VERSION,
        "engine_version": frensense_engine::VERSION,
        // Populated only when built with FRENSENSE_GIT_SHA set (the release
        // workflow sets it); `null` for an ordinary local build.
        "git_sha": option_env!("FRENSENSE_GIT_SHA"),
        "bundle_format": frensense_bundler::format::BUNDLE_VERSION,
        "min_bundle_format": frensense_bundler::format::MIN_SUPPORTED_VERSION,
        "fact_vocabulary_fingerprint": format!(
            "{:#018x}",
            frensense_engine::analysis::taint::facts::FACT_VOCABULARY_FINGERPRINT
        ),
        "report_schema": crate::REPORT_SCHEMA_VERSION,
        "default_pack": {
            "format": pack.header.version,
            "blake3": frensense_bundler::format::default_pack_blake3_hex(),
            "patterns": pack.patterns.len(),
            "learned_facts": pack.learned_facts.len(),
            "policy_pack": pack.policy_pack.len(),
            "legacy": pack.header.is_legacy(),
        },
    })
}

/// The `producer` block embedded in every emitted report (JSON `producer`
/// and SARIF `tool.driver.properties.frensense`).
///
/// Identifies the exact engine, fact vocabulary, and default pack that
/// produced a set of findings - so a consumer can tell which engine version
/// and pack a report came from without guessing from the crate string.
/// Kept deliberately smaller than [`identity`]: no `git_sha` (optional), no
/// self `schema_version` (the report carries its own), and the default pack
/// is named by digest only.
#[must_use]
pub fn producer() -> Value {
    json!({
        "name": "frensense",
        "version": crate::FRENSENSE_VERSION,
        "engine_version": frensense_engine::VERSION,
        "report_schema": crate::REPORT_SCHEMA_VERSION,
        "bundle_format": frensense_bundler::format::BUNDLE_VERSION,
        "fact_vocabulary_fingerprint": format!(
            "{:#018x}",
            frensense_engine::analysis::taint::facts::FACT_VOCABULARY_FINGERPRINT
        ),
        "default_pack_blake3": frensense_bundler::format::default_pack_blake3_hex(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity object carries the keys every consumer (release script,
    /// report `producer` block, support triage) relies on, with the values
    /// this build actually holds.
    #[test]
    fn identity_reports_this_build() {
        let id = identity();
        assert_eq!(id["schema_version"], IDENTITY_SCHEMA_VERSION);
        assert_eq!(id["name"], "frensense");
        assert_eq!(id["version"], crate::FRENSENSE_VERSION);
        assert_eq!(id["engine_version"], frensense_engine::VERSION);
        assert_eq!(
            id["bundle_format"],
            frensense_bundler::format::BUNDLE_VERSION
        );
        assert_eq!(
            id["min_bundle_format"],
            frensense_bundler::format::MIN_SUPPORTED_VERSION
        );
        assert_eq!(id["report_schema"], crate::REPORT_SCHEMA_VERSION);

        // The fingerprint is a 0x-prefixed, zero-padded 16-hex-digit token.
        let fp = id["fact_vocabulary_fingerprint"]
            .as_str()
            .expect("fingerprint is a string");
        assert!(fp.starts_with("0x") && fp.len() == 18, "fingerprint: {fp}");

        // Default-pack digest is a full BLAKE3 hex string.
        let digest = id["default_pack"]["blake3"].as_str().expect("digest");
        assert_eq!(digest.len(), 64, "blake3 digest: {digest}");
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        // `legacy` mirrors the embedded header, not a fixed value: the pack
        // is v6 (legacy) until regenerated as v7 in the release step.
        assert_eq!(
            id["default_pack"]["legacy"],
            frensense_bundler::format::default_pack().header.is_legacy()
        );
    }
}
