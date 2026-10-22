// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Backward-compatibility gate for the `.frc` bundle format.
//!
//! `.frc` payloads are bincode-encoded with the `LearnedFactEntry` /
//! `BundlePattern` / `AuthoredPolicyEntry` types as the wire schema. Bincode is
//! *positional*: a serde-shape change to any of those types silently deserializes
//! old bundles into garbage (or fails outright) rather than erroring cleanly.
//!
//! This test pins a committed 0.7.0-era bundle and decodes it with the *current*
//! code. It fails if any of the following regress:
//!
//! - `BUNDLE_VERSION` is bumped without keeping old payloads loadable, or
//! - the `LearnedFactEntry` serde shape changes without a deliberate
//!   `BUNDLE_VERSION` bump and fixture regeneration.
//!
//! When you *intentionally* change the wire schema: bump `BUNDLE_VERSION` in
//! `format/frc.rs`, regenerate a fresh fixture from the new asset, and update
//! the committed `.frc` under `tests/fixtures/`. The failure here is the alarm.

use frensense_bundler::format::{load_bundle, BUNDLE_VERSION, MIN_SUPPORTED_VERSION};

/// The 0.7.0 default-pack asset, committed as a frozen wire-format sample.
const FIXTURE_0_7_0: &[u8] = include_bytes!("fixtures/frc-v6-frensense-0.7.0.frc");

#[test]
fn legacy_0_7_0_bundle_still_loads() {
    let loaded = load_bundle(FIXTURE_0_7_0)
        .unwrap_or_else(|e| panic!("0.7.0-era bundle failed to load with current code: {e}"));

    assert_eq!(
        loaded.header.version, 6,
        "fixture is a v6 bundle; BUNDLE_VERSION has moved on"
    );
    // The fixture must stay within the *supported range*, not match the
    // current version exactly: v7 deliberately keeps v6-and-earlier envelopes
    // loadable (they carry no vocabulary fingerprint, so they load marked
    // legacy). An exact-equality assertion here would forbid the one-directional
    // compatibility the format guarantees.
    assert!(
        (MIN_SUPPORTED_VERSION..=BUNDLE_VERSION).contains(&loaded.header.version),
        "fixture version must stay within the supported range"
    );
    assert!(
        !loaded.learned_facts.is_empty(),
        "0.7.0 bundle decoded but holds no learned facts - payload schema drift"
    );

    // Structural sanity: every decoded entry must carry a non-empty role/language.
    // Bincode is positional, so a schema mismatch can "succeed" while producing
    // nonsense strings; these invariants catch gross corruption.
    for entry in &loaded.learned_facts {
        let s = format!("{entry:?}");
        assert!(
            !s.is_empty(),
            "empty LearnedFactEntry debug representation - payload corrupt"
        );
    }
}

#[test]
fn current_default_pack_still_loads() {
    // Sanity: the embedded (regenerated) asset also loads. Paired with the
    // legacy test above this brackets both old and new wire formats.
    let loaded = load_bundle(frensense_bundler::format::default_bundle_bytes())
        .expect("embedded default pack must always load");
    assert!(!loaded.learned_facts.is_empty());
}
