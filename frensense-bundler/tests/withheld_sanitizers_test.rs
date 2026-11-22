// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! A bundle whose trust tier withholds its sanitizers must say so. Withholding
//! is the safe direction (findings stay visible), but a user whose
//! false-positive fixes quietly stopped working needs the reason.

use frensense_bundler::format::{
    load_bundle, write_bundle_pinned_with_trust, BundlePayloadV8, BundleTrust, EngineRequirement,
    LoadedBundle, SanitizerScope,
};
use frensense_engine::analysis::taint::facts::LearnedFactEntry;

fn sanitizer(call: &str, package: Option<&str>) -> LearnedFactEntry {
    LearnedFactEntry::Sanitizer {
        call: call.to_string(),
        package: package.map(str::to_string),
        kind: "allowlist".to_string(),
        guard_style: true,
    }
}

/// Build and reload a two-sanitizer bundle at `trust`. `None` means the
/// write or reload failed, which every test below treats as a failure.
fn build(trust: BundleTrust, scopes: Vec<SanitizerScope>) -> Option<LoadedBundle> {
    let payload = BundlePayloadV8 {
        patterns: vec![],
        learned_facts: vec![
            sanitizer("isPublicHost", Some("net-utils")),
            sanitizer("looksSafe", None),
        ],
        policy_pack: vec![],
        sanitizer_scopes: scopes,
        policy_meta: vec![],
    };
    let req = EngineRequirement::same_series([0, 9, 1]);
    let bytes = write_bundle_pinned_with_trust(&payload, 0, req, trust).ok()?;
    load_bundle(&bytes).ok()
}

#[test]
fn custom_bundle_withholds_every_sanitizer_and_says_why() {
    let b = build(BundleTrust::Custom, vec![]);
    assert!(b.is_some(), "bundle must build and reload");
    let Some(b) = b else { return };
    assert_eq!(b.withheld_sanitizers(), 2);
    let notice = b.withheld_sanitizers_notice().unwrap_or_default();
    assert!(notice.contains("2 sanitizer fact(s)"), "{notice}");
    assert!(notice.contains("trust tier"), "{notice}");
}

#[test]
fn community_bundle_withholds_only_the_unscoped_sanitizer() {
    let scope = SanitizerScope {
        call: "isPublicHost".to_string(),
        package: Some("net-utils".to_string()),
        classes: vec!["net.ssrf".to_string()],
        family: None,
    };
    let b = build(BundleTrust::Community, vec![scope]);
    assert!(b.is_some(), "bundle must build and reload");
    let Some(b) = b else { return };
    assert_eq!(
        b.withheld_sanitizers(),
        1,
        "`looksSafe` has no class or package scope"
    );
}

#[test]
fn certified_bundle_withholds_nothing_and_stays_quiet() {
    let b = build(BundleTrust::Certified, vec![]);
    assert!(b.is_some(), "bundle must build and reload");
    let Some(b) = b else { return };
    assert_eq!(b.withheld_sanitizers(), 0);
    assert!(b.withheld_sanitizers_notice().is_none());
}
