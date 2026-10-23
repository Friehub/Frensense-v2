// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use frensense_bundler::extract::group_families;
use std::fs;
use tempfile::TempDir;

#[test]
fn member_qualified_check_call_learns_policy() {
    // A member-qualified predicate like `cfg.isSafePath(raw)` is called in
    // BOTH twins, so neither the call nor its receiver can be the learned
    // difference: the discriminator is the enforcement helper the negative
    // runs first. The check call must still be recognised as the family's
    // declared trigger (matching by its last segment, never by receiver),
    // so the learned policy fires on the positive and stays silent on the
    // negative - under one family id, not one family per receiver spelling.
    let dir = TempDir::new().unwrap();
    let pos = dir.path().join("path_validator_positive.ts");
    let neg = dir.path().join("path_validator_negative.ts");
    fs::write(
        &pos,
        r#"
// [frensense]
// observation = unsafe path used
// check-call: isSafePath
function handler(cfg: any, raw: any) {
  if (!cfg.isSafePath(raw)) {
    return sanitize(raw);
  }
  use(raw);
}
"#,
    )
    .unwrap();
    fs::write(
        &neg,
        r#"
// [frensense]
// observation = unsafe path used
// check-call: isSafePath
function handler(cfg: any, raw: any) {
  if (!isAllowed(raw)) {
    return sanitize(raw);
  }
  if (!cfg.isSafePath(raw)) {
    return sanitize(raw);
  }
  use(raw);
}
"#,
    )
    .unwrap();

    let families = group_families(dir.path()).unwrap();
    assert_eq!(families.len(), 1, "expected one typescript family");
    assert_eq!(families[0].id, "path_validator");
    assert_eq!(
        families[0].declared_check_call.as_deref(),
        Some("isSafePath")
    );
    let (learned, published) = frensense_bundler::extract::extract_facts_with_tables(
        &families,
        &Default::default(),
        &Default::default(),
    );
    let has_policy = learned
        .policy_facts
        .iter()
        .any(|(f, _)| f.rule == "policy_isSafePath");
    assert!(
        has_policy,
        "expected policy_isSafePath learned fact; learned={:?}, published={:?}",
        learned
            .policy_facts
            .iter()
            .map(|(f, _)| &f.rule)
            .collect::<Vec<_>>(),
        published.iter().map(|e| &e.entry).collect::<Vec<_>>()
    );
    assert!(
        published.iter().any(|e| match &e.entry {
            frensense_engine::analysis::taint::facts::LearnedFactEntry::Policy { rule, .. }
            | frensense_engine::analysis::taint::facts::LearnedFactEntry::PolicyScoped {
                rule,
                ..
            }
            | frensense_engine::analysis::taint::facts::LearnedFactEntry::Check { rule, .. } =>
                rule == "policy_isSafePath",
            _ => false,
        }),
        "expected policy_isSafePath in published entries"
    );
}
