// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! A family that states the identity its positive must report
//! (`expect: policy_<call>`) teaches that policy without the bundler having to
//! infer the trigger from the positive/negative delta.
//!
//! The call names here are deliberately outside the taint-relevance
//! vocabulary, which is what the declaration is for: an author who already
//! knows the rule can name it, and the proposal stage follows.

use std::fs;

use frensense_engine::analysis::taint::facts::LearnedFactEntry;
use tempfile::TempDir;

use super::*;

fn write(dir: &TempDir, name: &str, src: &str) {
    fs::write(dir.path().join(name), src).unwrap();
}

#[test]
fn declared_expected_identity_proposes_its_policy_rule() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "idor_positive.py",
        "# [frensense]\n# expect: policy_aget_user_by_uuid\n\nasync def h(state):\n    return await aget_user_by_uuid(state)\n",
    );
    write(&dir, "idor_negative.py", "def h(user):\n    return user\n");

    let families = group_families(dir.path()).unwrap();
    assert_eq!(
        families[0].declared_check_call.as_deref(),
        Some("aget_user_by_uuid"),
        "the declared identity names the trigger"
    );
    assert_eq!(
        families[0].metadata.declared_policy_call().as_deref(),
        Some("aget_user_by_uuid")
    );

    let (_, published) = extract_facts(&families);
    assert!(
        published.iter().any(|f| {
            let rule = match &f.entry {
                LearnedFactEntry::Policy { rule, .. } | LearnedFactEntry::Check { rule, .. } => {
                    rule
                }
                _ => return false,
            };
            rule == "policy_aget_user_by_uuid"
        }),
        "expected policy_aget_user_by_uuid, got: {:?}",
        published.iter().map(|f| &f.entry).collect::<Vec<_>>()
    );
}

#[test]
fn absent_expectation_leaves_the_trigger_undeclared() {
    let dir = TempDir::new().unwrap();
    write(
        &dir,
        "plain_positive.py",
        "# [frensense]\n# observation: state selects another user's record.\n\ndef h(state):\n    return aget_user_by_uuid(state)\n",
    );
    write(&dir, "plain_negative.py", "def h(user):\n    return user\n");

    let families = group_families(dir.path()).unwrap();
    assert_eq!(families[0].declared_check_call, None);
    assert!(families[0].metadata.declared_policy_call().is_none());
}
