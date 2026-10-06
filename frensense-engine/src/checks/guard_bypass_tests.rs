// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the guard-bypass / credential-policy seed checks.

#[cfg(test)]
#[allow(clippy::module_inception)] // test file convention: module name repeats parent path segment
pub mod guard_bypass_tests {
    use crate::analysis::taint::facts::FactTable;
    use crate::checks::Provenance;
    use crate::checks::guard_bypass;
    use crate::harness::lower_source;

    /// Spec-seeded table: the checks read `FactTable` only, so test
    /// fixtures must seed the vocabulary exactly like a production scan.
    fn ts_facts() -> FactTable {
        let spec = frensense_lang::spec_for_ext("ts").expect("ts spec");
        let mut t = crate::analysis::taint::facts::fact_table_from_spec(spec);
        t.merge(&crate::analysis::taint::facts::default_pack_table());
        t
    }

    /// The redirectChallenge shape: allowlist validation by substring
    /// containment over attacker-controlled URL input.
    #[test]
    fn substring_allowlist_guard_fires() {
        let src = r#"
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = ts_facts();
        let hits: Vec<_> = fns
            .values()
            .flat_map(|ir| guard_bypass::check(ir, &facts))
            .collect();
        assert!(!hits.is_empty(), "substring guard must fire");
        assert_eq!(hits[0].rule, "substring_allowlist_guard");
    }

    /// Non-URL containment (`list.includes(item)` on plain names) must NOT
    /// fire, the rule is scoped to URL/redirect-shaped validation.
    #[test]
    fn plain_includes_does_not_fire() {
        let src = r#"
export function hasItem (items: string[], needle: string) {
  return items.includes(needle)
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = ts_facts();
        let hits: Vec<_> = fns
            .values()
            .flat_map(|ir| guard_bypass::check(ir, &facts))
            .collect();
        assert!(hits.is_empty(), "non-URL includes must stay silent");
    }

    /// The containment result must FEED a predicate: a value that gates
    /// nothing (only logged, then discarded) is not a guard even on
    /// URL-shaped input with a URL parameter present.
    #[test]
    fn containment_result_must_feed_predicate() {
        let src = r#"
export const auditUrl = (url: string) => {
  const ok = url.includes("https://allowed.com")
  audit.record(ok)
  return true
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = ts_facts();
        let hits: Vec<_> = fns
            .values()
            .flat_map(|ir| guard_bypass::check(ir, &facts))
            .collect();
        assert!(
            hits.is_empty(),
            "containment gating nothing must stay silent: {:?}",
            hits
        );
    }

    /// A containment result feeding a branch condition is a guard: fires.
    #[test]
    fn containment_result_feeding_branch_fires() {
        let src = r#"
export const isRedirectAllowed = (url: string) => {
  if (url.includes("https://allowed.com")) {
    return url
  }
  return null
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = ts_facts();
        let hits: Vec<_> = fns
            .values()
            .flat_map(|ir| guard_bypass::check(ir, &facts))
            .collect();
        assert!(
            !hits.is_empty(),
            "branch-fed containment must fire as a guard"
        );
        assert_eq!(hits[0].rule, "substring_allowlist_guard");
    }

    /// The weakPasswordChallenge shape: a plaintext password parameter fed
    /// to a hash-named call.
    #[test]
    fn credential_kdf_fires() {
        let src = r#"
export function storePassword (clearTextPassword: string) {
  return security.hash(clearTextPassword)
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = ts_facts();
        let hits: Vec<_> = fns
            .values()
            .flat_map(|ir| guard_bypass::check_credentials(ir, &facts))
            .collect();
        assert!(!hits.is_empty(), "credential KDF policy must fire");
        assert_eq!(hits[0].rule, "credential_kdf_policy");
    }

    /// Verification shape: the digest result is only *compared* against a
    /// stored value (`security.hash(pw) !== stored`), never persisted -
    /// checking a password against the stored hash is not a KDF-storage
    /// violation. No finding.
    #[test]
    fn credential_kdf_comparison_is_silent() {
        let src = r#"
export function verifyLogin (password: string, stored: string) {
  if (security.hash(password) !== stored) {
    throw new Error('bad password')
  }
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = ts_facts();
        let hits: Vec<_> = fns
            .values()
            .flat_map(|ir| guard_bypass::check_credentials(ir, &facts))
            .collect();
        assert!(
            hits.is_empty(),
            "comparison-only digest must not fire the KDF policy, got {hits:?}"
        );
    }

    /// Hashing a non-credential value must not fire.
    #[test]
    fn non_credential_hash_stays_silent() {
        let src = r#"
export function cacheKey (userId: string) {
  return crypto.hash(userId)
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = ts_facts();
        let hits: Vec<_> = fns
            .values()
            .flat_map(|ir| guard_bypass::check_credentials(ir, &facts))
            .collect();
        assert!(hits.is_empty(), "non-credential hash must stay silent");
    }

    /// Learned containment callee positive & negative test.
    #[test]
    fn learned_containment_callee_positive_and_negative() {
        let mut facts = ts_facts();
        facts
            .containment_callees
            .insert("customSubstrMatch".into(), Provenance::Learned);

        // Positive sample: uses customSubstrMatch for allowlist validation on URL
        let pos_src = r#"
export const isRedirectAllowed = (url: string) => {
  return url.customSubstrMatch("https://allowed.com")
}
"#;
        let pos_fns = lower_source("t.ts", pos_src, "ts").unwrap();
        let pos_hits: Vec<_> = pos_fns
            .values()
            .flat_map(|ir| guard_bypass::check(ir, &facts))
            .collect();
        assert!(
            !pos_hits.is_empty(),
            "custom containment callee must fire on positive"
        );
        assert_eq!(pos_hits[0].rule, "substring_allowlist_guard");
        assert!(
            pos_hits.iter().any(|h| h.provenance == Provenance::Learned),
            "finding must be marked learned"
        );

        // Negative sample: uses exact origin equality comparison
        let neg_src = r#"
export const isRedirectAllowed = (url: string) => {
  return parseOrigin(url) === "https://allowed.com"
}
"#;
        let neg_fns = lower_source("t.ts", neg_src, "ts").unwrap();
        let neg_hits: Vec<_> = neg_fns
            .values()
            .flat_map(|ir| guard_bypass::check(ir, &facts))
            .collect();
        assert!(
            neg_hits.is_empty(),
            "exact match on negative must stay silent"
        );
    }

    /// Learned credential sink & param positive & negative test.
    #[test]
    fn learned_credential_sink_and_param_positive_and_negative() {
        let mut facts = ts_facts();
        facts
            .credential_sinks
            .insert("customFastDigest".into(), Provenance::Learned);
        facts
            .credential_params
            .insert("clientSecretToken".into(), Provenance::Learned);

        // Positive sample 1: learned sink with standard password param
        let pos_src1 = r#"
export function savePwd (password: string) {
  return customFastDigest(password);
}
"#;
        let pos_fns1 = lower_source("t.ts", pos_src1, "ts").unwrap();
        let hits1: Vec<_> = pos_fns1
            .values()
            .flat_map(|ir| guard_bypass::check_credentials(ir, &facts))
            .collect();
        assert_eq!(hits1.len(), 1, "learned sink must fire on password param");
        assert_eq!(hits1[0].provenance, Provenance::Learned);

        // Positive sample 2: standard sink with learned credential param
        let pos_src2 = r#"
export function saveToken (clientSecretToken: string) {
  return security.hash(clientSecretToken);
}
"#;
        let pos_fns2 = lower_source("t.ts", pos_src2, "ts").unwrap();
        let hits2: Vec<_> = pos_fns2
            .values()
            .flat_map(|ir| guard_bypass::check_credentials(ir, &facts))
            .collect();
        assert_eq!(hits2.len(), 1, "learned param must fire on credential sink");
        assert_eq!(hits2[0].provenance, Provenance::Learned);

        // Negative sample: secure memory-hard KDF or non-credential hash
        let neg_src = r#"
export function savePwd (password: string) {
  return bcrypt.hashSync(password, 12);
}
export function cacheTag (tagName: string) {
  return customFastDigest(tagName);
}
"#;
        let neg_fns = lower_source("t.ts", neg_src, "ts").unwrap();
        let neg_hits: Vec<_> = neg_fns
            .values()
            .flat_map(|ir| guard_bypass::check_credentials(ir, &facts))
            .collect();
        assert!(
            neg_hits.is_empty(),
            "safe KDF and non-credential hash must stay silent"
        );
    }
}
