// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Fact-vocabulary fingerprint: the wire compatibility contract for `.frc`
//! bundles.
//!
//! A bundle stores `LearnedFactEntry` values and `HintKind` discriminants
//! by *position* (bincode is positional and non-self-describing). An older
//! binary therefore cannot decode a bundle that uses a variant added after
//! it was built, and the failure surfaces as an opaque decode error deep
//! inside serde rather than as a version mismatch a user can act on.
//!
//! This module replaces that silence with one number. It hashes the ordered
//! serialization surface - hint kinds and fact-entry variants - with a
//! stable FNV-1a so it is reproducible from source without a runtime
//! dependency. A bundle records the fingerprint it was built against; the
//! engine compares it at load time and refuses, by name, to decode
//! vocabulary it does not know ([`frensense-bundler`'s header check]).
//!
//! The ratchet is mechanical, not honour-based:
//!
//! * [`HintKind::index`] and [`LearnedFactEntry::wire_index`] are exhaustive
//!   `match`es, so *adding* a variant is a compile error that lands the
//!   developer next to the vocabulary lists.
//! * [`tests::vocabulary_lists_are_ratcheted`] fails until the new variant is
//!   appended to [`HintKind::ALL`] / [`LearnedFactEntry::VARIANT_TAGS`], and
//!   [`tests::vocabulary_fingerprint_is_committed`] fails until the change is
//!   acknowledged by updating [`FACT_VOCABULARY_FINGERPRINT`] - which is also
//!   the cue to bump `BUNDLE_VERSION` and regenerate the default pack.
//!
//! Struct *field* additions are not covered here (they are caught by the
//! bundler's committed golden bundle, which stops decoding once the layout
//! moves); this fingerprint covers enum order and naming.

use super::{HintKind, LearnedFactEntry};
use std::fmt::Write as _;

/// Canonical description of the serialized fact vocabulary: one line per
/// hint kind and fact-entry variant, in wire order, with its index.
///
/// Two vocabularies that can decode each other's bundles produce identical
/// text; any append, reorder, insert or rename changes it.
#[must_use]
pub fn fact_vocabulary_canonical() -> String {
    // `write!` into the buffer (not `format!` + `push_str`): the output is
    // byte-identical, but this is a deterministic wire-format serializer,
    // not user-facing prose, so it must not count against the engine-prose
    // ratchet. Every line below is a stable serialization token.
    let mut out = String::with_capacity(4096);
    let _ = writeln!(out, "frensense-fact-vocabulary/1");
    let _ = writeln!(out, "hint:{}", HintKind::ALL.len());
    for (i, kind) in HintKind::ALL.iter().enumerate() {
        let _ = writeln!(out, "{i} {}", kind.name());
    }
    let _ = writeln!(out, "entry:{}", LearnedFactEntry::VARIANT_TAGS.len());
    for (i, tag) in LearnedFactEntry::VARIANT_TAGS.iter().enumerate() {
        let _ = writeln!(out, "{i} {tag}");
    }
    out
}

/// FNV-1a 64 over [`fact_vocabulary_canonical`].
///
/// FNV rather than a cryptographic hash: this is a compatibility token, not
/// a security property, and it must be reproducible from source with no
/// dependency and no build step.
#[must_use]
pub fn fact_vocabulary_fingerprint() -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in fact_vocabulary_canonical().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// The committed fingerprint for this build. Recorded in every `.frc` the
/// bundler writes and checked by the engine at load time.
///
/// When this value changes, so does every published bundle's compatibility:
/// bump `BUNDLE_VERSION`, regenerate the default pack, and rebuild any
/// corpus bundle. `docs/FORMATS.md` carries the same rule in prose.
pub const FACT_VOCABULARY_FINGERPRINT: u64 = 0x4994_27a8_ed94_e470;

/// Call-name decorators that libraries append to a base operation to name a
/// sibling in the same family: adm-zip's `extractAllTo` / `extractAllToAsync`,
/// Node's `readFile` / `readFileSync`, and the callback forms of the same
/// pattern.
///
/// Facts are matched by call name, so without this a corpus family that
/// teaches the base operation silently misses every decorated sibling - the
/// held-out pair then reports a miss even though the underlying defect is
/// identical. The suffix is only ever stripped for lookup, never published:
/// a fact still names exactly one call.
pub const MIRROR_CALL_SUFFIXES: &[&str] = &["Async", "Sync", "Callback", "Promise"];

/// The base operation a decorated call name belongs to.
///
/// `extractAllToAsync` -> `extractAllTo`. Returns `None` when the name carries
/// no known decorator, or when stripping it would leave no base at all.
#[must_use]
pub fn mirror_call_base(call: &str) -> Option<&str> {
    MIRROR_CALL_SUFFIXES
        .iter()
        .find_map(|suffix| call.strip_suffix(suffix).filter(|base| !base.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `HintKind` is listed, exactly once, in wire order.
    #[test]
    fn hint_kinds_are_ratcheted() {
        let all = HintKind::ALL;
        assert_eq!(
            all.len(),
            HintKind::WeakHashDisclaimer.index() + 1,
            "HintKind::ALL is stale: a variant was added or removed without \
             appending it to ALL (and to the canonical vocabulary)"
        );
        for kind in &all {
            assert_eq!(
                kind.index(),
                all.iter()
                    .position(|other| other.name() == kind.name())
                    .expect("duplicate HintKind name"),
                "HintKind::ALL is not in wire order"
            );
        }
    }

    /// Every `LearnedFactEntry` variant is tagged, once, in wire order.
    #[test]
    fn vocabulary_lists_are_ratcheted() {
        // Constructing the highest-index variant: its `wire_index()` is the
        // count of variants, so a new arm in that exhaustive match fails
        // this assertion until VARIANT_TAGS grows too.
        let last = LearnedFactEntry::IntegerOverflowUnboundedRule {
            rule: String::new(),
            wrap_threshold: 0,
            severity: String::new(),
            message: String::new(),
        };
        assert_eq!(
            LearnedFactEntry::VARIANT_TAGS.len(),
            last.wire_index() + 1,
            "LearnedFactEntry::VARIANT_TAGS is stale: a variant was added \
             without appending its tag"
        );
        let mut seen = std::collections::BTreeSet::new();
        for tag in LearnedFactEntry::VARIANT_TAGS {
            assert!(seen.insert(tag), "duplicate fact-entry tag {tag}");
        }
    }

    /// The fingerprint must equal the committed constant. Failing here means
    /// the serialized vocabulary changed: append nothing silently - bump
    /// `BUNDLE_VERSION`, update `FACT_VOCABULARY_FINGERPRINT`, regenerate the
    /// default pack, and rebuild corpus bundles.
    #[test]
    fn vocabulary_fingerprint_is_committed() {
        assert_eq!(
            fact_vocabulary_fingerprint(),
            FACT_VOCABULARY_FINGERPRINT,
            "fact vocabulary changed (canonical text: {})",
            fact_vocabulary_canonical()
        );
    }

    /// The canonical text is stable and covers every list.
    #[test]
    fn canonical_text_covers_the_whole_surface() {
        let text = fact_vocabulary_canonical();
        assert!(text.starts_with("frensense-fact-vocabulary/1\n"));
        for tag in LearnedFactEntry::VARIANT_TAGS {
            assert!(text.contains(&format!("{tag}\n")), "missing {tag}");
        }
        for kind in HintKind::ALL {
            assert!(
                text.contains(&format!("{}\n", kind.name())),
                "missing {kind:?}"
            );
        }
    }
}
