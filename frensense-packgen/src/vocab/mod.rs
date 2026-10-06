// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Generator-owned per-language provider vocabulary (Phase 6.3b).
//!
//! The static tables under [`javascript`] are verbatim copies of what the
//! `frensense-lang` providers still ship (lang sheds them in 6.3d); the
//! transitional parity test here proves the static path emits exactly the
//! same [`LearnedFactEntry`] sequence as the spec-derived path
//! ([`crate::language_entries_for_spec`]), per language. Emission still
//! goes through the specs until 6.3c; the parity test is what makes the
//! later switch and the lang deletion provably behavior-neutral.

use frensense_engine::analysis::taint::facts::LearnedFactEntry;
use frensense_lang::spec::{PropagatorRule, SanitizerKind, SinkLabel};

mod javascript;
pub(crate) use javascript::{javascript, typescript};

/// A language's provider vocabulary, static form. Mirrors the
/// `LanguageSpec::known_*` provider methods the generator reads, in
/// emission order.
pub(crate) struct LanguageVocab {
    /// The pack's language key (`spec.name()`).
    pub language: &'static str,
    pub sink_names: &'static [(&'static str, SinkLabel)],
    pub sink_signatures: &'static [(&'static str, &'static [usize], bool)],
    pub idor_sinks: &'static [(&'static str, &'static [&'static str])],
    pub source_patterns: &'static [&'static str],
    pub request_param_names: &'static [&'static str],
    pub sanitizer_names: &'static [&'static str],
    pub classify_sanitizer: fn(&str) -> Option<SanitizerKind>,
    pub propagators: &'static [PropagatorRule],
    pub session_roots: &'static [&'static str],
    pub route_patterns: &'static [&'static str],
}

/// The predicate-guard default (`LanguageSpec::is_predicate_guard`'s
/// default body). No provider overrides it, so the static path applies
/// the same heuristic the spec path gets via the trait.
fn is_predicate_guard(name: &str, kind: Option<&SanitizerKind>) -> bool {
    kind.is_some_and(|k| matches!(k, SanitizerKind::Full))
        || name == "test"
        || name == "isValid"
        || name.starts_with("is")
}

/// Emit one language's provider sections from static tables - the
/// emission-order twin of [`crate::language_entries_for_spec`].
pub(crate) fn entries_for_static(v: &'static LanguageVocab) -> Vec<LearnedFactEntry> {
    use frensense_engine::analysis::taint::role::sink_role_name;
    use frensense_lang::severity::SinkRole;

    let language = v.language.to_string();
    let mut entries = Vec::new();
    for (call, label) in v.sink_names {
        entries.push(LearnedFactEntry::LanguageSink {
            language: language.clone(),
            call: (*call).to_string(),
            role: sink_role_name(SinkRole::from_label(*label)).to_string(),
        });
    }
    for (call, slots, binding_safe) in v.sink_signatures {
        entries.push(LearnedFactEntry::LanguageSinkSlots {
            language: language.clone(),
            call: (*call).to_string(),
            dangerous_args: slots.iter().copied().collect(),
            binding_args_safe: *binding_safe,
        });
    }
    for (call, keys) in v.idor_sinks {
        entries.push(LearnedFactEntry::LanguageIdorSink {
            language: language.clone(),
            call: (*call).to_string(),
            keys: keys.iter().map(|s| (*s).to_string()).collect(),
        });
    }
    // Sources: conventional request-parameter names are sources too, and
    // the scan's source set folds both vocabularies together.
    for p in v.source_patterns {
        entries.push(LearnedFactEntry::LanguageSource {
            language: language.clone(),
            pattern: (*p).to_string(),
        });
    }
    for p in v.request_param_names {
        entries.push(LearnedFactEntry::LanguageSource {
            language: language.clone(),
            pattern: (*p).to_string(),
        });
    }
    for name in v.sanitizer_names {
        let classified = (v.classify_sanitizer)(name);
        let guard_style = is_predicate_guard(name, classified.as_ref());
        entries.push(LearnedFactEntry::LanguageSanitizer {
            language: language.clone(),
            call: (*name).to_string(),
            guard_style,
        });
    }
    for prop in v.propagators {
        entries.push(LearnedFactEntry::LanguagePropagator {
            language: language.clone(),
            call: prop.call.to_string(),
            tainted_arg: prop.tainted_arg,
            tainted_receiver: prop.tainted_receiver,
        });
    }
    for root in v.session_roots {
        entries.push(LearnedFactEntry::LanguageSessionRoot {
            language: language.clone(),
            root: (*root).to_string(),
        });
    }
    for pattern in v.route_patterns {
        entries.push(LearnedFactEntry::LanguageRoutePattern {
            language: language.clone(),
            pattern: (*pattern).to_string(),
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Transitional parity (6.3b): the extracted static vocabulary emits
    /// exactly what the spec-derived path emits, per extracted language.
    /// When 6.3c switches emission to the static path and 6.3d deletes
    /// the provider trait bodies, this test's spec half goes with them.
    #[test]
    fn extracted_vocab_matches_spec_derived_entries() {
        let spec_of = |name: &str| {
            frensense_lang::registry::LanguageRegistry::global()
                .for_name(name)
                .unwrap_or_else(|| panic!("{name} spec must be registered"))
        };
        for vocab in [javascript(), typescript()] {
            let spec = spec_of(vocab.language);
            let static_entries = entries_for_static(vocab);
            let spec_entries = crate::language_entries_for_spec(spec);
            assert_eq!(
                static_entries, spec_entries,
                "static vocab drifted from the spec for {}",
                vocab.language
            );
        }
    }
}
