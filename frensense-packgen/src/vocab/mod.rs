// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Generator-owned per-language provider vocabulary. Added go/python/rust/c
//! in Phase 6.3c (JS/TS in 6.3b); translation converts the former trait
//! method bodies and statics into one static [`LanguageVocab`] per
//! language key. A parity test proves each static path emits exactly the
//! spec-derived entries, and the committed asset (built from this data
//! since 6.3c) stays byte-identical through the migration.

use frensense_engine::analysis::taint::facts::LearnedFactEntry;
use frensense_lang::spec::SinkLabel;

mod c;
mod go;
mod javascript;
mod python;
mod rust;

/// Sanitizer classification helper: the last segment of a dotted call.
/// Moved from `frensense_lang` (used by the per-language classifiers).
pub(crate) fn call_last_segment(call: &str) -> &str {
    call.rsplit('.').next().unwrap_or(call)
}

/// A language's provider vocabulary, static form. Mirrors the
/// `LanguageSpec::known_*` provider methods the generator read, in
/// emission order. `known_idor_sinks` / `known_session_roots` had trait
/// defaults (empty); vocabulary-carrying languages list their data here.
pub(crate) struct LanguageVocab {
    /// The pack's language key (`spec.name()`).
    pub language: &'static str,
    pub sink_names: &'static [(&'static str, SinkLabel)],
    pub sink_signatures: &'static [(&'static str, &'static [usize], bool)],
    pub idor_sinks: &'static [(&'static str, &'static [&'static str])],
    pub source_patterns: &'static [&'static str],
    pub request_param_names: &'static [&'static str],
    pub sanitizer_names: &'static [&'static str],
    pub classify_sanitizer: fn(&str) -> Option<frensense_lang::spec::SanitizerKind>,
    pub propagators: &'static [frensense_lang::spec::PropagatorRule],
    pub session_roots: &'static [&'static str],
    pub route_patterns: &'static [&'static str],
}

/// The predicate-guard default (`LanguageSpec::is_predicate_guard`'s
/// default body). No provider overrides it, so the static path applies
/// the same heuristic the spec path gets via the trait.
fn is_predicate_guard(name: &str, kind: Option<&frensense_lang::spec::SanitizerKind>) -> bool {
    kind.is_some_and(|k| matches!(k, frensense_lang::spec::SanitizerKind::Full))
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

/// Every vocabulary, in the pack's emission order (sorted by language
/// name): c, go, javascript, python, rust, typescript.
pub(crate) fn all_vocab() -> Vec<&'static LanguageVocab> {
    vec![
        c::vocab(),
        go::vocab(),
        javascript::javascript_vocab(),
        python::vocab(),
        rust::vocab(),
        javascript::typescript_vocab(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parity gate (6.3b/c): every extracted language's static
    /// vocabulary emits exactly the spec-derived entries. While the
    /// provider trait methods still exist, both paths are live; when
    /// 6.3d deletes them, the spec half of this test goes with them.
    #[test]
    fn extracted_vocab_matches_spec_derived_entries() {
        for vocab in all_vocab() {
            let spec = frensense_lang::registry::LanguageRegistry::global()
                .for_name(vocab.language)
                .unwrap_or_else(|| panic!("{} spec must be registered", vocab.language));
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
