// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Generator-owned per-language provider vocabulary. Extracted from
//! `frensense-lang` in Phase 6.3b (JS/TS) and 6.3c (go/python/rust/c);
//! 6.3d deleted the trait methods and static tables these were translated
//! from, so this static data is the sole source of provider vocabulary.
//! The committed asset (built from this data since 6.3c) stayed
//! byte-identical through the whole migration.

use crate::role_map::{
    is_predicate_guard, sink_role_for_label, PropagatorRule, SanitizerKind, SinkLabel,
};
use frensense_engine::analysis::taint::facts::LearnedFactEntry;

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
    /// HTTP-method verbs ambiguous as bare last-segment call names
    /// (formerly `LanguageSpec::known_ambiguous_verbs`): dotted sink
    /// entries with one of these last segments arm receiver gating at
    /// install time. Every language ships the shared default; a vocab
    /// may narrow it.
    pub ambiguous_verbs: &'static [&'static str],
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

/// Emit one language's provider sections from static tables - the pack's
/// only provider path since 6.3d.
pub(crate) fn entries_for_static(v: &'static LanguageVocab) -> Vec<LearnedFactEntry> {
    use frensense_engine::analysis::taint::role::sink_role_name;

    let language = v.language.to_string();
    let mut entries = Vec::new();
    // Emitted first so the install's pre-scan finds the language's
    // ambiguous-verb vocabulary before any dotted sink entry consults it
    // (the install pre-scans anyway, so order is not load-bearing).
    entries.push(LearnedFactEntry::LanguageAmbiguousVerbs {
        language: language.clone(),
        values: v.ambiguous_verbs.iter().map(|s| (*s).to_string()).collect(),
    });
    for (call, label) in v.sink_names {
        entries.push(LearnedFactEntry::LanguageSink {
            language: language.clone(),
            call: (*call).to_string(),
            role: sink_role_name(sink_role_for_label(*label)).to_string(),
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
