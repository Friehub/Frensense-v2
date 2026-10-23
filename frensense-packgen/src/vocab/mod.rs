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
use frensense_engine::analysis::taint::facts::{LearnedFactEntry, PolicyRequirement, PolicyScope};

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
    /// Global-only builtin sinks (WI-12): the bare call form is the sink,
    /// while a receiver-qualified call (`engine.eval(x)`) matches only once
    /// its origin resolves to a known package. Emitted as the `global_only`
    /// flag on the language's `LanguageSink` entries.
    pub global_only_sinks: &'static [&'static str],
    /// Package-scoped framework sinks (dotted call, package, label):
    /// facts installed under (package, call) so a call only counts as a
    /// sink when import-origin resolution names the package.
    pub package_scoped_sinks: &'static [(&'static str, &'static str, SinkLabel)],
    pub sink_signatures: &'static [(&'static str, &'static [usize], bool)],
    pub idor_sinks: &'static [(&'static str, &'static [&'static str])],
    pub source_patterns: &'static [&'static str],
    pub request_param_names: &'static [&'static str],
    pub sanitizer_names: &'static [&'static str],
    pub classify_sanitizer: fn(&str) -> Option<SanitizerKind>,
    pub propagators: &'static [PropagatorRule],
    pub session_roots: &'static [&'static str],
    pub route_patterns: &'static [&'static str],
    /// Structural (non-dataflow) policies this language's vocabulary
    /// installs: a call plus the argument conditions that make it a
    /// violation. Emitted as bundle-shaped `Policy`/`PolicyScoped` facts, so
    /// the checker evaluates them with the same code path a corpus bundle
    /// uses - the language section only supplies data.
    pub policies: &'static [PolicySpec],
}

/// One static policy: when `when_call` occurs, every requirement in
/// `require` must hold, otherwise the call is a finding (an empty
/// `require` means the call itself is the violation).
pub(crate) struct PolicySpec {
    pub rule: &'static str,
    pub when_call: &'static str,
    pub require: &'static [RequirementSpec],
    pub message: &'static str,
    pub severity: &'static str,
    /// Only fire in files importing this package (`None` = unscoped).
    pub package: Option<&'static str>,
    /// Precision tier. Governs which scan profile reports this rule.
    #[allow(dead_code)]
    pub tier: RuleTier,
}

pub(crate) use frensense_lang::RuleTier;

/// Static form of a [`PolicyRequirement`]; owned strings are built at
/// emission time so the tables stay `&'static`.
pub(crate) enum RequirementSpec {
    /// The named argument must be present and, when its value is a
    /// provable literal, one of `values` (case-insensitive). See
    /// [`PolicyRequirement::RequireNamedArgLiteral`].
    RequireNamedArgLiteral {
        name: &'static str,
        values: &'static [&'static str],
    },
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
            role: format!(
                "{}:{}",
                sink_role_name(sink_role_for_label(*label)),
                label.slug()
            ),
        });
    }
    // Global-only builtin markers (WI-12): emitted after the sink names so
    // the install marks the already-published signatures.
    for call in v.global_only_sinks {
        entries.push(LearnedFactEntry::LanguageSinkGlobalOnly {
            language: language.clone(),
            call: (*call).to_string(),
        });
    }
    // Package-scoped framework sinks: package-qualified LanguageSinkSlots
    // entries (slot data synthesized as all-args dangerous) so packets
    // matching by lowered facts get the exact (package, call) binding.
    for (call, package, _label) in v.package_scoped_sinks {
        entries.push(LearnedFactEntry::LanguageSinkSlots {
            language: language.clone(),
            call: (*call).to_string(),
            package: Some((*package).to_string()),
            dangerous_args: std::collections::BTreeSet::new(),
            binding_args_safe: false,
        });
    }
    for (call, slots, binding_safe) in v.sink_signatures {
        entries.push(LearnedFactEntry::LanguageSinkSlots {
            language: language.clone(),
            call: (*call).to_string(),
            package: None,
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
            package: None,
        });
    }
    for p in v.request_param_names {
        entries.push(LearnedFactEntry::LanguageSource {
            language: language.clone(),
            pattern: (*p).to_string(),
            package: None,
        });
    }
    for name in v.sanitizer_names {
        let classified = (v.classify_sanitizer)(name);
        let guard_style = is_predicate_guard(name, classified.as_ref());
        let kind = classified.map(|k| k.slug().to_string()).unwrap_or_else(|| {
            if guard_style {
                frensense_engine::analysis::taint::facts::ALLOWLIST_SANITIZER_KIND.to_string()
            } else {
                frensense_engine::analysis::taint::facts::DEFAULT_SANITIZER_KIND.to_string()
            }
        });
        entries.push(LearnedFactEntry::LanguageSanitizer {
            language: language.clone(),
            call: (*name).to_string(),
            package: None,
            kind,
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
    // Structural policies: emitted as the same fact shapes a bundle uses,
    // so the conclusion (which call, which flags) is data from the moment
    // it is generated. Profile selection filters reportable tiers at scan time.
    for p in v.policies.iter() {
        let require: Vec<PolicyRequirement> = p
            .require
            .iter()
            .map(|r| match r {
                RequirementSpec::RequireNamedArgLiteral { name, values } => {
                    PolicyRequirement::RequireNamedArgLiteral {
                        name: (*name).to_string(),
                        values: values.iter().map(|s| (*s).to_string()).collect(),
                    }
                }
            })
            .collect();
        entries.push(match p.package {
            Some(pkg) => LearnedFactEntry::PolicyScoped {
                rule: p.rule.to_string(),
                when_call: p.when_call.to_string(),
                require,
                scope: PolicyScope::Function,
                message: p.message.to_string(),
                severity: p.severity.to_string(),
                package: pkg.to_string(),
            },
            None => LearnedFactEntry::Policy {
                rule: p.rule.to_string(),
                when_call: p.when_call.to_string(),
                require,
                scope: PolicyScope::Function,
                message: p.message.to_string(),
                severity: p.severity.to_string(),
            },
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
mod tier_tests {
    use super::*;
    use frensense_engine::analysis::taint::facts::LearnedFactEntry;

    fn policy_rules(entries: &[LearnedFactEntry]) -> Vec<String> {
        entries
            .iter()
            .filter_map(|e| match e {
                LearnedFactEntry::Policy { rule, .. }
                | LearnedFactEntry::PolicyScoped { rule, .. } => Some(rule.clone()),
                _ => None,
            })
            .collect()
    }

    /// The default pack carries the policies defined across all vocabularies.
    #[test]
    fn default_pack_holds_policies_with_tiers() {
        let rules: Vec<String> = all_vocab()
            .into_iter()
            .flat_map(|v| policy_rules(&entries_for_static(v)))
            .collect();
        assert!(
            rules.iter().any(|r| r == "cookie_secure_missing"),
            "{rules:?}"
        );
        assert!(
            rules.iter().any(|r| r == "cookie_httponly_missing"),
            "hygiene rule should be emitted for profile selection: {rules:?}"
        );
    }

    /// Every policy declares a tier.
    #[test]
    fn policy_declarations_have_expected_tiers() {
        let stable: Vec<&str> = all_vocab()
            .into_iter()
            .flat_map(|v| v.policies.iter())
            .filter(|p| p.tier == RuleTier::Stable)
            .map(|p| p.rule)
            .collect();
        assert!(stable.contains(&"cookie_secure_missing"), "{stable:?}");

        let hygiene: Vec<&str> = all_vocab()
            .into_iter()
            .flat_map(|v| v.policies.iter())
            .filter(|p| p.tier == RuleTier::Hygiene)
            .map(|p| p.rule)
            .collect();
        assert!(hygiene.contains(&"cookie_httponly_missing"), "{hygiene:?}");
    }
}
