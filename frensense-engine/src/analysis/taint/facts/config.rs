// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;
use rustc_hash::FxHashMap;

use crate::analysis::taint::config::TaintConfig;

/// Build the (empty) structural seed of a [`FactTable`] for a set of file
/// extensions (the harness/CLI contract's first seeding step: the scan
/// runner feeds it the scanned files' extensions, the fact bundler feeds
/// it a family's extensions).
///
/// Since Phase 6.5 the bare spec seed carries **no data at all**: every
/// table - including the seven structural vocabularies (guard denylist,
/// stack allocators, collection constructors, schema describe methods,
/// null tokens, session accessors, receiver params) - ships in the
/// default pack's language-agnostic entries, which every consumer merges
/// between this seed and the consumer bundle (seeding order: spec ->
/// default pack -> consumer, last-wins). What remains spec-derived is
/// mechanism read directly at scan time (grammar classification, route
/// verbs, ambiguous verbs at install time, the rule registry), never
/// through this seed.
pub fn tables_from_exts<'a>(_exts: impl IntoIterator<Item = &'a str>) -> (TaintConfig, FactTable) {
    (TaintConfig::default(), FactTable::default())
}

/// Production table assembly for a set of extensions: the (empty) spec
/// seed ([`tables_from_exts`]) + the default pack's language-agnostic
/// entries
/// merged at [`Provenance::Spec`], then its language-keyed sections
/// installed for those extensions' languages. This is byte-for-byte the
/// order `build_spec_tables` (scan runner) and `family_tables` (fact
/// bundler) use, exposed so tests can assemble tables that cannot drift
/// from production.
pub fn tables_from_exts_with_pack<'a>(
    exts: impl IntoIterator<Item = &'a str>,
    pack_entries: &[LearnedFactEntry],
) -> (TaintConfig, FactTable) {
    let exts: Vec<&'a str> = exts.into_iter().collect();
    let (mut config, mut facts) = tables_from_exts(exts.iter().copied());
    facts.merge(&fact_table_from_entries_with(
        pack_entries,
        Provenance::Spec,
    ));
    apply_language_entries(
        &mut config,
        &mut facts,
        pack_entries,
        &languages_for_exts(exts.iter().copied()),
    );
    (config, facts)
}

/// The distinct language names for a set of file extensions, in first
/// appearance order - the exact per-spec merge order the seeding pipeline
/// uses. Feed the result to [`apply_language_entries`] so its group merges
/// land in the same order as the seed.
pub fn languages_for_exts<'a>(exts: impl IntoIterator<Item = &'a str>) -> Vec<&'static str> {
    let mut seen: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for ext in exts {
        if let Some(spec) = frensense_lang::spec_for_ext(ext)
            && seen.insert(spec.name())
        {
            out.push(spec.name());
        }
    }
    out
}

// ── Phase 6.2: language-keyed default-pack knowledge ───────────────────────

/// The language key of a language-keyed pack entry, if this variant has
/// one. Language-agnostic bundle variants return `None`.
fn entry_language(e: &LearnedFactEntry) -> Option<&str> {
    match e {
        LearnedFactEntry::LanguageSink { language, .. }
        | LearnedFactEntry::LanguageSinkSlots { language, .. }
        | LearnedFactEntry::LanguageIdorSink { language, .. }
        | LearnedFactEntry::LanguageSource { language, .. }
        | LearnedFactEntry::LanguageSanitizer { language, .. }
        | LearnedFactEntry::LanguagePropagator { language, .. }
        | LearnedFactEntry::LanguageSessionRoot { language, .. }
        | LearnedFactEntry::LanguageRoutePattern { language, .. } => Some(language),
        _ => None,
    }
}

/// Install language-keyed default-pack knowledge (Phase 6.2) into the scan's
/// `TaintConfig` and `FactTable` together, filtered to the scan's languages
/// (`spec.name()` keys; `"*"` matches every language).
///
/// Since Phase 6.2d this is the SOLE source of the provider knowledge
/// (sinks, sources, sanitizers, propagators, IDOR vocabulary, session
/// roots, route patterns): the spec seed carries none of it. The
/// wildcard group installs first, then one group per scan language in
/// caller order (first appearance of each scanned extension), each built in
/// a fresh temp table with the same or-insert/bare-wins rules the former
/// per-spec seed used and merged in - cross-language key
/// collisions resolved by the same last-merge-wins rule.
pub fn apply_language_entries(
    config: &mut TaintConfig,
    facts: &mut FactTable,
    entries: &[LearnedFactEntry],
    languages: &[&str],
) {
    // Group the language-keyed entries by their language key, preserving
    // pack order within each group (sink names before per-slot rules
    // before idor keys, as the generator emits them).
    let mut groups: FxHashMap<&str, Vec<&LearnedFactEntry>> = FxHashMap::default();
    for e in entries {
        if let Some(lang) = entry_language(e) {
            groups.entry(lang).or_default().push(e);
        }
    }
    if groups.is_empty() {
        return;
    }
    // Install order: the wildcard group first (shared sections), then the
    // scan's languages in caller order, deduped.
    let mut order: Vec<&str> = Vec::with_capacity(languages.len() + 1);
    order.push("*");
    for l in languages {
        if *l != "*" && !order.contains(l) {
            order.push(l);
        }
    }
    for lang in order {
        let Some(group) = groups.get(lang) else {
            continue;
        };
        // The ambiguous-verb vocabulary stays spec-owned (mechanism): the
        // sink install uses it for verb-sink bookkeeping.
        let ambiguous: &[&str] = frensense_lang::registry::LanguageRegistry::global()
            .for_name(lang)
            .map_or(&[], |s| s.known_ambiguous_verbs());
        // Build this language's contribution in a fresh temp table, exactly
        // like a per-spec seed merge, then merge it in: the
        // merge's last-wins/widens rules resolve cross-language collisions
        // the same way `tables_from_exts` merges per-spec tables.
        let mut c = TaintConfig::default();
        let mut f = FactTable::default();
        install_language_group(&mut c, &mut f, group, ambiguous);
        config.sources.extend(c.sources);
        config.sinks.extend(c.sinks);
        config.sanitizers.extend(c.sanitizers);
        facts.merge(&f);
    }
}

/// One language group, in pack order: sink names, sink slots, idor sinks,
/// sources, sanitizers, propagators, session roots, route patterns.
fn install_language_group(
    config: &mut TaintConfig,
    facts: &mut FactTable,
    group: &[&LearnedFactEntry],
    ambiguous_verbs: &[&str],
) {
    for e in group {
        match e {
            LearnedFactEntry::LanguageSink { call, role, .. } => {
                let role = crate::analysis::taint::role::sink_role_from_name(role);
                let key = call.as_str();
                let last = key.rsplit('.').next().unwrap_or(key);
                facts
                    .sink_signatures
                    .entry(key.to_string())
                    .or_insert_with(|| SinkSignature {
                        role,
                        ..SinkSignature::all_args(key)
                    });
                config.sinks.insert(last.to_string());
                if last != key {
                    facts
                        .sink_signatures
                        .entry(last.to_string())
                        .or_insert_with(|| SinkSignature {
                            role,
                            ..SinkSignature::all_args(key)
                        });
                    if let Some(root) = key.split('.').next() {
                        facts
                            .receiver_roles
                            .entry((root.to_string(), last.to_string()))
                            .or_insert(role);
                        if ambiguous_verbs.contains(&last) {
                            facts.verb_sinks.insert(last.to_string());
                            facts.client_roots.insert(root.to_string());
                        }
                    }
                }
            }
            LearnedFactEntry::LanguageSinkSlots {
                call,
                dangerous_args,
                binding_args_safe,
                ..
            } => {
                let role = facts
                    .sink_signatures
                    .get(call.as_str())
                    .map(|s| s.role)
                    .unwrap_or_default();
                let entry = SinkSignature {
                    call: call.clone(),
                    dangerous_args: dangerous_args.clone(),
                    binding_args_safe: *binding_args_safe,
                    idor_keys: Vec::new(),
                    role,
                };
                facts.sink_signatures.insert(call.clone(), entry.clone());
                let last = call.rsplit('.').next().unwrap_or(call);
                if last != call {
                    // Bare-wins alias rule: a dotted per-slot rule may
                    // replace the mechanical dotted alias but never a
                    // bare-owned entry (mirrors the spec seed).
                    let alias_owned_by_dotted = facts
                        .sink_signatures
                        .get(last)
                        .map(|cur| cur.call.contains('.'))
                        .unwrap_or(false);
                    if alias_owned_by_dotted {
                        facts.sink_signatures.insert(last.to_string(), entry);
                    } else {
                        facts
                            .sink_signatures
                            .entry(last.to_string())
                            .or_insert(entry);
                    }
                }
            }
            LearnedFactEntry::LanguageIdorSink { call, keys, .. } => {
                let last = call.rsplit('.').next().unwrap_or(call).to_string();
                facts.idor_finder_sinks.insert(call.clone());
                facts.idor_finder_sinks.insert(last.clone());
                for k in keys {
                    facts.idor_keys.insert(k.clone());
                }
                let owned: Vec<String> = keys.clone();
                if let Some(sig) = facts.sink_signatures.get_mut(call) {
                    sig.idor_keys = owned.clone();
                }
                if last != *call
                    && let Some(sig) = facts.sink_signatures.get_mut(&last)
                {
                    sig.idor_keys = owned;
                }
            }
            LearnedFactEntry::LanguageSource { pattern, .. } => {
                config.sources.insert(pattern.clone());
            }
            LearnedFactEntry::LanguageSanitizer {
                call, guard_style, ..
            } => {
                config.sanitizers.insert(call.clone());
                let kind = if *guard_style {
                    ALLOWLIST_SANITIZER_KIND
                } else {
                    DEFAULT_SANITIZER_KIND
                }
                .to_string();
                facts
                    .sanitizer_facts
                    .entry(call.clone())
                    .or_insert_with(|| SanitizerFact {
                        call: call.clone(),
                        kind,
                        sanitizes_args: Default::default(),
                        guard_style: *guard_style,
                    });
            }
            LearnedFactEntry::LanguagePropagator {
                call,
                tainted_arg,
                tainted_receiver,
                ..
            } => {
                let key = call.clone();
                let last = call.rsplit('.').next().unwrap_or(call).to_string();
                let args: Vec<usize> = match tainted_arg {
                    Some(idx) => vec![*idx],
                    None => Vec::new(),
                };
                facts.propagators.insert(key.clone(), args.clone());
                facts.propagators.entry(last.clone()).or_insert(args);
                if !*tainted_receiver {
                    facts.propagator_blocks_receiver.insert(key);
                    facts.propagator_blocks_receiver.insert(last);
                }
            }
            LearnedFactEntry::LanguageSessionRoot { root, .. } => {
                facts.session_roots.insert(root.clone());
            }
            LearnedFactEntry::LanguageRoutePattern { language, pattern } => {
                let slot = facts.route_patterns.entry(language.clone()).or_default();
                if !slot.contains(pattern) {
                    slot.push(pattern.clone());
                }
            }
            _ => {}
        }
    }
}
