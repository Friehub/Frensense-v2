// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;
use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::taint::config::TaintConfig;

/// Build a [`FactTable`] from a `frensense-lang` [`LanguageSpec`], the
/// built-in per-language knowledge (known sinks, sanitizers).
///
/// Every known sink name becomes an all-args signature; every sanitizer the
/// spec classifies becomes a [`SanitizerFact`]. Bundle-learned facts can then
/// be merged *over* this table (learned wins on collision).
pub fn fact_table_from_spec(spec: &dyn frensense_lang::spec::LanguageSpec) -> FactTable {
    let mut t = FactTable::default();
    for (call, label) in spec.known_sink_names() {
        // Dotted names ("res.json") are keyed by full path AND by last
        // segment: the engine matches by last segment at the call site, so
        // `res.json(...)` must resolve to the same signature (and role) as
        // the dotted entry.
        //
        // The role is resolved from THIS entry's own label, not a
        // last-segment-shared map: two entries can share a last segment
        // with different roles (`decode` = JwtUnsafeDecode/Validation,
        // `msgpack.decode` = UnsafeDeserialize/Execution). A shared map let
        // whichever dotted entry came last silently re-role the bare name.
        // Bare (non-dotted) entries register first and win the shared
        // last-segment key below; dotted aliases only fill unclaimed keys.
        let key = (*call).to_string();
        let last = call.rsplit('.').next().unwrap_or(call).to_string();
        let role = crate::analysis::taint::role::SinkRole::from_label(*label);
        t.sink_signatures
            .entry(key)
            .or_insert_with(|| SinkSignature {
                role,
                ..SinkSignature::all_args(call)
            });
        if last != *call {
            t.sink_signatures
                .entry(last.clone())
                .or_insert_with(|| SinkSignature {
                    role,
                    ..SinkSignature::all_args(call)
                });
            // Dotted entry sharing its last segment with a DIFFERENT-role
            // bare (or earlier-dotted) entry: record a receiver-specific
            // role so `kv.put(...)` can resolve Storage while `axios.put`
            // stays Ssrf. Root = first segment of the dotted name.
            if let Some(root) = call.split('.').next() {
                t.receiver_roles
                    .entry((root.to_string(), last.clone()))
                    .or_insert(role);
            }
        }
        // A dotted entry whose last segment is an ambiguous HTTP verb is
        // an AMBIGUOUS verb sink: `Map.get`, router `app.post`, LRU `.put`
        // all share the name. Record it so sink matching can require that
        // the receiver actually resolves to the client root
        // (got/axios/http...). The verb vocabulary is spec-owned
        // (`known_ambiguous_verbs`), not hardcoded here.
        if last != *call && spec.known_ambiguous_verbs().contains(&last.as_str()) {
            t.verb_sinks.insert(last.clone());
            if let Some(root) = call.split('.').next() {
                t.client_roots.insert(root.to_string());
            }
        }
    }
    // Per-slot danger facts override the all-args default for the sinks that
    // declare them (jwt.verify(token, secret), parameterized query(sql, params)).
    for (call, dangerous_slots, binding_safe) in spec.known_sink_signatures() {
        // Per-slot entries carry no label of their own: inherit the role
        // from the all-args entry the first loop registered for this call
        // (same spec, so it is present), falling back to Other.
        let role = t
            .sink_signatures
            .get(*call)
            .map(|s| s.role)
            .unwrap_or_default();
        let entry = SinkSignature {
            call: (*call).to_string(),
            dangerous_args: dangerous_slots.iter().copied().collect(),
            binding_args_safe: *binding_safe,
            idor_keys: Vec::new(),
            role,
        };
        t.sink_signatures.insert((*call).to_string(), entry.clone());
        let last = call.rsplit('.').next().unwrap_or(call);
        if last != *call {
            // Call sites match by last segment (`res.render(...)` looks up
            // `render`), so a dotted per-slot rule must reach the bare key.
            // It may replace the all-args alias loop 1 auto-created from a
            // dotted sink-name entry (a mechanical alias of this same
            // chain), but never a bare-owned entry: a bare name declared in
            // its own right keeps its own rule, mirroring the bare-wins
            // role rule above.
            let alias_owned_by_dotted = t
                .sink_signatures
                .get(last)
                .map(|cur| cur.call.contains('.'))
                .unwrap_or(false);
            if alias_owned_by_dotted {
                t.sink_signatures.insert(last.to_string(), entry);
            } else {
                t.sink_signatures.entry(last.to_string()).or_insert(entry);
            }
        }
    }
    // IDOR finder vocabulary from the spec: which calls take an identity
    // payload, and which top-level keys mark one. Identity-keyed taint at
    // such a sink is an access-control finding (Idor class); everything
    // else on these sinks - clause leaf values, non-identity fields, bare
    // scalars - is not reported (zero-FP: structurally unprovable).
    for (call, keys) in spec.known_idor_sinks() {
        let last = call.rsplit('.').next().unwrap_or(call);
        t.idor_finder_sinks.insert((*call).to_string());
        t.idor_finder_sinks.insert(last.to_string());
        for k in *keys {
            t.idor_keys.insert((*k).to_string());
        }
        let owned: Vec<String> = keys.iter().map(|s| (*s).to_string()).collect();
        if let Some(sig) = t.sink_signatures.get_mut(*call) {
            sig.idor_keys = owned.clone();
        }
        if last != *call
            && let Some(sig) = t.sink_signatures.get_mut(last)
        {
            sig.idor_keys = owned;
        }
    }
    for root in spec.known_session_roots() {
        t.session_roots.insert((*root).to_string());
    }
    // Denylist-guard patterns (`path.contains("..")`): spec-owned
    // vocabulary, bundles may extend via GuardDenylistPattern facts.
    for pattern in spec.known_guard_denylist() {
        if !t.guard_denylist_patterns.contains(&(*pattern).to_string()) {
            t.guard_denylist_patterns.push((*pattern).to_string());
        }
    }
    // Memory contracts, buffer builtins, the guard/credential/schema
    // vocabularies, hint sets and weak-crypto policy tables no longer
    // seed from the spec (Phase 6.1): the default pack carries them and
    // every consumer merges it between this seed and the consumer bundle
    // (seeding order: spec -> default pack -> consumer). Spec-seeded
    // only: stack allocators and the small structural vocabularies below.
    // Stack-frame allocators (alloca, ...): spec-owned, consumed by the
    // allocation-lifetime (leak) check.
    t.stack_allocators = spec
        .known_stack_allocators()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    // Vocabularies the checks read directly: collection constructors
    // (allowlist definitions), schema describe methods, null-compare
    // tokens, session read accessors, receiver parameter names.
    t.collection_constructors = spec
        .known_collection_constructors()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.schema_describe_methods = spec
        .known_schema_describe_methods()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.null_tokens = spec
        .known_null_tokens()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.session_accessors = spec
        .known_session_accessors()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.receiver_params = spec
        .known_receiver_params()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    // Guard/allowlist, credential, schema, URL-hint, weak-crypto,
    // integer-overflow, key-size and insecure-config tables seed from the
    // default pack (Phase 6.1), not from the spec - see the note above.
    // Spec sanitizers: register each known sanitizer into `t.sanitizer_facts`.
    // Predicate-guard detection (regex `.test()`, `is...()` type-guards, Full
    // classification) is spec-owned: `LanguageSpec::is_predicate_guard`.
    for name in spec.known_sanitizer_names() {
        let classified = spec.classify_sanitizer(name);
        let guard_style = spec.is_predicate_guard(name, classified.as_ref());
        let kind = if guard_style {
            ALLOWLIST_SANITIZER_KIND
        } else {
            DEFAULT_SANITIZER_KIND
        }
        .to_string();
        t.sanitizer_facts
            .entry((*name).to_string())
            .or_insert_with(|| SanitizerFact {
                call: (*name).to_string(),
                kind,
                sanitizes_args: Default::default(),
                guard_style,
            });
    }
    for prop in spec.propagator_rules() {
        let key = prop.call.to_string();
        let last = prop
            .call
            .rsplit('.')
            .next()
            .unwrap_or(prop.call)
            .to_string();
        let args: Vec<usize> = match prop.tainted_arg {
            Some(idx) => vec![idx],
            None => Vec::new(),
        };
        t.propagators.insert(key.clone(), args.clone());
        t.propagators.entry(last.clone()).or_insert(args);
        // Receiver semantics are part of the rule, not an implementation
        // detail: `tainted_receiver: false` must suppress the receiver ->
        // return edge too. The receiver's negative set keeps unknown and
        // bundle-learned calls at the default pass-through.
        if !prop.tainted_receiver {
            t.propagator_blocks_receiver.insert(key);
            t.propagator_blocks_receiver.insert(last);
        }
    }
    t
}

/// Build a [`TaintConfig`] from a `frensense-lang` [`LanguageSpec`]:
/// known source patterns + known sink names (last segment) + the sanitizer
/// name space derived from the spec's sanitizer classification table.
pub fn config_from_spec(spec: &dyn frensense_lang::spec::LanguageSpec) -> TaintConfig {
    let mut sources: FxHashSet<String> = spec
        .known_source_patterns()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    // Conventional request-parameter names are sources too: a function
    // parameter named `req`/`input`/`body` carries user data by convention.
    for p in spec.request_param_names() {
        sources.insert((*p).to_string());
    }
    let sinks: FxHashSet<String> = spec
        .known_sink_names()
        .iter()
        .map(|(call, _)| {
            // Engine matching is by last segment of the member chain.
            call.rsplit('.').next().unwrap_or(call).to_string()
        })
        .collect();
    let sanitizers: FxHashSet<String> = spec
        .known_sanitizer_names()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    TaintConfig {
        sources,
        sinks,
        sanitizers,
    }
}

/// Build the merged `(TaintConfig, FactTable)` for a set of file
/// extensions: one entry per distinct language spec present, exactly as
/// the consumer CLI merges them when scanning those files.
///
/// This is the single table-assembly function for both sides of the
/// harness/CLI contract: the scan runner feeds it the extensions of the
/// scanned files, the fact bundler feeds it a family's extensions. Both
/// must produce the same tables, or a family can learn under one dialect
/// and be replayed under another - a Go propagator rule silencing taint
/// in a TypeScript positive, or a Python sanitizer quieting a TypeScript
/// negative the CLI would flag.
pub fn tables_from_exts<'a>(exts: impl IntoIterator<Item = &'a str>) -> (TaintConfig, FactTable) {
    let mut config = TaintConfig::default();
    let mut facts = FactTable::default();
    let mut seen: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    for ext in exts {
        if let Some(spec) = frensense_lang::spec_for_ext(ext)
            && seen.insert(spec.name())
        {
            let c = config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&fact_table_from_spec(spec));
        }
    }
    (config, facts)
}

/// The distinct language names for a set of file extensions, in first
/// appearance order - the exact per-spec merge order [`tables_from_exts`]
/// uses. Feed the result to [`apply_language_entries`] so its group merges
/// land in the same order the spec-seeded tables were merged.
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
/// This replaces the provider-knowledge halves of [`config_from_spec`] and
/// [`fact_table_from_spec`], mirroring [`tables_from_exts`] exactly: the
/// wildcard group installs first, then one group per scan language in
/// caller order (first appearance of each scanned extension), each built in
/// a fresh temp table with the same or-insert/bare-wins rules as the
/// per-spec seed and merged in - so a scan ends up with the same tables as
/// before the provider bodies moved into the pack, cross-language key
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
        // sink install mirrors `fact_table_from_spec`'s verb-sink bookkeeping.
        let ambiguous: &[&str] = frensense_lang::registry::LanguageRegistry::global()
            .for_name(lang)
            .map_or(&[], |s| s.known_ambiguous_verbs());
        // Build this language's contribution in a fresh temp table, exactly
        // like `fact_table_from_spec` does per spec, then merge it in: the
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
