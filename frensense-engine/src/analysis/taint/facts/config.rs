// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;
use rustc_hash::FxHashSet;

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
            .unwrap_or(crate::analysis::taint::role::SinkRole::Other);
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
    // Memory-function vocabulary (allocators/deallocators + capacity
    // contracts): spec-owned, consumed by the memory/UAF/OOB checks.
    t.memory_functions = spec.known_memory_functions().to_vec();
    // Buffer builtins (copy/fill/read with dst/src/len slots): spec-owned,
    // consumed by the spatial (OOB) check.
    t.buffer_builtins = spec.known_buffer_builtins().to_vec();
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
    // Guard/allowlist, credential, schema and URL-hint policy vocabulary:
    // spec-owned, read directly by the checks through these fields.
    t.containment_callees = spec
        .known_containment_callees()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.credential_sinks = spec
        .known_credential_sinks()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.credential_params = spec
        .known_credential_params()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.schema_builders = spec
        .known_schema_builders()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.schema_enforcers = spec
        .known_schema_enforcers()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.schema_keywords = spec
        .known_schema_keywords()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.url_param_hints = spec
        .known_url_param_hints()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.url_arg_hints = spec
        .known_url_arg_hints()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.url_literal_hints = spec
        .known_url_literal_hints()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.security_context_hints = spec
        .known_security_context_hints()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    // Qualification vocabularies: auth-guard call paths (idor suppression),
    // verifier hints (insecure-jwt), credential-context hints (weak digest).
    t.auth_guard_hints = spec
        .known_auth_guard_hints()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.jwt_algorithm_hints = spec
        .known_jwt_algorithm_hints()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    t.credential_context_hints = spec
        .known_credential_context_hints()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    // Weak-crypto policy tables: spec-owned; `weak_hash::check` unions the
    // bootstrap defaults with these.
    t.weak_hash_rules = spec.known_weak_hash_rules().to_vec();
    // Allocation-size overflow rules: spec-owned seed; the bundle extends
    // via `LearnedFactEntry::IntegerOverflowRule`; `int_overflow::check`
    // unions the bootstrap defaults with these.
    t.integer_overflow_rules = spec.known_integer_overflow_rules().to_vec();
    t.insecure_config_selectors = spec.known_insecure_config_selectors().to_vec();
    t.key_size_rules = spec.known_key_size_rules().to_vec();
    t.suspicious_hash_wrappers = spec
        .known_suspicious_hash_wrappers()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    // Spec sanitizers: register each known sanitizer into `t.sanitizer_facts`.
    // Predicate-guard detection (regex `.test()`, `is...()` type-guards, Full
    // classification) is spec-owned: `LanguageSpec::is_predicate_guard`.
    for name in spec.known_sanitizer_names() {
        let classified = spec.classify_sanitizer(name);
        let kind = classified
            .as_ref()
            .map(|k| format!("{k:?}"))
            .unwrap_or_else(|| "encode".into());
        let guard_style = spec.is_predicate_guard(name, classified.as_ref());
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
