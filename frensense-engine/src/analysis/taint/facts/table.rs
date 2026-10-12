// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use rustc_hash::{FxHashMap, FxHashSet};

use super::*;
use crate::analysis::taint::config::TaintConfig;

/// The merged fact table: built-in language tables + bundle-learned facts.
///
/// Built from a [`TaintConfig`] (name sets, backward compatible) plus
/// optional signatures/sanitizer facts supplied by `frensense-lang` specs or
/// a `.frc` bundle.
#[derive(Debug, Clone, Default)]
pub struct FactTable {
    /// By call name. Absent = default "all args dangerous" for configured
    /// sinks.
    pub sink_signatures: FxHashMap<String, SinkSignature>,
    pub sanitizer_facts: FxHashMap<String, SanitizerFact>,
    /// Scoped sink signatures: (package, call_name) -> SinkSignature.
    pub scoped_sink_signatures: FxHashMap<(String, String), SinkSignature>,
    /// Scoped sanitizers: (package, call_name) -> SanitizerFact.
    pub scoped_sanitizer_facts: FxHashMap<(String, String), SanitizerFact>,
    /// Scoped taint sources: (package, pattern).
    pub scoped_sources: FxHashSet<(String, String)>,
    /// Corpus-verified non-dataflow checks (order-preserving; dedup on
    /// `(rule, call)` at merge time, provenance-ordered per entry).
    pub learned_checks: Vec<(LearnedCheckFact, Provenance)>,
    /// Corpus-verified co-occurrence policies (the generalized check fact).
    /// Evaluated by `checks::policy`; legacy `learned_checks` entries ALSO
    /// evaluate there after `PolicyFact::from_legacy` conversion, so bundles
    /// never need to migrate to keep firing. Dedup on
    /// `(rule, when_call)` at merge time, provenance-ordered per entry.
    pub policy_facts: Vec<(PolicyFact, Provenance)>,
    /// Corpus-verified interprocedural memory contracts (allocators / deallocators).
    pub memory_contracts: Vec<MemoryContractFact>,
    /// Corpus-verified weak cryptography rules.
    pub weak_crypto_rules: Vec<WeakCryptoFact>,
    /// Containment callees (for allowlist bypass checks) with per-entry
    /// provenance: default-pack-seeded (Spec), bundle-applied (Learned).
    pub containment_callees: FxHashMap<String, Provenance>,
    /// Credential setter/hasher sinks with per-entry provenance (pack ->
    /// Spec, bundle -> Learned).
    pub credential_sinks: FxHashMap<String, Provenance>,
    /// Parameter names identifying credentials with per-entry provenance
    /// (pack -> Spec, bundle -> Learned).
    pub credential_params: FxHashMap<String, Provenance>,
    /// Schema builder methods with per-entry provenance (pack -> Spec,
    /// bundle -> Learned).
    pub schema_builders: FxHashMap<String, Provenance>,
    /// Corpus-verified schema enforcer methods (default-pack-seeded).
    pub schema_enforcers: FxHashSet<String>,
    /// Bound keywords with per-entry provenance (pack -> Spec, bundle ->
    /// Learned).
    pub schema_keywords: FxHashMap<String, Provenance>,
    /// URL/redirect parameter-name hints (default-pack-seeded).
    pub url_param_hints: FxHashSet<String>,
    /// URL-ish guard argument hints (default-pack-seeded).
    pub url_arg_hints: FxHashSet<String>,
    /// Absolute-URL literal hints (default-pack-seeded).
    pub url_literal_hints: FxHashSet<String>,
    /// Security-context name hints (default-pack-seeded).
    pub security_context_hints: FxHashSet<String>,
    /// Auth-guard call-path hints (default-pack-seeded); the idor emission
    /// gate suppresses identity findings behind a guard branch over these
    /// calls.
    pub auth_guard_hints: FxHashSet<String>,
    /// JWT algorithm-operation call-path hints (default-pack-seeded).
    pub jwt_algorithm_hints: FxHashSet<String>,
    /// Credential-context name hints (default-pack-seeded).
    pub credential_context_hints: FxHashSet<String>,
    /// Weak-hash policy rules (default-pack-seeded).
    pub weak_hash_rules: Vec<WeakPrimitiveRule>,
    /// Corpus-extendable allocation-size overflow rules (CWE-190 -> CWE-680;
    /// default-pack-seeded, bundle extension via
    /// `LearnedFactEntry::IntegerOverflowRule` from a family's
    /// `[frensense] check-rule:` declaration).
    pub integer_overflow_rules: Vec<(IntegerOverflowRule, Provenance)>,
    /// Insecure config selectors (default-pack-seeded).
    pub insecure_config_selectors: Vec<InsecureConfigRule>,
    /// Key-size policy rules (default-pack-seeded).
    pub key_size_rules: Vec<KeySizeRule>,
    /// Suspicious hash-wrapper names (default-pack-seeded).
    pub suspicious_hash_wrappers: FxHashSet<String>,
    /// Last segments that come ONLY from dotted client sinks (`got.get`,
    /// `axios.post`, ...). These verbs are ambiguous, `Map.get`, router
    /// `app.post`, LRU `.put` all share the names, so they match
    /// receiver-aware: the call only counts as a sink when the receiver's
    /// root is a known client (see [`client_roots`]).
    pub verb_sinks: FxHashSet<String>,
    /// Receiver roots that make [`verb_sinks`] real client calls, derived
    /// from the first segment of dotted verb sinks (`got`, `axios`, `http`).
    pub client_roots: FxHashSet<String>,
    /// Receiver-specific roles for dotted sinks that share their last
    /// segment with a different-role bare entry:
    /// `(receiver_root, method) -> role`.
    ///
    /// Example: `KVNamespace.put` is StorageWrite while bare `run` is
    /// SqlInjection; `shell.run` is CommandInjection. When the engine sees
    /// `kv.put(...)` and the receiver root resolves to `kv`'s declared
    /// dotted root, THIS role wins over the bare entry's, the receiver is
    /// the disambiguator, exactly like [`verb_sinks`] for match/no-match.
    pub receiver_roles: FxHashMap<(String, String), crate::analysis::taint::role::SinkRole>,
    /// Receiver-specific label slugs: (receiver_root, method) -> label slug.
    pub receiver_labels: FxHashMap<(String, String), String>,
    /// Receiver roots of trusted session stores (`authenticatedUsers`):
    /// `store.get(token)` returns a server-issued session object or
    /// undefined, values read off the result are not attacker-controlled
    /// (the pack ships these with session-trust sanitizer facts).
    pub session_roots: FxHashSet<String>,
    /// Taint-source patterns learned from a `.frc` bundle: call names or
    /// member-access paths whose results carry attacker-controlled data.
    /// Merged into the scan's `TaintConfig::sources` before analysis so
    /// bundles teach new frameworks without touching the built-in tables.
    pub learned_sources: FxHashSet<String>,
    /// Dynamic node role classifications learned from a `.frc` bundle:
    /// `(language, node_kind) -> role`. Stored as the owned
    /// [`TeachableNodeRole`] (bundle payload type) and converted to a
    /// `frensense_lang::NodeRole` on lookup, so applying a fact never
    /// allocates `'static` memory (the previous `Box::leak` intern leaked
    /// per merge, growing unboundedly in long-lived MCP/LSP processes).
    pub grammar_roles:
        FxHashMap<(String, String), crate::analysis::taint::facts::TeachableNodeRole>,
    /// Dynamic grammar features learned from a `.frc` bundle:
    /// `(language, node_kind) -> Set<GrammarFeature>`.
    pub grammar_features: FxHashMap<(String, String), FxHashSet<GrammarFeature>>,
    /// Dynamic custom memory allocators learned from a bundle or specification.
    pub custom_allocators: FxHashSet<String>,
    /// Dynamic custom memory deallocators learned from a bundle or specification.
    pub custom_deallocators: FxHashSet<String>,
    /// Memory-function vocabulary (allocators/deallocators and their
    /// capacity contracts), default-pack-seeded (Phase 6.1). Empty means
    /// the caller built a bare table; the checks then see no memory
    /// vocabulary at all.
    pub memory_functions: Vec<MemoryFuncSpec>,
    /// Buffer-manipulation vocabulary (copy/fill/read builtins with their
    /// dst/src/len argument slots), default-pack-seeded (Phase 6.1).
    /// Empty means the caller built a bare table; the OOB check then sees
    /// no buffer vocabulary.
    pub buffer_builtins: Vec<BufferBuiltinSpec>,
    /// Stack-frame allocators (`alloca`, ...), default-pack-seeded
    /// (Phase 6.5); leak-style checkers exclude them.
    pub stack_allocators: Vec<String>,
    /// Route-registration call patterns per language
    /// (`(language or "*", patterns)`), default-pack-seeded (Phase 6.2);
    /// the lowering harness unions these with the spec's route verbs.
    pub route_patterns: FxHashMap<String, Vec<String>>,
    /// Collection constructors (`Set`, `Map`), default-pack-seeded
    /// (Phase 6.5); the allowlist-definition check reads their literal
    /// elements.
    pub collection_constructors: FxHashSet<String>,
    /// Schema-describing methods (`describe`, `description`),
    /// default-pack-seeded (Phase 6.5).
    pub schema_describe_methods: FxHashSet<String>,
    /// String literals that compare as the null pointer (`NULL`),
    /// default-pack-seeded (Phase 6.5).
    pub null_tokens: FxHashSet<String>,
    /// Read-accessor method names of trusted session stores (`get`),
    /// default-pack-seeded (Phase 6.5).
    pub session_accessors: FxHashSet<String>,
    /// Formal parameter names receiving the implicit receiver (`self`,
    /// `this`), default-pack-seeded (Phase 6.5).
    pub receiver_params: FxHashSet<String>,
    /// Dynamic IDOR-class query keys learned from a bundle or specification.
    pub idor_keys: FxHashSet<String>,
    /// Dynamic IDOR-class finder sinks learned from a bundle or specification.
    pub idor_finder_sinks: FxHashSet<String>,
    /// Dynamic taint propagators: `call -> input_arg_slots`.
    pub propagators: FxHashMap<String, Vec<usize>>,
    /// Spec propagator rules that declare `tainted_receiver: false`: taint
    /// on the receiver must NOT reach the return of such calls. A negative
    /// set (only explicit declarations appear), so unknown calls and
    /// bundle-learned propagators keep the default receiver pass-through.
    pub propagator_blocks_receiver: FxHashSet<String>,
    /// Guard denylist string patterns: default-pack-seeded
    /// (`GuardDenylistPattern`, Phase 6.5) and bundle-learned
    /// (`GuardDenylistPattern`).
    pub guard_denylist_patterns: Vec<String>,
}

impl FactTable {
    /// Build from a plain [`TaintConfig`]: every configured sink gets the
    /// all-args signature; every configured sanitizer a default fact.
    pub fn from_config(config: &TaintConfig) -> Self {
        let mut t = Self::default();
        for s in &config.sinks {
            t.sink_signatures
                .insert(s.clone(), SinkSignature::all_args(s));
        }
        for s in &config.sanitizers {
            t.sanitizer_facts.insert(
                s.clone(),
                SanitizerFact {
                    call: s.clone(),
                    package: None,
                    kind: DEFAULT_SANITIZER_KIND.into(),
                    sanitizes_args: Default::default(),
                    guard_style: false,
                },
            );
        }
        t
    }

    /// Merge bundle-learned facts over the current table (learned wins on
    /// name collision, bundle facts are more specific than built-ins).
    ///
    /// All-args signatures never overwrite slot-restricted ones on collision:
    /// a slot-restricted signature is strictly more specific knowledge, so an
    /// all-args merge (e.g. another language spec declaring the same bare
    /// call name) must not widen it back to "everything dangerous".
    pub fn merge(&mut self, other: &FactTable) {
        for (k, v) in &other.sink_signatures {
            let widens = v.dangerous_args.is_empty()
                && !v.binding_args_safe
                && self
                    .sink_signatures
                    .get(k)
                    .map(|cur| !cur.dangerous_args.is_empty() || cur.binding_args_safe)
                    .unwrap_or(false);
            if widens {
                continue;
            }
            self.sink_signatures.insert(k.clone(), v.clone());
        }
        for (k, v) in &other.sanitizer_facts {
            self.sanitizer_facts.insert(k.clone(), v.clone());
        }
        for (k, v) in &other.scoped_sink_signatures {
            let widens = self
                .scoped_sink_signatures
                .get(k)
                .map(|cur| !cur.dangerous_args.is_empty() || cur.binding_args_safe)
                .unwrap_or(false);
            if widens {
                continue;
            }
            self.scoped_sink_signatures.insert(k.clone(), v.clone());
        }
        for (k, v) in &other.scoped_sanitizer_facts {
            self.scoped_sanitizer_facts.insert(k.clone(), v.clone());
        }
        self.scoped_sources
            .extend(other.scoped_sources.iter().cloned());
        // Provenance-ordered (Phase 5.3): learned checks accumulate with
        // dedup on (rule, call), but the higher-ranked provenance wins the
        // collision (Spec < Authored < Learned) and ties keep the existing
        // entry, so merge is order-independent across provenance tiers.
        for (c, prov) in &other.learned_checks {
            if let Some(existing) = self
                .learned_checks
                .iter_mut()
                .find(|(e, _)| e.rule == c.rule && e.call == c.call)
            {
                if *prov > existing.1 {
                    *existing = (c.clone(), *prov);
                }
            } else {
                self.learned_checks.push((c.clone(), *prov));
            }
        }
        // Policy facts order the same way, dedup on (rule, when_call).
        for (p, prov) in &other.policy_facts {
            if let Some(existing) = self
                .policy_facts
                .iter_mut()
                .find(|(e, _)| e.rule == p.rule && e.when_call == p.when_call)
            {
                if *prov > existing.1 {
                    *existing = (p.clone(), *prov);
                }
            } else {
                self.policy_facts.push((p.clone(), *prov));
            }
        }
        // Memory contracts accumulate, with newer/learned contracts replacing older ones on collision.
        for mc in &other.memory_contracts {
            if let Some(existing) = self.memory_contracts.iter_mut().find(|c| c.name == mc.name) {
                *existing = mc.clone();
            } else {
                self.memory_contracts.push(mc.clone());
            }
        }
        for wc in &other.weak_crypto_rules {
            if let Some(existing) = self
                .weak_crypto_rules
                .iter_mut()
                .find(|r| r.rule_id == wc.rule_id && r.call == wc.call)
            {
                *existing = wc.clone();
            } else {
                self.weak_crypto_rules.push(wc.clone());
            }
        }
        // Merged entries keep their own provenance; on collision the
        // higher-ranked provenance wins (Spec < Authored < Learned), ties
        // keep the existing entry - order-independent across tiers.
        for (k, v) in &other.containment_callees {
            if self.containment_callees.get(k).is_none_or(|cur| *v > *cur) {
                self.containment_callees.insert(k.clone(), *v);
            }
        }
        for (k, v) in &other.credential_sinks {
            if self.credential_sinks.get(k).is_none_or(|cur| *v > *cur) {
                self.credential_sinks.insert(k.clone(), *v);
            }
        }
        for (k, v) in &other.credential_params {
            if self.credential_params.get(k).is_none_or(|cur| *v > *cur) {
                self.credential_params.insert(k.clone(), *v);
            }
        }
        for (k, v) in &other.schema_builders {
            if self.schema_builders.get(k).is_none_or(|cur| *v > *cur) {
                self.schema_builders.insert(k.clone(), *v);
            }
        }
        self.schema_enforcers
            .extend(other.schema_enforcers.iter().cloned());
        for (k, v) in &other.schema_keywords {
            if self.schema_keywords.get(k).is_none_or(|cur| *v > *cur) {
                self.schema_keywords.insert(k.clone(), *v);
            }
        }
        self.url_param_hints
            .extend(other.url_param_hints.iter().cloned());
        self.url_arg_hints
            .extend(other.url_arg_hints.iter().cloned());
        self.url_literal_hints
            .extend(other.url_literal_hints.iter().cloned());
        self.security_context_hints
            .extend(other.security_context_hints.iter().cloned());
        self.auth_guard_hints
            .extend(other.auth_guard_hints.iter().cloned());
        self.jwt_algorithm_hints
            .extend(other.jwt_algorithm_hints.iter().cloned());
        self.credential_context_hints
            .extend(other.credential_context_hints.iter().cloned());
        for r in &other.weak_hash_rules {
            if !self.weak_hash_rules.contains(r) {
                self.weak_hash_rules.push(r.clone());
            }
        }
        // Provenance-ordered like the policy tables: a consumer bundle
        // redefining a spec-seeded rule now overrides it (Learned >
        // Spec), ties keep the existing entry.
        for (r, p) in &other.integer_overflow_rules {
            if let Some(existing) = self
                .integer_overflow_rules
                .iter_mut()
                .find(|(e, _)| e.rule_id == r.rule_id && e.wrap_threshold == r.wrap_threshold)
            {
                if *p > existing.1 {
                    *existing = (r.clone(), *p);
                }
            } else {
                self.integer_overflow_rules.push((r.clone(), *p));
            }
        }
        for s in &other.insecure_config_selectors {
            if !self.insecure_config_selectors.contains(s) {
                self.insecure_config_selectors.push(s.clone());
            }
        }
        for r in &other.key_size_rules {
            if !self.key_size_rules.contains(r) {
                self.key_size_rules.push(r.clone());
            }
        }
        self.suspicious_hash_wrappers
            .extend(other.suspicious_hash_wrappers.iter().cloned());

        // Verb-sink bookkeeping accumulates too: dotted client entries
        // (`got.get`, `axios.post`) from any merged spec/bundle widen the
        // receiver-aware sets.
        self.verb_sinks.extend(other.verb_sinks.iter().cloned());
        self.client_roots.extend(other.client_roots.iter().cloned());
        // Receiver-specific roles accumulate like the other receiver-aware
        // sets: two merged specs can declare different dotted roots for the
        // same method, and both disambiguation rules must survive.
        for (k, v) in &other.receiver_roles {
            self.receiver_roles.entry(k.clone()).or_insert(*v);
        }
        for (k, v) in &other.receiver_labels {
            self.receiver_labels
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        self.session_roots
            .extend(other.session_roots.iter().cloned());
        self.learned_sources
            .extend(other.learned_sources.iter().cloned());
        for (k, v) in &other.grammar_roles {
            self.grammar_roles.insert(k.clone(), v.clone());
        }
        for (lang, pats) in &other.route_patterns {
            let slot = self.route_patterns.entry(lang.clone()).or_default();
            for p in pats {
                if !slot.contains(p) {
                    slot.push(p.clone());
                }
            }
        }
        for (k, v) in &other.grammar_features {
            self.grammar_features
                .entry(k.clone())
                .or_default()
                .extend(v.iter().copied());
        }
        self.custom_allocators
            .extend(other.custom_allocators.iter().cloned());
        self.custom_deallocators
            .extend(other.custom_deallocators.iter().cloned());
        if !other.memory_functions.is_empty() {
            self.memory_functions = other.memory_functions.clone();
        }
        if !other.buffer_builtins.is_empty() {
            self.buffer_builtins = other.buffer_builtins.clone();
        }
        if !other.stack_allocators.is_empty() {
            self.stack_allocators = other.stack_allocators.clone();
        }
        self.collection_constructors
            .extend(other.collection_constructors.iter().cloned());
        self.schema_describe_methods
            .extend(other.schema_describe_methods.iter().cloned());
        self.null_tokens.extend(other.null_tokens.iter().cloned());
        self.session_accessors
            .extend(other.session_accessors.iter().cloned());
        self.receiver_params
            .extend(other.receiver_params.iter().cloned());
        self.idor_keys.extend(other.idor_keys.iter().cloned());
        self.idor_finder_sinks
            .extend(other.idor_finder_sinks.iter().cloned());
        for (k, v) in &other.propagators {
            self.propagators.insert(k.clone(), v.clone());
        }
        self.propagator_blocks_receiver
            .extend(other.propagator_blocks_receiver.iter().cloned());
        for p in &other.guard_denylist_patterns {
            if !self.guard_denylist_patterns.contains(p) {
                self.guard_denylist_patterns.push(p.clone());
            }
        }
    }

    /// Look up a dynamic AST node classification role learned from a `.frc` bundle.
    pub fn get_grammar_role(
        &self,
        language: &str,
        node_kind: &str,
    ) -> Option<frensense_lang::NodeRole> {
        let lang = language.to_lowercase();
        self.grammar_roles
            .get(&(lang, node_kind.to_string()))
            .or_else(|| {
                self.grammar_roles
                    .get(&("*".to_string(), node_kind.to_string()))
            })
            .map(|r| r.to_node_role())
    }

    /// Check if a dynamic AST grammar feature is learned from a `.frc` bundle.
    pub fn has_grammar_feature(
        &self,
        language: &str,
        node_kind: &str,
        feature: GrammarFeature,
    ) -> Option<bool> {
        let lang = language.to_lowercase();
        if let Some(set) = self.grammar_features.get(&(lang, node_kind.to_string()))
            && set.contains(&feature)
        {
            return Some(true);
        }
        if let Some(set) = self
            .grammar_features
            .get(&("*".to_string(), node_kind.to_string()))
            && set.contains(&feature)
        {
            return Some(true);
        }
        None
    }

    /// Check whether a key is an IDOR-class query parameter (spec/bundle
    /// vocabulary - the engine ships no built-in key set).
    pub fn is_idor_key(&self, key: &str) -> bool {
        self.idor_keys.contains(key)
    }

    /// Check whether a call is an IDOR finder sink (spec/bundle vocabulary -
    /// the engine ships no built-in sink set).
    pub fn is_idor_finder_sink(&self, sink: &str) -> bool {
        let last = sink.rsplit('.').next().unwrap_or(sink);
        self.idor_finder_sinks.contains(sink) || self.idor_finder_sinks.contains(last)
    }

    /// Is `name` (bare, dotted, or `::`-qualified) a declared stack
    /// allocator? Frame-local storage is never a leak candidate; the
    /// vocabulary is default-pack-seeded (Phase 6.5).
    pub fn is_stack_allocator(&self, name: &str) -> bool {
        let s = name.rsplit('.').next().unwrap_or(name);
        let s = s.rsplit("::").next().unwrap_or(s);
        self.stack_allocators.iter().any(|a| a == s)
    }

    /// Is `name` a declared collection constructor (`Set`, `Map`)?
    pub fn is_collection_ctor(&self, name: &str) -> bool {
        self.collection_constructors.contains(name)
    }

    /// Is `name` a schema-describing method (`describe`, `description`)?
    pub fn is_schema_describe_method(&self, name: &str) -> bool {
        self.schema_describe_methods.contains(name)
    }

    /// Does the string literal `s` compare as the language's null pointer?
    pub fn is_null_token(&self, s: &str) -> bool {
        self.null_tokens.contains(s)
    }

    /// Is `last` a read accessor of a trusted session store
    /// (`authenticatedUsers.get(...)`)? Receiver-aware callers combine
    /// this with [`Self::session_roots`] via [`Self::is_session_path`].
    pub fn is_session_accessor(&self, last: &str) -> bool {
        self.session_accessors.contains(last)
    }

    /// Is `name` a formal parameter that receives the implicit receiver
    /// (`self`, `this`)?
    pub fn is_receiver_param(&self, name: &str) -> bool {
        self.receiver_params.contains(name)
    }

    /// Provenance of the containment callee matching `seg`
    /// (case-insensitive), or None when not declared.
    pub fn containment_callee(&self, seg: &str) -> Option<Provenance> {
        self.containment_callees
            .iter()
            .find(|(c, _)| c.eq_ignore_ascii_case(seg))
            .map(|(_, p)| *p)
    }

    /// Provenance of the credential sink matching `seg`
    /// (case-insensitive), or None when not declared.
    pub fn credential_sink(&self, seg: &str) -> Option<Provenance> {
        self.credential_sinks
            .iter()
            .find(|(s, _)| s.eq_ignore_ascii_case(seg))
            .map(|(_, p)| *p)
    }

    /// Provenance of the credential parameter whose lowercased name equals
    /// `lowered`, or None when not declared.
    pub fn credential_param(&self, lowered: &str) -> Option<Provenance> {
        self.credential_params
            .iter()
            .find(|(c, _)| lowered == c.to_ascii_lowercase())
            .map(|(_, p)| *p)
    }

    /// Provenance of the schema builder matching `seg`
    /// (case-insensitive), or None when not declared.
    pub fn schema_builder(&self, seg: &str) -> Option<Provenance> {
        self.schema_builders
            .iter()
            .find(|(b, _)| b.eq_ignore_ascii_case(seg))
            .map(|(_, p)| *p)
    }

    /// Provenance of a bound keyword contained in the lowercased schema
    /// description `lower`, or None when none matches.
    pub fn schema_keyword(&self, lower: &str) -> Option<Provenance> {
        self.schema_keywords
            .iter()
            .find(|(k, _)| lower.contains(&k.to_ascii_lowercase()))
            .map(|(_, p)| *p)
    }

    /// Look up input argument slots that propagate taint through `call`.
    pub fn propagator_input_args(&self, call: &str) -> Option<&[usize]> {
        let last = call.rsplit('.').next().unwrap_or(call);
        self.propagators
            .get(call)
            .or_else(|| self.propagators.get(last))
            .map(|v| v.as_slice())
    }

    /// Does a spec rule declare that `call`'s receiver does not taint its
    /// return (`tainted_receiver: false`)? Keyed like `propagators`: full
    /// name first, then last segment.
    pub fn propagator_blocks_receiver(&self, call: &str) -> bool {
        if self.propagator_blocks_receiver.contains(call) {
            return true;
        }
        let last = call.rsplit('.').next().unwrap_or(call);
        last != call && self.propagator_blocks_receiver.contains(last)
    }

    /// Check whether a string literal matches a guard denylist pattern.
    /// Patterns are pack/bundle vocabulary (the default pack's
    /// `GuardDenylistPattern` entries, extended by learned
    /// `GuardDenylistPattern` facts) - the engine ships no built-in list.
    pub fn is_guard_denylist(&self, literal: &str) -> bool {
        self.guard_denylist_patterns
            .iter()
            .any(|p| literal.contains(p.as_str()))
    }

    /// Source patterns to merge into the scan's `TaintConfig`: the union of
    /// spec-derived names and bundle-learned ones. The engine matches both
    /// by full name and, for dotted entries, by last segment.
    pub fn source_patterns(&self) -> impl Iterator<Item = &str> {
        self.learned_sources.iter().map(|s| s.as_str())
    }
}
