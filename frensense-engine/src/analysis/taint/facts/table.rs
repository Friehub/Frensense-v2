// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeSet;

use super::*;
use crate::analysis::taint::config::TaintConfig;
use crate::checks::memory_summary::CapacitySpec;
use frensense_lang::policy::{
    InsecureConfigRule, IntegerOverflowRule, KeySizeRule, WeakPrimitiveRule,
};

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
    /// Corpus-verified non-dataflow checks (order-preserving; dedup on
    /// `(rule, call)` at merge time).
    pub learned_checks: Vec<LearnedCheckFact>,
    /// Corpus-verified co-occurrence policies (the generalized check fact).
    /// Evaluated by `checks::policy`; legacy `learned_checks` entries ALSO
    /// evaluate there after `PolicyFact::from_legacy` conversion, so bundles
    /// never need to migrate to keep firing.
    pub policy_facts: Vec<PolicyFact>,
    /// Corpus-verified interprocedural memory contracts (allocators / deallocators).
    pub memory_contracts: Vec<MemoryContractFact>,
    /// Corpus-verified weak cryptography rules.
    pub weak_crypto_rules: Vec<WeakCryptoFact>,
    /// Containment callees (for allowlist bypass checks) with per-entry
    /// provenance: spec-seeded via `LanguageSpec::known_containment_callees`
    /// (Spec), bundle-applied (Learned).
    pub containment_callees: FxHashMap<String, Provenance>,
    /// Credential setter/hasher sinks with per-entry provenance
    /// (spec-seeded via `LanguageSpec::known_credential_sinks` -> Spec,
    /// bundle -> Learned).
    pub credential_sinks: FxHashMap<String, Provenance>,
    /// Parameter names identifying credentials with per-entry provenance
    /// (spec-seeded via `LanguageSpec::known_credential_params` -> Spec,
    /// bundle -> Learned).
    pub credential_params: FxHashMap<String, Provenance>,
    /// Schema builder methods with per-entry provenance (spec-seeded via
    /// `LanguageSpec::known_schema_builders` -> Spec, bundle -> Learned).
    pub schema_builders: FxHashMap<String, Provenance>,
    /// Corpus-verified schema enforcer methods (spec-seeded via
    /// `LanguageSpec::known_schema_enforcers`).
    pub schema_enforcers: FxHashSet<String>,
    /// Bound keywords with per-entry provenance (spec-seeded via
    /// `LanguageSpec::known_schema_keywords` -> Spec, bundle -> Learned).
    pub schema_keywords: FxHashMap<String, Provenance>,
    /// URL/redirect parameter-name hints (spec-seeded via
    /// `LanguageSpec::known_url_param_hints`).
    pub url_param_hints: FxHashSet<String>,
    /// URL-ish guard argument hints (spec-seeded via
    /// `LanguageSpec::known_url_arg_hints`).
    pub url_arg_hints: FxHashSet<String>,
    /// Absolute-URL literal hints (spec-seeded via
    /// `LanguageSpec::known_url_literal_hints`).
    pub url_literal_hints: FxHashSet<String>,
    /// Security-context name hints (spec-seeded via
    /// `LanguageSpec::known_security_context_hints`).
    pub security_context_hints: FxHashSet<String>,
    /// Auth-guard call-path hints (spec-seeded via
    /// `LanguageSpec::known_auth_guard_hints`); the idor emission gate
    /// suppresses identity findings behind a guard branch over these calls.
    pub auth_guard_hints: FxHashSet<String>,
    /// JWT algorithm-operation call-path hints (spec-seeded via
    /// `LanguageSpec::known_jwt_algorithm_hints`).
    pub jwt_algorithm_hints: FxHashSet<String>,
    /// Credential-context name hints (spec-seeded via
    /// `LanguageSpec::known_credential_context_hints`).
    pub credential_context_hints: FxHashSet<String>,
    /// Weak-hash policy rules (spec-seeded via
    /// `LanguageSpec::known_weak_hash_rules`).
    pub weak_hash_rules: Vec<WeakPrimitiveRule>,
    /// Corpus-extendable allocation-size overflow rules (CWE-190 -> CWE-680;
    /// spec-seeded via `LanguageSpec::known_integer_overflow_rules`, bundle
    /// extension via `LearnedFactEntry::IntegerOverflowRule` from a family's
    /// `[frensense] check-rule:` declaration).
    pub integer_overflow_rules: Vec<(IntegerOverflowRule, Provenance)>,
    /// Insecure config selectors (spec-seeded via
    /// `LanguageSpec::known_insecure_config_selectors`).
    pub insecure_config_selectors: Vec<InsecureConfigRule>,
    /// Key-size policy rules (spec-seeded via
    /// `LanguageSpec::known_key_size_rules`).
    pub key_size_rules: Vec<KeySizeRule>,
    /// Suspicious hash-wrapper names (spec-seeded via
    /// `LanguageSpec::known_suspicious_hash_wrappers`).
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
    /// Receiver roots of trusted session stores (`authenticatedUsers`):
    /// `store.get(token)` returns a server-issued session object or
    /// undefined, values read off the result are not attacker-controlled
    /// (see [`SanitizerKind::SessionTrust`]).
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
    /// capacity contracts) seeded from the spec's
    /// `known_memory_functions`. Empty means the caller built a bare
    /// table; the checks then see no memory vocabulary at all.
    pub memory_functions: Vec<frensense_lang::memory::MemoryFuncSpec>,
    /// Buffer-manipulation vocabulary (copy/fill/read builtins with their
    /// dst/src/len argument slots) seeded from the spec's
    /// `known_buffer_builtins`. Empty means the caller built a bare
    /// table; the OOB check then sees no buffer vocabulary.
    pub buffer_builtins: Vec<frensense_lang::memory::BufferBuiltinSpec>,
    /// Stack-frame allocators (`alloca`, ...) seeded from the spec's
    /// `known_stack_allocators`; leak-style checkers exclude them.
    pub stack_allocators: Vec<String>,
    /// Collection constructors (`Set`, `Map`) seeded from the spec's
    /// `known_collection_constructors`; the allowlist-definition check
    /// reads their literal elements.
    pub collection_constructors: FxHashSet<String>,
    /// Schema-describing methods (`describe`, `description`) seeded from
    /// the spec's `known_schema_describe_methods`.
    pub schema_describe_methods: FxHashSet<String>,
    /// String literals that compare as the null pointer (`NULL`) seeded
    /// from the spec's `known_null_tokens`.
    pub null_tokens: FxHashSet<String>,
    /// Read-accessor method names of trusted session stores (`get`)
    /// seeded from the spec's `known_session_accessors`.
    pub session_accessors: FxHashSet<String>,
    /// Formal parameter names receiving the implicit receiver (`self`,
    /// `this`) seeded from the spec's `known_receiver_params`.
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
    /// Guard denylist string patterns: spec-seeded
    /// (`known_guard_denylist`) and bundle-learned
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
        // Learned checks accumulate: a bundle may install many rules, and
        // merging a second bundle must not drop the first's. Dedup on
        // (rule, call): the same fact arriving twice (shared dependencies,
        // re-merge) must not duplicate findings.
        for c in &other.learned_checks {
            if !self
                .learned_checks
                .iter()
                .any(|e| e.rule == c.rule && e.call == c.call)
            {
                self.learned_checks.push(c.clone());
            }
        }
        // Policy facts accumulate the same way, dedup on (rule, when_call):
        // the same policy arriving twice must not duplicate findings.
        for p in &other.policy_facts {
            if !self
                .policy_facts
                .iter()
                .any(|e| e.rule == p.rule && e.when_call == p.when_call)
            {
                self.policy_facts.push(p.clone());
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
        // Merged entries keep their own provenance (other wins on
        // collision: a bundle overrides a spec entry and carries Learned).
        for (k, v) in &other.containment_callees {
            self.containment_callees.insert(k.clone(), *v);
        }
        for (k, v) in &other.credential_sinks {
            self.credential_sinks.insert(k.clone(), *v);
        }
        for (k, v) in &other.credential_params {
            self.credential_params.insert(k.clone(), *v);
        }
        for (k, v) in &other.schema_builders {
            self.schema_builders.insert(k.clone(), *v);
        }
        self.schema_enforcers
            .extend(other.schema_enforcers.iter().cloned());
        for (k, v) in &other.schema_keywords {
            self.schema_keywords.insert(k.clone(), *v);
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
                self.weak_hash_rules.push(*r);
            }
        }
        for (r, p) in &other.integer_overflow_rules {
            if !self
                .integer_overflow_rules
                .iter()
                .any(|(e, _)| e.rule_id == r.rule_id && e.wrap_threshold == r.wrap_threshold)
            {
                self.integer_overflow_rules.push((r.clone(), *p));
            }
        }
        for s in &other.insecure_config_selectors {
            if !self.insecure_config_selectors.contains(s) {
                self.insecure_config_selectors.push(*s);
            }
        }
        for r in &other.key_size_rules {
            if !self.key_size_rules.contains(r) {
                self.key_size_rules.push(*r);
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
        self.session_roots
            .extend(other.session_roots.iter().cloned());
        self.learned_sources
            .extend(other.learned_sources.iter().cloned());
        for (k, v) in &other.grammar_roles {
            self.grammar_roles.insert(k.clone(), v.clone());
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

    /// Is `name` (bare, dotted, or `::`-qualified) a spec-declared stack
    /// allocator? Frame-local storage is never a leak candidate; the
    /// vocabulary is seeded via `known_stack_allocators`.
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
    /// Patterns are spec/bundle vocabulary (seeded from
    /// `LanguageSpec::known_guard_denylist`, extended by
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

/// One learned fact as persisted in a `.frc` bundle. A tagged union over the
/// three fact kinds, serde-friendly, decodable into a [`FactTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum LearnedFactEntry {
    /// A taint source pattern: a call name or member-access path whose
    /// result carries attacker-controlled data. Merged into the scan's
    /// [`TaintConfig::sources`] so bundles teach new frameworks without
    /// touching the built-in tables. Matches by full name or, for dotted
    /// entries, by last segment (same convention as sinks).
    Source { pattern: String },
    Sink {
        call: String,
        /// Dangerous argument slots; empty = all slots dangerous.
        dangerous_args: BTreeSet<usize>,
        /// Whether non-dangerous slots are safe binding channels.
        binding_args_safe: bool,
    },
    Sanitizer {
        call: String,
        kind: String,
        guard_style: bool,
    },
    /// Install a corpus-verified co-occurrence policy (the generalized
    /// check fact; see [`PolicyFact`]).
    Policy {
        rule: String,
        when_call: String,
        /// Requirements that must hold for the trigger to be compliant.
        #[cfg_attr(feature = "serialize", serde(default))]
        require: Vec<PolicyRequirement>,
        #[cfg_attr(feature = "serialize", serde(default))]
        scope: PolicyScope,
        message: String,
        severity: String,
    },
    /// Install a corpus-verified non-dataflow check.
    Check {
        rule: String,
        call: String,
        message: String,
        severity: String,
        /// Fire only when this guard call is absent from the function
        /// ("trigger without enforcement"). `None` = presence-only.
        #[cfg_attr(feature = "serialize", serde(default))]
        unless_guard: Option<String>,
        /// Fire only when the trigger's argument is NOT compared against a
        /// literal bound with one of these operators (inline enforcement).
        /// `None` = no range qualification.
        #[cfg_attr(feature = "serialize", serde(default))]
        unless_range_check: Option<Vec<String>>,
    },
    /// Install a corpus-verified memory allocation or deallocation contract.
    MemoryContract {
        name: String,
        returns_fresh: bool,
        return_capacity: CapacitySpec,
        consumes_params: Vec<usize>,
    },
    /// A weak cryptographic primitive or selector rule.
    WeakCrypto(WeakCryptoFact),
    /// Guard bypass parameters (containment check helpers or credential sinks).
    GuardBypass(GuardBypassFact),
    /// Schema validation builders, enforcers, or keywords.
    SchemaPolicy(SchemaPolicyFact),
    /// Dynamic AST grammar role mapping taught by a bundle.
    GrammarRole {
        language: String,
        node_kind: String,
        role: TeachableNodeRole,
    },
    /// Dynamic AST grammar feature taught by a bundle.
    GrammarFeature {
        language: String,
        node_kind: String,
        feature: GrammarFeature,
    },
    /// Register a custom memory allocator function name.
    Allocator { name: String },
    /// Register a custom memory deallocator function name.
    Deallocator { name: String },
    /// Register an IDOR-class finder sink and optional custom IDOR query payload keys.
    IdorFinderSink { call: String, keys: Vec<String> },
    /// Register an IDOR-class query payload key (e.g. "tenant_id", "workspace_id").
    IdorKey { key: String },
    /// Register a taint propagator rule for a function/method.
    Propagator {
        call: String,
        input_args: Vec<usize>,
        preserves_taint: bool,
    },
    /// Register a string pattern indicating a denylist-style guard comparison.
    GuardDenylistPattern { pattern: String },
    /// Register/extend an allocation-size integer-overflow rule: the corpus
    /// declares the prover rule id, wrap threshold, and advisory; the
    /// engine's stable prover evaluates it (CWE-190 -> CWE-680).
    IntegerOverflowRule {
        rule: String,
        wrap_threshold: u128,
        severity: String,
        message: String,
    },
}

impl LearnedFactEntry {
    /// Finding identities this fact's scanner output is keyed by: checker
    /// rule ids and learned sink call names. The bundle-advisory join
    /// (`BundlePattern::rules`) goes through this, so a family's
    /// `[frensense]` metadata can attach to the findings its facts cause.
    /// Entries whose findings use engine-internal rule ids (memory
    /// contracts, guard vocabularies, grammar) contribute none.
    pub fn finding_identities(&self) -> Vec<String> {
        match self {
            LearnedFactEntry::Sink { call, .. } | LearnedFactEntry::IdorFinderSink { call, .. } => {
                vec![call.clone()]
            }
            LearnedFactEntry::Policy { rule, .. }
            | LearnedFactEntry::Check { rule, .. }
            | LearnedFactEntry::IntegerOverflowRule { rule, .. } => vec![rule.clone()],
            LearnedFactEntry::WeakCrypto(fact) => vec![fact.rule_id.clone()],
            _ => Vec::new(),
        }
    }

    /// Insert this fact into a [`FactTable`].
    pub fn apply(&self, table: &mut FactTable) {
        match self {
            LearnedFactEntry::Source { pattern } => {
                table.learned_sources.insert(pattern.clone());
            }
            LearnedFactEntry::Sink {
                call,
                dangerous_args,
                binding_args_safe,
            } => {
                // Preserve a spec-derived role (and IDOR keys) if the built-in
                // table already classifies this call, learned facts refine
                // *slots*, they don't reclassify *semantics*.
                let prior = table.sink_signatures.get(call);
                let role = prior.map(|s| s.role).unwrap_or_default();
                let idor_keys = prior.map(|s| s.idor_keys.clone()).unwrap_or_default();
                table.sink_signatures.insert(
                    call.clone(),
                    SinkSignature {
                        call: call.clone(),
                        dangerous_args: dangerous_args.clone(),
                        binding_args_safe: *binding_args_safe,
                        idor_keys,
                        role,
                    },
                );
            }
            LearnedFactEntry::Sanitizer {
                call,
                kind,
                guard_style,
            } => {
                table.sanitizer_facts.insert(
                    call.clone(),
                    SanitizerFact {
                        call: call.clone(),
                        kind: kind.clone(),
                        sanitizes_args: Default::default(),
                        guard_style: *guard_style,
                    },
                );
            }
            LearnedFactEntry::Policy {
                rule,
                when_call,
                require,
                scope,
                message,
                severity,
            } => {
                let fact = PolicyFact {
                    rule: rule.clone(),
                    when_call: when_call.clone(),
                    require: require.clone(),
                    scope: *scope,
                    message: message.clone(),
                    severity: severity.clone(),
                };
                if !table
                    .policy_facts
                    .iter()
                    .any(|e| e.rule == fact.rule && e.when_call == fact.when_call)
                {
                    table.policy_facts.push(fact);
                }
            }
            LearnedFactEntry::Check {
                rule,
                call,
                message,
                severity,
                unless_guard,
                unless_range_check,
            } => {
                let fact = LearnedCheckFact {
                    rule: rule.clone(),
                    call: call.clone(),
                    message: message.clone(),
                    severity: severity.clone(),
                    unless_guard: unless_guard.clone(),
                    unless_range_check: unless_range_check.clone(),
                };
                if !table
                    .learned_checks
                    .iter()
                    .any(|e| e.rule == fact.rule && e.call == fact.call)
                {
                    table.learned_checks.push(fact);
                }
            }
            LearnedFactEntry::MemoryContract {
                name,
                returns_fresh,
                return_capacity,
                consumes_params,
            } => {
                let fact = MemoryContractFact {
                    name: name.clone(),
                    returns_fresh: *returns_fresh,
                    return_capacity: return_capacity.clone(),
                    consumes_params: consumes_params.clone(),
                };
                if let Some(existing) = table
                    .memory_contracts
                    .iter_mut()
                    .find(|c| c.name == fact.name)
                {
                    *existing = fact;
                } else {
                    table.memory_contracts.push(fact);
                }
            }
            LearnedFactEntry::WeakCrypto(fact) => {
                if let Some(existing) = table
                    .weak_crypto_rules
                    .iter_mut()
                    .find(|r| r.rule_id == fact.rule_id && r.call == fact.call)
                {
                    *existing = fact.clone();
                } else {
                    table.weak_crypto_rules.push(fact.clone());
                }
            }
            LearnedFactEntry::GuardBypass(fact) => {
                for c in &fact.containment_callees {
                    table
                        .containment_callees
                        .insert(c.clone(), Provenance::Learned);
                }
                for s in &fact.credential_sinks {
                    table
                        .credential_sinks
                        .insert(s.clone(), Provenance::Learned);
                }
                for p in &fact.credential_params {
                    table
                        .credential_params
                        .insert(p.clone(), Provenance::Learned);
                }
            }
            LearnedFactEntry::SchemaPolicy(fact) => {
                for b in &fact.builders {
                    table.schema_builders.insert(b.clone(), Provenance::Learned);
                }
                table
                    .schema_enforcers
                    .extend(fact.enforcers.iter().cloned());
                for k in &fact.bound_keywords {
                    table.schema_keywords.insert(k.clone(), Provenance::Learned);
                }
            }
            LearnedFactEntry::GrammarRole {
                language,
                node_kind,
                role,
            } => {
                table
                    .grammar_roles
                    .insert((language.to_lowercase(), node_kind.clone()), role.clone());
            }
            LearnedFactEntry::GrammarFeature {
                language,
                node_kind,
                feature,
            } => {
                table
                    .grammar_features
                    .entry((language.to_lowercase(), node_kind.clone()))
                    .or_default()
                    .insert(*feature);
            }
            LearnedFactEntry::Allocator { name } => {
                let last = name.rsplit('.').next().unwrap_or(name).to_string();
                table.custom_allocators.insert(name.clone());
                table.custom_allocators.insert(last);
            }
            LearnedFactEntry::Deallocator { name } => {
                let last = name.rsplit('.').next().unwrap_or(name).to_string();
                table.custom_deallocators.insert(name.clone());
                table.custom_deallocators.insert(last);
            }
            LearnedFactEntry::IdorFinderSink { call, keys } => {
                let last = call.rsplit('.').next().unwrap_or(call).to_string();
                table.idor_finder_sinks.insert(call.clone());
                table.idor_finder_sinks.insert(last.clone());
                for k in keys {
                    table.idor_keys.insert(k.clone());
                }
                let sig = SinkSignature {
                    call: call.clone(),
                    dangerous_args: std::collections::BTreeSet::new(),
                    binding_args_safe: false,
                    // Per-call keys when taught; otherwise the learned global
                    // identity keys (no engine built-in fallback - vocabulary
                    // is spec/bundle-owned, empty disables the gate).
                    idor_keys: if keys.is_empty() {
                        table.idor_keys.iter().cloned().collect()
                    } else {
                        keys.clone()
                    },
                    role: crate::analysis::taint::role::SinkRole::Resource,
                };
                table.sink_signatures.insert(call.clone(), sig.clone());
                table.sink_signatures.entry(last).or_insert(sig);
            }
            LearnedFactEntry::IdorKey { key } => {
                table.idor_keys.insert(key.clone());
            }
            LearnedFactEntry::Propagator {
                call,
                input_args,
                preserves_taint,
            } => {
                if *preserves_taint {
                    let last = call.rsplit('.').next().unwrap_or(call).to_string();
                    table.propagators.insert(call.clone(), input_args.clone());
                    table.propagators.insert(last, input_args.clone());
                }
            }
            LearnedFactEntry::GuardDenylistPattern { pattern } => {
                if !table.guard_denylist_patterns.contains(pattern) {
                    table.guard_denylist_patterns.push(pattern.clone());
                }
            }
            LearnedFactEntry::IntegerOverflowRule {
                rule,
                wrap_threshold,
                severity,
                message,
            } => {
                let fact = IntegerOverflowRule {
                    rule_id: rule.clone(),
                    wrap_threshold: *wrap_threshold,
                    severity: severity.clone(),
                    message: message.clone(),
                };
                if let Some(existing) = table.integer_overflow_rules.iter_mut().find(|(r, _)| {
                    r.rule_id == fact.rule_id && r.wrap_threshold == fact.wrap_threshold
                }) {
                    *existing = (fact, Provenance::Learned);
                } else {
                    table
                        .integer_overflow_rules
                        .push((fact, Provenance::Learned));
                }
            }
        }
    }
}

/// Build a [`FactTable`] from a list of learned bundle facts.
pub fn fact_table_from_entries(entries: &[LearnedFactEntry]) -> FactTable {
    let mut t = FactTable::default();
    for e in entries {
        e.apply(&mut t);
    }
    t
}

/// One hand-authored rule as persisted in a bundle's `policy_pack` section
/// (`.frc` v5). `policy.toml` (D2) parses into these; presence in the
/// section is what marks an entry's provenance [`Provenance::Authored`],
/// mirroring `learned_facts` -> [`Provenance::Learned`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthoredPolicyEntry {
    /// A generalized co-occurrence policy: same fields as [`PolicyFact`],
    /// carried whole so the author's severity/message travel with it.
    Policy(PolicyFact),
    /// An allocation-size integer-overflow rule: same fields as
    /// [`LearnedFactEntry::IntegerOverflowRule`] (the hand-authored
    /// precedent: `[frensense] wrap-max:` metadata, now also `policy.toml`).
    IntegerOverflowRule {
        rule: String,
        wrap_threshold: u128,
        severity: String,
        message: String,
    },
}
