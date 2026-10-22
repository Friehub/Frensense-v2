// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! `LearnedFactEntry`: the learned-fact tagged union persisted in `.frc`
//! bundles and applied into a [`FactTable`] (this module keeps only the
//! entry type and its `apply_with` lowering; the table itself lives in
//! `table.rs`).

use std::collections::BTreeSet;

use super::*;
use crate::checks::memory_summary::CapacitySpec;

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
    Source {
        pattern: String,
        #[cfg_attr(feature = "serialize", serde(default))]
        package: Option<String>,
    },
    Sink {
        call: String,
        #[cfg_attr(feature = "serialize", serde(default))]
        package: Option<String>,
        /// Dangerous argument slots; empty = all slots dangerous.
        dangerous_args: BTreeSet<usize>,
        /// Whether non-dangerous slots are safe binding channels.
        binding_args_safe: bool,
    },
    Sanitizer {
        call: String,
        #[cfg_attr(feature = "serialize", serde(default))]
        package: Option<String>,
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
    /// Substring-hint vocabulary for one hint table (Phase 6 format
    /// extension): bundles extend the URL/security/auth/credential hint
    /// sets the same way the spec seed provides them.
    Hints { kind: HintKind, values: Vec<String> },
    /// A weak-primitive policy rule (weak digest selectors), the bundle
    /// form of the bootstrap weak-hash table.
    WeakPrimitiveRule {
        rule_id: String,
        selector_calls: Vec<String>,
        bare_calls: Vec<String>,
        selector_slot: usize,
        weak_selectors: Vec<String>,
        requires_credential_context: bool,
        severity: String,
        message: String,
    },
    /// A string-literal insecure-configuration selector rule (the bundle
    /// form of the bootstrap insecure-config table).
    InsecureConfigRule {
        prefix: String,
        selectors: Vec<String>,
        rule_id: String,
        severity: String,
        message: String,
    },
    /// A minimum-key-size rule for a key-generation call (the bundle form
    /// of the bootstrap key-size table).
    KeySizeRule {
        rule_id: String,
        call: String,
        slot: usize,
        min_bits: i64,
        kind: String,
        severity: String,
        message: String,
    },
    /// Known wrapper calls whose entire purpose is hashing: the bundle
    /// form of the bootstrap suspicious-hash-wrapper vocabulary.
    SuspiciousHashWrappers { calls: Vec<String> },
    /// A buffer-manipulation builtin with destination/source/length slots:
    /// the bundle form of the bootstrap buffer vocabulary.
    BufferBuiltin {
        name: String,
        dst_arg: Option<usize>,
        src_arg: Option<usize>,
        len_arg: usize,
    },

    // ── Phase 6.2: language-keyed default-pack knowledge ──────────────────
    // These variants carry the per-language provider tables that used to
    // seed through `LanguageSpec::known_*` methods. They are applied by
    // `apply_language_entries` (config + facts together), filtered by the
    // scan's languages; `"*"` matches every language. Family bundles keep
    // using the language-agnostic variants above.
    /// An all-arguments dangerous sink for one language, with the role the
    /// pack generator derived from its vocabulary label (snake_case
    /// [`SinkRole`] name).
    LanguageSink {
        language: String,
        call: String,
        role: String,
    },
    /// Per-slot sink rules for one language (the generator's per-language
    /// sink signature vocabulary): which argument slots are
    /// dangerous / binding-safe.
    LanguageSinkSlots {
        language: String,
        call: String,
        #[cfg_attr(feature = "serialize", serde(default))]
        package: Option<String>,
        dangerous_args: BTreeSet<usize>,
        binding_args_safe: bool,
    },
    /// An IDOR-class finder sink for one language (the generator's
    /// per-language IDOR vocabulary).
    LanguageIdorSink {
        language: String,
        call: String,
        keys: Vec<String>,
    },
    /// A taint source pattern for one language (the generator's per-language
    /// source vocabulary and the conventional request-parameter names).
    LanguageSource {
        language: String,
        pattern: String,
        #[cfg_attr(feature = "serialize", serde(default))]
        package: Option<String>,
    },
    /// A sanitizer call for one language (the generator's per-language
    /// sanitizer vocabulary, with the predicate-guard
    /// classification precomputed by the pack generator).
    LanguageSanitizer {
        language: String,
        call: String,
        #[cfg_attr(feature = "serialize", serde(default))]
        package: Option<String>,
        kind: String,
        guard_style: bool,
    },
    /// A taint propagator rule for one language (the generator's
    /// per-language propagator vocabulary).
    LanguagePropagator {
        language: String,
        call: String,
        tainted_arg: Option<usize>,
        tainted_receiver: bool,
    },
    /// A session-root accessor for one language (the generator's
    /// per-language session-root vocabulary).
    LanguageSessionRoot { language: String, root: String },
    /// A route-registration call pattern for one language (the generator's
    /// per-language route vocabulary, formerly read from the language
    /// spec), keyed for the lowering
    /// harness.
    LanguageRoutePattern { language: String, pattern: String },
    /// Stack-frame allocators (`alloca`, ...) - the leak checker's
    /// frame-lifetime exclusion set (Phase 6.5: moved from the spec seed
    /// into the pack; `GuardDenylistPattern` already carries the guard
    /// denylist the same way).
    StackAllocators { values: Vec<String> },
    /// Collection constructors (`Set`, `Map`) whose literal elements the
    /// allowlist-definition check reads (Phase 6.5, pack-seeded).
    CollectionConstructors { values: Vec<String> },
    /// Schema-describing methods (`describe`, `description`) for the
    /// schema-policy check (Phase 6.5, pack-seeded).
    SchemaDescribeMethods { values: Vec<String> },
    /// String literals that compare as the language's null pointer
    /// (`NULL`) for the leak checker (Phase 6.5, pack-seeded).
    NullTokens { values: Vec<String> },
    /// Read-accessor method names of trusted session stores (`get`)
    /// (Phase 6.5, pack-seeded).
    SessionAccessors { values: Vec<String> },
    /// Formal parameter names receiving the implicit receiver (`self`,
    /// `this`) (Phase 6.5, pack-seeded).
    ReceiverParams { values: Vec<String> },
    /// HTTP-method verbs that are ambiguous as bare last-segment call
    /// names (routers `app.get`, maps `m.set`, http clients `got.post`,
    /// caches `kv.put` all share them). A dotted sink entry with one of
    /// these last segments arms receiver gating: the call only counts as
    /// a sink when its receiver root is a declared client root (the
    /// entry's first segment). Phase 6.6: moved from
    /// `LanguageSpec::known_ambiguous_verbs` (a trait default no
    /// provider ever overrode) into the pack, one entry per language.
    LanguageAmbiguousVerbs {
        language: String,
        values: Vec<String>,
    },
    /// A package-scoped co-occurrence policy (Phase 7: PolicyFact gained a
    /// `package` field so a learned policy only fires in files that import
    /// that package). Appended at the end so bincode variant indices for
    /// existing v6 bundles stay stable: old bundles deserialize the
    /// unscoped `Policy` variant (package = None) exactly as before.
    PolicyScoped {
        rule: String,
        when_call: String,
        #[cfg_attr(feature = "serialize", serde(default))]
        require: Vec<PolicyRequirement>,
        #[cfg_attr(feature = "serialize", serde(default))]
        scope: PolicyScope,
        message: String,
        severity: String,
        /// Only fire in files that import this package.
        package: String,
    },
    /// Global-only builtin sink marker (appended last: bincode encodes the
    /// variant index first, so existing wire bytes keep decoding unchanged).
    /// Marks the language's already-published `LanguageSink` entry with the
    /// `global_only` runtime flag: the bare call form is the sink, while a
    /// receiver-qualified call (`engine.eval(x)`) matches only once its
    /// origin resolves to a known package (WI-12).
    LanguageSinkGlobalOnly { language: String, call: String },
    /// Appended last (bincode encodes the variant index first, so existing
    /// wire bytes keep decoding unchanged): the SAME rule as
    /// `IntegerOverflowRule` with the unbounded-operand modality taught -
    /// the engine may fire on a size multiplication whose BOTH operands
    /// are unboundedly dynamic (`malloc(rows * cols)` CVE-190 shape).
    /// New intent must be added as its own trailing variant; never insert
    /// a variant before an established one.
    IntegerOverflowUnboundedRule {
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
            LearnedFactEntry::Sink { call, .. }
            | LearnedFactEntry::LanguageSink { call, .. }
            | LearnedFactEntry::LanguageSinkSlots { call, .. }
            | LearnedFactEntry::IdorFinderSink { call, .. }
            | LearnedFactEntry::LanguageIdorSink { call, .. } => {
                vec![call.clone()]
            }
            LearnedFactEntry::Policy { rule, .. }
            | LearnedFactEntry::PolicyScoped { rule, .. }
            | LearnedFactEntry::Check { rule, .. }
            | LearnedFactEntry::IntegerOverflowRule { rule, .. } => vec![rule.clone()],
            LearnedFactEntry::WeakPrimitiveRule { rule_id, .. }
            | LearnedFactEntry::InsecureConfigRule { rule_id, .. }
            | LearnedFactEntry::KeySizeRule { rule_id, .. } => vec![rule_id.clone()],
            LearnedFactEntry::WeakCrypto(fact) => vec![fact.rule_id.clone()],
            _ => Vec::new(),
        }
    }

    /// Insert this fact into a [`FactTable`] as [`Provenance::Learned`]
    /// (the bundle path: a corpus taught it).
    pub fn apply(&self, table: &mut FactTable) {
        self.apply_with(table, Provenance::Learned);
    }

    /// Insert this fact into a [`FactTable`] under an explicit
    /// [`Provenance`]. The embedded default pack (Phase 5.2) re-ships
    /// spec knowledge through the same entry type, so its provenance must
    /// stay [`Provenance::Spec`] instead of flipping to Learned.
    pub fn apply_with(&self, table: &mut FactTable, provenance: Provenance) {
        match self {
            LearnedFactEntry::Source { pattern, package } => {
                if let Some(pkg) = package {
                    table.scoped_sources.insert((pkg.clone(), pattern.clone()));
                } else {
                    table.learned_sources.insert(pattern.clone());
                }
            }
            LearnedFactEntry::Sink {
                call,
                package,
                dangerous_args,
                binding_args_safe,
            } => {
                // Preserve a spec-derived role (and IDOR keys) if the built-in
                // table already classifies this call, learned facts refine
                // *slots*, they don't reclassify *semantics*.
                let prior = if let Some(pkg) = package {
                    table
                        .scoped_sink_signatures
                        .get(&(pkg.clone(), call.clone()))
                } else {
                    table.sink_signatures.get(call)
                };
                let role = prior.map(|s| s.role).unwrap_or_default();
                let label = prior.and_then(|s| s.label.clone());
                let idor_keys = prior.map(|s| s.idor_keys.clone()).unwrap_or_default();
                let sig = SinkSignature {
                    call: call.clone(),
                    package: package.clone(),
                    dangerous_args: dangerous_args.clone(),
                    binding_args_safe: *binding_args_safe,
                    global_only: false,
                    idor_keys,
                    role,
                    label,
                };
                if let Some(pkg) = package {
                    table
                        .scoped_sink_signatures
                        .insert((pkg.clone(), call.clone()), sig);
                } else {
                    table.sink_signatures.insert(call.clone(), sig);
                }
            }
            LearnedFactEntry::Sanitizer {
                call,
                package,
                kind,
                guard_style,
            } => {
                let fact = SanitizerFact {
                    call: call.clone(),
                    package: package.clone(),
                    kind: kind.clone(),
                    sanitizes_args: Default::default(),
                    guard_style: *guard_style,
                };
                if let Some(pkg) = package {
                    table
                        .scoped_sanitizer_facts
                        .insert((pkg.clone(), call.clone()), fact);
                } else {
                    table.sanitizer_facts.insert(call.clone(), fact);
                }
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
                    package: None,
                };
                if let Some(existing) = table
                    .policy_facts
                    .iter_mut()
                    .find(|(e, _)| e.rule == fact.rule && e.when_call == fact.when_call)
                {
                    if provenance > existing.1 {
                        *existing = (fact, provenance);
                    }
                } else {
                    table.policy_facts.push((fact, provenance));
                }
            }
            LearnedFactEntry::PolicyScoped {
                rule,
                when_call,
                require,
                scope,
                message,
                severity,
                package,
            } => {
                let fact = PolicyFact {
                    rule: rule.clone(),
                    when_call: when_call.clone(),
                    require: require.clone(),
                    scope: *scope,
                    message: message.clone(),
                    severity: severity.clone(),
                    package: Some(package.clone()),
                };
                if let Some(existing) = table
                    .policy_facts
                    .iter_mut()
                    .find(|(e, _)| e.rule == fact.rule && e.when_call == fact.when_call)
                {
                    if provenance > existing.1 {
                        *existing = (fact, provenance);
                    }
                } else {
                    table.policy_facts.push((fact, provenance));
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
                if let Some(existing) = table
                    .learned_checks
                    .iter_mut()
                    .find(|(e, _)| e.rule == fact.rule && e.call == fact.call)
                {
                    if provenance > existing.1 {
                        *existing = (fact, provenance);
                    }
                } else {
                    table.learned_checks.push((fact, provenance));
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
                    table.containment_callees.insert(c.clone(), provenance);
                }
                for s in &fact.credential_sinks {
                    table.credential_sinks.insert(s.clone(), provenance);
                }
                for p in &fact.credential_params {
                    table.credential_params.insert(p.clone(), provenance);
                }
            }
            LearnedFactEntry::SchemaPolicy(fact) => {
                for b in &fact.builders {
                    table.schema_builders.insert(b.clone(), provenance);
                }
                table
                    .schema_enforcers
                    .extend(fact.enforcers.iter().cloned());
                for k in &fact.bound_keywords {
                    table.schema_keywords.insert(k.clone(), provenance);
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
                    package: None,
                    dangerous_args: std::collections::BTreeSet::new(),
                    binding_args_safe: false,
                    global_only: false,
                    // Per-call keys when taught; otherwise the learned global
                    // identity keys (no engine built-in fallback - vocabulary
                    // is spec/bundle-owned, empty disables the gate).
                    idor_keys: if keys.is_empty() {
                        table.idor_keys.iter().cloned().collect()
                    } else {
                        keys.clone()
                    },
                    role: crate::analysis::taint::role::SinkRole::Resource,
                    label: None,
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
            }
            | LearnedFactEntry::IntegerOverflowUnboundedRule {
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
                    // The trailing wire variant carries the modality; the
                    // base variant keeps the provable-range contract.
                    unbounded_product: matches!(
                        self,
                        LearnedFactEntry::IntegerOverflowUnboundedRule { .. }
                    ),
                };
                if let Some(existing) = table.integer_overflow_rules.iter_mut().find(|(r, _)| {
                    r.rule_id == fact.rule_id && r.wrap_threshold == fact.wrap_threshold
                }) {
                    if provenance > existing.1 {
                        *existing = (fact, provenance);
                    }
                } else {
                    table.integer_overflow_rules.push((fact, provenance));
                }
            }
            LearnedFactEntry::Hints { kind, values } => {
                let set = match kind {
                    HintKind::UrlParam => &mut table.url_param_hints,
                    HintKind::UrlArg => &mut table.url_arg_hints,
                    HintKind::UrlLiteral => &mut table.url_literal_hints,
                    HintKind::SecurityContext => &mut table.security_context_hints,
                    HintKind::AuthGuard => &mut table.auth_guard_hints,
                    HintKind::JwtAlgorithm => &mut table.jwt_algorithm_hints,
                    HintKind::CredentialContext => &mut table.credential_context_hints,
                    HintKind::KdfReceiver => &mut table.kdf_receiver_hints,
                    HintKind::PreparedStatementPrefix => &mut table.prepared_statement_prefixes,
                    HintKind::WeakHashDisclaimer => &mut table.weak_hash_disclaimer_tokens,
                };
                set.extend(values.iter().cloned());
            }
            LearnedFactEntry::WeakPrimitiveRule {
                rule_id,
                selector_calls,
                bare_calls,
                selector_slot,
                weak_selectors,
                requires_credential_context,
                severity,
                message,
            } => {
                let fact = WeakPrimitiveRule {
                    rule_id: rule_id.clone(),
                    selector_calls: selector_calls.clone(),
                    bare_calls: bare_calls.clone(),
                    selector_slot: *selector_slot,
                    weak_selectors: weak_selectors.clone(),
                    requires_credential_context: *requires_credential_context,
                    severity: severity.clone(),
                    message: message.clone(),
                };
                if !table.weak_hash_rules.contains(&fact) {
                    table.weak_hash_rules.push(fact);
                }
            }
            LearnedFactEntry::InsecureConfigRule {
                prefix,
                selectors,
                rule_id,
                severity,
                message,
            } => {
                let fact = InsecureConfigRule {
                    prefix: prefix.clone(),
                    selectors: selectors.clone(),
                    rule_id: rule_id.clone(),
                    severity: severity.clone(),
                    message: message.clone(),
                };
                if !table.insecure_config_selectors.contains(&fact) {
                    table.insecure_config_selectors.push(fact);
                }
            }
            LearnedFactEntry::KeySizeRule {
                rule_id,
                call,
                slot,
                min_bits,
                kind,
                severity,
                message,
            } => {
                let fact = KeySizeRule {
                    rule_id: rule_id.clone(),
                    call: call.clone(),
                    slot: *slot,
                    min_bits: *min_bits,
                    kind: kind.clone(),
                    severity: severity.clone(),
                    message: message.clone(),
                };
                if !table.key_size_rules.contains(&fact) {
                    table.key_size_rules.push(fact);
                }
            }
            LearnedFactEntry::SuspiciousHashWrappers { calls } => {
                table.suspicious_hash_wrappers.extend(calls.iter().cloned());
            }
            // Phase 6.5: the seven structural vocabularies ship in the
            // default pack (formerly the bare spec seed).
            LearnedFactEntry::StackAllocators { values } => {
                for v in values {
                    if !table.stack_allocators.contains(v) {
                        table.stack_allocators.push(v.clone());
                    }
                }
            }
            LearnedFactEntry::CollectionConstructors { values } => {
                table.collection_constructors.extend(values.iter().cloned());
            }
            LearnedFactEntry::SchemaDescribeMethods { values } => {
                table.schema_describe_methods.extend(values.iter().cloned());
            }
            LearnedFactEntry::NullTokens { values } => {
                table.null_tokens.extend(values.iter().cloned());
            }
            LearnedFactEntry::SessionAccessors { values } => {
                table.session_accessors.extend(values.iter().cloned());
            }
            LearnedFactEntry::ReceiverParams { values } => {
                table.receiver_params.extend(values.iter().cloned());
            }
            LearnedFactEntry::BufferBuiltin {
                name,
                dst_arg,
                src_arg,
                len_arg,
            } => {
                let fact = BufferBuiltinSpec {
                    name: name.clone(),
                    dst_arg: *dst_arg,
                    src_arg: *src_arg,
                    len_arg: *len_arg,
                };
                if !table.buffer_builtins.iter().any(|b| b.name == fact.name) {
                    table.buffer_builtins.push(fact);
                }
            }
            // Language-keyed pack knowledge is installed by
            // `apply_language_entries` (config + facts together, filtered
            // by the scan's languages); the language-agnostic bundle path
            // ignores it so a family bundle can never pollute another
            // language's tables.
            LearnedFactEntry::LanguageSink { .. }
            | LearnedFactEntry::LanguageSinkGlobalOnly { .. }
            | LearnedFactEntry::LanguageSinkSlots { .. }
            | LearnedFactEntry::LanguageIdorSink { .. }
            | LearnedFactEntry::LanguageSource { .. }
            | LearnedFactEntry::LanguageSanitizer { .. }
            | LearnedFactEntry::LanguagePropagator { .. }
            | LearnedFactEntry::LanguageSessionRoot { .. }
            | LearnedFactEntry::LanguageRoutePattern { .. }
            | LearnedFactEntry::LanguageAmbiguousVerbs { .. } => {}
        }
    }
}

/// Build a [`FactTable`] from a list of learned bundle facts.
pub fn fact_table_from_entries(entries: &[LearnedFactEntry]) -> FactTable {
    fact_table_from_entries_with(entries, Provenance::Learned)
}

/// Build a [`FactTable`] from bundle entries under an explicit
/// [`Provenance`]: the embedded default pack seeds its entries as
/// [`Provenance::Spec`] (Phase 5.2), corpus bundle facts as Learned.
pub fn fact_table_from_entries_with(
    entries: &[LearnedFactEntry],
    provenance: Provenance,
) -> FactTable {
    let mut t = FactTable::default();
    for e in entries {
        e.apply_with(&mut t, provenance);
    }
    t
}
