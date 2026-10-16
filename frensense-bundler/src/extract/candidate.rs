// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::collections::BTreeSet;

use frensense_engine::analysis::taint::facts::{
    FactTable, GuardBypassFact, LearnedCheckFact, LearnedFactEntry, MemoryContractFact, PolicyFact,
    PolicyRequirement, PolicyScope, Provenance, SanitizerFact, SchemaPolicyFact, SinkSignature,
    WeakCryptoFact,
};
use frensense_engine::checks::memory_summary::CapacitySpec;

/// A candidate fact proposed by delta analysis.
///
/// `#[non_exhaustive]`: an evolving internal DTO. Variant fields (e.g.
/// `Check.package` in 0.8.0) are added as minor releases; it never escapes the
/// bundler's functional API, so consumers match with a wildcard arm.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Candidate {
    /// Call is a dangerous sink at these arg slots.
    Sink {
        call: String,
        package: Option<String>,
        dangerous: BTreeSet<usize>,
    },
    /// Call sanitizes (guard-style or transform).
    Sanitizer {
        call: String,
        package: Option<String>,
        guard: bool,
    },
    /// Call is a policy violation per a corpus-verified non-dataflow rule
    /// (positive contains the call and alerts-or-should; negative lacks it,
    /// or enforces it with a guard the positive lacks).
    Check {
        rule: String,
        call: String,
        message: String,
        /// Fire only when this guard is absent (shape-b families).
        unless_guard: Option<String>,
        /// Fire only when the trigger arg has NO literal range comparison
        /// (inline enforcement modality).
        unless_range_check: Option<Vec<String>>,
        /// Optional package qualification from the family's `// package:`
        /// metadata. When set, the check is published as a package-scoped
        /// policy (`PolicyScoped`) so it cannot fire on unrelated files
        /// that merely share the trigger verb. `None` = unscoped `Check`.
        package: Option<String>,
    },
    /// Generalized co-occurrence policy (the `LearnedFactEntry::Policy`
    /// shape): trigger + a list of requirements the trigger's scope must
    /// satisfy.
    Policy {
        rule: String,
        call: String,
        message: String,
        require: Vec<PolicyRequirement>,
        scope: PolicyScope,
        /// Package qualification: when `Some(pkg)`, the policy only fires
        /// in files that import `pkg` (mirrors sink/source scoping).
        package: Option<String>,
    },
    /// A custom allocation/deallocation wrapper contract learned from corpus examples.
    MemoryContract {
        name: String,
        returns_fresh: bool,
        return_capacity: CapacitySpec,
        consumes_params: Vec<usize>,
    },
    /// Weak cryptographic primitive or algorithm selector learned from corpus examples.
    WeakCrypto { fact: WeakCryptoFact },
    /// Guard bypass pattern (containment callee, credential sink or credential param).
    GuardBypass { fact: GuardBypassFact },
    /// Schema policy rule (number builder, enforcer method, or bound keyword).
    SchemaPolicy { fact: SchemaPolicyFact },
    /// Allocation-size integer-overflow rule declared by the family's
    /// `[frensense] check-rule:` block (corpus extends the prover's rule
    /// table; the engine's prover stays stable).
    IntegerOverflowRule {
        rule: String,
        wrap_threshold: u128,
        severity: String,
        message: String,
    },
}

impl Candidate {
    pub fn to_learned_entry(&self) -> LearnedFactEntry {
        self.to_learned_entry_scoped(None)
    }

    pub fn to_learned_entry_scoped(&self, language: Option<&str>) -> LearnedFactEntry {
        if let Some(lang) = language {
            match self {
                Candidate::Sink {
                    call,
                    package,
                    dangerous,
                } => LearnedFactEntry::LanguageSinkSlots {
                    language: lang.to_string(),
                    call: call.clone(),
                    package: package.clone(),
                    dangerous_args: dangerous.clone(),
                    binding_args_safe: false,
                },
                Candidate::Sanitizer {
                    call,
                    package,
                    guard,
                } => LearnedFactEntry::LanguageSanitizer {
                    language: lang.to_string(),
                    call: call.clone(),
                    package: package.clone(),
                    kind: if *guard {
                        "allowlist".into()
                    } else {
                        "encode".into()
                    },
                    guard_style: *guard,
                },
                _ => self.to_learned_entry_unscoped(),
            }
        } else {
            self.to_learned_entry_unscoped()
        }
    }

    fn to_learned_entry_unscoped(&self) -> LearnedFactEntry {
        match self {
            Candidate::Sink {
                call,
                package,
                dangerous,
            } => LearnedFactEntry::Sink {
                call: call.clone(),
                package: package.clone(),
                dangerous_args: dangerous.clone(),
                binding_args_safe: false,
            },
            Candidate::Sanitizer {
                call,
                package,
                guard,
            } => LearnedFactEntry::Sanitizer {
                call: call.clone(),
                package: package.clone(),
                kind: if *guard {
                    "allowlist".into()
                } else {
                    "encode".into()
                },
                guard_style: *guard,
            },
            Candidate::Check {
                rule,
                call,
                message,
                unless_guard,
                unless_range_check,
                package,
            } => {
                // A family-declared package turns the check into a
                // package-scoped policy (same engine mechanism as
                // `Candidate::Policy` + package): the generic presence
                // trigger can then never collide with unrelated bundle
                // families that share the verb but not the package import.
                if let Some(pkg) = package {
                    let mut require = Vec::new();
                    if let Some(g) = unless_guard {
                        require.push(PolicyRequirement::GuardCall { call: g.clone() });
                    }
                    if let Some(ops) = unless_range_check {
                        require.push(PolicyRequirement::RangeCheck { ops: ops.clone() });
                    }
                    LearnedFactEntry::PolicyScoped {
                        rule: rule.clone(),
                        when_call: call.clone(),
                        require,
                        scope: PolicyScope::Function,
                        message: message.clone(),
                        severity: "warning".into(),
                        package: pkg.clone(),
                    }
                } else {
                    LearnedFactEntry::Check {
                        rule: rule.clone(),
                        call: call.clone(),
                        message: message.clone(),
                        severity: "warning".into(),
                        unless_guard: unless_guard.clone(),
                        unless_range_check: unless_range_check.clone(),
                    }
                }
            }
            Candidate::Policy {
                rule,
                call,
                message,
                require,
                scope,
                package,
            } => {
                if let Some(pkg) = package {
                    LearnedFactEntry::PolicyScoped {
                        rule: rule.clone(),
                        when_call: call.clone(),
                        require: require.clone(),
                        scope: *scope,
                        message: message.clone(),
                        severity: "warning".into(),
                        package: pkg.clone(),
                    }
                } else {
                    LearnedFactEntry::Policy {
                        rule: rule.clone(),
                        when_call: call.clone(),
                        require: require.clone(),
                        scope: *scope,
                        message: message.clone(),
                        severity: "warning".into(),
                    }
                }
            }
            Candidate::MemoryContract {
                name,
                returns_fresh,
                return_capacity,
                consumes_params,
            } => LearnedFactEntry::MemoryContract {
                name: name.clone(),
                returns_fresh: *returns_fresh,
                return_capacity: return_capacity.clone(),
                consumes_params: consumes_params.clone(),
            },
            Candidate::WeakCrypto { fact } => LearnedFactEntry::WeakCrypto(fact.clone()),
            Candidate::GuardBypass { fact } => LearnedFactEntry::GuardBypass(fact.clone()),
            Candidate::SchemaPolicy { fact } => LearnedFactEntry::SchemaPolicy(fact.clone()),
            Candidate::IntegerOverflowRule {
                rule,
                wrap_threshold,
                severity,
                message,
            } => LearnedFactEntry::IntegerOverflowRule {
                rule: rule.clone(),
                wrap_threshold: *wrap_threshold,
                severity: severity.clone(),
                message: message.clone(),
            },
        }
    }
}

/// Apply a candidate to a fact table (for replay).
pub fn apply_candidate(table: &mut FactTable, c: &Candidate) {
    match c {
        Candidate::Sink {
            call,
            package,
            dangerous,
        } => {
            let mut sig = if dangerous.is_empty() {
                SinkSignature::all_args(call)
            } else {
                SinkSignature::with_args(call, &dangerous.iter().copied().collect::<Vec<_>>())
            };
            sig.package = package.clone();
            if let Some(pkg) = package {
                table
                    .scoped_sink_signatures
                    .insert((pkg.clone(), call.clone()), sig.clone());
            }
            table.sink_signatures.insert(call.clone(), sig);
        }
        Candidate::Sanitizer {
            call,
            package,
            guard,
        } => {
            let fact = SanitizerFact {
                call: call.clone(),
                package: package.clone(),
                kind: if *guard {
                    "allowlist".into()
                } else {
                    "encode".into()
                },
                sanitizes_args: Default::default(),
                guard_style: *guard,
            };
            match package {
                Some(pkg) => {
                    // Package-scoped sanitizer: install ONLY under
                    // (package, call), mirroring the engine's load path
                    // (`apply_language_entries`). The gate must replay
                    // exactly the origin-gated semantics consumers get —
                    // a universal alias here would let the trial table
                    // cut any receiver and approve a fact that no longer
                    // cuts (or wrongly cuts) once loaded strictly.
                    table
                        .scoped_sanitizer_facts
                        .insert((pkg.clone(), call.clone()), fact);
                }
                None => {
                    table.sanitizer_facts.insert(call.clone(), fact);
                }
            }
        }
        Candidate::Check {
            rule,
            call,
            message,
            unless_guard,
            unless_range_check,
            package,
        } => {
            // Scoped checks are replayed as package-scoped policies so the
            // trial scan exercises the exact publish shape.
            if let Some(pkg) = package {
                let mut require = Vec::new();
                if let Some(g) = unless_guard {
                    require.push(PolicyRequirement::GuardCall { call: g.clone() });
                }
                if let Some(ops) = unless_range_check {
                    require.push(PolicyRequirement::RangeCheck { ops: ops.clone() });
                }
                table.policy_facts.push((
                    PolicyFact {
                        rule: rule.clone(),
                        when_call: call.clone(),
                        require,
                        scope: PolicyScope::Function,
                        message: message.clone(),
                        severity: "warning".into(),
                        package: Some(pkg.clone()),
                    },
                    Provenance::Learned,
                ));
            } else {
                table.learned_checks.push((
                    LearnedCheckFact {
                        rule: rule.clone(),
                        call: call.clone(),
                        message: message.clone(),
                        severity: "warning".into(),
                        unless_guard: unless_guard.clone(),
                        unless_range_check: unless_range_check.clone(),
                    },
                    Provenance::Learned,
                ));
            }
        }
        Candidate::Policy {
            rule,
            call,
            message,
            require,
            scope,
            package,
        } => {
            table.policy_facts.push((
                PolicyFact {
                    rule: rule.clone(),
                    when_call: call.clone(),
                    require: require.clone(),
                    scope: *scope,
                    message: message.clone(),
                    severity: "warning".into(),
                    package: package.clone(),
                },
                Provenance::Learned,
            ));
        }
        Candidate::MemoryContract {
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
        Candidate::WeakCrypto { fact } => {
            if let Some(existing) = table
                .weak_crypto_rules
                .iter_mut()
                .find(|c| c.rule_id == fact.rule_id && c.call == fact.call)
            {
                *existing = fact.clone();
            } else {
                table.weak_crypto_rules.push(fact.clone());
            }
        }
        Candidate::GuardBypass { fact } => {
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
        Candidate::SchemaPolicy { fact } => {
            for b in &fact.builders {
                table.schema_builders.insert(b.clone(), Provenance::Learned);
            }
            for e in &fact.enforcers {
                table.schema_enforcers.insert(e.clone());
            }
            for k in &fact.bound_keywords {
                table.schema_keywords.insert(k.clone(), Provenance::Learned);
            }
        }
        Candidate::IntegerOverflowRule {
            rule,
            wrap_threshold,
            severity,
            message,
        } => {
            let fact = frensense_engine::analysis::taint::facts::IntegerOverflowRule {
                rule_id: rule.clone(),
                wrap_threshold: *wrap_threshold,
                severity: severity.clone(),
                message: message.clone(),
            };
            if let Some(existing) = table
                .integer_overflow_rules
                .iter_mut()
                .find(|(r, _)| r.rule_id == fact.rule_id && r.wrap_threshold == fact.wrap_threshold)
            {
                *existing = (fact, Provenance::Learned);
            } else {
                table
                    .integer_overflow_rules
                    .push((fact, Provenance::Learned));
            }
        }
    }
}

pub fn fact_key(e: &LearnedFactEntry) -> (String, String) {
    match e {
        LearnedFactEntry::Source { pattern, .. } => ("source".into(), pattern.clone()),
        LearnedFactEntry::Sink { call, .. } => ("sink".into(), call.clone()),
        LearnedFactEntry::Sanitizer { call, .. } => ("san".into(), call.clone()),
        LearnedFactEntry::Check { rule, call, .. } => ("check".into(), format!("{rule}:{call}")),
        LearnedFactEntry::Policy {
            rule, when_call, ..
        } => ("policy".into(), format!("{rule}:{when_call}")),
        LearnedFactEntry::PolicyScoped {
            rule, when_call, ..
        } => ("policy".into(), format!("{rule}:{when_call}")),
        LearnedFactEntry::MemoryContract { name, .. } => ("mem".into(), name.clone()),
        LearnedFactEntry::WeakCrypto(f) => {
            ("weak_crypto".into(), format!("{}:{}", f.rule_id, f.call))
        }
        LearnedFactEntry::GuardBypass(f) => (
            "guard_bypass".into(),
            format!(
                "{:?}:{:?}:{:?}",
                f.containment_callees, f.credential_sinks, f.credential_params
            ),
        ),
        LearnedFactEntry::SchemaPolicy(f) => (
            "schema_policy".into(),
            format!("{:?}:{:?}:{:?}", f.builders, f.enforcers, f.bound_keywords),
        ),
        LearnedFactEntry::GrammarRole {
            language,
            node_kind,
            ..
        } => ("grammar_role".into(), format!("{language}:{node_kind}")),
        LearnedFactEntry::GrammarFeature {
            language,
            node_kind,
            feature,
        } => (
            "grammar_feature".into(),
            format!("{language}:{node_kind}:{feature:?}"),
        ),
        LearnedFactEntry::Allocator { name } => ("allocator".into(), name.clone()),
        LearnedFactEntry::Deallocator { name } => ("deallocator".into(), name.clone()),
        LearnedFactEntry::IdorFinderSink { call, .. } => ("idor_sink".into(), call.clone()),
        LearnedFactEntry::IdorKey { key } => ("idor_key".into(), key.clone()),
        LearnedFactEntry::Propagator { call, .. } => ("propagator".into(), call.clone()),
        LearnedFactEntry::GuardDenylistPattern { pattern } => {
            ("guard_denylist".into(), pattern.clone())
        }
        LearnedFactEntry::IntegerOverflowRule { rule, .. } => ("io_rule".into(), rule.clone()),
        LearnedFactEntry::Hints { kind, .. } => ("hints".into(), format!("{kind:?}")),
        LearnedFactEntry::WeakPrimitiveRule { rule_id, .. } => {
            ("weak_primitive".into(), rule_id.clone())
        }
        LearnedFactEntry::InsecureConfigRule { rule_id, .. } => {
            ("insecure_config".into(), rule_id.clone())
        }
        LearnedFactEntry::KeySizeRule { rule_id, call, .. } => {
            ("key_size".into(), format!("{rule_id}:{call}"))
        }
        LearnedFactEntry::SuspiciousHashWrappers { calls } => {
            ("hash_wrappers".into(), calls.join(","))
        }
        LearnedFactEntry::BufferBuiltin { name, .. } => ("buffer_builtin".into(), name.clone()),
        LearnedFactEntry::LanguageSink { language, call, .. } => {
            ("language_sink".into(), format!("{language}:{call}"))
        }
        LearnedFactEntry::LanguageSinkSlots { language, call, .. } => {
            ("language_sink_slots".into(), format!("{language}:{call}"))
        }
        LearnedFactEntry::LanguageIdorSink { language, call, .. } => {
            ("language_idor_sink".into(), format!("{language}:{call}"))
        }
        LearnedFactEntry::LanguageSource {
            language, pattern, ..
        } => ("language_source".into(), format!("{language}:{pattern}")),
        LearnedFactEntry::LanguageSanitizer { language, call, .. } => {
            ("language_sanitizer".into(), format!("{language}:{call}"))
        }
        LearnedFactEntry::LanguagePropagator { language, call, .. } => {
            ("language_propagator".into(), format!("{language}:{call}"))
        }
        LearnedFactEntry::LanguageSessionRoot { language, root } => {
            ("language_session_root".into(), format!("{language}:{root}"))
        }
        LearnedFactEntry::LanguageRoutePattern { language, pattern } => (
            "language_route_pattern".into(),
            format!("{language}:{pattern}"),
        ),
        // Phase 6.5 structural vocabularies: pack-only whole-table
        // entries, keyed by their contents like the other table-shaped
        // facts.
        LearnedFactEntry::StackAllocators { values } => {
            ("stack_allocators".into(), values.join(","))
        }
        LearnedFactEntry::CollectionConstructors { values } => {
            ("collection_constructors".into(), values.join(","))
        }
        LearnedFactEntry::SchemaDescribeMethods { values } => {
            ("schema_describe_methods".into(), values.join(","))
        }
        LearnedFactEntry::NullTokens { values } => ("null_tokens".into(), values.join(",")),
        LearnedFactEntry::SessionAccessors { values } => {
            ("session_accessors".into(), values.join(","))
        }
        LearnedFactEntry::ReceiverParams { values } => ("receiver_params".into(), values.join(",")),
        LearnedFactEntry::LanguageAmbiguousVerbs { language, values } => (
            "language_ambiguous_verbs".into(),
            format!("{language}:{}", values.join(",")),
        ),
    }
}
