// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Frozen v4/v5 fact vocabulary.
//!
//! [`LearnedFactEntryV5`] is the positional wire shape of v4 and v5 bundles
//! and must never change: the live [`LearnedFactEntry`] is a different type,
//! and a v5 payload is decoded with this one and converted into it. It lives
//! here, away from the live payload, so a field added to the current
//! vocabulary cannot be added here by accident.

use frensense_engine::analysis::taint::facts::LearnedFactEntry;
/// Frozen v5 layout of `LearnedFactEntry` for deserializing v4 and v5 bundles.
/// Bincode is positional and non-self-describing; adding fields like `package`
/// to `LearnedFactEntry` requires freezing this structure for backwards compatibility.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum LearnedFactEntryV5 {
    Source {
        pattern: String,
    },
    Sink {
        call: String,
        dangerous_args: std::collections::BTreeSet<usize>,
        binding_args_safe: bool,
    },
    Sanitizer {
        call: String,
        kind: String,
        guard_style: bool,
    },
    Policy {
        rule: String,
        when_call: String,
        #[serde(default)]
        require: Vec<frensense_engine::analysis::taint::facts::PolicyRequirement>,
        #[serde(default)]
        scope: frensense_engine::analysis::taint::facts::PolicyScope,
        message: String,
        severity: String,
    },
    Check {
        rule: String,
        call: String,
        message: String,
        severity: String,
        #[serde(default)]
        unless_guard: Option<String>,
        #[serde(default)]
        unless_range_check: Option<Vec<String>>,
    },
    MemoryContract {
        name: String,
        returns_fresh: bool,
        return_capacity: frensense_engine::checks::memory_summary::CapacitySpec,
        consumes_params: Vec<usize>,
    },
    WeakCrypto(frensense_engine::analysis::taint::facts::WeakCryptoFact),
    GuardBypass(frensense_engine::analysis::taint::facts::GuardBypassFact),
    SchemaPolicy(frensense_engine::analysis::taint::facts::SchemaPolicyFact),
    GrammarRole {
        language: String,
        node_kind: String,
        role: frensense_engine::analysis::taint::facts::TeachableNodeRole,
    },
    GrammarFeature {
        language: String,
        node_kind: String,
        feature: frensense_engine::analysis::taint::facts::GrammarFeature,
    },
    Allocator {
        name: String,
    },
    Deallocator {
        name: String,
    },
    IdorFinderSink {
        call: String,
        keys: Vec<String>,
    },
    IdorKey {
        key: String,
    },
    Propagator {
        call: String,
        input_args: Vec<usize>,
        preserves_taint: bool,
    },
    GuardDenylistPattern {
        pattern: String,
    },
    IntegerOverflowRule {
        rule: String,
        wrap_threshold: u128,
        severity: String,
        message: String,
    },
    Hints {
        kind: frensense_engine::analysis::taint::facts::HintKind,
        values: Vec<String>,
    },
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
    InsecureConfigRule {
        prefix: String,
        selectors: Vec<String>,
        rule_id: String,
        severity: String,
        message: String,
    },
    KeySizeRule {
        rule_id: String,
        call: String,
        slot: usize,
        min_bits: i64,
        kind: String,
        severity: String,
        message: String,
    },
    SuspiciousHashWrappers {
        calls: Vec<String>,
    },
    BufferBuiltin {
        name: String,
        dst_arg: Option<usize>,
        src_arg: Option<usize>,
        len_arg: usize,
    },
    LanguageSink {
        language: String,
        call: String,
        role: String,
    },
    LanguageSinkSlots {
        language: String,
        call: String,
        dangerous_args: std::collections::BTreeSet<usize>,
        binding_args_safe: bool,
    },
    LanguageIdorSink {
        language: String,
        call: String,
        keys: Vec<String>,
    },
    LanguageSource {
        language: String,
        pattern: String,
    },
    LanguageSanitizer {
        language: String,
        call: String,
        kind: String,
        guard_style: bool,
    },
    LanguagePropagator {
        language: String,
        call: String,
        tainted_arg: Option<usize>,
        tainted_receiver: bool,
    },
    LanguageSessionRoot {
        language: String,
        root: String,
    },
    LanguageRoutePattern {
        language: String,
        pattern: String,
    },
    StackAllocators {
        values: Vec<String>,
    },
    CollectionConstructors {
        values: Vec<String>,
    },
    SchemaDescribeMethods {
        values: Vec<String>,
    },
    NullTokens {
        values: Vec<String>,
    },
    SessionAccessors {
        values: Vec<String>,
    },
    ReceiverParams {
        values: Vec<String>,
    },
    LanguageAmbiguousVerbs {
        language: String,
        values: Vec<String>,
    },
}

impl From<LearnedFactEntryV5> for LearnedFactEntry {
    fn from(v: LearnedFactEntryV5) -> Self {
        match v {
            LearnedFactEntryV5::Source { pattern } => LearnedFactEntry::Source {
                pattern,
                package: None,
            },
            LearnedFactEntryV5::Sink {
                call,
                dangerous_args,
                binding_args_safe,
            } => LearnedFactEntry::Sink {
                call,
                package: None,
                dangerous_args,
                binding_args_safe,
            },
            LearnedFactEntryV5::Sanitizer {
                call,
                kind,
                guard_style,
            } => LearnedFactEntry::Sanitizer {
                call,
                package: None,
                kind,
                guard_style,
            },
            LearnedFactEntryV5::Policy {
                rule,
                when_call,
                require,
                scope,
                message,
                severity,
            } => LearnedFactEntry::Policy {
                rule,
                when_call,
                require,
                scope,
                message,
                severity,
            },
            LearnedFactEntryV5::Check {
                rule,
                call,
                message,
                severity,
                unless_guard,
                unless_range_check,
            } => LearnedFactEntry::Check {
                rule,
                call,
                message,
                severity,
                unless_guard,
                unless_range_check,
            },
            LearnedFactEntryV5::MemoryContract {
                name,
                returns_fresh,
                return_capacity,
                consumes_params,
            } => LearnedFactEntry::MemoryContract {
                name,
                returns_fresh,
                return_capacity,
                consumes_params,
            },
            LearnedFactEntryV5::WeakCrypto(f) => LearnedFactEntry::WeakCrypto(f),
            LearnedFactEntryV5::GuardBypass(f) => LearnedFactEntry::GuardBypass(f),
            LearnedFactEntryV5::SchemaPolicy(f) => LearnedFactEntry::SchemaPolicy(f),
            LearnedFactEntryV5::GrammarRole {
                language,
                node_kind,
                role,
            } => LearnedFactEntry::GrammarRole {
                language,
                node_kind,
                role,
            },
            LearnedFactEntryV5::GrammarFeature {
                language,
                node_kind,
                feature,
            } => LearnedFactEntry::GrammarFeature {
                language,
                node_kind,
                feature,
            },
            LearnedFactEntryV5::Allocator { name } => LearnedFactEntry::Allocator { name },
            LearnedFactEntryV5::Deallocator { name } => LearnedFactEntry::Deallocator { name },
            LearnedFactEntryV5::IdorFinderSink { call, keys } => {
                LearnedFactEntry::IdorFinderSink { call, keys }
            }
            LearnedFactEntryV5::IdorKey { key } => LearnedFactEntry::IdorKey { key },
            LearnedFactEntryV5::Propagator {
                call,
                input_args,
                preserves_taint,
            } => LearnedFactEntry::Propagator {
                call,
                input_args,
                preserves_taint,
            },
            LearnedFactEntryV5::GuardDenylistPattern { pattern } => {
                LearnedFactEntry::GuardDenylistPattern { pattern }
            }
            LearnedFactEntryV5::IntegerOverflowRule {
                rule,
                wrap_threshold,
                severity,
                message,
            } => LearnedFactEntry::IntegerOverflowRule {
                rule,
                wrap_threshold,
                severity,
                message,
            },
            LearnedFactEntryV5::Hints { kind, values } => LearnedFactEntry::Hints { kind, values },
            LearnedFactEntryV5::WeakPrimitiveRule {
                rule_id,
                selector_calls,
                bare_calls,
                selector_slot,
                weak_selectors,
                requires_credential_context,
                severity,
                message,
            } => LearnedFactEntry::WeakPrimitiveRule {
                rule_id,
                selector_calls,
                bare_calls,
                selector_slot,
                weak_selectors,
                requires_credential_context,
                severity,
                message,
            },
            LearnedFactEntryV5::InsecureConfigRule {
                prefix,
                selectors,
                rule_id,
                severity,
                message,
            } => LearnedFactEntry::InsecureConfigRule {
                prefix,
                selectors,
                rule_id,
                severity,
                message,
            },
            LearnedFactEntryV5::KeySizeRule {
                rule_id,
                call,
                slot,
                min_bits,
                kind,
                severity,
                message,
            } => LearnedFactEntry::KeySizeRule {
                rule_id,
                call,
                slot,
                min_bits,
                kind,
                severity,
                message,
            },
            LearnedFactEntryV5::SuspiciousHashWrappers { calls } => {
                LearnedFactEntry::SuspiciousHashWrappers { calls }
            }
            LearnedFactEntryV5::BufferBuiltin {
                name,
                dst_arg,
                src_arg,
                len_arg,
            } => LearnedFactEntry::BufferBuiltin {
                name,
                dst_arg,
                src_arg,
                len_arg,
            },
            LearnedFactEntryV5::LanguageSink {
                language,
                call,
                role,
            } => LearnedFactEntry::LanguageSink {
                language,
                call,
                role,
            },
            LearnedFactEntryV5::LanguageSinkSlots {
                language,
                call,
                dangerous_args,
                binding_args_safe,
            } => LearnedFactEntry::LanguageSinkSlots {
                language,
                call,
                package: None,
                dangerous_args,
                binding_args_safe,
            },
            LearnedFactEntryV5::LanguageIdorSink {
                language,
                call,
                keys,
            } => LearnedFactEntry::LanguageIdorSink {
                language,
                call,
                keys,
            },
            LearnedFactEntryV5::LanguageSource { language, pattern } => {
                LearnedFactEntry::LanguageSource {
                    language,
                    pattern,
                    package: None,
                }
            }
            LearnedFactEntryV5::LanguageSanitizer {
                language,
                call,
                kind,
                guard_style,
            } => LearnedFactEntry::LanguageSanitizer {
                language,
                call,
                package: None,
                kind,
                guard_style,
            },
            LearnedFactEntryV5::LanguagePropagator {
                language,
                call,
                tainted_arg,
                tainted_receiver,
            } => LearnedFactEntry::LanguagePropagator {
                language,
                call,
                tainted_arg,
                tainted_receiver,
            },
            LearnedFactEntryV5::LanguageSessionRoot { language, root } => {
                LearnedFactEntry::LanguageSessionRoot { language, root }
            }
            LearnedFactEntryV5::LanguageRoutePattern { language, pattern } => {
                LearnedFactEntry::LanguageRoutePattern { language, pattern }
            }
            LearnedFactEntryV5::StackAllocators { values } => {
                LearnedFactEntry::StackAllocators { values }
            }
            LearnedFactEntryV5::CollectionConstructors { values } => {
                LearnedFactEntry::CollectionConstructors { values }
            }
            LearnedFactEntryV5::SchemaDescribeMethods { values } => {
                LearnedFactEntry::SchemaDescribeMethods { values }
            }
            LearnedFactEntryV5::NullTokens { values } => LearnedFactEntry::NullTokens { values },
            LearnedFactEntryV5::SessionAccessors { values } => {
                LearnedFactEntry::SessionAccessors { values }
            }
            LearnedFactEntryV5::ReceiverParams { values } => {
                LearnedFactEntry::ReceiverParams { values }
            }
            LearnedFactEntryV5::LanguageAmbiguousVerbs { language, values } => {
                LearnedFactEntry::LanguageAmbiguousVerbs { language, values }
            }
        }
    }
}
