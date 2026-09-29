// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Task 4.3 completion: **sink signatures**, per-API argument-position facts.
//!
//! A blanket "every argument of a sink is dangerous" model causes the largest
//! FP class in the e2e report: `pool.query(sql, [email])` (parameterized,
//! safe) alerts because the tainted value sits in arg 1, the *safe* channel.
//!
//! A [`SinkSignature`] fixes this without engine surgery: it lists which
//! argument slots of a named call are dangerous, and whether a *binding*
//! parameter array (the parameterized-query safe channel) must be absent for
//! the call to be dangerous.
//!
//! Signatures come from the **fact tables** (`frensense-lang` built-ins merged
//! with bundler-extracted learned facts via a [`FactTable`]). The engine only
//! consumes them; updating a framework never touches engine code.

use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeSet;

use crate::analysis::taint::config::TaintConfig;
use crate::checks::memory_summary::CapacitySpec;

/// Per-argument classification for one sink API.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct SinkSignature {
    /// Call name matched against `CallStatic.func` / `CallVirtual.method`
    /// (last segment of a member chain).
    pub call: String,
    /// Argument slots that are dangerous when tainted. Empty = every slot.
    pub dangerous_args: BTreeSet<usize>,
    /// When `true`, a tainted argument in a *non-dangerous* slot (e.g. the
    /// params array of a parameterized query) is treated as **sanitized**
    /// (the API's binding channel makes it safe), not just ignored. Without
    /// this, `query(sql, [tainted])` silently degrades to no-op instead of a
    /// definite "safe" verdict, same outcome for alerts, different for
    /// verdicts/statistics.
    pub binding_args_safe: bool,
    /// Object-literal keys whose presence in a tainted argument marks it as
    /// an IDOR-class *object payload* (e.g. `{ where: { id: ... } }` reaching
    /// `findOne`) rather than a raw injection string. Empty for sinks whose
    /// dangerous shape is always a raw value.
    pub idor_keys: Vec<String>,
    /// What this sink does with its input (drives severity ranking).
    pub role: crate::analysis::taint::role::SinkRole,
}

impl SinkSignature {
    /// A signature where every argument is dangerous (the legacy default).
    pub fn all_args(call: &str) -> Self {
        Self {
            call: call.to_string(),
            dangerous_args: BTreeSet::new(),
            binding_args_safe: false,
            idor_keys: Vec::new(),
            role: crate::analysis::taint::role::SinkRole::Other,
        }
    }

    /// A signature with explicit dangerous slots.
    pub fn with_args(call: &str, slots: &[usize]) -> Self {
        Self {
            call: call.to_string(),
            dangerous_args: slots.iter().copied().collect(),
            binding_args_safe: false,
            idor_keys: Vec::new(),
            role: crate::analysis::taint::role::SinkRole::Other,
        }
    }

    /// Is argument slot `slot` dangerous when tainted?
    pub fn is_dangerous(&self, slot: usize) -> bool {
        self.dangerous_args.is_empty() || self.dangerous_args.contains(&slot)
    }

    /// Is this slot an explicitly-safe binding channel?
    pub fn is_binding(&self, slot: usize) -> bool {
        self.binding_args_safe && !self.is_dangerous(slot)
    }
}

/// One learned/built-in sanitizer fact: a call that neutralizes taint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct SanitizerFact {
    pub call: String,
    /// Per-kind strength label (advisory; the engine treats all kinds as cut).
    /// e.g. "encode", "validate", "allowlist", "parameterize".
    pub kind: String,
    /// Argument slots whose taint is removed. Empty = all arguments.
    pub sanitizes_args: BTreeSet<usize>,
    /// If `true`, a *guard-style* sanitizer: the call only protects values on
    /// paths where it returned true / threw (e.g. `SAFE_RE.test(x)`).
    /// The engine currently treats guard-style like an ordinary sanitizer on
    /// the explored branch (sound under flow-insensitive reading of the
    /// branch).
    pub guard_style: bool,
}

/// One corpus-verified non-dataflow check, installed by a `.frc` bundle.
///
/// This is the learned counterpart of the built-in seed checks in
/// `crate::checks`: the engine supplies the *mechanism* (call matching over
/// the lowered IR), the bundle supplies the *conclusion* (which call is a
/// violation, under which rule, with what advisory text). A rule fires when
/// the function contains a call whose last segment matches `call`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct LearnedCheckFact {
    /// Stable rule id, e.g. `"redirect_substring_guard"`.
    pub rule: String,
    /// Trigger: a call whose last segment matches this name fires the rule.
    pub call: String,
    /// Advisory text shown to the user (bundle-authored).
    pub message: String,
    /// Advisory severity hint: "warning" or "critical".
    pub severity: String,
    /// Optional guard qualification (bundle-authored): the rule only fires
    /// when NO call whose last segment matches this name appears in the
    /// same function. This expresses "trigger without enforcement", e.g.
    /// a privileged tool action executed without its policy-check helper.
    /// `None` = plain presence trigger.
    #[serde(default)]
    pub unless_guard: Option<String>,
    /// Optional range-check qualification (bundle-authored): the rule only
    /// fires when the trigger's guarded argument is NOT compared against a
    /// literal bound in the function. A negative enforcing policy inline
    /// (`if (discount < 0 || discount > MAX) return …`) contains a
    /// comparison of the guarded var against a literal; the positive has
    /// none. This expresses enforcement without requiring a named helper.
    /// The value is the operator set accepted as a bound check
    /// (e.g. `["<", ">", "<=", ">="]`); `None` = no range qualification.
    #[serde(default)]
    pub unless_range_check: Option<Vec<String>>,
}

/// A requirement that must hold for a policy's trigger to be considered compliant.
///
/// Serde representation note: this enum must stay **externally tagged**
/// (the default; no `serde(tag = ...)`). Internally-tagged enums require
/// `Deserializer::deserialize_any`, which bincode 1.x — the `.frc` bundle
/// codec — does not support: any bundle containing such a fact fails to
/// deserialize at load time. External tagging serializes the variant name
/// as a prefix, which bincode round-trips losslessly and JSON renders as
/// `{"GuardCall":{"call":"audit_log"}}`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum PolicyRequirement {
    /// A named guard call must be present in the scope (e.g. `audit_log`,
    /// `authorize`, `validate_origin`).
    GuardCall {
        /// Call name or last segment.
        call: String,
    },
    /// A call must NOT be present in the scope (forbid a deprecated or
    /// banned alternative from co-occurring with the trigger).
    NotCall { call: String },
    /// The trigger's guarded argument must participate in a comparison
    /// against a literal bound with one of `ops`. Direct generalization
    /// of `LearnedCheckFact::unless_range_check` (inverted).
    RangeCheck {
        /// Comparison operators accepted as the bound check.
        ops: Vec<String>,
    },
    /// One of these call names must appear in the scope, presence-required
    /// (an audit-log write must accompany the privileged action).
    RequireCall {
        /// Last-segment names, any one of which satisfies the requirement.
        any_of: Vec<String>,
    },
    /// The call's argument at `slot` must NOT match any of `values`
    /// (case-insensitive comparison over string, boolean, or integer literals).
    BannedArgLiteral { slot: usize, values: Vec<String> },
    /// The call's argument at `slot` MUST match one of `values`
    /// (case-insensitive comparison over string, boolean, or integer literals).
    RequiredArgLiteral { slot: usize, values: Vec<String> },
}

impl PolicyRequirement {
    /// Last-segment names this requirement matches on (for diagnostics).
    pub fn call_names(&self) -> Vec<&str> {
        match self {
            PolicyRequirement::GuardCall { call } | PolicyRequirement::NotCall { call } => {
                vec![call.as_str()]
            }
            PolicyRequirement::RequireCall { any_of } => {
                any_of.iter().map(|s| s.as_str()).collect()
            }
            PolicyRequirement::RangeCheck { .. }
            | PolicyRequirement::BannedArgLiteral { .. }
            | PolicyRequirement::RequiredArgLiteral { .. } => Vec::new(),
        }
    }
}

/// Where a policy's trigger and requirements are evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[serde(rename_all = "snake_case")]
pub enum PolicyScope {
    /// Trigger and requirements live in the same function (the default;
    /// matches the legacy `LearnedCheckFact` semantics exactly).
    #[default]
    Function,
    /// Requirements may be satisfied by ANY function in the scanned program
    /// (cross-function enforcement: a route handler's guard helper defined
    /// in a sibling module still counts). More FPs than `Function` when the
    /// helper is genuinely unrelated; use when the mine loop shows
    /// cross-file enforcement in the negatives.
    Module,
}

/// A corpus-verified co-occurrence policy: WHEN the trigger call appears in
/// the scope, every requirement must ALSO be satisfiable in the scope, else
/// the function violates the policy.
///
/// The generalization of [`LearnedCheckFact`]: that type's `unless_guard` /
/// `unless_range_check` fields are exactly `require: [GuardCall{..}]` /
/// `require: [RangeCheck{..}]` under `PolicyScope::Function`; `to_policy()`
/// converts losslessly so old bundles keep firing through the new path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyFact {
    /// Stable rule id, e.g. `"policy_redirect_challenge"`.
    pub rule: String,
    /// The trigger call (last segment matched) whose unqualified presence
    /// raises the policy question.
    pub when_call: String,
    /// Requirements that must hold in the scope for the trigger to be
    /// compliant. Empty = presence-only policy (any trigger fires).
    #[serde(default)]
    pub require: Vec<PolicyRequirement>,
    /// Where trigger and requirements are evaluated.
    #[serde(default)]
    pub scope: PolicyScope,
    /// Advisory text shown to the user (bundle-authored).
    pub message: String,
    /// Advisory severity hint: "warning" or "critical".
    pub severity: String,
}

impl PolicyFact {
    /// Convert a legacy [`LearnedCheckFact`] into the generalized form.
    /// `unless_guard` and `unless_range_check` become requirements; scope is
    /// always [`PolicyScope::Function`], matching the legacy semantics.
    pub fn from_legacy(f: &LearnedCheckFact) -> Self {
        let mut require = Vec::new();
        if let Some(g) = &f.unless_guard {
            require.push(PolicyRequirement::GuardCall { call: g.clone() });
        }
        if let Some(ops) = &f.unless_range_check {
            require.push(PolicyRequirement::RangeCheck { ops: ops.clone() });
        }
        Self {
            rule: f.rule.clone(),
            when_call: f.call.clone(),
            require,
            scope: PolicyScope::Function,
            message: f.message.clone(),
            severity: f.severity.clone(),
        }
    }
}

/// One corpus-verified memory allocation or deallocation contract.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryContractFact {
    /// Function or method name.
    pub name: String,
    /// Whether calling this function returns fresh heap memory.
    pub returns_fresh: bool,
    /// Capacity specification for the allocated buffer.
    pub return_capacity: CapacitySpec,
    /// Parameter indices consumed/deallocated by this call.
    pub consumes_params: Vec<usize>,
}

/// One corpus-verified weak cryptography rule.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct WeakCryptoFact {
    pub rule_id: String,
    pub call: String,
    pub selector_slot: Option<usize>,
    pub weak_selectors: Vec<String>,
}

/// One corpus-verified guard bypass fact (containment callee or credential sink).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct GuardBypassFact {
    #[serde(default)]
    pub containment_callees: Vec<String>,
    #[serde(default)]
    pub credential_sinks: Vec<String>,
    #[serde(default)]
    pub credential_params: Vec<String>,
}

/// One corpus-verified tool/API schema policy fact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct SchemaPolicyFact {
    #[serde(default)]
    pub builders: Vec<String>,
    #[serde(default)]
    pub enforcers: Vec<String>,
    #[serde(default)]
    pub bound_keywords: Vec<String>,
}

/// Syntactic grammar features that can be dynamically learned or configured via bundle facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum GrammarFeature {
    Cast,
    TemplateString,
    TemplateFragment,
    DestructuringPattern,
    PairPattern,
    PairEntry,
    TernaryStraightLine,
    DeclarationAssignment,
    PropertyKind,
}

/// An owned, serializable representation of [`frensense_lang::NodeRole`] for bundle facts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum TeachableNodeRole {
    Function {
        is_method: bool,
        name_field: Option<String>,
        params_field: String,
        body_field: String,
    },
    Declaration {
        name_field: String,
        value_field: String,
    },
    Assignment {
        lhs_field: String,
        rhs_field: String,
    },
    Call {
        callee_field: String,
        args_field: String,
    },
    MemberAccess {
        object_field: String,
        property_field: String,
    },
    Branch,
    Conditional,
    Loop,
    Return,
    Try,
    Catch,
    Finally,
    Throw,
    ErrorGuard,
    ContextManager,
    ErrorPropagation,
    Await,
    Block,
    Composite,
    Import,
    Export,
    Identifier,
    Literal,
    Parameters,
    Arguments,
    ClassDef,
    BinaryOp,
    UnaryOp,
    Match,
    Unsafe,
    AsyncBlock,
    Other,
}

impl TeachableNodeRole {
    /// Convert this owned teachable role into the engine's standard [`frensense_lang::NodeRole`].
    pub fn to_node_role(&self) -> frensense_lang::NodeRole {
        fn leak_field(s: &str) -> &'static str {
            Box::leak(s.to_string().into_boxed_str())
        }

        match self {
            TeachableNodeRole::Function {
                is_method,
                name_field,
                params_field,
                body_field,
            } => frensense_lang::NodeRole::Function {
                is_method: *is_method,
                name_field: name_field.as_deref().map(leak_field),
                params_field: leak_field(params_field),
                body_field: leak_field(body_field),
            },
            TeachableNodeRole::Declaration {
                name_field,
                value_field,
            } => frensense_lang::NodeRole::Declaration {
                name_field: leak_field(name_field),
                value_field: leak_field(value_field),
            },
            TeachableNodeRole::Assignment {
                lhs_field,
                rhs_field,
            } => frensense_lang::NodeRole::Assignment {
                lhs_field: leak_field(lhs_field),
                rhs_field: leak_field(rhs_field),
            },
            TeachableNodeRole::Call {
                callee_field,
                args_field,
            } => frensense_lang::NodeRole::Call {
                callee_field: leak_field(callee_field),
                args_field: leak_field(args_field),
            },
            TeachableNodeRole::MemberAccess {
                object_field,
                property_field,
            } => frensense_lang::NodeRole::MemberAccess {
                object_field: leak_field(object_field),
                property_field: leak_field(property_field),
            },
            TeachableNodeRole::Branch => frensense_lang::NodeRole::Branch,
            TeachableNodeRole::Conditional => frensense_lang::NodeRole::Conditional,
            TeachableNodeRole::Loop => frensense_lang::NodeRole::Loop,
            TeachableNodeRole::Return => frensense_lang::NodeRole::Return,
            TeachableNodeRole::Try => frensense_lang::NodeRole::Try,
            TeachableNodeRole::Catch => frensense_lang::NodeRole::Catch,
            TeachableNodeRole::Finally => frensense_lang::NodeRole::Finally,
            TeachableNodeRole::Throw => frensense_lang::NodeRole::Throw,
            TeachableNodeRole::ErrorGuard => frensense_lang::NodeRole::ErrorGuard,
            TeachableNodeRole::ContextManager => frensense_lang::NodeRole::ContextManager,
            TeachableNodeRole::ErrorPropagation => frensense_lang::NodeRole::ErrorPropagation,
            TeachableNodeRole::Await => frensense_lang::NodeRole::Await,
            TeachableNodeRole::Block => frensense_lang::NodeRole::Block,
            TeachableNodeRole::Composite => frensense_lang::NodeRole::Composite,
            TeachableNodeRole::Import => frensense_lang::NodeRole::Import,
            TeachableNodeRole::Export => frensense_lang::NodeRole::Export,
            TeachableNodeRole::Identifier => frensense_lang::NodeRole::Identifier,
            TeachableNodeRole::Literal => frensense_lang::NodeRole::Literal,
            TeachableNodeRole::Parameters => frensense_lang::NodeRole::Parameters,
            TeachableNodeRole::Arguments => frensense_lang::NodeRole::Arguments,
            TeachableNodeRole::ClassDef => frensense_lang::NodeRole::ClassDef,
            TeachableNodeRole::BinaryOp => frensense_lang::NodeRole::BinaryOp,
            TeachableNodeRole::UnaryOp => frensense_lang::NodeRole::UnaryOp,
            TeachableNodeRole::Match => frensense_lang::NodeRole::Match,
            TeachableNodeRole::Unsafe => frensense_lang::NodeRole::Unsafe,
            TeachableNodeRole::AsyncBlock => frensense_lang::NodeRole::AsyncBlock,
            TeachableNodeRole::Other => frensense_lang::NodeRole::Other,
        }
    }
}

impl From<&frensense_lang::NodeRole> for TeachableNodeRole {
    fn from(role: &frensense_lang::NodeRole) -> Self {
        match role {
            frensense_lang::NodeRole::Function {
                is_method,
                name_field,
                params_field,
                body_field,
            } => TeachableNodeRole::Function {
                is_method: *is_method,
                name_field: name_field.map(|s| s.to_string()),
                params_field: params_field.to_string(),
                body_field: body_field.to_string(),
            },
            frensense_lang::NodeRole::Declaration {
                name_field,
                value_field,
            } => TeachableNodeRole::Declaration {
                name_field: name_field.to_string(),
                value_field: value_field.to_string(),
            },
            frensense_lang::NodeRole::Assignment {
                lhs_field,
                rhs_field,
            } => TeachableNodeRole::Assignment {
                lhs_field: lhs_field.to_string(),
                rhs_field: rhs_field.to_string(),
            },
            frensense_lang::NodeRole::Call {
                callee_field,
                args_field,
            } => TeachableNodeRole::Call {
                callee_field: callee_field.to_string(),
                args_field: args_field.to_string(),
            },
            frensense_lang::NodeRole::MemberAccess {
                object_field,
                property_field,
            } => TeachableNodeRole::MemberAccess {
                object_field: object_field.to_string(),
                property_field: property_field.to_string(),
            },
            frensense_lang::NodeRole::Branch => TeachableNodeRole::Branch,
            frensense_lang::NodeRole::Conditional => TeachableNodeRole::Conditional,
            frensense_lang::NodeRole::Loop => TeachableNodeRole::Loop,
            frensense_lang::NodeRole::Return => TeachableNodeRole::Return,
            frensense_lang::NodeRole::Try => TeachableNodeRole::Try,
            frensense_lang::NodeRole::Catch => TeachableNodeRole::Catch,
            frensense_lang::NodeRole::Finally => TeachableNodeRole::Finally,
            frensense_lang::NodeRole::Throw => TeachableNodeRole::Throw,
            frensense_lang::NodeRole::ErrorGuard => TeachableNodeRole::ErrorGuard,
            frensense_lang::NodeRole::ContextManager => TeachableNodeRole::ContextManager,
            frensense_lang::NodeRole::ErrorPropagation => TeachableNodeRole::ErrorPropagation,
            frensense_lang::NodeRole::Await => TeachableNodeRole::Await,
            frensense_lang::NodeRole::Block => TeachableNodeRole::Block,
            frensense_lang::NodeRole::Composite => TeachableNodeRole::Composite,
            frensense_lang::NodeRole::Import => TeachableNodeRole::Import,
            frensense_lang::NodeRole::Export => TeachableNodeRole::Export,
            frensense_lang::NodeRole::Identifier => TeachableNodeRole::Identifier,
            frensense_lang::NodeRole::Literal => TeachableNodeRole::Literal,
            frensense_lang::NodeRole::Parameters => TeachableNodeRole::Parameters,
            frensense_lang::NodeRole::Arguments => TeachableNodeRole::Arguments,
            frensense_lang::NodeRole::ClassDef => TeachableNodeRole::ClassDef,
            frensense_lang::NodeRole::BinaryOp => TeachableNodeRole::BinaryOp,
            frensense_lang::NodeRole::UnaryOp => TeachableNodeRole::UnaryOp,
            frensense_lang::NodeRole::Match => TeachableNodeRole::Match,
            frensense_lang::NodeRole::Unsafe => TeachableNodeRole::Unsafe,
            frensense_lang::NodeRole::AsyncBlock => TeachableNodeRole::AsyncBlock,
            frensense_lang::NodeRole::Other => TeachableNodeRole::Other,
        }
    }
}

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
    /// Corpus-verified containment callees (for allowlist bypass checks).
    pub containment_callees: FxHashSet<String>,
    /// Corpus-verified credential setter/hasher sinks.
    pub credential_sinks: FxHashSet<String>,
    /// Corpus-verified parameter names identifying credentials.
    pub credential_params: FxHashSet<String>,
    /// Corpus-verified schema builder methods.
    pub schema_builders: FxHashSet<String>,
    /// Corpus-verified schema enforcer methods.
    pub schema_enforcers: FxHashSet<String>,
    /// Corpus-verified bound keywords.
    pub schema_keywords: FxHashSet<String>,
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
    /// `(language, node_kind) -> NodeRole`.
    pub grammar_roles: FxHashMap<(String, String), frensense_lang::NodeRole>,
    /// Dynamic grammar features learned from a `.frc` bundle:
    /// `(language, node_kind) -> Set<GrammarFeature>`.
    pub grammar_features: FxHashMap<(String, String), FxHashSet<GrammarFeature>>,
    /// Dynamic custom memory allocators learned from a bundle or specification.
    pub custom_allocators: FxHashSet<String>,
    /// Dynamic custom memory deallocators learned from a bundle or specification.
    pub custom_deallocators: FxHashSet<String>,
    /// Dynamic IDOR-class query keys learned from a bundle or specification.
    pub idor_keys: FxHashSet<String>,
    /// Dynamic IDOR-class finder sinks learned from a bundle or specification.
    pub idor_finder_sinks: FxHashSet<String>,
    /// Dynamic taint propagators: `call -> input_arg_slots`.
    pub propagators: FxHashMap<String, Vec<usize>>,
    /// Dynamic guard denylist string patterns (default fallback: `[".."]`).
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
                    kind: "encode".into(),
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
        self.containment_callees
            .extend(other.containment_callees.iter().cloned());
        self.credential_sinks
            .extend(other.credential_sinks.iter().cloned());
        self.credential_params
            .extend(other.credential_params.iter().cloned());
        self.schema_builders
            .extend(other.schema_builders.iter().cloned());
        self.schema_enforcers
            .extend(other.schema_enforcers.iter().cloned());
        self.schema_keywords
            .extend(other.schema_keywords.iter().cloned());

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
        self.idor_keys.extend(other.idor_keys.iter().cloned());
        self.idor_finder_sinks
            .extend(other.idor_finder_sinks.iter().cloned());
        for (k, v) in &other.propagators {
            self.propagators.insert(k.clone(), v.clone());
        }
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
    ) -> Option<&frensense_lang::NodeRole> {
        let lang = language.to_lowercase();
        self.grammar_roles
            .get(&(lang, node_kind.to_string()))
            .or_else(|| {
                self.grammar_roles
                    .get(&("*".to_string(), node_kind.to_string()))
            })
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

    /// Check whether a call allocates heap memory (checks dynamic custom allocators, then built-in defaults).
    pub fn is_allocator(&self, name: &str) -> bool {
        const DIRECT_ALLOC_CALLS: &[&str] = &[
            "malloc",
            "calloc",
            "realloc",
            "aligned_alloc",
            "valloc",
            "alloca",
        ];
        let last = name.rsplit('.').next().unwrap_or(name);
        self.custom_allocators.contains(name)
            || self.custom_allocators.contains(last)
            || DIRECT_ALLOC_CALLS.contains(&name)
            || DIRECT_ALLOC_CALLS.contains(&last)
    }

    /// Check whether a call deallocates heap memory (checks dynamic custom deallocators, then built-in defaults).
    pub fn is_deallocator(&self, name: &str) -> bool {
        const DIRECT_FREE_CALLS: &[&str] = &["free"];
        let last = name.rsplit('.').next().unwrap_or(name);
        self.custom_deallocators.contains(name)
            || self.custom_deallocators.contains(last)
            || DIRECT_FREE_CALLS.contains(&name)
            || DIRECT_FREE_CALLS.contains(&last)
    }

    /// Check whether a key is an IDOR-class query parameter (checks dynamic keys, then built-in defaults).
    pub fn is_idor_key(&self, key: &str) -> bool {
        self.idor_keys.contains(key) || crate::analysis::forward::DEFAULT_IDOR_KEYS.contains(&key)
    }

    /// Check whether a call is an IDOR finder sink (checks dynamic sinks, then built-in defaults).
    pub fn is_idor_finder_sink(&self, sink: &str) -> bool {
        let last = sink.rsplit('.').next().unwrap_or(sink);
        self.idor_finder_sinks.contains(sink)
            || self.idor_finder_sinks.contains(last)
            || crate::analysis::forward::IDOR_FINDER_SINKS.contains(&sink)
            || crate::analysis::forward::IDOR_FINDER_SINKS.contains(&last)
    }

    /// Look up input argument slots that propagate taint through `call`.
    pub fn propagator_input_args(&self, call: &str) -> Option<&[usize]> {
        let last = call.rsplit('.').next().unwrap_or(call);
        self.propagators
            .get(call)
            .or_else(|| self.propagators.get(last))
            .map(|v| v.as_slice())
    }

    /// Check whether a string literal matches a guard denylist pattern (default: contains "..").
    pub fn is_guard_denylist(&self, literal: &str) -> bool {
        if self.guard_denylist_patterns.is_empty() {
            literal.contains("..")
        } else {
            self.guard_denylist_patterns
                .iter()
                .any(|p| literal.contains(p.as_str()))
        }
    }

    /// Source patterns to merge into the scan's `TaintConfig`: the union of
    /// spec-derived names and bundle-learned ones. The engine matches both
    /// by full name and, for dotted entries, by last segment.
    pub fn source_patterns(&self) -> impl Iterator<Item = &str> {
        self.learned_sources.iter().map(|s| s.as_str())
    }

    /// Is `last(receiver_root)` a trusted session-store accessor?
    /// Receiver-aware like [`Self::is_sink_call`]: `authenticatedUsers.get(t)`
    /// is a session read; `myMap.get(t)` is not.
    pub fn is_session_accessor(&self, last: &str, receiver_root: Option<&str>) -> bool {
        self.sanitizer_facts
            .get(last)
            .map(|f| f.kind == "session")
            .unwrap_or(false)
            || match receiver_root {
                Some(root) => self.session_roots.contains(root) && last == "get",
                None => false,
            }
    }

    /// Session-accessor check over the receiver's full access path.
    /// Session stores are usually namespaced (`security.authenticatedUsers`),
    /// so ANY dotted segment matching a declared root qualifies:
    /// `security.authenticatedUsers.get(t)` hits root `authenticatedUsers`.
    pub fn is_session_path(&self, last: &str, receiver_path: Option<&str>) -> bool {
        if last != "get" {
            return false;
        }
        let Some(path) = receiver_path else {
            return false;
        };
        path.split('.').any(|seg| self.session_roots.contains(seg))
    }

    /// Resolve the receiver's full member-access path from the IR by
    /// walking LoadField defs and joining named segments:
    /// `security.authenticatedUsers.get(...)` →
    /// `Some("security.authenticatedUsers")`.
    ///
    /// Mirrors [`FactTable::receiver_root`] but keeps every named hop, so
    /// namespaced session stores match their declared root segment.
    pub fn receiver_access_path(
        ir: &crate::ir::function::FunctionIR,
        var: crate::ir::function::VarId,
    ) -> Option<String> {
        let mut segments: Vec<String> = Vec::new();
        let mut cur = var;
        for _ in 0..8 {
            if let Some(meta) = ir.var_metadata.get(&cur)
                && let Some(name) = &meta.source_name
            {
                segments.push(name.clone());
                break;
            }
            // Find the LoadField that defines `cur`, continue through its base.
            let mut found = None;
            'outer: for b in ir.blocks.values() {
                for instr in b.instructions.iter() {
                    if let crate::ir::function::Instruction::LoadField {
                        dest, base, field, ..
                    } = instr
                        && *dest == cur
                    {
                        segments.push(field.clone());
                        found = Some(*base);
                        break 'outer;
                    }
                }
            }
            cur = found?;
        }
        if segments.is_empty() {
            return None;
        }
        segments.reverse();
        Some(segments.join("."))
    }

    /// Signature for a sink call; `None` if the call is not a configured sink.
    pub fn sink_signature(&self, call: &str) -> Option<&SinkSignature> {
        self.sink_signatures.get(call)
    }

    /// Role for a sink call, receiver-aware.
    ///
    /// When the receiver root matches a dotted entry's declared root (e.g.
    /// `KVNamespace` for `kv.put(t)`), that entry's role wins over the bare
    /// last-segment entry's. Falls back to [`Self::sink_signature`] when no
    /// receiver-specific role exists.
    pub fn role_for_call(
        &self,
        last: &str,
        receiver_root: Option<&str>,
    ) -> Option<crate::analysis::taint::role::SinkRole> {
        if let Some(root) = receiver_root
            && let Some(role) = self
                .receiver_roles
                .get(&(root.to_string(), last.to_string()))
        {
            return Some(*role);
        }
        self.sink_signature(last).map(|s| s.role)
    }

    /// Sanitizer fact for a call; `None` if not a sanitizer.
    pub fn sanitizer_fact(&self, call: &str) -> Option<&SanitizerFact> {
        self.sanitizer_facts.get(call)
    }

    /// Receiver-aware sink check for virtual calls. `last` is the method
    /// name; `receiver_root` the first segment of the receiver's access
    /// path (e.g. `got` for `got.get(url)`), `None` when unresolvable.
    ///
    /// - Non-verb names match as before (name-configured sinks).
    /// - Verb names (`get`, `post`, ...) only match when they were sourced
    ///   from dotted client entries AND the receiver root is a known
    ///   client, `m.get(t)` on an arbitrary Map is never a sink, while
    ///   `got.get(taint)` is.
    pub fn is_sink_call(&self, last: &str, receiver_root: Option<&str>) -> bool {
        if !self.verb_sinks.contains(last) {
            // Ordinary sink: presence in the signature table decides.
            return self.sink_signatures.contains_key(last);
        }
        match receiver_root {
            Some(root) => self.client_roots.contains(root),
            // Unresolvable receiver: over-approximate (sound, noisier).
            None => true,
        }
    }

    /// Walk a receiver var to the root of its member-access chain via the
    /// IR: `const c = got; got.get(x)` and direct `got.get(x)` both
    /// resolve to root `got`. Returns `None` when the def is not a
    /// LoadField chain grounded in a named var.
    pub fn receiver_root(
        ir: &crate::ir::function::FunctionIR,
        var: crate::ir::function::VarId,
    ) -> Option<String> {
        let mut cur = var;
        for _ in 0..8 {
            if let Some(meta) = ir.var_metadata.get(&cur)
                && let Some(name) = &meta.source_name
            {
                return Some(name.split('.').next().unwrap_or(name).to_string());
            }
            // Find the LoadField that defines `cur`, continue through its base.
            let mut found = None;
            'outer: for b in ir.blocks.values() {
                for instr in b.instructions.iter() {
                    if let crate::ir::function::Instruction::LoadField { dest, base, .. } = instr
                        && *dest == cur
                    {
                        found = Some(*base);
                        break 'outer;
                    }
                }
            }
            cur = found?;
        }
        None
    }

    /// Learned checks whose trigger call's last segment matches `call`.
    /// The engine matches calls by last segment, so a bundle rule written
    /// for `security.hash` also fires on bare `hash`, same over-approximate
    /// semantics as built-in seed checks.
    pub fn learned_checks_for(&self, call: &str) -> Vec<&LearnedCheckFact> {
        let seg = call.rsplit('.').next().unwrap_or(call);
        self.learned_checks
            .iter()
            .filter(|c| c.call.rsplit('.').next() == Some(seg))
            .collect()
    }

    /// Co-occurrence policies whose trigger call's last segment matches
    /// `call` (same last-segment matching as [`Self::learned_checks_for`]).
    pub fn policies_for(&self, call: &str) -> Vec<&PolicyFact> {
        let seg = call.rsplit('.').next().unwrap_or(call);
        self.policy_facts
            .iter()
            .filter(|p| p.when_call.rsplit('.').next() == Some(seg))
            .collect()
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
        #[serde(default)]
        require: Vec<PolicyRequirement>,
        #[serde(default)]
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
        #[serde(default)]
        unless_guard: Option<String>,
        /// Fire only when the trigger's argument is NOT compared against a
        /// literal bound with one of these operators (inline enforcement).
        /// `None` = no range qualification.
        #[serde(default)]
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
}

impl LearnedFactEntry {
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
                let role = prior
                    .map(|s| s.role)
                    .unwrap_or(crate::analysis::taint::role::SinkRole::Other);
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
                table
                    .containment_callees
                    .extend(fact.containment_callees.iter().cloned());
                table
                    .credential_sinks
                    .extend(fact.credential_sinks.iter().cloned());
                table
                    .credential_params
                    .extend(fact.credential_params.iter().cloned());
            }
            LearnedFactEntry::SchemaPolicy(fact) => {
                table.schema_builders.extend(fact.builders.iter().cloned());
                table
                    .schema_enforcers
                    .extend(fact.enforcers.iter().cloned());
                table
                    .schema_keywords
                    .extend(fact.bound_keywords.iter().cloned());
            }
            LearnedFactEntry::GrammarRole {
                language,
                node_kind,
                role,
            } => {
                table.grammar_roles.insert(
                    (language.to_lowercase(), node_kind.clone()),
                    role.to_node_role(),
                );
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
                    idor_keys: if keys.is_empty() {
                        crate::analysis::forward::DEFAULT_IDOR_KEYS
                            .iter()
                            .map(|s| s.to_string())
                            .collect()
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
        // A dotted entry whose last segment is a bare HTTP verb is an
        // AMBIGUOUS verb sink: `Map.get`, router `app.post`, LRU `.put` all
        // share the name. Record it so sink matching can require that the
        // receiver actually resolves to the client root (got/axios/http...).
        if last != *call
            && matches!(
                last.as_str(),
                "get"
                    | "post"
                    | "put"
                    | "delete"
                    | "patch"
                    | "head"
                    | "options"
                    | "request"
                    | "set"
            )
        {
            t.verb_sinks.insert(last.clone());
            if let Some(root) = call.split('.').next() {
                t.client_roots.insert(root.to_string());
            }
        }
    }
    // Per-slot danger facts override the all-args default for the sinks that
    // declare them (jwt.verify(token, secret), parameterized query(sql, params)).
    for (call, dangerous_slots, binding_safe) in spec.known_sink_signatures() {
        // Finder/updater sinks carry the default IDOR key set: a tainted
        // argument arriving as an object literal with these keys is an
        // access-control query payload, not an injection string.
        let idor_keys: Vec<String> = if t.is_idor_finder_sink(call) {
            if !t.idor_keys.is_empty() {
                t.idor_keys.iter().cloned().collect()
            } else {
                crate::analysis::forward::DEFAULT_IDOR_KEYS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            }
        } else {
            Vec::new()
        };
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
            idor_keys,
            role,
        };
        t.sink_signatures.insert((*call).to_string(), entry.clone());
        let last = call.rsplit('.').next().unwrap_or(call);
        if last != *call {
            t.sink_signatures.entry(last.to_string()).or_insert(entry);
        }
    }
    for root in spec.known_session_roots() {
        t.session_roots.insert((*root).to_string());
    }
    // Spec sanitizers: register each known sanitizer into `t.sanitizer_facts`.
    // Identify predicate guards (regex `.test()`, `.isValid()`, `is...()` type-guards,
    // or Full classification) and set `guard_style = true`.
    for name in spec.known_sanitizer_names() {
        let kind = spec
            .classify_sanitizer(name)
            .map(|k| format!("{k:?}"))
            .unwrap_or_else(|| "encode".into());
        let guard_style =
            *name == "test" || *name == "isValid" || name.starts_with("is") || kind == "Full";
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
        t.propagators.insert(key, args.clone());
        t.propagators.entry(last).or_insert(args);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TaintConfig {
        TaintConfig {
            sources: ["req.body".to_string()].into_iter().collect(),
            sinks: ["query".to_string(), "exec".to_string()]
                .into_iter()
                .collect(),
            sanitizers: ["escapeHtml".to_string()].into_iter().collect(),
        }
    }

    #[test]
    fn test_fact_table_defaults_all_args_dangerous() {
        let t = FactTable::from_config(&cfg());
        let sig = t.sink_signature("query").unwrap();
        assert!(sig.is_dangerous(0));
        assert!(sig.is_dangerous(1));
        assert!(sig.is_dangerous(9));
    }

    #[test]
    fn test_parameterized_query_signature() {
        let mut t = FactTable::from_config(&cfg());
        let mut sig = SinkSignature::with_args("query", &[0]);
        sig.binding_args_safe = true;
        t.sink_signatures.insert("query".into(), sig);

        let s = t.sink_signature("query").unwrap();
        assert!(s.is_dangerous(0), "sql template slot is dangerous");
        assert!(
            !s.is_dangerous(1),
            "params array slot is the safe binding channel"
        );
        assert!(s.is_binding(1));
    }

    #[test]
    fn test_merge_learns_over_builtins() {
        let mut t = FactTable::from_config(&cfg());
        assert!(t.sink_signature("query").unwrap().is_dangerous(1));

        let mut learned = FactTable::default();
        let mut sig = SinkSignature::with_args("query", &[0]);
        sig.binding_args_safe = true;
        learned.sink_signatures.insert("query".into(), sig);
        t.merge(&learned);

        assert!(!t.sink_signature("query").unwrap().is_dangerous(1));
    }

    #[test]
    fn test_sanitizer_fact_lookup() {
        let t = FactTable::from_config(&cfg());
        let f = t.sanitizer_fact("escapeHtml").unwrap();
        assert_eq!(f.kind, "encode");
        assert!(t.sanitizer_fact("exec").is_none());
    }

    #[test]
    fn test_verb_sink_receiver_aware() {
        // The JS spec carries dotted client sinks (got.get, axios.post, ...);
        // their bare verb segments must be receiver-aware, not blanket sinks.
        let spec = frensense_lang::spec_for_ext("ts").unwrap();
        let t = fact_table_from_spec(spec);

        assert!(
            t.verb_sinks.contains("get"),
            "dotted got.get registers verb"
        );
        assert!(t.client_roots.contains("got"), "client root from got.get");

        // Known client root: real SSRF channel, sink.
        assert!(t.is_sink_call("get", Some("got")));
        // Arbitrary Map/receiver root: accessor, NOT a sink.
        assert!(!t.is_sink_call("get", Some("authenticatedUsers")));
        // Non-verb sinks match by name regardless of receiver.
        assert!(t.is_sink_call("findOne", Some("anything")));
    }

    #[test]
    fn test_verb_sink_merge_accumulates() {
        let spec = frensense_lang::spec_for_ext("ts").unwrap();
        let base = fact_table_from_spec(spec);
        let mut merged = FactTable::default();
        merged.merge(&base);
        assert!(merged.verb_sinks.contains("post"));
        assert!(merged.client_roots.contains("axios"));
    }

    #[test]
    fn test_last_segment_role_collision_bare_wins() {
        // `decode` (JwtUnsafeDecode) and `msgpack.decode` (UnsafeDeserialize)
        // share a last segment with different roles. The bare entry must keep
        // Validation; a dotted sibling must never silently re-role it.
        let spec = frensense_lang::spec_for_ext("ts").unwrap();
        let t = fact_table_from_spec(spec);
        let sig = t.sink_signature("decode").expect("decode registered");
        assert_eq!(sig.role, crate::analysis::taint::role::SinkRole::Validation);
        // The dotted entry keeps its own role under its full-path key.
        let msgpack = t
            .sink_signature("msgpack.decode")
            .expect("msgpack.decode registered");
        assert_eq!(
            msgpack.role,
            crate::analysis::taint::role::SinkRole::Execution
        );
    }

    #[test]
    fn test_per_slot_signature_inherits_label_role() {
        // Per-slot entries (JS_SINK_SIGNATURES) carry no label of their own;
        // they must inherit the role of the same call's all-args entry.
        let spec = frensense_lang::spec_for_ext("ts").unwrap();
        let t = fact_table_from_spec(spec);
        let query = t.sink_signature("query").expect("query registered");
        assert_eq!(
            query.role,
            crate::analysis::taint::role::SinkRole::Execution
        );
        assert!(
            query.binding_args_safe,
            "parameterized query keeps binding safety"
        );
        let fetch = t.sink_signature("fetch").expect("bare fetch registered");
        assert_eq!(fetch.role, crate::analysis::taint::role::SinkRole::Resource);
    }

    #[test]
    fn test_rust_fetch_single_label() {
        // The Rust spec once declared `fetch` twice (SqlInjection + Ssrf);
        // insertion-order races decided its role. Exactly one label wins now.
        let spec = frensense_lang::spec_for_ext("rs").unwrap();
        let t = fact_table_from_spec(spec);
        let fetch = t.sink_signature("fetch").expect("fetch registered");
        assert_eq!(
            fetch.role,
            crate::analysis::taint::role::SinkRole::Execution
        );
    }

    #[test]
    fn test_receiver_role_disambiguates_dotted_vs_bare() {
        // The JS spec declares dotted KVNamespace.put (StorageWrite) whose
        // last segment collides with the bare HTTP-verb space, and
        // `res.send` (ResponseLeak) colliding with `Queue.send` (Ssrf).
        // A receiver root matching the dotted entry's declared root must
        // flip the role; an unmatched receiver keeps the bare entry's.
        let spec = frensense_lang::spec_for_ext("ts").unwrap();
        let t = fact_table_from_spec(spec);

        // res.send: receiver `res` matches the dotted root -> ResponseLeak.
        let res_send = t.role_for_call("send", Some("res"));
        assert_eq!(
            res_send,
            Some(crate::analysis::taint::role::SinkRole::Response),
            "res.send resolves via dotted ResponseLeak entry"
        );
        // queue.send: receiver `queue` does NOT match `res`'s root, but
        // Queue.send is its own dotted entry with root `Queue` -> Ssrf.
        let queue_send = t.role_for_call("send", Some("Queue"));
        assert_eq!(
            queue_send,
            Some(crate::analysis::taint::role::SinkRole::Resource),
            "Queue.send resolves via dotted Ssrf entry"
        );
        // Unresolvable receiver: falls back to the bare last-segment entry.
        let bare = t.role_for_call("send", None);
        assert!(bare.is_some(), "bare send still a sink");
    }

    #[test]
    fn test_receiver_roles_survive_merge() {
        let spec = frensense_lang::spec_for_ext("ts").unwrap();
        let base = fact_table_from_spec(spec);
        let mut merged = FactTable::default();
        merged.merge(&base);
        let role = merged.role_for_call("put", Some("KVNamespace"));
        assert_eq!(
            role,
            Some(crate::analysis::taint::role::SinkRole::Storage),
            "KVNamespace.put role survives FactTable::merge"
        );
    }
}

/// Corpus-owned seed facts: deployment/deployment-specific knowledge that
/// is NOT language semantics, framework/session-store names, project
/// conventions, kept OUT of `frensense-lang` so the spec layer stays
/// general and the corpus stays ownable.
///
/// Loaded from a JSON file and merged over the spec-built fact table;
/// entries here win (they are more specific than any language default).
#[cfg(feature = "serialize")]
pub mod seed {
    use super::FactTable;
    use serde::Deserialize;

    /// File schema. Only fields present are applied; unknown fields are
    /// ignored so older engines load newer files without failing.
    #[derive(Debug, Deserialize, Default)]
    pub struct SeedFacts {
        /// Receiver roots of trusted session stores
        /// (`security.authenticatedUsers` -> root `authenticatedUsers`).
        #[serde(default)]
        pub session_roots: Vec<String>,
    }

    impl SeedFacts {
        /// Parse a seed-facts JSON document.
        pub fn parse(json: &str) -> Result<Self, String> {
            serde_json::from_str(json).map_err(|e| format!("seed facts: {e}"))
        }

        /// Load from disk.
        pub fn load(path: &std::path::Path) -> Result<Self, String> {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("seed facts {}: {e}", path.display()))?;
            Self::parse(&text)
        }

        /// Merge into a fact table (self wins on collision).
        pub fn apply_to(&self, t: &mut FactTable) {
            for r in &self.session_roots {
                t.session_roots.insert(r.clone());
            }
        }

        /// Load a seed file (if it exists) and merge over `t`.
        pub fn load_and_apply(path: &std::path::Path, t: &mut FactTable) -> Result<(), String> {
            if !path.exists() {
                return Ok(());
            }
            Self::load(path)?.apply_to(t);
            Ok(())
        }
    }
}

#[cfg(test)]
mod teachable_subsystem_tests {
    use super::*;
    use crate::checks::memory_summary::MemorySummaryRegistry;

    #[test]
    fn test_teachable_allocator_and_deallocator() {
        let mut table = FactTable::default();
        // Fallback built-ins work
        assert!(table.is_allocator("malloc"));
        assert!(table.is_allocator("calloc"));
        assert!(table.is_deallocator("free"));
        assert!(!table.is_allocator("custom_arena_alloc"));
        assert!(!table.is_deallocator("custom_arena_free"));

        // Learn custom primitives from bundle
        let alloc_fact = LearnedFactEntry::Allocator {
            name: "custom_arena_alloc".into(),
        };
        let dealloc_fact = LearnedFactEntry::Deallocator {
            name: "custom_arena_free".into(),
        };
        alloc_fact.apply(&mut table);
        dealloc_fact.apply(&mut table);

        assert!(table.is_allocator("custom_arena_alloc"));
        assert!(table.is_deallocator("custom_arena_free"));
        // Built-ins still work
        assert!(table.is_allocator("malloc"));
        assert!(table.is_deallocator("free"));

        // MemorySummaryRegistry consumes dynamic facts seamlessly
        let reg = MemorySummaryRegistry::from_facts(&table);
        assert!(reg.returns_fresh("custom_arena_alloc"));
        assert_eq!(reg.consumes_params("custom_arena_free"), &[0]);
    }

    #[test]
    fn test_teachable_idor_finder_sinks_and_keys() {
        let mut table = FactTable::default();
        // Fallback built-ins work
        assert!(table.is_idor_finder_sink("find"));
        assert!(table.is_idor_finder_sink("findOne"));
        assert!(table.is_idor_key("id"));
        assert!(table.is_idor_key("where"));
        assert!(!table.is_idor_finder_sink("findCompanyRecord"));
        assert!(!table.is_idor_key("organization_id"));

        // Learn custom IDOR sink and keys
        let fact = LearnedFactEntry::IdorFinderSink {
            call: "findCompanyRecord".into(),
            keys: vec!["organization_id".into(), "tenant_id".into()],
        };
        fact.apply(&mut table);

        assert!(table.is_idor_finder_sink("findCompanyRecord"));
        assert!(table.is_idor_key("organization_id"));
        assert!(table.is_idor_key("tenant_id"));
        // Built-in fallbacks intact
        assert!(table.is_idor_finder_sink("findOne"));
        assert!(table.is_idor_key("id"));
    }

    #[test]
    fn test_teachable_propagator_rules() {
        let mut table = FactTable::default();
        assert_eq!(table.propagator_input_args("custom_transform"), None);

        let fact = LearnedFactEntry::Propagator {
            call: "custom_transform".into(),
            input_args: vec![0, 2],
            preserves_taint: true,
        };
        fact.apply(&mut table);

        assert_eq!(
            table.propagator_input_args("custom_transform"),
            Some(&[0, 2][..])
        );
        assert_eq!(
            table.propagator_input_args("mod.custom_transform"),
            Some(&[0, 2][..])
        );
    }

    #[test]
    fn test_teachable_guard_denylist_patterns() {
        let mut table = FactTable::default();
        // Default fallback to ".."
        assert!(table.is_guard_denylist("../etc/shadow"));
        assert!(!table.is_guard_denylist("/private/vault"));

        let fact = LearnedFactEntry::GuardDenylistPattern {
            pattern: "/private/vault".into(),
        };
        fact.apply(&mut table);

        assert!(table.is_guard_denylist("/private/vault"));
    }

    #[test]
    #[cfg(feature = "serialize")]
    fn test_bincode_roundtrip_all_new_variants() {
        let facts = vec![
            LearnedFactEntry::Allocator {
                name: "arena_alloc".into(),
            },
            LearnedFactEntry::Deallocator {
                name: "arena_free".into(),
            },
            LearnedFactEntry::IdorFinderSink {
                call: "query_repo".into(),
                keys: vec!["workspace_id".into()],
            },
            LearnedFactEntry::IdorKey {
                key: "team_id".into(),
            },
            LearnedFactEntry::Propagator {
                call: "format_str".into(),
                input_args: vec![0, 1],
                preserves_taint: true,
            },
            LearnedFactEntry::GuardDenylistPattern {
                pattern: ".env".into(),
            },
        ];

        let bytes = bincode::serialize(&facts).expect("serialization succeeds");
        let decoded: Vec<LearnedFactEntry> =
            bincode::deserialize(&bytes).expect("deserialization succeeds");
        assert_eq!(facts, decoded);
    }
}
