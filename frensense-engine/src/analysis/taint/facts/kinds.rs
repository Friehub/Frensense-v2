// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::borrow::Cow;
use std::collections::BTreeSet;

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

/// Sanitizer-kind label for non-guard sanitizers: one dialect across every
/// producer (spec seeding, the built-in table, bundle-learned facts).
/// Advisory only; the engine cuts on every kind and branches on
/// [`SanitizerFact::guard_style`].
pub const DEFAULT_SANITIZER_KIND: &str = "encode";
/// Sanitizer-kind label for guard-style sanitizers (the other half of the
/// single producer dialect; see [`DEFAULT_SANITIZER_KIND`]).
pub const ALLOWLIST_SANITIZER_KIND: &str = "allowlist";

/// One learned/built-in sanitizer fact: a call that neutralizes taint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct SanitizerFact {
    pub call: String,
    /// Strength/style label (advisory; the engine cuts on every kind and
    /// branches on `guard_style`). One dialect across every producer:
    /// [`DEFAULT_SANITIZER_KIND`] / [`ALLOWLIST_SANITIZER_KIND`].
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
    #[cfg_attr(feature = "serialize", serde(default))]
    pub unless_guard: Option<String>,
    /// Optional range-check qualification (bundle-authored): the rule only
    /// fires when the trigger's guarded argument is NOT compared against a
    /// literal bound in the function. A negative enforcing policy inline
    /// (`if (discount < 0 || discount > MAX) return …`) contains a
    /// comparison of the guarded var against a literal; the positive has
    /// none. This expresses enforcement without requiring a named helper.
    /// The value is the operator set accepted as a bound check
    /// (e.g. `["<", ">", "<=", ">="]`); `None` = no range qualification.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub unless_range_check: Option<Vec<String>>,
}

/// A requirement that must hold for a policy's trigger to be considered compliant.
///
/// Serde representation note: this enum must stay **externally tagged**
/// (the default; no `serde(tag = ...)`). Internally-tagged enums require
/// `Deserializer::deserialize_any`, which bincode 1.x - the `.frc` bundle
/// codec - does not support: any bundle containing such a fact fails to
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
#[cfg_attr(feature = "serialize", serde(rename_all = "snake_case"))]
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
    #[cfg_attr(feature = "serialize", serde(default))]
    pub require: Vec<PolicyRequirement>,
    /// Where trigger and requirements are evaluated.
    #[cfg_attr(feature = "serialize", serde(default))]
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
    /// Advisory severity hint: "warning" or "critical".
    #[cfg_attr(feature = "serialize", serde(default))]
    pub severity: String,
    /// Corpus-authored advisory observation.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub message: String,
}

/// One corpus-verified guard bypass fact (containment callee or credential sink).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct GuardBypassFact {
    #[cfg_attr(feature = "serialize", serde(default))]
    pub containment_callees: Vec<String>,
    #[cfg_attr(feature = "serialize", serde(default))]
    pub credential_sinks: Vec<String>,
    #[cfg_attr(feature = "serialize", serde(default))]
    pub credential_params: Vec<String>,
}

/// One corpus-verified tool/API schema policy fact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct SchemaPolicyFact {
    #[cfg_attr(feature = "serialize", serde(default))]
    pub builders: Vec<String>,
    #[cfg_attr(feature = "serialize", serde(default))]
    pub enforcers: Vec<String>,
    #[cfg_attr(feature = "serialize", serde(default))]
    pub bound_keywords: Vec<String>,
}

/// Which hint table a `LearnedFactEntry::Hints` entry feeds. The hint
/// vocabularies are flat string sets keyed by purpose (Phase 6 format
/// extension): one entry kind, seven tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum HintKind {
    /// [`FactTable::url_param_hints`]: a function parameter is URL-like.
    UrlParam,
    /// [`FactTable::url_arg_hints`]: a guard argument is URL-ish.
    UrlArg,
    /// [`FactTable::url_literal_hints`]: a literal is an absolute URL.
    UrlLiteral,
    /// [`FactTable::security_context_hints`]: a name marks security code.
    SecurityContext,
    /// [`FactTable::auth_guard_hints`]: a call is an authentication check.
    AuthGuard,
    /// [`FactTable::jwt_algorithm_hints`]: an algorithm choice is
    /// security-sensitive.
    JwtAlgorithm,
    /// [`FactTable::credential_context_hints`]: an enclosing name marks
    /// credential context.
    CredentialContext,
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
    /// Bundle field names become `Cow::Owned` (allocated per fact, never
    /// leaked); spec-provided roles stay `Cow::Borrowed` upstream.
    pub fn to_node_role(&self) -> frensense_lang::NodeRole {
        match self {
            TeachableNodeRole::Function {
                is_method,
                name_field,
                params_field,
                body_field,
            } => frensense_lang::NodeRole::Function {
                is_method: *is_method,
                name_field: name_field.as_ref().map(|s| Cow::Owned(s.clone())),
                params_field: Cow::Owned(params_field.clone()),
                body_field: Cow::Owned(body_field.clone()),
            },
            TeachableNodeRole::Declaration {
                name_field,
                value_field,
            } => frensense_lang::NodeRole::Declaration {
                name_field: Cow::Owned(name_field.clone()),
                value_field: Cow::Owned(value_field.clone()),
            },
            TeachableNodeRole::Assignment {
                lhs_field,
                rhs_field,
            } => frensense_lang::NodeRole::Assignment {
                lhs_field: Cow::Owned(lhs_field.clone()),
                rhs_field: Cow::Owned(rhs_field.clone()),
            },
            TeachableNodeRole::Call {
                callee_field,
                args_field,
            } => frensense_lang::NodeRole::Call {
                callee_field: Cow::Owned(callee_field.clone()),
                args_field: Cow::Owned(args_field.clone()),
            },
            TeachableNodeRole::MemberAccess {
                object_field,
                property_field,
            } => frensense_lang::NodeRole::MemberAccess {
                object_field: Cow::Owned(object_field.clone()),
                property_field: Cow::Owned(property_field.clone()),
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
                name_field: name_field.as_ref().map(|s| s.to_string()),
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

// ---------------------------------------------------------------------------
// Fact-rule types moved out of `frensense-lang` (Phase 6.1: lang keeps only
// mechanism - grammar/classification/queries/registry - while these types
// and their bootstrap tables live here and in the default pack).
// ---------------------------------------------------------------------------

/// A weak-primitive policy rule: a call whose string-literal selector (or
/// bare name) selects a weak digest algorithm. Matches the two shapes
/// real code uses: `createHash('md5')` (selector in an argument slot) and
/// bare `md5(data)`.
///
/// Owned fields: bundle-loaded rules carry corpus-authored text, so
/// nothing `FactTable` stores may be `&'static str`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeakPrimitiveRule {
    /// Finding rule id.
    pub rule_id: String,
    /// Callee last-segment names that take a selector literal argument.
    pub selector_calls: Vec<String>,
    /// Bare function names that are weak by themselves.
    pub bare_calls: Vec<String>,
    /// Argument slot of the selector literal (ignored for bare calls).
    pub selector_slot: usize,
    /// Selector literals that mark the call weak (case-insensitive, quotes
    /// stripped by the caller).
    pub weak_selectors: Vec<String>,
    /// When true, the selector shape fires only inside a credential
    /// context; bare weak names fire unconditionally.
    pub requires_credential_context: bool,
    /// Advisory severity hint: "warning" or "critical".
    pub severity: String,
    /// Advisory observation body.
    pub message: String,
}

/// An allocation-size integer-overflow prover rule (CWE-190 wrap ->
/// CWE-680 undersized allocation). The engine owns the prover; this type
/// owns the conclusion: rule id, wrap threshold, advisory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct IntegerOverflowRule {
    /// Finding rule id.
    pub rule_id: String,
    /// Products exceeding this value cannot be represented as an
    /// allocation size on the target platform.
    pub wrap_threshold: u128,
    /// Advisory severity hint: "critical" or "warning".
    pub severity: String,
    /// Corpus-authored advisory message (rendered with prover detail).
    pub message: String,
}

/// A string-literal insecure-configuration selector: a call whose
/// argument literal selects an insecure mode regardless of algorithm.
/// The literal selector and its advisory travel together so the check
/// stays fact-driven end to end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsecureConfigRule {
    /// Callee-path prefix the selector applies to (`jwt.verify`, ...).
    pub prefix: String,
    /// Selector literals that select the insecure mode (lowercase match).
    pub selectors: Vec<String>,
    /// Finding rule id.
    pub rule_id: String,
    /// Advisory severity hint: "warning" or "critical".
    pub severity: String,
    /// Advisory observation body.
    pub message: String,
}

/// A key-size rule: a generation call whose constant bit-length argument
/// falls below the security floor. Value-aware: the argument may be a var
/// whose lattice value is a provable constant, not just a bare literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySizeRule {
    /// Finding rule id.
    pub rule_id: String,
    /// Callee last segment (case-insensitive match).
    pub call: String,
    /// Argument slot carrying the bit length.
    pub slot: usize,
    /// Minimum acceptable bits.
    pub min_bits: i64,
    /// Human label of what the key protects.
    pub kind: String,
    /// Advisory severity hint: "warning" or "critical".
    pub severity: String,
    /// Advisory observation body.
    pub message: String,
}

/// Capacity of a fresh allocation, derived from the call's arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocCapacity {
    /// Fresh, but capacity is dynamic or unconstrained (`strdup(s)`).
    Unknown,
    /// Capacity is the argument at this index (`malloc(n)`).
    Param(usize),
    /// Capacity is the product of two arguments (`calloc(n, size)`).
    ParamProduct(usize, usize),
}

/// One memory-function contract: what the call returns and which slots
/// it consumes. Spec vocabulary only - bundle contracts travel as
/// `LearnedFactEntry::MemoryContract` (owned strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFuncSpec {
    /// Callee name (bare or dotted; the engine matches exact-or-last).
    pub name: &'static str,
    /// Does the call return freshly allocated memory?
    pub returns_fresh: bool,
    /// Capacity of the returned allocation (meaningful when fresh).
    pub capacity: AllocCapacity,
    /// Parameter indices the call consumes (deallocates / takes ownership).
    pub consumes_params: &'static [usize],
}

/// One buffer-manipulation builtin: which arguments are the destination
/// buffer, the source data, and the length, so the spatial checker can
/// verify write/read bounds against the tracked capacity.
///
/// Owned name: bundle-loaded builtins carry corpus text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferBuiltinSpec {
    /// Callee last-segment name.
    pub name: String,
    /// Argument index of the destination buffer (`None` = none).
    pub dst_arg: Option<usize>,
    /// Argument index of the source data (`None` = none).
    pub src_arg: Option<usize>,
    /// Argument index of the length.
    pub len_arg: usize,
}
