// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

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
    /// Optional package qualification (e.g. "pg", "mysql", "child_process").
    /// `None` indicates a universal built-in or unscoped sink.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub package: Option<String>,
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
    /// Semantic label slug for identity reporting (e.g. "prototype", "ssrf", "regex").
    pub label: Option<String>,
    /// When `true`, this sink is a *global* builtin: it matches the bare /
    /// unqualified call form, and a receiver-qualified call (`engine.eval(x)`)
    /// only matches once the receiver's origin resolves to a known package
    /// (schema "global-only" fact: JS `eval` vs an unrelated `engine.eval`).
    #[cfg_attr(feature = "serialize", serde(default))]
    pub global_only: bool,
    /// Store-base kinds this sink may fire on; empty = any. Non-empty: the
    /// receiver must come from one of these calls (or carry the name as its
    /// declared type), so a field name alone never arms a write sink.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub base_kinds: Vec<String>,
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
    /// Name of the sanitizing call.
    pub call: String,
    /// Optional package qualification (e.g. "pg", "validator").
    /// `None` indicates a universal sanitizer.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub package: Option<String>,
    /// Strength/style label (advisory; the engine cuts on every kind and
    /// branches on `guard_style`). One dialect across every producer:
    /// [`DEFAULT_SANITIZER_KIND`] / [`ALLOWLIST_SANITIZER_KIND`].
    pub kind: String,
    /// Slots whose taint is removed. Empty = all args (and a guard receiver).
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
    /// Advisory severity label from the shared six-label vocabulary
    /// ([`frensense_lang::severity::SEVERITY_LABELS`]); consumers map it onto
    /// the reporting ladder with
    /// [`frensense_lang::severity::Severity::parse_label`].
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
    NotCall {
        /// Call name or last segment that must be absent.
        call: String,
    },
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
    BannedArgLiteral {
        /// Zero-based argument slot to inspect.
        slot: usize,
        /// Literal values that are forbidden at that slot.
        values: Vec<String>,
    },
    /// The call's argument at `slot` MUST match one of `values`
    /// (case-insensitive comparison over string, boolean, or integer literals).
    RequiredArgLiteral {
        /// Zero-based argument slot to inspect.
        slot: usize,
        /// Literal values, one of which the argument must be.
        values: Vec<String>,
    },
    /// The call's argument at `slot` must trace to an object construction
    /// carrying at least one of `keys` as an object-literal pair key
    /// (`updateMany({ where: ... })`: the where clause scopes which rows
    /// the bulk write touches). `slot` indexes the call's argument list as
    /// the lowering records it (receiver excluded); `usize::MAX` matches
    /// ANY argument position. Traceability: fully-keyed object literals
    /// lower to `Allocate(kind: Object)` plus one `StoreField` per key,
    /// and the lowering records the pair keys on the composite var, so
    /// key presence is checkable in the IR without value analysis.
    RequireArgKey {
        /// Argument slot to inspect; `usize::MAX` matches any argument position.
        slot: usize,
        /// Object-literal keys, at least one of which must be present in the argument.
        keys: Vec<String>,
    },
    /// The **named** argument `name` must be present and, when its value is
    /// a provable literal, carry one of `values` (case-insensitive).
    ///
    /// Distinct from [`Self::RequiredArgLiteral`]: a keyword argument's
    /// position moves when the caller omits earlier optional parameters
    /// (`set_cookie("k", "v", path="/", secure=False)` puts `secure` at
    /// slot 3, not 2), so a slot rule cannot express it correctly. Names
    /// arrive from the lowering's `arg_names` (Python `keyword_argument`).
    ///
    /// Absent name = violation (the caller did not set the flag at all).
    /// Present with an unresolvable value (a variable, a call result) is
    /// **not** a violation: the check proves literal violations only.
    ///
    /// Appended last: bincode encodes the variant index first, so existing
    /// wire bytes keep decoding with their original indices.
    RequireNamedArgLiteral {
        /// Name of the keyword argument.
        name: String,
        /// Literal values the argument must carry (case-insensitive).
        values: Vec<String>,
    },
    /// When `name` is present as a named argument, its value must NOT match
    /// any of `values` (case-insensitive literal comparison).
    ///
    /// Distinct from [`Self::RequireNamedArgLiteral`]: absent name is NOT a
    /// violation (allows framework defaults / benign calls to omit the flag
    /// without false positives).
    BannedNamedArgLiteral {
        /// Name of the keyword argument.
        name: String,
        /// Literal values the argument must not carry (case-insensitive).
        values: Vec<String>,
    },
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
            | PolicyRequirement::RequiredArgLiteral { .. }
            | PolicyRequirement::RequireArgKey { .. }
            | PolicyRequirement::RequireNamedArgLiteral { .. }
            | PolicyRequirement::BannedNamedArgLiteral { .. } => Vec::new(),
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
    /// Advisory severity label from the shared vocabulary owned by
    /// `frensense-lang` ([`frensense_lang::severity::Severity`]); consumers
    /// map it onto the three-tier reporting ladder.
    pub severity: String,
    /// Optional package qualification: when `Some(pkg)`, the policy only
    /// fires in files that import `pkg` (mirrors the sink/source
    /// package-scoping model). `None` = fires globally.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub package: Option<String>,
}

impl PolicyFact {
    /// Convert a legacy [`LearnedCheckFact`] into the generalized form.
    /// `unless_guard` and `unless_range_check` become requirements; scope is
    /// always [`PolicyScope::Function`], matching the legacy semantics.
    pub(crate) fn from_legacy(f: &LearnedCheckFact) -> Self {
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
            package: None,
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
    /// Stable rule id reported on a match.
    pub rule_id: String,
    /// Call whose last segment triggers the rule.
    pub call: String,
    /// Argument slot holding the algorithm selector literal. When `None` the rule fires on any call to `call`, with no selector check.
    pub selector_slot: Option<usize>,
    /// Selector literals considered weak (compared case-insensitively against the argument at `selector_slot`).
    pub weak_selectors: Vec<String>,
    /// Advisory severity label from the shared vocabulary owned by
    /// `frensense-lang` ([`frensense_lang::severity::Severity`]); consumers
    /// map it onto the three-tier reporting ladder.
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
    /// Calls that perform a containment or allowlist check on a value.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub containment_callees: Vec<String>,
    /// Calls that store, set or hash a credential.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub credential_sinks: Vec<String>,
    /// Parameter names that identify a credential.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub credential_params: Vec<String>,
}

/// One corpus-verified tool/API schema policy fact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct SchemaPolicyFact {
    /// Schema-builder method names (for example a number or string constructor of a validation library).
    #[cfg_attr(feature = "serialize", serde(default))]
    pub builders: Vec<String>,
    /// Methods that enforce or finalise a schema.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub enforcers: Vec<String>,
    /// Schema keywords that bound a value (for example a minimum or maximum).
    #[cfg_attr(feature = "serialize", serde(default))]
    pub bound_keywords: Vec<String>,
}

/// Which hint table a `LearnedFactEntry::Hints` entry feeds. The hint
/// vocabularies are flat string sets keyed by purpose (Phase 6 format
/// extension): one entry kind, seven tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum HintKind {
    /// [`super::FactTable::url_param_hints`]: a function parameter is URL-like.
    UrlParam,
    /// [`super::FactTable::url_arg_hints`]: a guard argument is URL-ish.
    UrlArg,
    /// [`super::FactTable::url_literal_hints`]: a literal is an absolute URL.
    UrlLiteral,
    /// [`super::FactTable::security_context_hints`]: a name marks security code.
    SecurityContext,
    /// [`super::FactTable::auth_guard_hints`]: a call is an authentication check.
    AuthGuard,
    /// [`super::FactTable::jwt_algorithm_hints`]: an algorithm choice is
    /// security-sensitive.
    JwtAlgorithm,
    /// [`super::FactTable::credential_context_hints`]: an enclosing name marks
    /// credential context.
    CredentialContext,
    /// [`super::FactTable::kdf_receiver_hints`]: a receiver whose name marks a
    /// password-hashing library (a credential hashed through it is the
    /// intended use, not a policy violation). Appended last: bundles
    /// encode the variant position.
    KdfReceiver,
    /// [`super::FactTable::prepared_statement_prefixes`]: a call whose last segment
    /// starts with one of these prefixes creates a bound-parameter statement
    /// handle (`Prepare`, `prepareStatement`, `prepare_cached`), so the
    /// handle's later arguments are bindings rather than SQL. Appended last:
    /// bundles encode the variant position.
    PreparedStatementPrefix,
    /// [`super::FactTable::weak_hash_disclaimer_tokens`]: an argument token that
    /// disclaims security use of a weak digest - a literal `false` flag
    /// marking the digest as a checksum or cache key. Appended last: bundles
    /// encode the variant position.
    WeakHashDisclaimer,
}

impl HintKind {
    /// Every variant, in wire order. `.frc` bundles encode the variant
    /// *position*, so this list is the serialization contract: appending a
    /// variant changes
    /// [`fact_vocabulary_fingerprint`](super::fact_vocabulary_fingerprint)
    /// and therefore invalidates every bundle built before the change
    /// (rebuild the bundle, or keep the engine that built it).
    pub const ALL: [HintKind; 10] = [
        HintKind::UrlParam,
        HintKind::UrlArg,
        HintKind::UrlLiteral,
        HintKind::SecurityContext,
        HintKind::AuthGuard,
        HintKind::JwtAlgorithm,
        HintKind::CredentialContext,
        HintKind::KdfReceiver,
        HintKind::PreparedStatementPrefix,
        HintKind::WeakHashDisclaimer,
    ];

    /// Wire discriminant of this variant. Exhaustive on purpose: adding a
    /// variant is a compile error here, which is the reminder to append it
    /// to [`Self::ALL`] (the ratchet test fails until it is).
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            HintKind::UrlParam => 0,
            HintKind::UrlArg => 1,
            HintKind::UrlLiteral => 2,
            HintKind::SecurityContext => 3,
            HintKind::AuthGuard => 4,
            HintKind::JwtAlgorithm => 5,
            HintKind::CredentialContext => 6,
            HintKind::KdfReceiver => 7,
            HintKind::PreparedStatementPrefix => 8,
            HintKind::WeakHashDisclaimer => 9,
        }
    }

    /// Stable name used in the vocabulary fingerprint and in diagnostics.
    /// Renaming a variant is a wire change too: the fingerprint catches it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            HintKind::UrlParam => "url_param",
            HintKind::UrlArg => "url_arg",
            HintKind::UrlLiteral => "url_literal",
            HintKind::SecurityContext => "security_context",
            HintKind::AuthGuard => "auth_guard",
            HintKind::JwtAlgorithm => "jwt_algorithm",
            HintKind::CredentialContext => "credential_context",
            HintKind::KdfReceiver => "kdf_receiver",
            HintKind::PreparedStatementPrefix => "prepared_statement_prefix",
            HintKind::WeakHashDisclaimer => "weak_hash_disclaimer",
        }
    }
}

/// Syntactic grammar features that can be dynamically learned or configured via bundle facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum GrammarFeature {
    /// A type cast or type assertion node (`x as T`, `(T)x`).
    Cast,
    /// A template or interpolated string node.
    TemplateString,
    /// An untainted literal text fragment of a template string (it carries no interpolated value).
    TemplateFragment,
    /// A destructuring pattern (`{ a, b }`, `[x, y]`).
    DestructuringPattern,
    /// A key/value pair inside a destructuring pattern.
    PairPattern,
    /// A key/value pair inside an object literal.
    PairEntry,
    /// A ternary-style conditional (`ternary_expression`, `conditional_expression`) whose condition and arms are evaluated straight-line in the current block instead of forming a branch.
    TernaryStraightLine,
    /// A node kind that can be the left-hand side of an assignment written in declaration position (for example Python `subscript` and `attribute`: `m["k"] = v`, `obj.attr = v`), so the assignment lowers as a store to that member or element instead of a plain declaration.
    DeclarationAssignment,
    /// The node kind of the property child of a member access (for example Python `identifier`, Go `field_identifier`). A wrong answer turns method calls into pointer calls and loses sink matching.
    PropertyKind,
}

/// An owned, serializable representation of [`frensense_lang::NodeRole`] for bundle facts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum TeachableNodeRole {
    /// A function, method or closure definition. Mirrors [`frensense_lang::NodeRole::Function`].
    Function {
        /// Whether the grammar distinguishes methods from free functions.
        is_method: bool,
        /// Field holding the function's name, if any.
        name_field: Option<String>,
        /// Field holding the parameter list.
        params_field: String,
        /// Field holding the body.
        body_field: String,
    },
    /// A variable declaration with an initializer. Mirrors [`frensense_lang::NodeRole::Declaration`].
    Declaration {
        /// Field holding the declared name.
        name_field: String,
        /// Field holding the initializer.
        value_field: String,
    },
    /// A mutation of an existing binding. Mirrors [`frensense_lang::NodeRole::Assignment`].
    Assignment {
        /// Field holding the assignment target.
        lhs_field: String,
        /// Field holding the assigned value.
        rhs_field: String,
    },
    /// A function or method invocation. Mirrors [`frensense_lang::NodeRole::Call`].
    Call {
        /// Field holding the callee expression.
        callee_field: String,
        /// Field holding the argument list.
        args_field: String,
    },
    /// A member or field access that produces a value. Mirrors [`frensense_lang::NodeRole::MemberAccess`].
    MemberAccess {
        /// Field holding the object being accessed.
        object_field: String,
        /// Field holding the member name.
        property_field: String,
    },
    /// A branch: `if`, `switch` or a match arm.
    Branch,
    /// A ternary conditional expression whose arms are values.
    Conditional,
    /// A `for`, `while`, `do` or `loop` construct.
    Loop,
    /// A return statement or expression.
    Return,
    /// A `try` block.
    Try,
    /// A `catch` or `except` clause.
    Catch,
    /// A `finally` clause.
    Finally,
    /// A `throw` or `raise`.
    Throw,
    /// An error-propagation guard such as Go `if err != nil { return … }`.
    ErrorGuard,
    /// A context-manager entry such as Python `with expr as var:`.
    ContextManager,
    /// An error-propagating postfix operator such as Rust `?`.
    ErrorPropagation,
    /// An `await` expression or async block entry.
    Await,
    /// A braced or indented statement block.
    Block,
    /// A value-position composite literal (object or array).
    Composite,
    /// An import, `use` or `require`.
    Import,
    /// An export (JavaScript and TypeScript).
    Export,
    /// A bare name reference.
    Identifier,
    /// A string, number or boolean literal.
    Literal,
    /// A parameter list node.
    Parameters,
    /// An argument list node.
    Arguments,
    /// A named call argument: the name travels with the value so slot
    /// policies can key on the argument's identity, not its position.
    KeywordArgument {
        /// Field holding the argument name.
        name_field: String,
        /// Field holding the argument value.
        value_field: String,
    },
    /// A class or type definition.
    ClassDef,
    /// A binary operation.
    BinaryOp,
    /// A unary operation.
    UnaryOp,
    /// A pattern match: `match`, or a `switch` that matches on a type or value.
    Match,
    /// An `unsafe` block.
    Unsafe,
    /// An async block.
    AsyncBlock,
    /// A node kind with no specific role.
    Other,
}

impl TeachableNodeRole {
    /// Convert this owned teachable role into the engine's standard [`frensense_lang::NodeRole`].
    /// Bundle field names become `Cow::Owned` (allocated per fact, never
    /// leaked); spec-provided roles stay `Cow::Borrowed` upstream.
    pub(crate) fn to_node_role(&self) -> frensense_lang::NodeRole {
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
            TeachableNodeRole::KeywordArgument {
                name_field,
                value_field,
            } => frensense_lang::NodeRole::KeywordArgument {
                name_field: name_field.clone().into(),
                value_field: value_field.clone().into(),
            },
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
            frensense_lang::NodeRole::KeywordArgument {
                name_field,
                value_field,
            } => TeachableNodeRole::KeywordArgument {
                name_field: name_field.to_string(),
                value_field: value_field.to_string(),
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
    /// Advisory severity label from the shared vocabulary owned by
    /// `frensense-lang` ([`frensense_lang::severity::Severity`]); consumers
    /// map it onto the three-tier reporting ladder.
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
    /// The unbounded-product modality (opt-in, default off). Default rules
    /// keep the zero-FP property: both operand intervals must be provable
    /// and non-negative, and unknown operands skip the site. When the
    /// corpus teaches `unbounded_product`, a site whose multiplication has
    /// BOTH operands unboundedly dynamic (no provable interval on either
    /// side, no constant) is the plain `malloc(rows * cols)` CVE-190 shape
    /// and fires; mixed shapes like `strlen(s) * 2` stay silent, as do
    /// bounded operands.
    #[cfg_attr(feature = "serialize", serde(default))]
    pub unbounded_product: bool,
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
    /// Advisory severity label from the shared vocabulary owned by
    /// `frensense-lang` ([`frensense_lang::severity::Severity`]); consumers
    /// map it onto the three-tier reporting ladder.
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
    /// Advisory severity label from the shared vocabulary owned by
    /// `frensense-lang` ([`frensense_lang::severity::Severity`]); consumers
    /// map it onto the three-tier reporting ladder.
    pub severity: String,
    /// Advisory observation body.
    pub message: String,
}

impl WeakPrimitiveRule {
    /// Whether `other` names the same rule: same rule id and the same call
    /// coverage.
    ///
    /// Identity deliberately excludes severity, message, and
    /// `requires_credential_context`: those are the conclusion a later seed
    /// (a consumer bundle) may want to override. Two facts with the same
    /// identity replace each other; two with different calls are distinct
    /// rules and both fire.
    #[must_use]
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.rule_id == other.rule_id
            && self.selector_calls == other.selector_calls
            && self.bare_calls == other.bare_calls
    }
}

impl InsecureConfigRule {
    /// Whether `other` names the same rule: same rule id and callee prefix.
    /// Selectors, severity, and message are overridable conclusion fields.
    #[must_use]
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.rule_id == other.rule_id && self.prefix == other.prefix
    }
}

impl KeySizeRule {
    /// Whether `other` names the same rule: same rule id, call, and bit-length
    /// slot. Severity, message, and `kind` are overridable conclusion fields.
    #[must_use]
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.rule_id == other.rule_id && self.call == other.call && self.slot == other.slot
    }

    /// Replace this rule with a newer fact of the same identity, keeping the
    /// security floor monotone: a later seed may raise `min_bits`, never
    /// lower it.
    pub(crate) fn override_with(&mut self, newer: &Self) {
        let min_bits = self.min_bits.max(newer.min_bits);
        *self = newer.clone();
        self.min_bits = min_bits;
    }
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
