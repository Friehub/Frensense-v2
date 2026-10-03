// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Policy vocabulary: guard/allowlist, credential, schema-bound, URL-hint
//! and weak-crypto tables consumed by the engine's non-taint checks.
//!
//! Language specs extend these via the corresponding `LanguageSpec` methods
//! (`known_containment_callees`, `known_weak_hash_rules`, ...); the engine
//! seeds them into `FactTable` and unions the bootstrap defaults at check
//! time, so no language-specific names live in `frensense-engine`.
//!
//! (Not to be confused with `frensense_engine::checks::policy`, the
//! co-occurrence policy evaluator over learned `PolicyFact`s.)

/// Containment-test callees (last segment): `includes` is the canonical JS
/// shape; `indexOf`/`contains` count when the result feeds a boolean guard.
pub static BOOTSTRAP_CONTAINMENT_CALLEES: &[&str] = &["includes", "indexOf", "contains"];

/// Credential-setting call names (last segment): functions whose argument
/// is a plaintext password by convention.
pub static BOOTSTRAP_CREDENTIAL_SINKS: &[&str] = &[
    "hash",
    "hashPassword",
    "hashpw",
    "setPassword",
    "set_password",
    "setSecret",
    "set_secret",
];

/// Credential parameter names (source_name of the arg var) that mark a
/// value as a plaintext credential.
pub static BOOTSTRAP_CREDENTIAL_PARAMS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "clearTextPassword",
    "clearPassword",
    "newPassword",
];

/// Schema number-builder methods (last segment) that produce an unbounded
/// numeric field when their builder chain lacks a `.max()`/`.min()` call.
pub static BOOTSTRAP_SCHEMA_BUILDERS: &[&str] = &["number", "int", "float", "bigint"];

/// Methods that would actually enforce a bound on the builder chain.
pub static BOOTSTRAP_SCHEMA_ENFORCERS: &[&str] = &[
    "max",
    "min",
    "minimum",
    "maximum",
    "int",
    "multipleOf",
    "step",
];

/// Bound keywords whose appearance in a description implies a declared
/// (but unenforced) numeric policy.
pub static BOOTSTRAP_SCHEMA_KEYWORDS: &[&str] =
    &["maximum", "max", "minimum", "min", "limit", "up to"];

/// Substring hints marking a *function parameter* as a URL/redirect target
/// (`url`, `toUrl`, `redirect`, ...).
pub static BOOTSTRAP_URL_PARAM_HINTS: &[&str] = &["url", "redirect"];

/// Substring hints marking an *argument* as URL-ish in a containment guard.
pub static BOOTSTRAP_URL_ARG_HINTS: &[&str] = &["url", "redirect", "allowed"];

/// Substring hints marking a string literal as an absolute URL
/// (`http...`, `scheme://...`).
pub static BOOTSTRAP_URL_LITERAL_HINTS: &[&str] = &["http", "://"];

/// Substring hints marking a function/module name as security-context code
/// (used by the opaque hash-wrapper heuristic).
pub static BOOTSTRAP_SECURITY_CONTEXT_HINTS: &[&str] = &["insecure", "security"];

/// Substring hints marking a call as an *authentication check* whose result
/// gates an early-return branch (`security.authenticatedUsers.from(req)` →
/// `if (!user) return`). Matched against the dotted call path
/// (`receiver chain + method` or static callee), lowercased substring.
pub static BOOTSTRAP_AUTH_GUARD_HINTS: &[&str] = &[
    "authenticate",
    "isauthorized",
    "isaccounting",
    "req.user",
    "currentuser",
    "loggedinuser",
    "requireauth",
    "checkauth",
    "ensureloggedin",
    "session.user",
];

/// Substring hints marking a callee whose *algorithm choice* is security-
/// sensitive (`jwt.verify(t, s, 'none')`, `jwtSign(p, s, alg)`): the
/// `insecure_jwt_algorithm` rule fires only on these operations - harness
/// wrappers that merely embed the literal (`jwtChallenge(...)`) are not
/// algorithm decisions. Matched against the full call path.
pub static BOOTSTRAP_JWT_ALGORITHM_HINTS: &[&str] =
    &["verify", "decode", "validate", "check", "parse", "sign"];

/// Substring hints marking an *enclosing function or parameter* as
/// credential context: a weak digest there is a password-KDF shape
/// (`hashPassword(clearTextPassword)`), while the same primitive in a
/// generic utility (`const digest = (data) => ...`) is not.
pub static BOOTSTRAP_CREDENTIAL_CONTEXT_HINTS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "credential",
    "token",
    "login",
    "signin",
    "passphrase",
    "privatekey",
    "kdf",
    "apikey",
];

/// A known call whose string-literal argument selects a weak primitive.
///
/// Matches the two shapes real code uses:
/// - `createHash('md5')`, the selector literal is argument 0.
/// - `md5(data)` / `MD5(...)`, bare weak-hash functions; no selector needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeakPrimitiveRule {
    /// Finding rule id.
    pub rule_id: &'static str,
    /// Callee last-segment names that take a selector literal argument.
    pub selector_calls: &'static [&'static str],
    /// Bare function names that are weak by themselves.
    pub bare_calls: &'static [&'static str],
    /// Argument slot of the selector literal (ignored for bare calls).
    pub selector_slot: usize,
    /// Selector literals that mark the call weak (case-insensitive, quotes
    /// stripped by the caller).
    pub weak_selectors: &'static [&'static str],
    /// When true, the selector shape fires only inside a credential context
    /// (function or parameter names hint password/secret/token/...).
    /// `crypto.createHash` doubles as a general-purpose checksum API, so
    /// JS-shaped selector rules stay qualified; explicit weak-algorithm
    /// selectors like `hashlib.new('md5')` fire unconditionally.
    pub requires_credential_context: bool,
}

/// The bootstrap weak-hash policy table: universal crypto policy facts
/// (Node `createHash`, Python `hashlib.new`, bare `md5`/`sha1`).
pub static BOOTSTRAP_WEAK_HASH_RULES: &[WeakPrimitiveRule] = &[
    // Node crypto: createHash('md5'), createHash('sha1')
    WeakPrimitiveRule {
        rule_id: "weak_hash",
        selector_calls: &["createHash"],
        bare_calls: &["md5", "sha1"],
        selector_slot: 0,
        weak_selectors: &["md5", "md4", "sha1", "sha"],
        requires_credential_context: true,
    },
    // Python hashlib / passlib: hashlib.new('md5', ...)
    WeakPrimitiveRule {
        rule_id: "weak_hash",
        selector_calls: &["new"],
        bare_calls: &["md5", "sha1"],
        selector_slot: 0,
        weak_selectors: &["md5", "md4", "sha1", "sha"],
        requires_credential_context: false,
    },
];

/// A corpus-extendable rule activating the allocation-size integer-overflow
/// prover (CWE-190 wrap -> CWE-680 undersized allocation -> heap overflow).
///
/// The engine owns the prover ("how to look": provable operand ranges whose
/// product can exceed the wrap threshold, flowing into an allocation's
/// capacity argument); this table owns the conclusion ("what to conclude":
/// which rule id fires, at which threshold, with which advisory). Lang
/// ships the bootstrap seed below; a corpus bundle extends the table via
/// `LearnedFactEntry::IntegerOverflowRule` from a family's `[frensense]`
/// `check-rule:` declaration, so new rules of this class never require an
/// engine or lang edit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntegerOverflowRule {
    /// Finding rule id.
    pub rule_id: String,
    /// Products exceeding this value cannot be represented as an allocation
    /// size on the target platform (`u64::MAX` == `SIZE_MAX` on LP64/LLP64).
    pub wrap_threshold: u128,
    /// Advisory severity hint: "critical" or "warning".
    pub severity: String,
    /// Corpus-authored advisory message (rendered with prover detail).
    pub message: String,
}

/// The bootstrap allocation-size overflow rules (LP64 `SIZE_MAX` threshold).
pub static BOOTSTRAP_INTEGER_OVERFLOW_RULES: std::sync::LazyLock<Vec<IntegerOverflowRule>> =
    std::sync::LazyLock::new(|| {
        vec![IntegerOverflowRule {
            rule_id: crate::rules::INTEGER_OVERFLOW_ALLOC.to_string(),
            wrap_threshold: 18_446_744_073_709_551_615,
            severity: "critical".to_string(),
            message: "Integer overflow in allocation size (CWE-190/CWE-680): \
                      the size multiplication can wrap past SIZE_MAX, so the \
                      allocation is undersized and the count-driven fill \
                      overflows the heap buffer"
                .to_string(),
        }]
    });

/// Known *string-literal* insecure configuration selectors: calls whose
/// argument literal itself selects an insecure mode regardless of
/// algorithm. Tuple: `(callee prefix, selector literals, rule id)`.
pub static BOOTSTRAP_INSECURE_CONFIG_SELECTORS: &[(&str, &[&str], &str)] = &[
    // jwt.sign(payload, secret, { algorithm: 'none' }) style appears as a
    // string selector on some APIs; `none`/`HS1` in the `alg` slot.
    ("jwt", &["none", "hs1"], "insecure_jwt_algorithm"),
];

/// A key-size rule: a generation call whose constant bit-length argument
/// falls below the security floor. Value-aware: the argument may be a var
/// whose lattice value is a provable constant, not just a bare literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeySizeRule {
    /// Finding rule id.
    pub rule_id: &'static str,
    /// Callee last segment (case-insensitive match).
    pub call: &'static str,
    /// Argument slot carrying the bit length.
    pub slot: usize,
    /// Minimum acceptable bits.
    pub min_bits: i64,
    /// Human label of what the key protects.
    pub kind: &'static str,
}

/// The bootstrap key-size policy table.
pub static BOOTSTRAP_KEY_SIZE_RULES: &[KeySizeRule] = &[
    KeySizeRule {
        rule_id: "weak_rsa_key_size",
        call: "generateKeyPair",
        slot: 0,
        min_bits: 2048,
        kind: "RSA",
    },
    KeySizeRule {
        rule_id: "weak_rsa_key_size",
        call: "generateKey",
        slot: 0,
        min_bits: 128,
        kind: "symmetric keys",
    },
];

/// Known *wrapper* names whose entire purpose is hashing: a weak selector
/// inside the wrapper (checked cross-function by the corpus replay gate) or
/// a suspicious receiver qualification makes these worth flagging. Bare
/// wrappers like `security.hash(...)` are the Juice Shop weakPassword
/// shape: the wrapper resolves to `createHash('md5')` elsewhere in the
/// same file.
pub static BOOTSTRAP_SUSPICIOUS_HASH_WRAPPERS: &[&str] =
    &["hash", "hashpw", "hashPassword", "digest"];

/// The default containment-test callees (see [`BOOTSTRAP_CONTAINMENT_CALLEES`]).
pub fn bootstrap_containment_callees() -> &'static [&'static str] {
    BOOTSTRAP_CONTAINMENT_CALLEES
}

/// The default credential sinks (see [`BOOTSTRAP_CREDENTIAL_SINKS`]).
pub fn bootstrap_credential_sinks() -> &'static [&'static str] {
    BOOTSTRAP_CREDENTIAL_SINKS
}

/// The default credential parameter names (see [`BOOTSTRAP_CREDENTIAL_PARAMS`]).
pub fn bootstrap_credential_params() -> &'static [&'static str] {
    BOOTSTRAP_CREDENTIAL_PARAMS
}

/// The default schema builders (see [`BOOTSTRAP_SCHEMA_BUILDERS`]).
pub fn bootstrap_schema_builders() -> &'static [&'static str] {
    BOOTSTRAP_SCHEMA_BUILDERS
}

/// The default schema enforcers (see [`BOOTSTRAP_SCHEMA_ENFORCERS`]).
pub fn bootstrap_schema_enforcers() -> &'static [&'static str] {
    BOOTSTRAP_SCHEMA_ENFORCERS
}

/// The default schema bound keywords (see [`BOOTSTRAP_SCHEMA_KEYWORDS`]).
pub fn bootstrap_schema_keywords() -> &'static [&'static str] {
    BOOTSTRAP_SCHEMA_KEYWORDS
}

/// The default URL parameter hints (see [`BOOTSTRAP_URL_PARAM_HINTS`]).
pub fn bootstrap_url_param_hints() -> &'static [&'static str] {
    BOOTSTRAP_URL_PARAM_HINTS
}

/// The default URL argument hints (see [`BOOTSTRAP_URL_ARG_HINTS`]).
pub fn bootstrap_url_arg_hints() -> &'static [&'static str] {
    BOOTSTRAP_URL_ARG_HINTS
}

/// The default URL literal hints (see [`BOOTSTRAP_URL_LITERAL_HINTS`]).
pub fn bootstrap_url_literal_hints() -> &'static [&'static str] {
    BOOTSTRAP_URL_LITERAL_HINTS
}

/// The default security-context hints (see [`BOOTSTRAP_SECURITY_CONTEXT_HINTS`]).
pub fn bootstrap_security_context_hints() -> &'static [&'static str] {
    BOOTSTRAP_SECURITY_CONTEXT_HINTS
}

/// The default auth-guard hints (see [`BOOTSTRAP_AUTH_GUARD_HINTS`]).
pub fn bootstrap_auth_guard_hints() -> &'static [&'static str] {
    BOOTSTRAP_AUTH_GUARD_HINTS
}

/// The default JWT algorithm-operation hints (see [`BOOTSTRAP_JWT_ALGORITHM_HINTS`]).
pub fn bootstrap_jwt_algorithm_hints() -> &'static [&'static str] {
    BOOTSTRAP_JWT_ALGORITHM_HINTS
}

/// The default credential-context hints (see [`BOOTSTRAP_CREDENTIAL_CONTEXT_HINTS`]).
pub fn bootstrap_credential_context_hints() -> &'static [&'static str] {
    BOOTSTRAP_CREDENTIAL_CONTEXT_HINTS
}

/// The default weak-hash rules (see [`BOOTSTRAP_WEAK_HASH_RULES`]).
pub fn bootstrap_weak_hash_rules() -> &'static [WeakPrimitiveRule] {
    BOOTSTRAP_WEAK_HASH_RULES
}

/// The default allocation-size overflow rules (see
/// [`BOOTSTRAP_INTEGER_OVERFLOW_RULES`]).
pub fn bootstrap_integer_overflow_rules() -> &'static [IntegerOverflowRule] {
    &BOOTSTRAP_INTEGER_OVERFLOW_RULES
}

/// The default insecure config selectors (see [`BOOTSTRAP_INSECURE_CONFIG_SELECTORS`]).
pub fn bootstrap_insecure_config_selectors(
) -> &'static [(&'static str, &'static [&'static str], &'static str)] {
    BOOTSTRAP_INSECURE_CONFIG_SELECTORS
}

/// The default key-size rules (see [`BOOTSTRAP_KEY_SIZE_RULES`]).
pub fn bootstrap_key_size_rules() -> &'static [KeySizeRule] {
    BOOTSTRAP_KEY_SIZE_RULES
}

/// The default suspicious hash wrappers (see [`BOOTSTRAP_SUSPICIOUS_HASH_WRAPPERS`]).
pub fn bootstrap_suspicious_hash_wrappers() -> &'static [&'static str] {
    BOOTSTRAP_SUSPICIOUS_HASH_WRAPPERS
}
