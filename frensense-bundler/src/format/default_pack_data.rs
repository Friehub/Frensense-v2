// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Bootstrap policy-cluster and memory-vocabulary data (Phase 6.1).
//!
//! The tables `frensense-lang` used to ship as `policy.rs` /
//! `memory.rs` bootstrap statics, moved here because the default pack is
//! now their only home: the generator reads them to emit
//! [`LearnedFactEntry`](frensense_engine::analysis::taint::facts::LearnedFactEntry)s,
//! the committed `.frc` asset carries them, and the spec-side `known_*`
//! seeds are gone from lang. Consumed only by [`super::default_pack`];
//! nothing in lang or the engine references these names anymore.

use frensense_engine::analysis::taint::facts::{
    AllocCapacity, BufferBuiltinSpec, InsecureConfigRule, IntegerOverflowRule, KeySizeRule,
    MemoryFuncSpec, WeakPrimitiveRule,
};

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

/// Shared advisory body for the bootstrap weak-hash rules (the `weak_hash`
/// observation template's text, static form).
const WEAK_HASH_MESSAGE: &str = "Weak hash primitive selected, not acceptable \
                                 for passwords or security-sensitive digests \
                                 (use bcrypt/argon2/scrypt or SHA-256+)";

/// The bootstrap weak-hash policy table: universal crypto policy facts
/// (Node `createHash`, Python `hashlib.new`, bare `md5`/`sha1`).
pub static BOOTSTRAP_WEAK_HASH_RULES: std::sync::LazyLock<Vec<WeakPrimitiveRule>> =
    std::sync::LazyLock::new(|| {
        vec![
            // Node crypto: createHash('md5'), createHash('sha1')
            WeakPrimitiveRule {
                rule_id: "weak_hash".to_string(),
                selector_calls: ["createHash"].iter().map(|s| s.to_string()).collect(),
                bare_calls: ["md5", "sha1"].iter().map(|s| s.to_string()).collect(),
                selector_slot: 0,
                weak_selectors: ["md5", "md4", "sha1", "sha"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                requires_credential_context: true,
                severity: "warning".to_string(),
                message: WEAK_HASH_MESSAGE.to_string(),
            },
            // Python hashlib / passlib: hashlib.new('md5', ...)
            WeakPrimitiveRule {
                rule_id: "weak_hash".to_string(),
                selector_calls: ["new"].iter().map(|s| s.to_string()).collect(),
                bare_calls: ["md5", "sha1"].iter().map(|s| s.to_string()).collect(),
                selector_slot: 0,
                weak_selectors: ["md5", "md4", "sha1", "sha"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                requires_credential_context: false,
                severity: "warning".to_string(),
                message: WEAK_HASH_MESSAGE.to_string(),
            },
        ]
    });

/// The bootstrap allocation-size overflow rules (LP64 `SIZE_MAX` threshold).
pub static BOOTSTRAP_INTEGER_OVERFLOW_RULES: std::sync::LazyLock<Vec<IntegerOverflowRule>> =
    std::sync::LazyLock::new(|| {
        vec![IntegerOverflowRule {
            rule_id: frensense_lang::rules::INTEGER_OVERFLOW_ALLOC.to_string(),
            wrap_threshold: 18_446_744_073_709_551_615,
            severity: "critical".to_string(),
            message: "Integer overflow in allocation size (CWE-190/CWE-680): \
                      the size multiplication can wrap past SIZE_MAX, so the \
                      allocation is undersized and the count-driven fill \
                      overflows the heap buffer"
                .to_string(),
        }]
    });

/// The bootstrap insecure-config table.
pub static BOOTSTRAP_INSECURE_CONFIG_SELECTORS: std::sync::LazyLock<Vec<InsecureConfigRule>> =
    std::sync::LazyLock::new(|| {
        vec![
            // jwt.sign(payload, secret, { algorithm: 'none' }) style appears as a
            // string selector on some APIs; `none`/`HS1` in the `alg` slot.
            InsecureConfigRule {
                prefix: "jwt".to_string(),
                selectors: ["none", "hs1"].iter().map(|s| s.to_string()).collect(),
                rule_id: "insecure_jwt_algorithm".to_string(),
                severity: "warning".to_string(),
                message: "Insecure configuration: an insecure JWT algorithm selector \
                          ('none'/'hs1') was accepted (use RS256/ES256)"
                    .to_string(),
            },
        ]
    });

/// The bootstrap key-size policy table.
pub static BOOTSTRAP_KEY_SIZE_RULES: std::sync::LazyLock<Vec<KeySizeRule>> =
    std::sync::LazyLock::new(|| {
        vec![
            KeySizeRule {
                rule_id: "weak_rsa_key_size".to_string(),
                call: "generateKeyPair".to_string(),
                slot: 0,
                min_bits: 2048,
                kind: "RSA".to_string(),
                severity: "warning".to_string(),
                message: "Key generation call with RSA key size below 2048 bits \
                          (use >= 2048 bits for RSA)"
                    .to_string(),
            },
            KeySizeRule {
                rule_id: "weak_rsa_key_size".to_string(),
                call: "generateKey".to_string(),
                slot: 0,
                min_bits: 128,
                kind: "symmetric keys".to_string(),
                severity: "warning".to_string(),
                message: "Key generation call with symmetric key size below 128 bits \
                          (use >= 128 bits for symmetric keys)"
                    .to_string(),
            },
        ]
    });

/// Known *wrapper* names whose entire purpose is hashing: a weak selector
/// inside the wrapper (checked cross-function by the corpus replay gate) or
/// a suspicious receiver qualification makes these worth flagging. Bare
/// wrappers like `security.hash(...)` are the Juice Shop weakPassword
/// shape: the wrapper resolves to `createHash('md5')` elsewhere in the
/// same file.
pub static BOOTSTRAP_SUSPICIOUS_HASH_WRAPPERS: &[&str] =
    &["hash", "hashpw", "hashPassword", "digest"];

const fn fresh(name: &'static str, capacity: AllocCapacity) -> MemoryFuncSpec {
    MemoryFuncSpec {
        name,
        returns_fresh: true,
        capacity,
        consumes_params: &[],
    }
}

const fn fresh_consuming(
    name: &'static str,
    capacity: AllocCapacity,
    consumes_params: &'static [usize],
) -> MemoryFuncSpec {
    MemoryFuncSpec {
        name,
        returns_fresh: true,
        capacity,
        consumes_params,
    }
}

const fn dealloc(name: &'static str) -> MemoryFuncSpec {
    MemoryFuncSpec {
        name,
        returns_fresh: false,
        capacity: AllocCapacity::Unknown,
        consumes_params: &[0],
    }
}

/// The bootstrap memory vocabulary: the C family plus the common bindings
/// (GLib, kernel, sqlite, OpenSSL, Apache, libxml, cJSON) that server
/// code links against. This is the default for every spec - providers
/// whose language has a different memory model (Go GC, JVM, JS) may
/// override with a narrower table.
pub static BOOTSTRAP_MEMORY_FUNCS: &[MemoryFuncSpec] = &[
    // Deallocators: consume parameter 0, return nothing fresh.
    dealloc("free"),
    dealloc("g_free"),
    dealloc("kfree"),
    dealloc("cJSON_Delete"),
    dealloc("apr_palloc"), // pool-allocated, ownership passes to the pool
    dealloc("CRYPTO_free"),
    dealloc("xmlFree"),
    dealloc("sqlite3_free"),
    // Sized allocators: capacity = argument 0.
    fresh("malloc", AllocCapacity::Param(0)),
    fresh("valloc", AllocCapacity::Param(0)),
    fresh("alloca", AllocCapacity::Param(0)),
    fresh("g_malloc", AllocCapacity::Param(0)),
    fresh("g_malloc0", AllocCapacity::Param(0)),
    fresh("kmalloc", AllocCapacity::Param(0)),
    fresh("kzalloc", AllocCapacity::Param(0)),
    fresh("sqlite3_malloc", AllocCapacity::Param(0)),
    // Count × size allocators.
    fresh("calloc", AllocCapacity::ParamProduct(0, 1)),
    fresh("sqlite3_malloc64", AllocCapacity::ParamProduct(0, 1)),
    fresh("kcalloc", AllocCapacity::ParamProduct(0, 1)),
    // Realloc-style: capacity = argument 1, consumes the old pointer.
    fresh_consuming("realloc", AllocCapacity::Param(1), &[0]),
    fresh_consuming("g_realloc", AllocCapacity::Param(1), &[0]),
    fresh_consuming("sqlite3_realloc", AllocCapacity::Param(1), &[0]),
    // Aligned allocator: capacity = argument 1 (size), arg 0 is alignment.
    fresh("aligned_alloc", AllocCapacity::Param(1)),
    // String duplicators: fresh, capacity unknown.
    fresh("strdup", AllocCapacity::Unknown),
    fresh("strndup", AllocCapacity::Unknown),
    fresh("g_strdup", AllocCapacity::Unknown),
];

/// Is `name` one of the pack's built-in memory contracts?
///
/// Used by the bundler to avoid re-emitting built-in contracts into a
/// `.frc` bundle (they already ship with the pack). Exact-name match.
pub fn is_pack_memory_builtin(name: &str) -> bool {
    BOOTSTRAP_MEMORY_FUNCS.iter().any(|m| m.name == name)
}

/// The bootstrap buffer vocabulary: C's copy/fill/read primitives.
///
/// Owned names (Phase 6): bundle-loaded builtins carry corpus text, so the
/// shared spec type may not be `&'static str`.
pub static BOOTSTRAP_BUFFER_BUILTINS: std::sync::LazyLock<Vec<BufferBuiltinSpec>> =
    std::sync::LazyLock::new(|| {
        fn bi(name: &str, dst: Option<usize>, src: Option<usize>, len: usize) -> BufferBuiltinSpec {
            BufferBuiltinSpec {
                name: name.to_string(),
                dst_arg: dst,
                src_arg: src,
                len_arg: len,
            }
        }
        vec![
            bi("memset", Some(0), None, 2),
            bi("bzero", Some(0), None, 1),
            bi("memcpy", Some(0), Some(1), 2),
            bi("memmove", Some(0), Some(1), 2),
            bi("strncpy", Some(0), None, 2),
            bi("snprintf", Some(0), None, 1),
            bi("fgets", Some(0), None, 1),
            bi("read", Some(1), None, 2),
        ]
    });
