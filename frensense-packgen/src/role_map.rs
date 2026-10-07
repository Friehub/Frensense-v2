// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Vocabulary types and pack-byte derivations, re-homed from
//! `frensense-lang` in Phase 6.3d (lang is mechanism-only from here on).
//!
//! - [`SinkLabel`] / [`SanitizerKind`] / [`PropagatorRule`] - the provider
//!   vocabulary *types* the per-language tables in [`crate::vocab`] use.
//!   Nothing in the engine or lang needs them: engine facts store roles
//!   and guard styles as precomputed strings/bools on the wire.
//! - [`sink_role_for_label`] - the label→role mapping (moved verbatim from
//!   `frensense_lang::severity::SinkRole::from_label`; the role type, the
//!   role→tier ladder and the reporting tag stay in lang per D4).
//! - [`is_predicate_guard`] - the sanitizer guard-style heuristic (moved
//!   verbatim from the `LanguageSpec::is_predicate_guard` trait default;
//!   no provider ever overrode it).

use frensense_lang::severity::SinkRole;

/// Standard classification labels for sink functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SinkLabel {
    CodeExecution,
    SqlInjection,
    NoSqlInjection,
    CommandInjection,
    PathTraversal,
    Ssrf,
    OpenRedirect,
    Xss,
    XssDom,
    XssReflected,
    HeaderInjection,
    CookiePoisoning,
    ContentTypeInjection,
    StorageWrite,
    LogLeak,
    ResponseLeak,
    CredentialLeak,
    TemplateSsti,
    UnsafeDeserialize,
    LdapInjection,
    XpathInjection,
    PrototypePollution,
    Toctou,
    GraphqlInjection,
    Xxe,
    Jwt,
    JwtWeakAlgorithm,
    JwtUnsafeDecode,
    UnsafeMemory,
    BufferOverflow,
    FormatString,
    Regex,
    Unknown,
}

impl SinkLabel {
    #[must_use]
    pub fn slug(&self) -> &'static str {
        match self {
            Self::PrototypePollution => "prototype",
            Self::Ssrf => "ssrf",
            Self::Regex => "regex",
            Self::OpenRedirect => "redirect",
            Self::SqlInjection => "sql",
            Self::NoSqlInjection => "nosql",
            Self::CommandInjection => "command",
            Self::CodeExecution => "execution",
            Self::PathTraversal => "traversal",
            Self::Xss | Self::XssDom | Self::XssReflected => "xss",
            Self::TemplateSsti => "template",
            Self::UnsafeDeserialize => "deserialize",
            Self::LdapInjection => "ldap",
            Self::XpathInjection => "xpath",
            Self::GraphqlInjection => "graphql",
            Self::Xxe => "xxe",
            Self::StorageWrite => "storage",
            Self::LogLeak => "log_leak",
            Self::ResponseLeak => "response",
            Self::CredentialLeak => "credential_leak",
            Self::HeaderInjection => "header_injection",
            Self::CookiePoisoning => "cookie_poisoning",
            Self::ContentTypeInjection => "content_type",
            Self::Toctou => "toctou",
            Self::Jwt | Self::JwtWeakAlgorithm | Self::JwtUnsafeDecode => "jwt",
            Self::UnsafeMemory | Self::BufferOverflow => "buffer_overflow",
            Self::FormatString => "format_string",
            Self::Unknown => "other",
        }
    }
}

/// Sanitizer strength: what kind of injection does this call defeat?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SanitizerKind {
    /// Completely removes taint (e.g. numeric coercion: `int(user_input)`).
    Full,
    /// Defeats HTML/XSS injection only.
    HtmlEscape,
    /// Defeats URL-based attacks only.
    UrlEncode,
    /// Parameterised query - defeats SQL injection only.
    SqlParameterize,
    /// NoSQL sanitization - defeats NoSQL injection only.
    NoSqlParameterize,
    /// Session-store accessor trust: `store.get(token)` returns a
    /// server-issued session object (undefined for unknown tokens), so
    /// identity fields read off the result are not attacker-controlled.
    /// Receiver-aware: only applies when the receiver root is a declared
    /// session store.
    SessionTrust,
    /// Path canonicalization - defeats path traversal only.
    PathNormalize,
}

/// A propagator rule describes how taint flows through a specific call.
///
/// Example: `fmt.Sprintf` in Go - the format string is not tainted, but
/// if *any argument* is tainted the return value is tainted.
#[derive(Debug, Clone)]
pub struct PropagatorRule {
    /// Short call name or method name, e.g. `"Sprintf"`, `"format"`, `"join"`.
    /// Matched against the last segment of a member chain.
    pub call: &'static str,
    /// Argument index that carries taint into the return (0-based).
    /// `None` means *no* argument taints the return: only the receiver can
    /// (per `tainted_receiver`). Arguments of such calls are typically the
    /// changed data (replacement strings, match patterns, indices); letting
    /// them inherit taint would re-flag outputs that only replaced the
    /// tainted content - the zero-FP contract wins over recall here.
    pub tainted_arg: Option<usize>,
    /// If `true`, a tainted receiver taints the return value.
    pub tainted_receiver: bool,
}

/// Map a vocabulary label to a severity role. Labels not listed here keep
/// `Other` (conservative: treated as execution by the consumer). Moved
/// verbatim from `frensense_lang::severity::SinkRole::from_label`.
#[must_use]
pub fn sink_role_for_label(label: SinkLabel) -> SinkRole {
    use SinkLabel as L;
    match label {
        L::SqlInjection
        | L::NoSqlInjection
        | L::CommandInjection
        | L::CodeExecution
        | L::TemplateSsti
        | L::UnsafeDeserialize
        | L::LdapInjection
        | L::XpathInjection
        | L::GraphqlInjection
        | L::Xxe
        | L::PrototypePollution
        | L::Regex
        | L::FormatString => SinkRole::Execution,

        L::Ssrf | L::OpenRedirect | L::PathTraversal | L::Toctou => SinkRole::Resource,

        L::StorageWrite => SinkRole::Storage,

        L::Jwt => SinkRole::Crypto,

        L::Xss | L::XssDom | L::XssReflected => SinkRole::Xss,

        L::ResponseLeak | L::HeaderInjection | L::CookiePoisoning | L::ContentTypeInjection => {
            SinkRole::Response
        }

        L::JwtUnsafeDecode => SinkRole::Validation,

        L::LogLeak | L::CredentialLeak => SinkRole::Response,

        L::JwtWeakAlgorithm | L::UnsafeMemory | L::BufferOverflow | L::Unknown => SinkRole::Other,
    }
}

/// Is this sanitizer a *predicate guard* - a boolean check consumed by a
/// branch (`if (isSafe(x)) return;`) rather than a value transforming
/// call? Guards gate paths; transforms rewrite values.
///
/// Moved verbatim from the `LanguageSpec::is_predicate_guard` trait
/// default: full sanitizers plus JS-style predicate naming (`test`,
/// `isValid`, `is*`). No provider ever overrode it.
#[must_use]
pub fn is_predicate_guard(name: &str, kind: Option<&SanitizerKind>) -> bool {
    kind.is_some_and(|k| matches!(k, SanitizerKind::Full))
        || name == "test"
        || name == "isValid"
        || name.starts_with("is")
}
