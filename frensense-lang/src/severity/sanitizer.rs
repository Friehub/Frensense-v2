// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Sanitizer strength: what kind of injection a sanitizing call defeats.
//!
//! One responsibility, split out of `severity.rs` for the file-size
//! ratchet. The slug is the wire form carried on fact tables and bundles.

use super::{resolved_sink_class, sink_class, SinkRole};
use serde::{Deserialize, Serialize};

/// Sanitizer strength: what kind of injection does this call defeat?
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Shell quoting - defeats command injection only. `shlex.quote` makes a
    /// value one literal shell word; it says nothing about SQL, HTML, NoSQL
    /// or paths, so it must never be a [`Self::Full`] cut.
    ShellQuote,
    /// Session-store accessor trust: `store.get(token)` returns a
    /// server-issued session object (undefined for unknown tokens), so
    /// identity fields read off the result are not attacker-controlled.
    /// Receiver-aware: only applies when the receiver root is a declared
    /// session store.
    SessionTrust,
    /// Path canonicalization - defeats path traversal only.
    PathNormalize,
}

impl SanitizerKind {
    /// The serialized slug stored on a sanitizer fact.
    #[must_use]
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::HtmlEscape => "html_escape",
            Self::UrlEncode => "url_encode",
            Self::SqlParameterize => "sql_parameterize",
            Self::NoSqlParameterize => "nosql_parameterize",
            Self::ShellQuote => "shell_quote",
            Self::SessionTrust => "session_trust",
            Self::PathNormalize => "path_normalize",
        }
    }

    /// Parse a fact/bundle slug back into a kind.
    ///
    /// Accepts the legacy aliases (`encode`, `allowlist`, `generic`) as
    /// [`SanitizerKind::Full`] and returns `None` for anything unknown, which
    /// the role-qualified evaluator treats as "no cut".
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "full" => Some(Self::Full),
            // Legacy dialect aliases: `DEFAULT_SANITIZER_KIND` ("encode")
            // and `ALLOWLIST_SANITIZER_KIND` ("allowlist") are the labels
            // `FactTable::from_config` and bundle-learned sanitizers emit.
            // Map them to Full so role-qualified evaluation sees a known
            // kind instead of falling through to the sink-agnostic path.
            "encode" | "allowlist" | "generic" => Some(Self::Full),
            // Anything else is a genuinely unknown slug. The role-
            // qualified evaluator (`is_sanitizer_effective_for_role`)
            // treats `None` as "no cut": an unrecognized label must
            // never silence a sink it was never proven to defeat
            // (residual #15). Producers that need an opaque full cut
            // must emit one of the aliases above.
            "html_escape" => Some(Self::HtmlEscape),
            "url_encode" => Some(Self::UrlEncode),
            "sql_parameterize" => Some(Self::SqlParameterize),
            "nosql_parameterize" => Some(Self::NoSqlParameterize),
            "shell_quote" | "shell" => Some(Self::ShellQuote),
            "session_trust" => Some(Self::SessionTrust),
            "path_normalize" => Some(Self::PathNormalize),
            _ => None,
        }
    }

    /// Does this sanitizer defeat a sink of `classes`?
    ///
    /// An empty scope is the legacy universal fact (built-in table and
    /// pre-v8 bundles): it keeps the old role/label qualification. A
    /// non-empty scope is authoritative: the sink's class must be listed
    /// (or the list must carry `*`), so an `isURL` sanitizer proven for SSRF
    /// can never clear a command-injection sink.
    #[must_use]
    pub fn defeats_classes(&self, role: SinkRole, label: Option<&str>, classes: &[String]) -> bool {
        if classes.is_empty() {
            return self.defeats_role_and_label(role, label);
        }
        if !self.defeats_role_and_label(role, label) {
            return false;
        }
        if classes.iter().any(|c| c == "*") {
            return true;
        }
        match sink_class(role, label) {
            Some(class) => classes.iter().any(|c| c == class),
            None => false,
        }
    }

    /// [`Self::defeats_classes`] with a fallback to the class implied by the
    /// sink's call name. Config-declared sinks carry no vocabulary label, so
    /// without this a class-scoped fact could never clear them.
    #[must_use]
    pub fn defeats_sink(
        &self,
        role: SinkRole,
        label: Option<&str>,
        sink_name: Option<&str>,
        classes: &[String],
    ) -> bool {
        if classes.is_empty() {
            return self.defeats_role_and_label(role, label);
        }
        if !self.defeats_role_and_label(role, label) {
            return false;
        }
        if classes.iter().any(|c| c == "*") {
            return true;
        }
        resolved_sink_class(role, label, sink_name)
            .is_some_and(|class| classes.iter().any(|c| c == class))
    }

    /// Determines whether this sanitizer defeats a sink with the specified role and optional label.
    #[must_use]
    pub fn defeats_role_and_label(&self, role: SinkRole, label: Option<&str>) -> bool {
        match self {
            Self::Full => true,
            Self::HtmlEscape => {
                matches!(role, SinkRole::Xss | SinkRole::Response)
            }
            Self::UrlEncode => {
                matches!(role, SinkRole::Response | SinkRole::Resource)
            }
            Self::SqlParameterize => label == Some("sql"),
            Self::NoSqlParameterize => label == Some("nosql"),
            Self::ShellQuote => label == Some("command") || label == Some("shell"),
            Self::SessionTrust => true,
            Self::PathNormalize => matches!(role, SinkRole::Resource) || label == Some("traversal"),
        }
    }
}

#[cfg(test)]
mod sanitizer_kind_tests {
    use super::SanitizerKind;
    use crate::severity::SinkRole;

    /// `shlex.quote` makes a value one literal shell word. It must clear a
    /// command sink and nothing else: classifying it `Full` let it silence
    /// SQL, HTML and path findings it never sanitized.
    #[test]
    fn shell_quote_defeats_command_sinks_only() {
        let kind = SanitizerKind::ShellQuote;
        assert!(kind.defeats_sink(SinkRole::Execution, Some("command"), Some("system"), &[]));
        assert!(!kind.defeats_sink(SinkRole::Execution, Some("sql"), Some("execute"), &[]));
        assert!(!kind.defeats_sink(SinkRole::Xss, None, Some("render"), &[]));
        assert!(!kind.defeats_sink(SinkRole::Resource, Some("traversal"), None, &[]));
        // Class scope cannot widen it either.
        assert!(!kind.defeats_sink(SinkRole::Execution, Some("sql"), None, &["*".into()]));
    }

    #[test]
    fn shell_quote_slug_round_trips() {
        assert_eq!(SanitizerKind::ShellQuote.slug(), "shell_quote");
        assert_eq!(
            SanitizerKind::from_slug("shell_quote"),
            Some(SanitizerKind::ShellQuote)
        );
        // Bundles that predate the split read the legacy spellings.
        assert_eq!(
            SanitizerKind::from_slug("shell"),
            Some(SanitizerKind::ShellQuote)
        );
    }
}
