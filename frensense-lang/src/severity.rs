// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Severity declarations, the tier ladder, and advisory registries.
//!
//! Everything report-shaped lives here, not in the engine or the app:
//!
//! - [`Severity`] - the ranking type used by every reporter surface.
//! - [`SinkRole`] - what a sink does with the data it receives, plus the
//!   default role->tier map ([`SinkRole::default_level`]) and the stable
//!   reporting tag ([`SinkRole::tag`]). The engine re-exports the type and
//!   emits it on findings; it holds zero tier strings (D4).
//! - [`RuleAdvisory`] / [`RuleEntry`] - per-language rule registries
//!   (`LanguageSpec::known_rule_registry`): each language declares the
//!   severity and message templates for the rules it owns.
//! - [`generic_rule_advisory`] - the cross-cutting fallback for any rule no
//!   language declares (preserves the historical "Policy violation" shape).
//! - [`taint_advisory`] - the cross-cutting class x role ranking for dataflow
//!   findings.

use serde::{Deserialize, Serialize};

use crate::spec::SinkLabel;

/// Advisory severity ranking.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

impl Severity {
    #[must_use]
    pub fn meets_threshold(&self, threshold: Severity) -> bool {
        match (self, threshold) {
            (Severity::Critical, _)
            | (Severity::Info, Severity::Info)
            | (Severity::Warning, Severity::Warning | Severity::Info) => true,
            (Severity::Warning, Severity::Critical) | (Severity::Info, _) => false,
        }
    }

    /// Parse a level name; unknown names rank as [`Severity::Info`].
    pub fn parse(level: &str) -> Severity {
        match level {
            "critical" => Severity::Critical,
            "warning" => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

/// What the sink does with the value flowing into it.
///
/// Two sinks that both "receive tainted data" are not equally dangerous:
/// `eval(userInput)` executes it, `db.query({ where: { id } })` controls
/// row selection, and `res.json(userInput)` merely reflects it back, the
/// last is normally not a bug at all unless the client renders it
/// unescaped. Classifying by role lets consumers rank findings by what
/// the sink does instead of treating every flow as Critical.
///
/// Roles are derived from this crate's per-sink [`SinkLabel`]s (single
/// source of truth, no parallel table) and ride on the engine's sink
/// signatures so both taint engines see them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkRole {
    /// Data is interpreted as code: eval, exec, deserialize, template
    /// engines, SQL/NoSQL/LDAP strings. Highest severity.
    Execution,
    /// Data selects or reads a resource (IDOR-class query payloads, path
    /// traversal). Access-control concern, ranked below execution.
    Resource,
    /// Data is written to persistent storage (KV put, file write).
    Storage,
    /// Data goes into a cryptographic operation (sign, cipher, hash).
    Crypto,
    /// Data is reflected into an HTTP response. Usually not a bug by
    /// itself, review-level, the client-side rendering decides.
    Response,
    /// Cross-site scripting (DOM, Reflected, Stored). Client-side code
    /// execution in the browser context.
    Xss,
    /// Data enters a validation/verification routine (jwt.verify,
    /// `.test()`, comparators). Consuming tainted data is these APIs'
    /// *job*; a finding here is almost always noise.
    Validation,
    /// Unknown or unlabeled sink, keep the conservative default.
    #[default]
    Other,
}

impl SinkRole {
    /// Map a language-spec label to a role. Labels not listed here keep
    /// `Other` (conservative: treated as execution by the consumer).
    #[must_use]
    pub fn from_label(label: SinkLabel) -> Self {
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

            L::JwtWeakAlgorithm | L::UnsafeMemory | L::BufferOverflow | L::Unknown => {
                SinkRole::Other
            }
        }
    }

    /// The default tier for this role: the ladder lives here (D4), not in
    /// the engine. Consumers map it onto their own reporting policy.
    #[must_use]
    pub fn default_level(&self) -> Severity {
        match self {
            SinkRole::Execution | SinkRole::Other => Severity::Critical,
            SinkRole::Resource | SinkRole::Storage | SinkRole::Crypto | SinkRole::Xss => {
                Severity::Warning
            }
            SinkRole::Response | SinkRole::Validation => Severity::Info,
        }
    }

    /// Stable tag for reporting (SARIF properties, CLI JSON).
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            SinkRole::Execution => "execution",
            SinkRole::Resource => "resource",
            SinkRole::Storage => "storage",
            SinkRole::Crypto => "crypto",
            SinkRole::Response => "response",
            SinkRole::Validation => "validation",
            SinkRole::Xss => "xss",
            SinkRole::Other => "other",
        }
    }
}

/// Shape classification of a dataflow finding (mirrors the engine's
/// `FindingClass`, which cannot be referenced from this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintClass {
    /// Taint reaches a raw injection channel (SQL string, exec, redirect...).
    Injection,
    /// Taint controls a field of an identity-payload query object, an
    /// access-control concern.
    Idor,
}

/// Advisory metadata for one declared rule: a level plus message templates.
///
/// Templates use the placeholders `{rule}`, `{function}`, `{file}` and
/// `{line}`, substituted by [`RuleAdvisory::render`].
#[derive(Debug)]
pub struct RuleAdvisory {
    pub level: Severity,
    pub title: &'static str,
    pub impact: &'static str,
    pub improvement: &'static str,
    pub tag: &'static str,
}

impl RuleAdvisory {
    /// Substitute placeholders and return the rendered advisory parts.
    pub fn render(
        &self,
        rule: &str,
        function: &str,
        file: &str,
        line: u32,
    ) -> (Severity, String, String, String, &'static str) {
        let render = |template: &str| {
            template
                .replace("{rule}", rule)
                .replace("{function}", function)
                .replace("{file}", file)
                .replace("{line}", &line.to_string())
        };
        (
            self.level,
            render(self.title),
            render(self.impact),
            render(self.improvement),
            self.tag,
        )
    }
}

/// One rule id bound to its declared advisory metadata.
#[derive(Debug)]
pub struct RuleEntry {
    pub rule: &'static str,
    pub advisory: RuleAdvisory,
}

/// The cross-cutting fallback for a checker rule no language declares:
/// ranked Warning under the generic "Policy violation" shape.
pub fn generic_rule_advisory(
    rule: &str,
    function: &str,
    file: &str,
    line: u32,
) -> (Severity, String, String, String, &'static str) {
    (
        Severity::Warning,
        format!("Policy violation: {rule} ({function})"),
        format!("{rule} at {file}:{line}, insecure cryptographic/configuration choice."),
        format!(
            "Replace the weak primitive in `{function}` with a modern alternative \
             (bcrypt/argon2 for passwords, SHA-256+ for digests)."
        ),
        "policy",
    )
}

/// Substitute the standard placeholders plus every `{key}` param placeholder
/// in an observation template.
fn render_observation(
    template: &str,
    rule: &str,
    function: &str,
    file: &str,
    line: u32,
    params: &[(&'static str, String)],
) -> String {
    let mut out = template
        .replace("{rule}", rule)
        .replace("{function}", function)
        .replace("{file}", file)
        .replace("{line}", &line.to_string());
    for (key, value) in params {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}

/// Observation templates for the cross-cutting crypto-policy rules no
/// language registry owns. Returns `None` for rule ids these templates do
/// not cover (learned bundle rule ids fall through to the generic shape).
fn builtin_observation(rule: &str, params: &[(&'static str, String)]) -> Option<&'static str> {
    let has = |key: &str| params.iter().any(|(k, _)| *k == key);
    Some(match rule {
        "weak_hash" if has("sel") => {
            "Weak hash primitive '{sel}' selected by `{callee}`, not acceptable \
             for passwords or security-sensitive digests (use bcrypt/argon2/scrypt \
             or SHA-256+)"
        }
        "weak_hash" => {
            "Weak hash function `{callee}`, not acceptable for passwords or \
             security-sensitive digests (use bcrypt/argon2/scrypt or SHA-256+)"
        }
        crate::rules::WEAK_HASH_WRAPPER => {
            "Password hashing routed through opaque wrapper `{path}`, verify it \
             uses bcrypt/argon2/scrypt, not MD5/SHA-1"
        }
        "weak_rsa_key_size" => {
            "Weak key size passed to `{callee}`: provably below {min_bits} bits \
             (use >= {min_bits} bits for {kind})"
        }
        "insecure_jwt_algorithm" => {
            "Insecure configuration: `{callee}` called with insecure selector '{sel}'"
        }
        _ => return None,
    })
}

/// Fallback observation for a checker rule no template covers: the rule id,
/// the location, and the finding's structured params, so learned bundle
/// rule ids still render an informative body.
pub fn generic_rule_observation(
    rule: &str,
    function: &str,
    file: &str,
    line: u32,
    params: &[(&'static str, String)],
) -> String {
    let mut out = format!("{rule} violated in `{function}` at {file}:{line}");
    if !params.is_empty() {
        let kv: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        out.push_str(&format!(" ({})", kv.join(", ")));
    }
    out.push('.');
    out
}

/// Resolve advisory metadata for a checker finding: the language registry
/// first ([`crate::spec::LanguageSpec::known_rule_registry`]), the generic
/// policy fallback otherwise. The observation body renders from the
/// cross-cutting builtin templates (`builtin_observation`) keyed by rule
/// id and the finding's structured `params`, falling back to
/// [`generic_rule_observation`].
pub fn checker_advisory(
    spec: Option<&dyn crate::spec::LanguageSpec>,
    rule: &str,
    function: &str,
    file: &str,
    line: u32,
    params: &[(&'static str, String)],
) -> (Severity, String, String, String, &'static str, String) {
    let (level, title, impact, improvement, tag) = if let Some(spec) = spec {
        if let Some(entry) = spec.known_rule_registry().iter().find(|e| e.rule == rule) {
            entry.advisory.render(rule, function, file, line)
        } else {
            generic_rule_advisory(rule, function, file, line)
        }
    } else {
        generic_rule_advisory(rule, function, file, line)
    };
    let observation = match builtin_observation(rule, params) {
        Some(template) => render_observation(template, rule, function, file, line, params),
        None => generic_rule_observation(rule, function, file, line, params),
    };
    (level, title, impact, improvement, tag, observation)
}

/// Cross-cutting ranking for dataflow findings: what the sink does with the
/// data (role level) decides the default level; the shape class (Idor) can
/// only lower it further.
pub fn taint_advisory(
    class: TaintClass,
    role_level: Severity,
    role_tag: &str,
    sink: &str,
    src: &str,
) -> (Severity, String) {
    match (class, role_level) {
        // Access-control query payloads: ranked by role, retitled.
        (TaintClass::Idor, Severity::Critical) => (
            Severity::Warning,
            format!("User-controlled query field in `{sink}` (access-control review)"),
        ),
        // Response/validation sinks: review-level regardless of shape.
        (_, Severity::Info) => {
            let class_desc = match class {
                TaintClass::Idor => "as a query field",
                TaintClass::Injection => "as a value",
            };
            (
                Severity::Info,
                format!("User data reaches `{sink}` {class_desc} (review: role={role_tag})"),
            )
        }
        (_, level) => (
            level,
            format!("Unsanitized data from `{src}` reaches sink `{sink}`"),
        ),
    }
}

#[cfg(test)]
mod checker_observation_tests {
    use super::checker_advisory;

    fn observation(rule: &str, params: &[(&'static str, String)]) -> String {
        checker_advisory(None, rule, "handler", "a.ts", 7, params).5
    }

    #[test]
    fn weak_hash_selector_shape_renders_selected_primitive() {
        let obs = observation(
            "weak_hash",
            &[("callee", "createHash".into()), ("sel", "md5".into())],
        );
        assert_eq!(
            obs,
            "Weak hash primitive 'md5' selected by `createHash`, not acceptable \
             for passwords or security-sensitive digests (use bcrypt/argon2/scrypt \
             or SHA-256+)"
        );
    }

    #[test]
    fn weak_hash_bare_shape_renders_bare_call() {
        let obs = observation("weak_hash", &[("callee", "md5".into())]);
        assert_eq!(
            obs,
            "Weak hash function `md5`, not acceptable for passwords or \
             security-sensitive digests (use bcrypt/argon2/scrypt or SHA-256+)"
        );
    }

    #[test]
    fn weak_hash_wrapper_and_key_size_render_params() {
        let wrapper = observation("weak_hash_wrapper", &[("path", "vault.hash".into())]);
        assert_eq!(
            wrapper,
            "Password hashing routed through opaque wrapper `vault.hash`, verify it \
             uses bcrypt/argon2/scrypt, not MD5/SHA-1"
        );
        let key = observation(
            "weak_rsa_key_size",
            &[
                ("callee", "generateKey".into()),
                ("min_bits", "128".into()),
                ("kind", "symmetric keys".into()),
            ],
        );
        assert_eq!(
            key,
            "Weak key size passed to `generateKey`: provably below 128 bits \
             (use >= 128 bits for symmetric keys)"
        );
    }

    #[test]
    fn insecure_config_selector_renders_literal() {
        let obs = observation(
            "insecure_jwt_algorithm",
            &[("callee", "jwt".into()), ("sel", "none".into())],
        );
        assert_eq!(
            obs,
            "Insecure configuration: `jwt` called with insecure selector 'none'"
        );
    }

    #[test]
    fn unknown_rule_ids_fall_back_to_generic_observation_with_params() {
        let obs = observation(
            "learned_md5_policy",
            &[("callee", "createHash".into()), ("sel", "md5".into())],
        );
        assert_eq!(
            obs,
            "learned_md5_policy violated in `handler` at a.ts:7 \
             (callee=createHash, sel=md5)."
        );
    }

    #[test]
    fn registry_rules_keep_their_advisory_and_use_generic_observation() {
        let path = std::path::Path::new("a.c");
        let spec = crate::spec_for_path(path);
        let (level, title, _, _, _, obs) =
            checker_advisory(spec, crate::rules::BUFFER_OVERFLOW, "f", "a.c", 3, &[]);
        assert_eq!(level, super::Severity::Critical);
        assert_eq!(title, "Memory safety violation: buffer_overflow (f)");
        assert_eq!(obs, "buffer_overflow violated in `f` at a.c:3.");
    }
}
