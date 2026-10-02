// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Severity declarations and advisory registries.
//!
//! Everything report-shaped lives here, not in the engine or the app:
//!
//! - [`Severity`] - the ranking type used by every reporter surface.
//! - [`RuleAdvisory`] / [`RuleEntry`] - per-language rule registries
//!   (`LanguageSpec::known_rule_registry`): each language declares the
//!   severity and message templates for the rules it owns.
//! - [`generic_rule_advisory`] - the cross-cutting fallback for any rule no
//!   language declares (preserves the historical "Policy violation" shape).
//! - [`taint_advisory`] - the cross-cutting class x role ranking for dataflow
//!   findings.

use serde::{Deserialize, Serialize};

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

/// Resolve advisory metadata for a checker finding: the language registry
/// first ([`crate::spec::LanguageSpec::known_rule_registry`]), the generic
/// policy fallback otherwise.
pub fn checker_advisory(
    spec: Option<&dyn crate::spec::LanguageSpec>,
    rule: &str,
    function: &str,
    file: &str,
    line: u32,
) -> (Severity, String, String, String, &'static str) {
    if let Some(spec) = spec {
        if let Some(entry) = spec.known_rule_registry().iter().find(|e| e.rule == rule) {
            return entry.advisory.render(rule, function, file, line);
        }
    }
    generic_rule_advisory(rule, function, file, line)
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
