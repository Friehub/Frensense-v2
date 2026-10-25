// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::collections::BTreeSet;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::engine::{BackwardVerdict, FindingClass};
use frensense_engine::analysis::taint::facts::FactTable;
use frensense_engine::analysis::taint::path::PathStep;
use frensense_engine::scan;
use frensense_lang::rule_card::names_vulnerability_class;
use frensense_lang::Severity;

use super::call_analysis::collect_calls;
use super::family::Family;

/// The replay gate's alert predicate: does this scan result count as
/// *alerting*?
///
/// This is bundler-local verdict policy (ENGINE_PURITY_REFACTOR 1.3): the
/// engine emits findings, the consumer decides what alerts. Both clauses
/// of the predicate are declared here, next to the gate that needs them:
///
/// 1. **Info-tier exclusion.** A taint finding alerts only when its sink
///    role ranks above Info ([`SinkRole::default_level`]) - lang-declared
///    Response/Validation roles (reflect-into-response, decode APIs) are
///    *observations*, not alerts: the engine analyses and records them
///    (role never gates exploration) but the gate counts only warning+
///    findings. Otherwise every benign `res.json(...)` echo on a negative
///    would pin `negative_alerts` to true and no sanitizer/check candidate
///    could ever separate a family. Only [`BackwardVerdict::Vulnerable`]
///    findings on a dangerous sink slot (`alert.is_some()`, the
///    sink-signature-aware slot check) are considered.
/// 2. **Checker-inclusion.** Learned/built-in policy checks are alerts
///    too: a corpus family whose positive violates a learned check must
///    separate exactly like a taint family. Without this, Check facts
///    could never be validated by the replay gate.
///
/// [`SinkRole::default_level`]: frensense_lang::severity::SinkRole::default_level
#[must_use]
pub fn alerts(result: &scan::ScanResult) -> bool {
    alerts_with_cwe(result, None)
}

/// [`alerts`] under a family's declared CWE.
///
/// A learned sink has no vocabulary of its own; the family's `cwe:` is what
/// classifies it, exactly as the published bundle does for its consumers. The
/// gate must classify the same way, or it scores findings the CLI drops - the
/// "gate passes, CLI is silent" disagreement.
#[must_use]
pub fn alerts_with_cwe(result: &scan::ScanResult, cwe: Option<&str>) -> bool {
    result.findings.iter().any(|f| {
        let mut classified;
        let f = match cwe {
            Some(cwe) => {
                classified = f.clone();
                classified.classify_from_cwe(cwe);
                &classified
            }
            None => f,
        };
        f.verdict == BackwardVerdict::Vulnerable
            && f.alert.is_some()
            && f.role.default_level() != Severity::Info
            && names_vulnerability_class(
                f.label.as_deref(),
                f.role,
                matches!(f.finding_class, FindingClass::Idor),
            )
    }) || !result.checker.is_empty()
}

/// Taint-relevant calls observed in one variant, with arg-slot detail.
/// Uses the engine's scan; the deltas come from comparing what taint reached.
pub fn scan_variant(
    files: &[(String, String, String)],
    config: &TaintConfig,
    facts: &FactTable,
) -> scan::ScanResult {
    scan::scan(files, config, facts)
}

/// One family's variants, lowered once. The gate re-scans families per
/// candidate fact; without pre-lowering the gate is O(candidates x families)
/// lowerings and times out at corpus scale.
///
/// Lowering runs under the family's own seeded tables (spec + default
/// pack) so the gate lowers with exactly the pack vocabulary the CLI
/// scan lowers with (route-registration patterns since Phase 6.4,
/// dynamic grammar facts once a family teaches them) - gate and CLI
/// lowering can never diverge on pack vocabulary.
pub struct PreparedFamily {
    pub id: String,
    pub pos: scan::PreparedProgram,
    pub neg: scan::PreparedProgram,
    /// All call names appearing in any variant, used to skip gate trials
    /// for facts that cannot affect this family.
    pub calls: BTreeSet<String>,
    /// The family's declared `cwe:` - the class its feedback is reported
    /// under, and therefore the class the gate must score its findings with.
    pub cwe: Option<String>,
}

impl PreparedFamily {
    pub fn new(f: &Family, facts: &FactTable) -> Result<Self, String> {
        let pos = scan::prepare_with_facts(&f.positives, Some(facts))?;
        let neg = scan::prepare_with_facts(&f.negatives, Some(facts))?;
        let mut calls = BTreeSet::new();
        calls.extend(
            collect_calls(&f.positives, Some(facts))
                .keys()
                .cloned()
                .chain(collect_calls(&f.negatives, Some(facts)).keys().cloned()),
        );
        Ok(Self {
            id: f.id.clone(),
            pos,
            neg,
            calls,
            cwe: f.metadata.cwe.clone(),
        })
    }

    /// Alert flags under a fact table: (positive alerts, negative alerts).
    ///
    /// Separation is `positive && !negative`, but the gate's rejection
    /// messages need to say WHICH side failed: a fact that silences the
    /// positive is worthless, one that leaves the negative noisy is a false
    /// positive waiting to happen.
    pub fn alert_flags(&self, config: &TaintConfig, facts: &FactTable) -> (bool, bool) {
        let pos = scan::scan_prepared(&self.pos, config, facts);
        let neg = scan::scan_prepared(&self.neg, config, facts);
        (
            alerts_with_cwe(&pos, self.cwe.as_deref()),
            alerts_with_cwe(&neg, self.cwe.as_deref()),
        )
    }

    /// Family separation under a fact table. Reuses the lowered IRs;
    /// each call re-runs the taint engine + checker only.
    pub fn separates(&self, config: &TaintConfig, facts: &FactTable) -> bool {
        let (pos_alerts, neg_alerts) = self.alert_flags(config, facts);
        pos_alerts && !neg_alerts
    }

    /// The candidate sink this call's tainted argument flows *through*, if
    /// any.
    ///
    /// A positive can taint more than one call: the defect, and calls that
    /// merely receive its result (the response writer that echoes a query's
    /// rows, the logger that prints a deserialized document). Separation
    /// cannot tell them apart - the negative validated the value upstream, so
    /// every downstream echo is silent there too, and both candidates pass.
    /// Learning the echo publishes a sink that fires on *any* tainted value of
    /// that shape, which is exactly the false positive the corpus review found
    /// (`JsonResponse`, `annotate`, `list` taught by the Django Trunc family).
    ///
    /// The captured source→sink path answers it directly: a call whose
    /// argument path already names another candidate sink is downstream of it,
    /// so the upstream candidate is the one carrying the family's knowledge.
    pub fn downstream_echo(
        &self,
        config: &TaintConfig,
        facts: &FactTable,
        call: &str,
        siblings: &BTreeSet<String>,
    ) -> Option<String> {
        if siblings.len() < 2 {
            return None;
        }
        for f in &scan::scan_prepared(&self.pos, config, facts).findings {
            if f.sink != call || f.verdict != BackwardVerdict::Vulnerable || f.alert.is_none() {
                continue;
            }
            for step in &f.path.steps {
                let callee = match step {
                    PathStep::CallArgument { callee, .. } | PathStep::CallReturn { callee, .. } => {
                        callee
                    }
                    _ => continue,
                };
                if callee != call && siblings.contains(callee) {
                    return Some(callee.clone());
                }
            }
        }
        None
    }
}

/// Family separation check under a fact table (single-shot variant; the
/// gate uses the pre-lowered [`PreparedFamily::separates`] instead).
pub fn separates(family: &Family, config: &TaintConfig, facts: &FactTable) -> bool {
    let pos = scan_variant(&family.positives, config, facts);
    let neg = scan_variant(&family.negatives, config, facts);
    alerts(&pos) && !alerts(&neg)
}
