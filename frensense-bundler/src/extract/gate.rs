// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::collections::BTreeSet;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::engine::BackwardVerdict;
use frensense_engine::analysis::taint::facts::FactTable;
use frensense_engine::scan;
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
    result.findings.iter().any(|f| {
        f.verdict == BackwardVerdict::Vulnerable
            && f.alert.is_some()
            && f.role.default_level() != Severity::Info
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
        (alerts(&pos), alerts(&neg))
    }

    /// Family separation under a fact table. Reuses the lowered IRs;
    /// each call re-runs the taint engine + checker only.
    pub fn separates(&self, config: &TaintConfig, facts: &FactTable) -> bool {
        let (pos_alerts, neg_alerts) = self.alert_flags(config, facts);
        pos_alerts && !neg_alerts
    }
}

/// Family separation check under a fact table (single-shot variant; the
/// gate uses the pre-lowered [`PreparedFamily::separates`] instead).
pub fn separates(family: &Family, config: &TaintConfig, facts: &FactTable) -> bool {
    let pos = scan_variant(&family.positives, config, facts);
    let neg = scan_variant(&family.negatives, config, facts);
    alerts(&pos) && !alerts(&neg)
}
