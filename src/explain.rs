// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! `--explain`: why the engine stayed silent - the "engine limitation" map.
//!
//! Collected under `--explain` so users can see *where* analysis stopped.
//! The reporting policy (which findings become advisories, and the
//! severity/confidence floor) lives in [`crate::policy`].

use crate::policy::reports_finding;
use frensense_engine::analysis::taint::engine::BackwardVerdict;
use frensense_engine::scan::LocatedFinding;

/// One explored sink argument that did NOT become an advisory, with the
/// reason the engine stayed silent. Collected under `--explain` so users
/// can see *where* analysis stopped - the "engine limitation" map.
///
/// `#[non_exhaustive]`: an evolving diagnostic DTO; new fields are minor
/// releases.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExplainRecord {
    pub file: String,
    pub line: u32,
    pub sink: String,
    pub arg_slot: usize,
    /// Short verdict label: `"clean"`, `"sanitized"`, `"unknown"`, or
    /// `"safe-channel"` (vulnerable flow into a non-dangerous slot).
    pub verdict: String,
    /// Distinct silent stop sites hit during the walk (`"guard"`,
    /// `"value-const"`, `"sanitizer"`, `"unresolvable"`); empty when the
    /// walk simply exhausted its predecessors without a source.
    pub cut_reasons: Vec<&'static str>,
    /// Human summary of why nothing was reported.
    pub reason: String,
    /// The source access path, when the walk did reach one (e.g. a
    /// `Vulnerable` flow into a safe channel).
    pub source_desc: Option<String>,
}

fn verdict_label(v: &BackwardVerdict) -> &'static str {
    match v {
        BackwardVerdict::Vulnerable => "vulnerable",
        BackwardVerdict::Sanitized => "sanitized",
        BackwardVerdict::Unknown => "unknown",
        BackwardVerdict::Clean => "clean",
    }
}

fn cut_summary(cuts: &[&'static str]) -> String {
    if cuts.is_empty() {
        return "no attacker source reached the sink; the backward walk exhausted its predecessors (flow died or was never tainted)".to_string();
    }
    let names: Vec<&str> = cuts
        .iter()
        .map(|c| match *c {
            "guard" => "a validating guard dominated the use",
            "value-const" => "the value folded to an attacker-independent constant",
            "sanitizer" => "a sanitizer transformed the value",
            "unresolvable" => "the flow hit a value the engine cannot resolve",
            other => other,
        })
        .collect();
    names.join("; ")
}

/// Build an [`ExplainRecord`] for a located finding that will not be
/// reported. Returns `None` for findings that *are* reported (callers
/// should only pass silent ones).
#[must_use]
pub fn explain_silent(loc: &LocatedFinding) -> Option<ExplainRecord> {
    if reports_finding(&loc.finding) {
        return None;
    }
    let f = &loc.finding;
    let (verdict, reason) = if f.verdict == BackwardVerdict::Vulnerable {
        // Vulnerable but alert is None: the flow landed in a safe channel.
        (
            "safe-channel".to_string(),
            format!(
                "taint reaches `{}` but argument {} is a safe (non-injection) channel",
                f.sink, f.arg_slot
            ),
        )
    } else {
        (
            verdict_label(&f.verdict).to_string(),
            cut_summary(&f.cut_reasons),
        )
    };
    Some(ExplainRecord {
        file: loc.file.clone(),
        line: loc.line,
        sink: f.sink.clone(),
        arg_slot: f.arg_slot,
        verdict,
        cut_reasons: f.cut_reasons.clone(),
        reason,
        source_desc: f.source_desc.clone(),
    })
}

#[cfg(test)]
mod explain_tests {
    use super::*;
    use frensense_engine::analysis::forward::SinkAlert;
    use frensense_engine::analysis::taint::engine::{FindingClass, SinkFinding};
    use frensense_engine::analysis::taint::path::TaintPath;
    use frensense_engine::analysis::taint::role::SinkRole;

    fn loc(
        verdict: BackwardVerdict,
        alert: Option<SinkAlert>,
        cuts: Vec<&'static str>,
    ) -> LocatedFinding {
        LocatedFinding {
            finding: SinkFinding::builder()
                .function("handler")
                .sink("exec")
                .arg_slot(0)
                .alert(alert)
                .verdict(verdict)
                .finding_class(FindingClass::Injection)
                .role(SinkRole::Execution)
                .path(TaintPath::default())
                .cut_reasons(cuts)
                .build(),
            file: "app.py".to_string(),
            line: 42,
            column: 1,
        }
    }

    #[test]
    fn vulnerable_with_alert_is_not_explained() {
        let alert = Some(SinkAlert {
            sink: "exec".to_string(),
            slot: 0,
            function: "handler".to_string(),
            class: FindingClass::Injection,
        });
        let l = loc(BackwardVerdict::Vulnerable, alert, Vec::new());
        assert!(explain_silent(&l).is_none());
    }

    #[test]
    fn vulnerable_without_alert_is_safe_channel() {
        let l = loc(BackwardVerdict::Vulnerable, None, Vec::new());
        let rec = explain_silent(&l).expect("record");
        assert_eq!(rec.verdict, "safe-channel");
        assert!(rec.reason.contains("safe"));
    }

    #[test]
    fn clean_with_cuts_reports_reason() {
        let l = loc(BackwardVerdict::Clean, None, vec!["guard"]);
        let rec = explain_silent(&l).expect("record");
        assert_eq!(rec.verdict, "clean");
        assert!(rec.reason.contains("guard"));
    }

    #[test]
    fn clean_without_cuts_reports_exhausted() {
        let l = loc(BackwardVerdict::Clean, None, Vec::new());
        let rec = explain_silent(&l).expect("record");
        assert!(rec.reason.contains("exhausted"));
    }

    #[test]
    fn sanitized_verdict_label() {
        let l = loc(BackwardVerdict::Sanitized, None, vec!["sanitizer"]);
        let rec = explain_silent(&l).expect("record");
        assert_eq!(rec.verdict, "sanitized");
    }
}
