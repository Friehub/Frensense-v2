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
use frensense_engine::scan::{LocatedCutSite, LocatedFinding};

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
    /// Function holding the sink call.
    pub function: String,
    /// Where the walk met a value it could not resolve (the actionable half
    /// of the `unresolvable` reason): callee, parameter or global, with its
    /// file and line.
    pub cut_sites: Vec<LocatedCutSite>,
}

impl ExplainRecord {
    /// Machine-readable form, for `--explain-json` (blindness challenge cards).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "file": self.file,
            "line": self.line,
            "function": self.function,
            "sink": self.sink,
            "arg_slot": self.arg_slot,
            "verdict": self.verdict,
            "cut_reasons": self.cut_reasons,
            "reason": self.reason,
            "source": self.source_desc,
            "cut_sites": self.cut_sites.iter().map(|c| serde_json::json!({
                "kind": c.kind,
                "function": c.function,
                "detail": c.detail,
                "file": c.file,
                "line": c.line,
            })).collect::<Vec<_>>(),
        })
    }
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
    let (verdict, reason) = if f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some() {
        // Vulnerable on a dangerous slot, but the sink resolves to a
        // fallback rule card: it names no vulnerability class, so the
        // reporting policy drops it (nothing to fix, suppress or trend).
        (
            "unclassified".to_string(),
            format!(
                "taint reaches `{}` but the sink names no vulnerability class, so no advisory is reported",
                f.sink
            ),
        )
    } else if f.verdict == BackwardVerdict::Vulnerable {
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
        function: f.function.clone(),
        cut_sites: loc.cut_sites.clone(),
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
                // A class the sink names: unlabeled Execution resolves to the
                // generic card and would never be reported.
                .label(Some("command".to_string()))
                .path(TaintPath::default())
                .cut_reasons(cuts)
                .build(),
            file: "app.py".to_string(),
            line: 42,
            column: 1,
            cut_sites: Vec::new(),
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
    fn unclassified_vulnerable_sink_is_explained() {
        let mut l = loc(
            BackwardVerdict::Vulnerable,
            Some(SinkAlert {
                sink: "exec".to_string(),
                slot: 0,
                function: "handler".to_string(),
                class: FindingClass::Injection,
            }),
            Vec::new(),
        );
        l.finding.label = None;
        let rec = explain_silent(&l).expect("record");
        assert_eq!(rec.verdict, "unclassified");
        assert!(
            rec.reason.contains("names no vulnerability class"),
            "{}",
            rec.reason
        );
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

    #[test]
    fn unknown_record_carries_its_stop_sites_in_json() {
        let mut l = loc(BackwardVerdict::Unknown, None, vec!["unresolvable"]);
        l.cut_sites = vec![LocatedCutSite {
            kind: "external-call",
            function: "handler".into(),
            detail: "os.path.join".into(),
            file: "app.py".into(),
            line: 40,
        }];
        let rec = explain_silent(&l).expect("record");
        let j = rec.to_json();
        assert_eq!(j["function"], "handler");
        assert_eq!(j["cut_sites"][0]["kind"], "external-call");
        assert_eq!(j["cut_sites"][0]["detail"], "os.path.join");
        assert_eq!(j["cut_sites"][0]["line"], 40);
    }
}
