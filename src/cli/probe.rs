// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! `frensense probe <family>`: why a corpus family does or does not teach.
//!
//! The engine is the deciding factor during corpus curation, not the gate
//! afterwards. This module scans a family's training pair under the shipped
//! fact table and reports, per side, which sink calls the engine recognized,
//! which of those became advisories, and - for the ones that stayed silent -
//! the engine's own reason (`--explain`'s verdict, cut reasons and cut
//! sites). The family ends in one disposition:
//!
//! | verdict | what it means | action |
//! |---|---|---|
//! | `class-not-expressible` | no built-in card names the family's CWE | engine gap: leave the family out |
//! | `no-sink-recognised` | the positive has no modelled sink call | vocabulary gap: add the sink |
//! | `no-source-recognised` | the sink is known, no modelled source reaches it | source vocabulary gap |
//! | `flow-not-proven` | sink and source are known, no path | dataflow gap: ledger it |
//! | `sanitized-before-sink` | a known guard cuts the flow | the positive is shaped wrong |
//! | `fact-does-not-separate` | both twins alert | family bug |
//! | `separated` | positive alerts, negative is silent | accept (anchor family) |
//!
//! Read-only: it scans, it never edits a family, a pack or a bundle.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[path = "probe_scan.rs"]
mod scan;
pub use scan::pack_models;
use scan::{expressible_for, language_of, parse_header, scan_side, training_pair};

use serde_json::{Value, json};

/// What the engine concluded about one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// The family's CWE names no built-in class.
    ClassNotExpressible,
    /// No sink call in the positive is one the pack models.
    NoSinkRecognised,
    /// A sink was recognized, but no source reaches it.
    NoSourceRecognised,
    /// Sink and source are modelled but the walk found no path.
    FlowNotProven,
    /// A known guard or sanitizer cut the flow before the sink.
    SanitizedBeforeSink,
    /// Both twins alert.
    FactDoesNotSeparate,
    /// Positive alerts, negative is silent.
    Separated,
}

impl Verdict {
    /// The stable machine name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClassNotExpressible => "class-not-expressible",
            Self::NoSinkRecognised => "no-sink-recognised",
            Self::NoSourceRecognised => "no-source-recognised",
            Self::FlowNotProven => "flow-not-proven",
            Self::SanitizedBeforeSink => "sanitized-before-sink",
            Self::FactDoesNotSeparate => "fact-does-not-separate",
            Self::Separated => "separated",
        }
    }

    /// What the corpus author should do next.
    #[must_use]
    pub fn action(self) -> &'static str {
        match self {
            Self::ClassNotExpressible => {
                "engine gap: no built-in card names this CWE; leave the family out until the class exists"
            }
            Self::NoSinkRecognised => {
                "vocabulary gap: add the sink call to the language's pack vocabulary, then re-probe"
            }
            Self::NoSourceRecognised => {
                "source gap: add the source pattern to the language's pack vocabulary, then re-probe"
            }
            Self::FlowNotProven => {
                "dataflow gap: sink and source are modelled but no path exists; record it in the gap ledger"
            }
            Self::SanitizedBeforeSink => {
                "family shape: a known guard already cuts this flow; the positive needs a different shape"
            }
            Self::FactDoesNotSeparate => {
                "family bug: the negative alerts too, so no fact can separate the pair"
            }
            Self::Separated => "accept: the engine already separates the pair (anchor family)",
        }
    }

    /// Whether the engine can carry this family today.
    #[must_use]
    pub fn accepted(self) -> bool {
        matches!(self, Self::Separated)
    }
}

/// One side of the pair: what the scan found and what it could not decide.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Side {
    /// The file that was scanned.
    pub path: PathBuf,
    /// Advisories the scan reported, one JSON object each.
    pub advisories: Vec<Value>,
    /// Distinct sink calls the engine recognized, whether or not they fired.
    pub sinks_recognised: BTreeSet<String>,
    /// Silent sink arguments with the engine's reason.
    pub explain: Vec<Value>,
    /// Coverage counts behind the result.
    pub coverage: Value,
}

/// The whole probe result for one family.
#[derive(Debug)]
#[non_exhaustive]
pub struct ProbeReport {
    /// Family name (the directory or file stem).
    pub family: String,
    /// Language key the extension resolved to.
    pub language: String,
    /// Class declared in the positive's `[frensense]` block.
    pub class: Option<String>,
    /// CWE declared in the positive's `[frensense]` block.
    pub cwe: Option<String>,
    /// Purpose declared in the positive's `[frensense]` block.
    pub purpose: Option<String>,
    /// Whether a built-in card can express the declared CWE.
    pub expressible: Value,
    /// The training positive.
    pub positive: Side,
    /// The training negative, when the family has one.
    pub negative: Option<Side>,
    /// The engine's conclusion.
    pub verdict: Verdict,
}

impl ProbeReport {
    /// Machine-readable form.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "schema_version": "1",
            "family": self.family,
            "language": self.language,
            "class": self.class,
            "cwe": self.cwe,
            "purpose": self.purpose,
            "expressible": self.expressible,
            "positive": side_json(&self.positive),
            "negative": self.negative.as_ref().map(side_json),
            "verdict": self.verdict.as_str(),
            "action": self.verdict.action(),
            "accepted": self.verdict.accepted(),
        })
    }

    /// Human-readable form. Returns a string; the binary prints it.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        let class = self.class.as_deref().unwrap_or("-");
        let cwe = self.cwe.as_deref().unwrap_or("-");
        let _ = writeln!(
            out,
            "family {} · {} · {class} · {cwe}",
            self.family, self.language
        );
        if let Some(purpose) = &self.purpose {
            let _ = writeln!(out, "declared purpose: {purpose}");
        }
        let _ = writeln!(out, "\n[positive] {}", self.positive.path.display());
        render_side(&mut out, &self.positive);
        if let Some(negative) = &self.negative {
            let _ = writeln!(out, "\n[negative] {}", negative.path.display());
            render_side(&mut out, negative);
        }
        let _ = writeln!(
            out,
            "\nverdict: {}\naction:  {}",
            self.verdict.as_str(),
            self.verdict.action()
        );
        out
    }
}

fn render_side(out: &mut String, side: &Side) {
    use std::fmt::Write as _;

    let _ = writeln!(
        out,
        "  advisories: {}   sink sites: {}   unresolved: {}",
        side.advisories.len(),
        side.coverage
            .get("sink_sites")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        side.coverage
            .get("unresolved_sites")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    );
    if side.advisories.is_empty() {
        let matched = if side.sinks_recognised.is_empty() {
            "none".to_string()
        } else {
            side.sinks_recognised
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        };
        let _ = writeln!(out, "  models matched (silent): {matched}");
    }
    for advisory in &side.advisories {
        let rule = advisory.get("rule").and_then(Value::as_str).unwrap_or("?");
        let line = advisory.get("line").and_then(Value::as_u64).unwrap_or(0);
        let _ = writeln!(out, "  fired: {rule} at line {line}");
    }
    for record in &side.explain {
        let sink = record.get("sink").and_then(Value::as_str).unwrap_or("?");
        let verdict = record.get("verdict").and_then(Value::as_str).unwrap_or("?");
        let reason = record.get("reason").and_then(Value::as_str).unwrap_or("");
        let _ = writeln!(out, "  silent: {sink} ({verdict}) {reason}");
    }
}

fn side_json(side: &Side) -> Value {
    json!({
        "path": side.path.display().to_string(),
        "sinks_recognised": side.sinks_recognised.iter().cloned().collect::<Vec<_>>(),
        "advisories": side.advisories,
        "explain": side.explain,
        "coverage": side.coverage,
    })
}

/// Decide the family's disposition from what the two scans showed.
fn classify(expressible: &Value, positive: &Side, negative: Option<&Side>) -> Verdict {
    if expressible.get("expressible").and_then(Value::as_bool) == Some(false) {
        return Verdict::ClassNotExpressible;
    }
    if !positive.advisories.is_empty() {
        let negative_alerts = negative.is_some_and(|side| !side.advisories.is_empty());
        return if negative_alerts {
            Verdict::FactDoesNotSeparate
        } else {
            Verdict::Separated
        };
    }
    if positive.sinks_recognised.is_empty() {
        return Verdict::NoSinkRecognised;
    }
    let verdicts: Vec<&str> = positive
        .explain
        .iter()
        .filter_map(|record| record.get("verdict").and_then(Value::as_str))
        .collect();
    if !verdicts.is_empty() && verdicts.iter().all(|v| *v == "no-source") {
        return Verdict::NoSourceRecognised;
    }
    if verdicts.contains(&"sanitized") {
        return Verdict::SanitizedBeforeSink;
    }
    Verdict::FlowNotProven
}

/// Probe one family directory (or one positive file).
///
/// # Errors
/// A missing positive file, an unreadable directory, or a scan failure.
pub fn probe(path: &Path, bundle: Option<&Path>) -> Result<ProbeReport, String> {
    let (positive_path, negative_path) = if path.is_dir() {
        training_pair(path)?
    } else {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let sibling = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|name| name.replace("_positive", "_negative"));
        let negative = sibling
            .map(|name| parent.join(name))
            .filter(|candidate| candidate.is_file());
        (path.to_path_buf(), negative)
    };

    let source = std::fs::read_to_string(&positive_path)
        .map_err(|e| format!("cannot read {}: {e}", positive_path.display()))?;
    let header = parse_header(&source);
    let ext = positive_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    let language = language_of(ext);
    let family = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("family")
        .to_string();

    let positive = scan_side(&positive_path, bundle)?;
    let negative = match negative_path {
        Some(negative) => Some(scan_side(&negative, bundle)?),
        None => None,
    };
    let expressible = expressible_for(header.cwe.as_deref());
    let verdict = classify(&expressible, &positive, negative.as_ref());

    Ok(ProbeReport {
        family,
        language,
        class: header.class,
        cwe: header.cwe,
        purpose: header.purpose,
        expressible,
        positive,
        negative,
        verdict,
    })
}
