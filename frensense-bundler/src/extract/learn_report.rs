// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The learn report (`FXREPORT=<path>` / `FXDBG=1`): why each family taught
//! what it taught, written as JSON beside the bundle.
//!
//! Split out of `extract` because it is a pure writer over the extraction
//! run's records - it reads the families, their baseline flags, the proposal
//! notes and the gate's candidate reasons, and decides nothing.

use rustc_hash::FxHashMap;
use serde::Serialize;

use super::{fact_key, Family, LearnedFact, PreparedFamily};

/// Baseline separation evidence for one family (built-in tables only).
#[derive(Debug, Clone, Copy, Serialize)]
pub(super) struct Baseline {
    pub(super) positive_alerts: bool,
    pub(super) negative_alerts: bool,
    pub(super) separates: bool,
}

/// One candidate's journey through the replay gate. A rejected candidate
/// used to vanish with no output at all; `reason` is why it vanished.
#[derive(Debug, Clone, Serialize)]
pub(super) struct CandidateReport {
    pub(super) key: String,
    pub(super) support: u32,
    /// Independent shape cells among the voters. Confirmation needs two;
    /// `support` alone cannot tell copies from corroboration.
    pub(super) cells: u32,
    pub(super) voted_by: Vec<String>,
    pub(super) verdict: &'static str,
    pub(super) reason: Option<String>,
}

/// Everything the bundler decided about one family.
#[derive(Debug, Clone, Serialize)]
struct FamilyReport {
    id: String,
    baseline: Baseline,
    notes: Vec<String>,
    candidates: Vec<CandidateReport>,
    learned: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LearnSummary {
    families: usize,
    candidates: usize,
    published: usize,
    rejected: usize,
    families_not_separating_at_baseline: Vec<String>,
    families_that_taught_nothing: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LearnReport {
    schema: &'static str,
    summary: LearnSummary,
    /// One row per published fact: how many witnesses backed it (`support`),
    /// how many were *independent* (`cells`), whether that reached
    /// `confirmed`, and the classes its voters declared. A sink's classes are
    /// provenance here; the payload has no sink-scope table yet, so this row
    /// is where over-reach is auditable today.
    facts: Vec<PublishedFact>,
    families: Vec<FamilyReport>,
}

/// One row per published fact, in the payload's own key order.
fn published_facts(published: &[LearnedFact]) -> Vec<PublishedFact> {
    published
        .iter()
        .map(|f| {
            let (kind, name) = fact_key(&f.entry);
            PublishedFact {
                key: format!("{kind}:{name}"),
                support: f.support,
                cells: f.cells,
                status: f.status.clone(),
                classes: f.classes.clone(),
                families: f.families.clone(),
            }
        })
        .collect()
}

#[derive(Debug, Serialize)]
struct PublishedFact {
    key: String,
    support: u32,
    cells: u32,
    status: String,
    classes: Vec<String>,
    families: Vec<String>,
}

/// Per-family outcome log: printed under `FXDBG`, written as JSON when
/// `FXREPORT=<path>` is set. This is the answer to "why didn't the bundle
/// learn X": baseline flags say what the engine saw, `notes` say what the
/// proposal stage did with it, and each candidate's `reason` says why the
/// replay gate refused it.
pub(super) fn emit_learn_report(
    families: &[Family],
    prepared: &[PreparedFamily],
    baseline: &FxHashMap<String, Baseline>,
    family_notes: &FxHashMap<String, Vec<String>>,
    candidate_reports: &[CandidateReport],
    published: &[LearnedFact],
) {
    let dbg = std::env::var("FXDBG").is_ok();
    let report_path = std::env::var("FXREPORT").ok().filter(|p| !p.is_empty());
    if !dbg && report_path.is_none() {
        return;
    }

    let mut ids: Vec<String> = families.iter().map(|f| f.id.clone()).collect();
    ids.sort();
    ids.dedup();
    let prepared_ids: Vec<&str> = prepared.iter().map(|p| p.id.as_str()).collect();

    let mut family_reports = Vec::with_capacity(ids.len());
    for id in ids {
        let mut notes = family_notes.get(&id).cloned().unwrap_or_default();
        if !prepared_ids.contains(&id.as_str()) {
            notes.push(
                "family skipped: it could not be lowered, so the replay gate never saw it"
                    .to_string(),
            );
        }
        let baseline = baseline.get(&id).copied().unwrap_or(Baseline {
            positive_alerts: false,
            negative_alerts: false,
            separates: false,
        });
        let fam_candidates: Vec<CandidateReport> = candidate_reports
            .iter()
            .filter(|c| c.voted_by.contains(&id))
            .cloned()
            .collect();
        let learned: Vec<String> = published
            .iter()
            .filter(|f| f.families.contains(&id))
            .map(|f| {
                let (kind, name) = fact_key(&f.entry);
                format!("{kind}:{name}")
            })
            .collect();

        if dbg {
            print_family(&id, baseline, &fam_candidates, &learned, &notes);
        }

        family_reports.push(FamilyReport {
            id,
            baseline,
            notes,
            candidates: fam_candidates,
            learned,
        });
    }

    let report = LearnReport {
        schema: "frensense-learn-report/2",
        summary: LearnSummary {
            families: family_reports.len(),
            candidates: candidate_reports.len(),
            published: candidate_reports
                .iter()
                .filter(|c| c.verdict == "published")
                .count(),
            rejected: candidate_reports
                .iter()
                .filter(|c| c.verdict == "rejected")
                .count(),
            families_not_separating_at_baseline: family_reports
                .iter()
                .filter(|f| !f.baseline.separates)
                .map(|f| f.id.clone())
                .collect(),
            families_that_taught_nothing: family_reports
                .iter()
                .filter(|f| f.learned.is_empty())
                .map(|f| f.id.clone())
                .collect(),
        },
        facts: published_facts(published),
        families: family_reports,
    };

    if let Some(path) = report_path {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => match std::fs::write(&path, json) {
                Ok(()) => eprintln!("[facts] learn report written to {path}"),
                Err(e) => eprintln!("[facts] learn report write failed for {path}: {e}"),
            },
            Err(e) => eprintln!("[facts] learn report serialization failed: {e}"),
        }
    }
}

/// The `FXDBG` line for one family plus every reason it taught nothing.
fn print_family(
    id: &str,
    baseline: Baseline,
    candidates: &[CandidateReport],
    learned: &[String],
    notes: &[String],
) {
    let cand_summary = if candidates.is_empty() {
        "(none proposed)".to_string()
    } else {
        candidates
            .iter()
            .map(|c| {
                format!(
                    "{}={}(support={}, cells={})",
                    c.key,
                    c.verdict.to_uppercase(),
                    c.support,
                    c.cells
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    eprintln!(
        "[facts] family {id}: baseline positive_alerts={} negative_alerts={} separates={} | candidates: {cand_summary} | learned {} fact(s){}",
        baseline.positive_alerts,
        baseline.negative_alerts,
        baseline.separates,
        learned.len(),
        if learned.is_empty() { " <- TAUGHT NOTHING" } else { "" }
    );
    if learned.is_empty() {
        for c in candidates {
            if let Some(reason) = &c.reason {
                eprintln!("[facts]   rejected {}: {reason}", c.key);
            }
        }
    }
    for note in notes {
        eprintln!("[facts]   note: {note}");
    }
}
