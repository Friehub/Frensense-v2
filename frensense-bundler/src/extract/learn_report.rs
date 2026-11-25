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
    families: Vec<FamilyReport>,
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
            let cand_summary = if fam_candidates.is_empty() {
                "(none proposed)".to_string()
            } else {
                fam_candidates
                    .iter()
                    .map(|c| {
                        if c.verdict == "published" {
                            format!("{}=PUBLISHED", c.key)
                        } else {
                            format!("{}=rejected", c.key)
                        }
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
                for c in &fam_candidates {
                    if let Some(r) = &c.reason {
                        eprintln!("[facts]   rejected {c}: {r}", c = c.key);
                    }
                }
            }
            for n in &notes {
                eprintln!("[facts]   note: {n}");
            }
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
        schema: "frensense-learn-report/1",
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
