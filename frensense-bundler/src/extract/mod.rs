// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Fact extraction from positive/negative corpus pairs (§9).
//!
//! Replaces the old shape/fingerprint pipeline. For every corpus family:
//!
//! 1. Scan positives and negatives through the **shared engine harness**
//!    (`engine::data_flow::scan`) under the language specs of the family's
//!    own extensions - exactly the tables the consumer CLI scans with.
//! 2. Compute the delta: sink/sanitizer candidates from how taint moves (or
//!    fails to move) through each variant.
//! 3. **Replay gate**: apply candidate facts, re-scan the family; publish a
//!    fact only if the family separates (positives alert, negatives don't)
//!    and no other family's negatives newly alert.
//! 4. Publish with `support` = number of variants that voted. support >= 2 is
//!    `confirmed`, otherwise `provisional`.

pub mod call_analysis;
pub mod candidate;
pub mod family;
pub mod gate;
pub mod noise;
pub mod propose;

#[cfg(test)]
pub mod tests;

use rustc_hash::FxHashMap;
use serde::Serialize;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::FactTable;

pub use call_analysis::{
    collect_calls, cross_function_helper, defined_function_names, extract_call_arg_literals,
    variant_has_range_check_on_call, CallShape,
};
pub use candidate::{apply_candidate, fact_key, Candidate};
pub use family::{group_families, Family, FamilyMetadata, LearnedFact};
pub use gate::{scan_variant, separates, PreparedFamily};
pub use noise::{guard_priority, is_exception_name, looks_taint_relevant};
pub use propose::{propose, propose_with_trace};

/// Full extraction: propose per family -> replay-gate -> merged learned table.
///
/// Production path: every family is proposed, baselined and gate-trialed
/// under exactly the language specs of its own files - the same tables the
/// consumer CLI builds for those files ([`family_tables`]). Harness/CLI
/// parity matters in both directions: a foreign-language rule must not
/// silence a positive during learning, and a foreign-language sanitizer
/// must not quiet a negative the CLI would flag.
pub fn extract_facts(families: &[Family]) -> (FactTable, Vec<LearnedFact>) {
    extract_facts_with(families, &family_tables)
}

/// Extraction under caller-supplied tables, identical for every family.
/// Unit tests use this to exercise the gate with synthetic vocabularies no
/// language spec declares; production goes through [`extract_facts`].
pub fn extract_facts_with_tables(
    families: &[Family],
    config: &TaintConfig,
    builtin: &FactTable,
) -> (FactTable, Vec<LearnedFact>) {
    extract_facts_with(families, &|_| (config.clone(), builtin.clone()))
}

/// The tables the consumer CLI will scan a family's files under: the
/// language specs of the family's own extensions, nothing else.
fn family_tables(f: &Family) -> (TaintConfig, FactTable) {
    frensense_engine::analysis::taint::facts::tables_from_exts(
        f.positives
            .iter()
            .chain(f.negatives.iter())
            .map(|(_, _, ext)| ext.as_str()),
    )
}

fn extract_facts_with(
    families: &[Family],
    tables_for: &dyn Fn(&Family) -> (TaintConfig, FactTable),
) -> (FactTable, Vec<LearnedFact>) {
    // Each family's tables resolve once; the proposal pass, the baselines
    // and every gate trial all run under them.
    let fam_tables: FxHashMap<String, (TaintConfig, FactTable)> = families
        .iter()
        .map(|f| (f.id.clone(), tables_for(f)))
        .collect();

    // votes: candidate-key -> (support, families)
    let mut votes: FxHashMap<String, (Candidate, u32, Vec<String>)> = FxHashMap::default();

    // Pass 1: proposals per family (accumulate votes). The trace notes are
    // kept alongside so a family that teaches nothing can explain itself in
    // the learn report instead of the pipeline staying silent.
    let mut family_notes: FxHashMap<String, Vec<String>> = FxHashMap::default();
    for f in families {
        let (f_config, f_builtin) = &fam_tables[&f.id];
        let (cands, notes) = propose_with_trace(f, f_config, f_builtin);
        family_notes.insert(f.id.clone(), notes);
        for c in cands {
            let key = match &c {
                Candidate::Sink { call, .. } => format!("sink:{call}"),
                Candidate::Sanitizer { call, guard } => format!("san:{call}:{guard}"),
                Candidate::Check { rule, call, .. } => format!("check:{rule}:{call}"),
                Candidate::Policy { rule, call, .. } => format!("policy:{rule}:{call}"),
                Candidate::MemoryContract { name, .. } => format!("mem:{name}"),
                Candidate::WeakCrypto { fact } => format!(
                    "weak_crypto:{}:{}:{:?}",
                    fact.rule_id, fact.call, fact.selector_slot
                ),
                Candidate::GuardBypass { fact } => format!(
                    "gb:{:?}:{:?}:{:?}",
                    fact.containment_callees, fact.credential_sinks, fact.credential_params
                ),
                Candidate::SchemaPolicy { fact } => format!(
                    "sp:{:?}:{:?}:{:?}",
                    fact.builders, fact.enforcers, fact.bound_keywords
                ),
                Candidate::IntegerOverflowRule { rule, .. } => format!("io_rule:{rule}"),
            };

            let entry = votes.entry(key).or_insert_with(|| (c, 0, Vec::new()));
            entry.1 += 1;
            if !entry.2.contains(&f.id) {
                entry.2.push(f.id.clone());
            }
        }
    }

    // Pass 2: replay gate. Every family is lowered once up front; each
    // candidate trial then re-runs only the taint engine + checker per
    // family (no re-lowering). Baseline separation is measured under each
    // family's own language tables; a candidate fact must be validated by
    // at least one voting family that separates under it, and must NOT
    // break any family that already separates at baseline. Families that
    // never separate under any table (corrupted positives, see
    // docs/E2E_REPORT.md §1b) are excluded from the regression check:
    // they can't be "broken" further, and gating on them would reject
    // every fact.
    let prepared: Vec<PreparedFamily> = families
        .iter()
        .filter_map(|f| match PreparedFamily::new(f) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("[facts] skip family {}: {e}", f.id);
                None
            }
        })
        .collect();

    // Baseline per family under its own language tables: both alert flags,
    // not just the boolean verdict, so every report line can say whether
    // the positive is silent or the negative is noisy.
    let mut baseline: FxHashMap<String, Baseline> = FxHashMap::default();
    for p in &prepared {
        let (f_config, f_builtin) = &fam_tables[&p.id];
        let (pos_alerts, neg_alerts) = p.alert_flags(f_config, f_builtin);
        baseline.insert(
            p.id.clone(),
            Baseline {
                positive_alerts: pos_alerts,
                negative_alerts: neg_alerts,
                separates: pos_alerts && !neg_alerts,
            },
        );
    }
    if std::env::var("FXDBG").is_ok() {
        for p in &prepared {
            if let Some(b) = baseline.get(&p.id) {
                eprintln!(
                    "[facts] family {}: baseline positive_alerts={} negative_alerts={} separates={}",
                    p.id, b.positive_alerts, b.negative_alerts, b.separates
                );
            }
        }
    }

    let mut learned = FactTable::default();
    let mut published: Vec<LearnedFact> = Vec::new();

    // Deterministic gate order: `votes` is an `FxHashMap`, and its
    // iteration order decides equal-key tie-breaks downstream. Sort by
    // candidate key so bundle bytes never depend on hasher layout or
    // insertion history.
    let mut ordered_votes: Vec<(String, Candidate, u32, Vec<String>)> = votes
        .into_iter()
        .map(|(key, (cand, support, fams))| (key, cand, support, fams))
        .collect();
    ordered_votes.sort_by(|a, b| a.0.cmp(&b.0));

    let mut candidate_reports: Vec<CandidateReport> = Vec::new();

    for (key, cand, support, fams) in ordered_votes {
        // The fact must be validated by at least one voting family that
        // separates under it, and must not break any family that separated
        // at baseline. Trials run under each family's own tables.
        if std::env::var("FXDBG").is_ok() {
            eprintln!("[gate] candidate key={} support={}", key, support);
        }
        // Candidate call names (trigger + guard), a family whose variants
        // never call any of them cannot change separation under this fact,
        // so keep its baseline verdict without re-scanning.
        let cand_calls: Vec<&str> = match &cand {
            Candidate::Sink { call, .. } => vec![call.as_str()],
            Candidate::Sanitizer { call, .. } => vec![call.as_str()],
            Candidate::Check {
                call, unless_guard, ..
            } => match unless_guard {
                Some(g) => vec![call.as_str(), g.as_str()],
                None => vec![call.as_str()],
            },
            // Trigger plus every requirement's call names: a family whose
            // variants never touch any of them cannot change separation.
            Candidate::Policy { call, require, .. } => {
                let mut calls = vec![call.as_str()];
                for req in require {
                    for name in req.call_names() {
                        if !calls.contains(&name) {
                            calls.push(name);
                        }
                    }
                }
                calls
            }
            Candidate::MemoryContract { name, .. } => vec![name.as_str()],
            Candidate::WeakCrypto { fact } => vec![fact.call.as_str()],
            Candidate::GuardBypass { fact } => {
                let mut calls = Vec::new();
                for c in &fact.containment_callees {
                    calls.push(c.as_str());
                }
                for s in &fact.credential_sinks {
                    calls.push(s.as_str());
                }
                calls
            }
            Candidate::SchemaPolicy { fact } => {
                let mut calls = Vec::new();
                for b in &fact.builders {
                    calls.push(b.as_str());
                }
                for e in &fact.enforcers {
                    calls.push(e.as_str());
                }
                for k in &fact.bound_keywords {
                    calls.push(k.as_str());
                }
                calls
            }
            // The prover rule fires on allocation shapes, not a named call:
            // empty = always relevant, every family re-checked for
            // regression under this fact.
            Candidate::IntegerOverflowRule { .. } => Vec::new(),
        };

        let mut reject: Option<String> = None;
        // Existential vote: at least one voting family must separate under
        // the fact. The old rule required EVERY voting family to separate
        // (`voted && !sep` -> reject), which let a voter whose own baseline
        // never separates (blind positive, noisy negative) permanently veto
        // the fact its sibling family needs - it can never confirm anything,
        // so it must not be able to block anything either. No voter
        // separating still rejects: an unvalidated fact must not publish.
        let mut any_voter_separates = false;
        let mut first_failing_voter: Option<(String, bool, bool)> = None;
        for p in &prepared {
            let (f_config, f_builtin) = &fam_tables[&p.id];
            let voted = fams.contains(&p.id);
            let relevant =
                voted || cand_calls.is_empty() || cand_calls.iter().any(|c| p.calls.contains(*c));
            let sep = if relevant {
                let mut trial = f_builtin.clone();
                apply_candidate(&mut trial, &cand);
                p.separates(f_config, &trial)
            } else {
                baseline.get(&p.id).map(|b| b.separates).unwrap_or(false)
            };
            if voted {
                if sep {
                    any_voter_separates = true;
                } else if first_failing_voter.is_none() {
                    // Remember which side still fails: "does not separate"
                    // alone cannot be acted on in the learn report.
                    let mut trial = f_builtin.clone();
                    apply_candidate(&mut trial, &cand);
                    let (pos_alerts, neg_alerts) = p.alert_flags(f_config, &trial);
                    first_failing_voter = Some((p.id.clone(), pos_alerts, neg_alerts));
                }
            } else if baseline.get(&p.id).map(|b| b.separates).unwrap_or(false) && !sep {
                // Cross-family regression: the fact broke a previously
                // separating family. Reject the fact (shape-thinking creep).
                let mut trial = f_builtin.clone();
                apply_candidate(&mut trial, &cand);
                let (pos_alerts, neg_alerts) = p.alert_flags(f_config, &trial);
                reject = Some(format!(
                    "cross-family regression: '{}' separated at baseline but not under this \
                     fact (positive_alerts={pos_alerts}, negative_alerts={neg_alerts})",
                    p.id
                ));
                break;
            }
        }
        if reject.is_none() && !any_voter_separates {
            reject = Some(match first_failing_voter {
                Some((id, pos_alerts, neg_alerts)) => format!(
                    "no voting family separates under this fact ('{id}' \
                     positive_alerts={pos_alerts}, negative_alerts={neg_alerts})"
                ),
                None => "no voting family could validate this fact".to_string(),
            });
        }
        if let Some(reason) = reject {
            if std::env::var("FXDBG").is_ok() {
                eprintln!("[gate] REJECT key={key} support={support} reason={reason}");
            }
            candidate_reports.push(CandidateReport {
                key: key.clone(),
                support,
                voted_by: fams.clone(),
                verdict: "rejected",
                reason: Some(reason),
            });
            continue;
        }
        if std::env::var("FXDBG").is_ok() {
            eprintln!("[gate] PUBLISH key={key} support={support}");
        }
        candidate_reports.push(CandidateReport {
            key: key.clone(),
            support,
            voted_by: fams.clone(),
            verdict: "published",
            reason: None,
        });

        apply_candidate(&mut learned, &cand);
        let entry = cand.to_learned_entry();

        published.push(LearnedFact {
            entry,
            support,
            status: if support >= 2 {
                "confirmed"
            } else {
                "provisional"
            }
            .into(),
            families: fams,
        });
    }

    emit_learn_report(
        families,
        &prepared,
        &baseline,
        &family_notes,
        &candidate_reports,
        &published,
    );

    published.sort_by(|a, b| {
        let ka = fact_key(&a.entry);
        let kb = fact_key(&b.entry);
        ka.cmp(&kb)
    });
    (learned, published)
}

/// Baseline separation evidence for one family (built-in tables only).
#[derive(Debug, Clone, Copy, Serialize)]
struct Baseline {
    positive_alerts: bool,
    negative_alerts: bool,
    separates: bool,
}

/// One candidate's journey through the replay gate. A rejected candidate
/// used to vanish with no output at all; `reason` is why it vanished.
#[derive(Debug, Clone, Serialize)]
struct CandidateReport {
    key: String,
    support: u32,
    voted_by: Vec<String>,
    verdict: &'static str,
    reason: Option<String>,
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
fn emit_learn_report(
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
