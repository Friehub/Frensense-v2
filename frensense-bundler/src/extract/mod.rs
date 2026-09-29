// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Fact extraction from positive/negative corpus pairs (§9).
//!
//! Replaces the old shape/fingerprint pipeline. For every corpus family:
//!
//! 1. Scan positives and negatives through the **shared engine harness**
//!    (`engine::data_flow::scan`) under the built-in fact table.
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
pub use propose::propose;

/// Full extraction: propose per family -> replay-gate -> merged learned table.
pub fn extract_facts(
    families: &[Family],
    config: &TaintConfig,
    builtin: &FactTable,
) -> (FactTable, Vec<LearnedFact>) {
    // votes: candidate-key -> (support, families)
    let mut votes: FxHashMap<String, (Candidate, u32, Vec<String>)> = FxHashMap::default();

    // Pass 1: proposals per family (accumulate votes).
    for f in families {
        for c in propose(f, config, builtin) {
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
    // family (no re-lowering). Baseline separation is measured under the
    // built-in table; a candidate fact must (a) make (or keep) its voting
    // families separate and (b) NOT break any family that already separates
    // at baseline. Families that never separate under any table (corrupted
    // positives, see docs/E2E_REPORT.md §1b) are excluded from the
    // regression check: they can't be "broken" further, and gating on them
    // would reject every fact.
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

    let baseline: FxHashMap<String, bool> = prepared
        .iter()
        .map(|p| (p.id.clone(), p.separates(config, builtin)))
        .collect();

    let mut learned = FactTable::default();
    let mut published: Vec<LearnedFact> = Vec::new();

    for (key, (cand, support, fams)) in votes {
        let mut trial = builtin.clone();
        apply_candidate(&mut trial, &cand);

        // The fact must make each voting family separate (or keep it
        // separate), and must not break any family that separated at
        // baseline.
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
                calls
            }
        };

        let mut ok = true;
        for p in &prepared {
            let voted = fams.contains(&p.id);
            let relevant =
                voted || cand_calls.is_empty() || cand_calls.iter().any(|c| p.calls.contains(*c));
            let sep = if relevant {
                p.separates(config, &trial)
            } else {
                baseline.get(&p.id).copied().unwrap_or(false)
            };
            if voted && !sep {
                ok = false; // its own vote failed
                break;
            }
            if !voted && baseline.get(&p.id).copied().unwrap_or(false) && !sep {
                // Cross-family regression: the fact broke a previously
                // separating family. Reject the fact (shape-thinking creep).
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }

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
        let _ = key;
    }

    published.sort_by(|a, b| {
        let ka = fact_key(&a.entry);
        let kb = fact_key(&b.entry);
        ka.cmp(&kb)
    });
    (learned, published)
}
