// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Bundle construction: corpus pairs → replay-verified facts → `.frc` bytes.

use crate::fact_extract::{extract_facts, group_families};
use crate::format::{write_bundle, BundlePattern, BundlePayloadV5};

/// §9 pipeline: corpus pairs → replay-verified learned facts → bundle bytes.
///
/// Returns the bundle plus a summary of the published facts for reporting.
pub fn build_facts_bundle(
    corpus_dir: &std::path::Path,
) -> Result<(Vec<u8>, Vec<crate::fact_extract::LearnedFact>), String> {
    let families = group_families(corpus_dir)?;
    eprintln!(
        "[facts] {} families grouped from {}",
        families.len(),
        corpus_dir.display()
    );

    let (learned_table, published) = extract_facts(&families);

    // Payload: one metadata pattern per family + the published facts.
    let entries: Vec<frensense_engine::analysis::taint::facts::LearnedFactEntry> =
        published.iter().map(|f| f.entry.clone()).collect();

    // One advisory pattern per family, sorted by id for a deterministic
    // payload. Metadata comes from the family's `[frensense]` comment block
    // (parsed during grouping); families without a block ship all-None.
    let mut family_ids: Vec<String> = families.iter().map(|f| f.id.clone()).collect();
    family_ids.sort();
    let mut patterns: Vec<BundlePattern> = Vec::with_capacity(family_ids.len());
    let empty = crate::fact_extract::FamilyMetadata::default();
    for id in &family_ids {
        let family = families.iter().find(|f| f.id == *id);
        let meta = family.map(|f| &f.metadata).unwrap_or(&empty);
        patterns.push(BundlePattern {
            id: id.clone(),
            observation: meta.observation.clone(),
            impact: meta.impact.clone(),
            improvement: meta.improvement.clone(),
            cwe: meta.cwe.clone(),
            cvss: meta.cvss,
            owasp: meta.owasp.clone(),
            severity: meta.severity.clone(),
        });
    }

    let count = entries.len().max(patterns.len()) as u32;
    // v5 payload; `policy_pack` fills once `--policy` ingestion lands (5.1).
    let payload = BundlePayloadV5 {
        patterns,
        learned_facts: entries,
        policy_pack: Vec::new(),
    };
    let _ = learned_table;
    let bytes = write_bundle(&payload, count)?;
    Ok((bytes, published))
}
