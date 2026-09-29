// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::collections::BTreeSet;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::FactTable;
use frensense_engine::scan;

use super::call_analysis::collect_calls;
use super::family::Family;

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
pub struct PreparedFamily {
    pub id: String,
    pub pos: scan::PreparedProgram,
    pub neg: scan::PreparedProgram,
    /// All call names appearing in any variant, used to skip gate trials
    /// for facts that cannot affect this family.
    pub calls: BTreeSet<String>,
}

impl PreparedFamily {
    pub fn new(f: &Family) -> Result<Self, String> {
        let pos = scan::prepare(&f.positives)?;
        let neg = scan::prepare(&f.negatives)?;
        let mut calls = BTreeSet::new();
        calls.extend(
            collect_calls(&f.positives)
                .keys()
                .cloned()
                .chain(collect_calls(&f.negatives).keys().cloned()),
        );
        Ok(Self {
            id: f.id.clone(),
            pos,
            neg,
            calls,
        })
    }

    /// Family separation under a fact table. Reuses the lowered IRs;
    /// each call re-runs the taint engine + checker only.
    pub fn separates(&self, config: &TaintConfig, facts: &FactTable) -> bool {
        let pos = scan::scan_prepared(&self.pos, config, facts);
        let neg = scan::scan_prepared(&self.neg, config, facts);
        pos.has_alert() && !neg.has_alert()
    }
}

/// Family separation check under a fact table (single-shot variant; the
/// gate uses the pre-lowered [`PreparedFamily::separates`] instead).
pub fn separates(family: &Family, config: &TaintConfig, facts: &FactTable) -> bool {
    let pos = scan_variant(&family.positives, config, facts);
    let neg = scan_variant(&family.negatives, config, facts);
    pos.has_alert() && !neg.has_alert()
}
