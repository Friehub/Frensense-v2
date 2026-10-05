// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! One reporting policy for every consumer surface (audit runner, MCP
//! tools; the LSP reports everything the engine flags).
//!
//! The engine emits verdicts; what becomes a *reported* advisory is
//! consumer policy (ENGINE_PURITY_REFACTOR 1.3). This module is the only
//! place that answers
//!
//! 1. which engine findings become advisories ([`reports_finding`]), and
//! 2. which advisories survive the severity/confidence floor ([`apply`]).
//!
//! `reporter` renders what survives; nothing else filters. Distinct from
//! [`crate::reporter`], which is presentation, not policy.

use crate::{Advisory, Severity};
use frensense_engine::analysis::taint::engine::{BackwardVerdict, SinkFinding};

/// Engine output that becomes an advisory: a vulnerable verdict on a
/// dangerous sink slot (sink-signature aware).
///
/// `alert` is `None` exactly when the slot is a safe channel - the engine
/// already evaluated per-slot danger (`jwt.verify(token, secret)` slot 1 =
/// secret, `query(sql, params)` slot 1+ = binding channel). A
/// [`BackwardVerdict::Vulnerable`] verdict on a non-dangerous slot must
/// not become an advisory.
#[must_use]
pub fn reports_finding(f: &SinkFinding) -> bool {
    f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some()
}

/// Apply the reporting floor: drop advisories below `min_confidence` or
/// under the severity floor (`None` = every tier; `Some(Severity::Info)`
/// is the no-op floor, so tool surfaces that default to `"info"` pass
/// everything through).
#[must_use]
pub fn apply(
    advisories: Vec<Advisory>,
    min_confidence: f64,
    severity_floor: Option<Severity>,
) -> Vec<Advisory> {
    advisories
        .into_iter()
        .filter(|a| a.confidence >= min_confidence)
        .filter(|a| severity_floor.is_none_or(|floor| a.severity.meets_threshold(floor)))
        .collect()
}
