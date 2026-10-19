// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Reporting policy: which engine findings become advisories, and which
//! survive the severity/confidence floor (ENGINE_PURITY_REFACTOR 1.3).
//!
//! The engine emits verdicts; what becomes a *reported* advisory is
//! consumer policy. This module is the only place that answers
//!
//! 1. which engine findings become advisories ([`reports_finding`]), and
//! 2. which advisories survive the severity/confidence floor ([`apply`]).
//!
//! [`crate::reporter`] renders what survives; nothing else filters.
//! The `--explain` "why the engine stayed silent" map lives in
//! [`crate::explain`].

use crate::{Advisory, Profile, RuleTier, Severity};
use frensense_engine::analysis::taint::engine::{BackwardVerdict, SinkFinding};
use std::collections::BTreeMap;

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
/// everything through). Uses [`Profile::Default`].
#[must_use]
pub fn apply(
    advisories: Vec<Advisory>,
    min_confidence: f64,
    severity_floor: Option<Severity>,
) -> Vec<Advisory> {
    apply_with_profile(advisories, min_confidence, severity_floor, Profile::Default).0
}

/// Apply the reporting floor and active scan profile: drop advisories below
/// `min_confidence`, under `severity_floor`, or excluded by `profile`.
/// Returns the surviving advisories and the count of hidden findings by tier.
#[must_use]
pub fn apply_with_profile(
    advisories: Vec<Advisory>,
    min_confidence: f64,
    severity_floor: Option<Severity>,
    profile: Profile,
) -> (Vec<Advisory>, BTreeMap<RuleTier, usize>) {
    let mut kept = Vec::new();
    let mut hidden_by_tier = BTreeMap::new();

    for a in advisories {
        if !profile.includes_tier(a.tier) {
            *hidden_by_tier.entry(a.tier).or_insert(0) += 1;
            continue;
        }
        if a.confidence < min_confidence {
            continue;
        }
        if !severity_floor.is_none_or(|floor| a.severity.meets_threshold(floor)) {
            continue;
        }
        kept.push(a);
    }

    (kept, hidden_by_tier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn mock_advisory(tier: RuleTier, severity: Severity) -> Advisory {
        Advisory::bare(
            "test_finding",
            severity,
            crate::FileId(1),
            Path::new("test.py"),
            "test observation",
        )
        .with_tier(tier)
        .with_confidence(1.0)
    }

    #[test]
    fn default_profile_hides_hygiene_and_tracks_count() {
        let advisories = vec![
            mock_advisory(RuleTier::Stable, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
        ];

        let (reported, hidden) = apply_with_profile(advisories, 0.0, None, Profile::Default);
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].tier, RuleTier::Stable);
        assert_eq!(hidden.get(&RuleTier::Hygiene), Some(&2));
        assert_eq!(hidden.get(&RuleTier::Stable), None);
    }

    #[test]
    fn strict_profile_includes_hygiene() {
        let advisories = vec![
            mock_advisory(RuleTier::Stable, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
        ];

        let (reported, hidden) = apply_with_profile(advisories, 0.0, None, Profile::Strict);
        assert_eq!(reported.len(), 2);
        assert!(hidden.is_empty());
    }

    #[test]
    fn recommended_profile_includes_beta_only() {
        let advisories = vec![
            mock_advisory(RuleTier::Stable, Severity::Warning),
            mock_advisory(RuleTier::Beta, Severity::Warning),
            mock_advisory(RuleTier::Experimental, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
        ];

        let (reported, hidden) = apply_with_profile(advisories, 0.0, None, Profile::Recommended);
        assert_eq!(reported.len(), 2);
        assert_eq!(hidden.get(&RuleTier::Experimental), Some(&1));
        assert_eq!(hidden.get(&RuleTier::Hygiene), Some(&1));
    }
}
