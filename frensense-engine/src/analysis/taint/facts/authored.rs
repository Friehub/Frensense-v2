// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! `AuthoredPolicyEntry`: hand-authored policy rules persisted in a
//! bundle's `policy_pack` section (this module keeps only the entry type;
//! the table itself lives in `table.rs`, the learned entries in
//! `entries.rs`).

use super::*;

/// One hand-authored rule as persisted in a bundle's `policy_pack` section
/// (`.frc` v5). The section is reserved (D2 cancelled: corpus-only
/// authoring); presence in the section is what marks an entry's
/// provenance [`Provenance::Authored`], mirroring `learned_facts` ->
/// [`Provenance::Learned`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthoredPolicyEntry {
    /// A generalized co-occurrence policy: same fields as [`PolicyFact`],
    /// carried whole so the author's severity/message travel with it.
    Policy(PolicyFact),
    /// An allocation-size integer-overflow rule: same fields as
    /// [`LearnedFactEntry::IntegerOverflowRule`] (the hand-authored
    /// precedent: `[frensense] wrap-max:` corpus metadata).
    IntegerOverflowRule {
        rule: String,
        wrap_threshold: u128,
        severity: String,
        message: String,
    },
}
