// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Task 4.3 completion: **sink signatures**, per-API argument-position facts.
//!
//! A blanket "every argument of a sink is dangerous" model causes the largest
//! FP class in the e2e report: `pool.query(sql, [email])` (parameterized,
//! safe) alerts because the tainted value sits in arg 1, the *safe* channel.
//!
//! A [`SinkSignature`] fixes this without engine surgery: it lists which
//! argument slots of a named call are dangerous, and whether a *binding*
//! parameter array (the parameterized-query safe channel) must be absent for
//! the call to be dangerous.
//!
//! Signatures come from the **fact tables** (`frensense-lang` built-ins merged
//! with bundler-extracted learned facts via a [`FactTable`]). The engine only
//! consumes them; updating a framework never touches engine code.

/// Where the knowledge behind a fact or finding came from. Stored
/// per-entry in the [`FactTable`] so checks report the real origin of the
/// knowledge that fired (spec seed vs bundle) instead of guessing.
///
/// Derives `Ord` in declaration order, which doubles as the merge
/// precedence ladder (Phase 5.3): [`Provenance::Spec`] <
/// [`Provenance::Authored`] < [`Provenance::Learned`] - a merge keeps the
/// higher-ranked entry on collision and the existing one on a tie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Provenance {
    /// Built-in seed knowledge shipped with the specs.
    Spec,
    /// Structured co-occurrence policy (the authored-policy shape).
    Authored,
    /// Corpus-learned fact supplied by a bundle.
    Learned,
}

pub mod config;
pub mod kinds;
pub mod signatures;
pub mod table;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod teachable_subsystem_tests;

pub use config::*;
pub use kinds::*;
pub use table::*;

/// The shipped default-pack fact table exactly as every consumer sees it
/// ([`LearnedFactEntry`]s -> [`FactTable`] under [`Provenance::Spec`]).
/// Engine tests merge this instead of relying on deleted spec seeds
/// (Phase 6.1).
///
/// The pack crosses the engine<->bundler dev-dependency cycle as raw
/// bytes: bundler-typed or engine-typed values returned through the
/// bundler would resolve to a duplicate `frensense-engine` crate unit.
#[cfg(test)]
pub fn default_pack_table() -> FactTable {
    fact_table_from_entries_with(&default_pack_entries(), Provenance::Spec)
}

/// The default pack's entries as the engine decodes them (bytes cross the
/// bundler dev-dependency cycle; see [`default_pack_table`]).
#[cfg(test)]
pub fn default_pack_entries() -> Vec<LearnedFactEntry> {
    let bytes = frensense_bundler::format::default_pack_entry_bytes();
    bincode::deserialize(&bytes).expect("default pack entries decode")
}

/// Production tables for a set of extensions (spec seed -> default pack ->
/// pack language sections), exactly as `build_spec_tables` assembles them.
#[cfg(test)]
pub fn seeded_tables<'a>(
    exts: impl IntoIterator<Item = &'a str>,
) -> (crate::analysis::taint::config::TaintConfig, FactTable) {
    config::tables_from_exts_with_pack(exts, &default_pack_entries())
}

/// Production tables for every registered language: extensions collected
/// from `all_specs()` in registry order, which is the same order the
/// per-spec merge uses (extensions are disjoint across specs).
#[cfg(test)]
pub fn seeded_tables_all() -> (crate::analysis::taint::config::TaintConfig, FactTable) {
    let exts: Vec<&str> = frensense_lang::all_specs()
        .flat_map(|s| s.extensions().iter().copied())
        .collect();
    debug_assert_eq!(
        config::languages_for_exts(exts.iter().copied()).len(),
        frensense_lang::all_specs().count(),
        "extensions must cover every registered language exactly once"
    );
    seeded_tables(exts)
}
