// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

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

/// Insert `fact` into a provenance-tagged table, or resolve a key collision.
///
/// `same_key` says whether an existing entry is the same fact. On a collision
/// the higher-ranked provenance wins (`Spec < Authored < Learned`) and a tie
/// keeps the existing entry, so merging is order-independent across tiers.
/// This is the one implementation of that rule; every table that ranks facts
/// by provenance goes through it.
pub(crate) fn upsert_by_provenance<T>(
    items: &mut Vec<(T, Provenance)>,
    fact: T,
    provenance: Provenance,
    same_key: impl Fn(&T, &T) -> bool,
) {
    if let Some(existing) = items.iter_mut().find(|(e, _)| same_key(e, &fact)) {
        if provenance > existing.1 {
            *existing = (fact, provenance);
        }
    } else {
        items.push((fact, provenance));
    }
}

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

pub mod authored;
/// Seeding a taint config and fact table from language-keyed pack entries.
pub mod config;
pub mod entries;
/// The fact data types: sink signatures, sanitizer, check, policy and grammar facts.
pub mod kinds;
/// Lookup of sink signatures for a call site's import origin.
pub mod signatures;
/// The merged [`FactTable`] consulted during analysis.
pub mod table;
pub mod vocabulary;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod teachable_subsystem_tests;

pub use authored::*;
pub use config::*;
pub use entries::*;
pub use kinds::*;
pub use table::*;
pub use vocabulary::*;

/// The default pack's entries as the engine decodes them (bytes cross the
/// engine<->packgen dependency edge).
///
/// The pack crosses that edge as raw bytes: bundler-typed or engine-typed
/// values returned through the bundler would resolve to a duplicate
/// `frensense-engine` crate unit.
#[cfg(test)]
pub fn default_pack_entries() -> Vec<LearnedFactEntry> {
    let bytes = frensense_packgen::default_pack_entry_bytes();
    bincode::deserialize(&bytes).expect("default pack entries decode")
}

/// Production tables for a set of extensions (spec seed -> default pack ->
/// pack language sections), exactly as `build_spec_tables` assembles them.
#[cfg(test)]
pub(crate) fn seeded_tables<'a>(
    exts: impl IntoIterator<Item = &'a str>,
) -> (crate::analysis::taint::config::TaintConfig, FactTable) {
    config::tables_from_exts_with_pack(exts, &default_pack_entries())
}

/// Production tables for every registered language: extensions collected
/// from `all_specs()` in registry order, which is the same order the
/// per-spec merge uses (extensions are disjoint across fact languages;
/// a container spec like Vue shares its code language's facts).
#[cfg(test)]
pub(crate) fn seeded_tables_all() -> (crate::analysis::taint::config::TaintConfig, FactTable) {
    let exts: Vec<&str> = frensense_lang::all_specs()
        .flat_map(|s| s.extensions().iter().copied())
        .collect();
    let from_exts: std::collections::BTreeSet<&str> =
        config::languages_for_exts(exts.iter().copied())
            .into_iter()
            .collect();
    let from_specs: std::collections::BTreeSet<&str> = frensense_lang::all_specs()
        .map(|s| s.fact_language())
        .collect();
    debug_assert_eq!(
        from_exts, from_specs,
        "extensions must cover every fact language"
    );
    seeded_tables(exts)
}
