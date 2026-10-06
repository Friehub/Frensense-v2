// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! The embedded default pack (Phase 5.2 / decision D1, extended in Phase 6).
//!
//! `frensense-lang`'s bootstrap policy tables re-shipped as a `.frc`
//! bundle, embedded in the bundler and merged between the spec seed and
//! the consumer bundle (seeding order: spec -> default pack -> consumer,
//! last-wins). Both consumers - the bundler gate's per-family tables and
//! the CLI scan runner - merge it with [`Provenance::Spec`], so consumer
//! bundle facts still win and provenance reporting stays truthful.
//!
//! Since Phase 6.3a the pack is *generated* by the `frensense-packgen`
//! crate (which owns the vocabularies); this module only embeds the
//! committed asset via `include_bytes!` and parses it lazily. The drift
//! test lives in packgen; `packgen --check` guards it in CI.

use std::sync::OnceLock;

use super::types::{load_bundle, LoadedBundle};
use frensense_engine::analysis::taint::facts::LearnedFactEntry;

/// Whether `name` is one of the default pack's memory-contract functions:
/// proposals must not re-propose vocabulary the pack already ships.
/// Derived from the loaded pack (the shipped truth) rather than the
/// generator's source tables, so the two can never disagree.
pub fn is_pack_memory_builtin(name: &str) -> bool {
    default_pack()
        .learned_facts
        .iter()
        .any(|e| matches!(e, LearnedFactEntry::MemoryContract { name: n, .. } if n == name))
}

/// Bytes of the committed `assets/frensense-default.frc`.
pub fn default_bundle_bytes() -> &'static [u8] {
    include_bytes!("../../assets/frensense-default.frc")
}

/// The embedded default pack, parsed once. Panics only if the committed
/// asset is stale or corrupt - the drift test in this module keeps that
/// from reaching a release.
pub fn default_pack() -> &'static LoadedBundle {
    static PACK: OnceLock<LoadedBundle> = OnceLock::new();
    PACK.get_or_init(|| {
        load_bundle(default_bundle_bytes())
            .unwrap_or_else(|e| panic!("embedded default pack failed to load: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use frensense_engine::analysis::taint::config::TaintConfig;
    use frensense_engine::analysis::taint::facts::{
        apply_language_entries, FactTable, LearnedFactEntry,
    };

    /// The wildcard group installs before language groups, and a language
    /// absent from the scan's language set is filtered out entirely.
    #[test]
    fn language_entries_filter_by_language_with_wildcard_first() {
        let entries = vec![
            LearnedFactEntry::LanguageSink {
                language: "*".to_string(),
                call: "shared.eval".to_string(),
                role: "execution".to_string(),
            },
            LearnedFactEntry::LanguageSink {
                language: "go".to_string(),
                call: "os/exec.Command".to_string(),
                role: "execution".to_string(),
            },
        ];
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        apply_language_entries(&mut config, &mut facts, &entries, &["typescript"]);
        assert!(
            config.sinks.contains("eval"),
            "wildcard sink installs for any language"
        );
        assert!(
            !config.sinks.contains("Command"),
            "go-only sink filtered out of a typescript scan"
        );
    }
}
