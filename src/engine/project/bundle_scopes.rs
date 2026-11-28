// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Applying a loaded bundle's payload side tables to the installed facts.
//!
//! Some published engine fields have no `LearnedFactEntry` variant to ride
//! on (payload encoding is positional, so adding a field would break every
//! older bundle). Those ride in versioned tables beside the facts and are
//! applied here, once, so a consumer cannot apply half a fact: sanitizer
//! class/slot scopes (v8/v9) and store-sink base kinds (v10).

use frensense_bundler::format::LoadedBundle;
use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::FactTable;

/// Join the bundle's side tables onto the facts installed from it, and widen
/// the taint config with the bundle's learned source patterns.
pub(super) fn apply(facts: &mut FactTable, config: &mut TaintConfig, loaded: &LoadedBundle) {
    for s in loaded.effective_sanitizer_scopes() {
        facts.qualify_sanitizer(s.call, s.package, s.classes, s.args);
    }
    apply_pack(facts, loaded);
    for pattern in facts.source_patterns() {
        config.sources.insert(pattern.to_string());
    }
}

/// Apply a pack's store-sink base kinds to the facts installed from it.
///
/// The embedded default pack declares hints for the DOM store sinks, so the
/// same table must be joined here as for a consumer bundle; skipping it leaves
/// a bare `x.innerHTML = t` alerting on any receiver.
pub(super) fn apply_pack(facts: &mut FactTable, pack: &LoadedBundle) {
    facts.apply_sink_base_kinds(
        pack.sink_base_kinds
            .iter()
            .map(|s| (s.call.as_str(), s.package.as_deref(), s.kinds.as_slice())),
    );
}
