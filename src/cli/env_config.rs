// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Ambient configuration, read in one place.
//!
//! `clippy.toml` bans `std::env::var` so configuration travels explicitly
//! instead of being read from the middle of the analysis. A frontend still has
//! to read the environment somewhere, and before this module four call sites
//! spelled the same three lines each. This is that one place: an empty value
//! counts as unset, so `FRENSENSE_CORPUS_BUNDLE=` behaves like an unset
//! variable instead of naming the empty path.

/// `FRENSENSE_CORPUS_BUNDLE`: a `.frc` rules bundle to load when no flag names
/// one.
#[must_use]
pub fn corpus_bundle() -> Option<String> {
    value("FRENSENSE_CORPUS_BUNDLE")
}

/// `FRENSENSE_TELEMETRY_PATHS`: how much of a path a telemetry payload keeps
/// (`absolute`, `relative` or `basename`).
#[must_use]
pub fn telemetry_paths() -> Option<String> {
    value("FRENSENSE_TELEMETRY_PATHS")
}

/// One non-empty environment value.
fn value(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|raw| !raw.trim().is_empty())
}
