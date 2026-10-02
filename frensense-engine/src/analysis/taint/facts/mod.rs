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

pub mod config;
pub mod kinds;
pub mod signatures;
pub mod table;

/// Corpus-owned seed facts: deployment/deployment-specific knowledge that
/// is NOT language semantics, framework/session-store names, project
/// conventions, kept OUT of `frensense-lang` so the spec layer stays
/// general and the corpus stays ownable.
///
/// Loaded from a JSON file and merged over the spec-built fact table;
/// entries here win (they are more specific than any language default).
#[cfg(feature = "serialize")]
pub mod seed;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod teachable_subsystem_tests;

pub use config::*;
pub use kinds::*;
pub use table::*;
