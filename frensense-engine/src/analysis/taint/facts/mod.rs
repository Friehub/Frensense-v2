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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
