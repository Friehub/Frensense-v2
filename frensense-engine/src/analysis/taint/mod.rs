// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The demand-driven backward taint engine and its parameterization.
//!
//! * [`config`], `TaintConfig`: source/sink/sanitizer name sets.
//! * [`facts`], `FactTable`, `SinkSignature`, per-slot danger facts, and
//!   spec/bundle table construction.
//! * [`engine`], `BackwardTaintEngine`: sink-rooted backward traversal.

pub mod config;
pub mod engine;
pub mod facts;
pub mod path;
#[cfg(test)]
mod path_tests;
pub mod role;
#[cfg(test)]
mod sibling_path_tests;

#[cfg(test)]
mod engine_tests;
#[cfg(test)]
mod session_trust_tests;
