// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Backward-exploration counters for one engine run.

/// Traversal statistics, proof of the demand-driven cost model.
///
/// `#[non_exhaustive]`: evolving metrics DTO; new counters are minor releases.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct BackwardStats {
    /// `(function, node)` pairs visited during backward exploration.
    pub nodes_visited: usize,
    /// Distinct functions entered (should be ≪ total functions on big repos).
    pub functions_visited: usize,
    /// Number of sink arguments explored.
    pub sink_args_explored: usize,
    /// Per-verdict counts.
    pub vulnerable: usize,
    /// Sink arguments judged sanitized.
    pub sanitized: usize,
    /// Sink arguments the walk could not decide.
    pub unknown: usize,
    /// Sink arguments with no path to a source.
    pub clean: usize,
}
