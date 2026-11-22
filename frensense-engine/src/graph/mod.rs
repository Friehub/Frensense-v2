// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Program-graph construction: def-use made explicit and interprocedural.
//!
//! * [`svfg`], per-function sparse value-flow graph.
//! * [`callgraph`], dispatch resolution (aliases, methods, re-exports).
//! * [`heap`], points-to analysis (Andersen, inclusion-based).
//! * `steensgaard`, unification points-to (near-linear; R4 phase 1).

pub mod callgraph;
pub mod heap;
pub mod module;
pub(crate) mod steensgaard;
pub mod svfg;

#[cfg(test)]
mod callgraph_tests;
#[cfg(test)]
mod heap_tests;
#[cfg(test)]
mod steensgaard_tests;
#[cfg(test)]
mod two_phase_tests;
