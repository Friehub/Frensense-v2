// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Program-graph construction: def-use made explicit and interprocedural.
//!
//! * [`svfg`], per-function sparse value-flow graph.
//! * `callgraph`, dispatch resolution (aliases, methods, re-exports).
//! * `heap`, points-to analysis (Andersen, inclusion-based).
//! * `steensgaard`, unification points-to (near-linear; R4 phase 1).
//!
//! Only `svfg` is part of the crate's published surface; the rest build it.

pub(crate) mod callgraph;
pub(crate) mod heap;
pub(crate) mod module;
pub(crate) mod steensgaard;
pub mod svfg;

#[cfg(test)]
mod callgraph_query_tests;
mod callgraph_tests;
#[cfg(test)]
mod callgraph_this_class_tests;
#[cfg(test)]
mod heap_tests;
#[cfg(test)]
mod steensgaard_tests;
#[cfg(test)]
mod two_phase_tests;
