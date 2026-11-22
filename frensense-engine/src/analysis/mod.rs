// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Analysis engines: the consumers of the IR and program graph.
//!
//! * [`taint`], the demand-driven backward taint engine, its fact table,
//!   and context sensitivity.
//! * [`forward`], the whole-program value-flow structure: per-function SVFGs
//!   linked by explicit interprocedural edges, with the bottom-up
//!   compositional `TaintSummary`s that suppress the conservative
//!   pass-through edge a known callee replaces.

pub mod forward;
pub mod taint;
pub mod value;

#[cfg(test)]
mod value_tests;
