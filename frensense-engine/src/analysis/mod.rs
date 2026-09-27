// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Analysis engines: the consumers of the IR and program graph.
//!
//! * [`taint`], the demand-driven backward taint engine, its fact table,
//!   and context sensitivity.
//! * [`forward`], the interprocedural forward engine (BFS over the whole
//!   program value-flow structure; its bottom-up compositional `TaintSummary`s
//!   replace the old standalone summary module).

pub mod forward;
pub mod taint;

#[cfg(test)]
mod forward_tests;
#[cfg(test)]
mod svfg_tests;
