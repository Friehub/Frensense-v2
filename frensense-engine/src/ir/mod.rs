// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The IR layer: pure data and the compiler frontend.
//!
//! * [`function`], `FunctionIR`, `Instruction`, `Operand`, `VarMetadata`:
//!   the typed representation every analysis consumes.
//! * [`lowering`], tree-sitter AST → `FunctionIR` (via `frensense-lang`).
//! * [`ssa`], Memory SSA construction.
//! * `control`, dominators / post-dominators / control dependence.
//!
//! This layer knows nothing about taint, checks, or program graphs, it is
//! the reusable compiler frontend.

pub(crate) mod control;
pub mod function;
pub mod lowering;
pub mod ssa;

#[cfg(test)]
mod tests;
