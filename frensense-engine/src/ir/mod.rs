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

/// Declared type the JSX lowering gives the props object it synthesizes.
///
/// It is a base *kind* for store-sink hints: an attribute written as
/// `<div dangerouslySetInnerHTML={{ __html: html }} />` reaches the same
/// property-write path as `el.innerHTML = html`, and this name lets a fact
/// require a JSX base instead of matching the attribute name alone.
pub const JSX_PROPS_BASE_KIND: &str = "JSXProps";

pub(crate) mod control;
pub mod function;
pub mod lowering;
pub mod ssa;

#[cfg(test)]
mod tests;
