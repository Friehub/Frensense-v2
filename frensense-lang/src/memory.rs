// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Stack-allocator vocabulary (Phase 6.1 residual).
//!
//! The memory-function contracts, buffer builtins, and their capacity
//! types moved to `frensense-engine::analysis::taint::facts::kinds` with
//! their data living in the bundler's default-pack generator; only the
//! frame-lifetime stack vocabulary stays here, because a stack
//! allocator's lifetime is a language-mechanism property, not corpus
//! knowledge, and it still seeds through
//! [`LanguageSpec::known_stack_allocators`](crate::spec::LanguageSpec::known_stack_allocators).

/// Calls whose results live on the current stack frame, not the heap.
/// Declared here because the vocabulary owner is lang: their lifetime
/// ends with the frame by definition, so leak-style checkers must never
/// treat them as leakable allocations (spatial checks still track their
/// capacity like any other buffer).
pub static BOOTSTRAP_STACK_ALLOCATORS: &[&str] = &["alloca", "_alloca", "__builtin_alloca"];

/// Is `name` (bare, dotted, or `::`-qualified) a lang-declared stack
/// allocator?
pub fn is_stack_allocator(name: &str) -> bool {
    let s = name.rsplit('.').next().unwrap_or(name);
    let s = s.rsplit("::").next().unwrap_or(s);
    BOOTSTRAP_STACK_ALLOCATORS.iter().any(|a| *a == s)
}
