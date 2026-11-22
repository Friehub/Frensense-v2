// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Calls that never return to their caller.
//!
//! A path that ends in `exit(1)` is not a function exit: the process (or the
//! thread) is gone, so nothing allocated on that path "leaks past the call".
//! Without this, every `if (!p) { perror(..); exit(1); }` after an
//! allocation reported the allocation (redis-cli: six `zrealloc` findings).
//!
//! The list is the libc/POSIX set that is noreturn by specification, so it is
//! language-level knowledge, not a per-project fact.

use crate::checks::last_segment;
use crate::ir::function::{BasicBlock, Instruction};

const NORETURN: &[&str] = &[
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "abort",
    "pthread_exit",
    "longjmp",
    "siglongjmp",
    "__builtin_unreachable",
    "__builtin_trap",
    "thr_exit",
];

/// True if `func` (last path segment) is a noreturn library call.
pub(crate) fn is_noreturn(func: &str) -> bool {
    NORETURN.contains(&last_segment(func))
}

/// True if the block contains a call that never returns.
pub(crate) fn block_diverges(block: &BasicBlock) -> bool {
    block.instructions.iter().any(|i| match i {
        Instruction::CallStatic { func, .. } => is_noreturn(func),
        _ => false,
    })
}

#[cfg(test)]
/// Assertions lifted from the doc examples of items that are now
/// crate-private; a doctest cannot see them.
mod doc_examples {
    #[test]
    fn doc_example_is_noreturn() {
        use crate::checks::noreturn::is_noreturn;

        assert!(is_noreturn("exit"));
        assert!(is_noreturn("libc::_exit")); // only the last path segment is compared
        assert!(!is_noreturn("printf"));
    }
}
