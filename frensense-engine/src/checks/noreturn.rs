// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

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
pub fn is_noreturn(func: &str) -> bool {
    NORETURN.contains(&last_segment(func))
}

/// True if the block contains a call that never returns.
pub fn block_diverges(block: &BasicBlock) -> bool {
    block.instructions.iter().any(|i| match i {
        Instruction::CallStatic { func, .. } => is_noreturn(func),
        _ => false,
    })
}
