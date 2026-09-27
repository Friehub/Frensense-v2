// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Debug-tracing flags, read from the environment once per process.
//!
//! Analysis hot loops (BFS over the value-flow graph) previously consulted
//! `std::env::var` per node to decide whether to emit a trace line. An env
//! lookup is a lock + linear scan per call; at millions of nodes per scan
//! that is measurable overhead in the engine's hottest path, all to support
//! a diagnostic nobody sets in production. [`DebugFlags::get`] reads the
//! environment exactly once and caches the result for the process lifetime.
//!
//! Flags (all off by default):
//! * `FRENSdbg_WALK`      - trace every BFS node visit in the backward engine
//! * `FRENSdbg_DEADEND`   - trace dead-end classification decisions
//! * `FRENSdbg_UNRES`     - trace unresolvable-node reasoning
//! * `FRENSdbg_IS_SOURCE` - trace source-matching in the forward engine
//! * `FRENSdbg_STATIC`    - harness-level static-analysis trace

use std::sync::OnceLock;

/// Cached per-process debug flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DebugFlags {
    pub walk: bool,
    pub deadend: bool,
    pub unres: bool,
    pub is_source: bool,
    pub static_trace: bool,
}

impl DebugFlags {
    /// Read `FRENSdbg_*` environment variables once; subsequent calls are a
    /// cheap struct copy.
    pub fn get() -> Self {
        static FLAGS: OnceLock<DebugFlags> = OnceLock::new();
        *FLAGS.get_or_init(|| DebugFlags {
            walk: std::env::var_os("FRENSdbg_WALK").is_some(),
            deadend: std::env::var_os("FRENSdbg_DEADEND").is_some(),
            unres: std::env::var_os("FRENSdbg_UNRES").is_some(),
            is_source: std::env::var_os("FRENSdbg_IS_SOURCE").is_some(),
            static_trace: std::env::var_os("FRENSdbg_STATIC").is_some(),
        })
    }
}

/// Trace helper: `dbg_trace!(flags.walk, "fmt args...")`.
///
/// The format arguments are only evaluated when the flag is on, so building
/// trace strings costs nothing when tracing is off.
#[macro_export]
macro_rules! dbg_trace {
    ($on:expr, $($arg:tt)*) => {
        if $on {
            eprintln!($($arg)*);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_consistent_value() {
        let a = DebugFlags::get();
        let b = DebugFlags::get();
        assert_eq!(a, b);
    }
}
