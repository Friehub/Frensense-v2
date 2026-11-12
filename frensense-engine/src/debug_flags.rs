// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Debug-tracing flags, installed once per process by the binary.
//!
//! Analysis hot loops (BFS over the value-flow graph) consult these flags
//! per node; [`DebugFlags::get`] is a struct copy (no env lookup, no lock
//! on the read path). The engine never reads the process environment: the
//! binary that owns the process calls [`DebugFlags::install_from`] at
//! startup with its own environment lookup.
//!
//! Flags (all off by default):
//! * `FRENSdbg_WALK`      - trace every BFS node visit in the backward engine
//! * `FRENSdbg_DEADEND`   - trace dead-end classification decisions
//! * `FRENSdbg_UNRES`     - trace unresolvable-node reasoning
//! * `FRENSdbg_IS_SOURCE` - trace source-matching in the forward engine
//! * `FRENSdbg_STATIC`    - harness-level static-analysis trace//! * `FRENSdbg_PTS`      - points-to fixed-point cost (passes, set sizes)
//! * `FRENSdbg_MEM`      - phase boundary RSS + graph sizes (memory attribution)

use std::ffi::OsString;
use std::sync::OnceLock;

/// Cached per-process debug flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DebugFlags {
    pub walk: bool,
    pub deadend: bool,
    pub unres: bool,
    pub is_source: bool,
    pub static_trace: bool,
    pub pts: bool,
    pub mem: bool,
}

static FLAGS: OnceLock<DebugFlags> = OnceLock::new();

impl DebugFlags {
    /// Install the process-wide flags by querying the caller's lookup for
    /// each `FRENSdbg_*` name. The first install wins; once [`Self::get`]
    /// has cached a value (any earlier call), later installs are ignored -
    /// binaries call this as the first statement of `main`.
    pub fn install_from(lookup: impl Fn(&'static str) -> Option<OsString>) {
        let _ = FLAGS.set(DebugFlags {
            walk: lookup("FRENSdbg_WALK").is_some(),
            deadend: lookup("FRENSdbg_DEADEND").is_some(),
            unres: lookup("FRENSdbg_UNRES").is_some(),
            is_source: lookup("FRENSdbg_IS_SOURCE").is_some(),
            static_trace: lookup("FRENSdbg_STATIC").is_some(),
            pts: lookup("FRENSdbg_PTS").is_some(),
            mem: lookup("FRENSdbg_MEM").is_some(),
        });
    }

    /// The installed flags (all-off default until [`Self::install_from`]
    /// runs); subsequent calls are a cheap struct copy.
    pub fn get() -> Self {
        *FLAGS.get_or_init(DebugFlags::default)
    }
}

/// Resident set size of the current process, in KiB (0 when unreadable).
///
/// Used only by the `FRENSdbg_MEM` phase probes: memory attribution for a
/// whole-program scan has to come from the process itself, since no external
/// profiler can attach in a restricted-ptrace environment.
#[must_use]
pub fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|p| p.parse::<u64>().ok())
        })
        .unwrap_or(0)
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
