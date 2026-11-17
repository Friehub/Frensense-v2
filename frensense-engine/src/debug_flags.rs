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
//! * `FRENSdbg_STATIC`    - harness-level static-analysis trace
//! * `FRENSdbg_PTS`       - points-to fixed-point cost (passes, set sizes)
//! * `FRENSdbg_MEM`       - phase boundary RSS + graph sizes (memory attribution)
//! * `FRENSdbg_CAPS`      - announce each safety-cap firing once per scan
//! * `FRENSdbg_CHECKS`    - announce learned-check path divergences

use std::ffi::OsString;
use std::sync::OnceLock;

/// Cached per-process debug flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DebugFlags {
    /// `FRENSdbg_WALK`: trace every node visit in the backward engine.
    pub walk: bool,
    /// `FRENSdbg_DEADEND`: trace dead-end classification decisions.
    pub deadend: bool,
    /// `FRENSdbg_UNRES`: trace unresolvable-node reasoning.
    pub unres: bool,
    /// `FRENSdbg_IS_SOURCE`: trace source matching in the forward engine.
    pub is_source: bool,
    /// `FRENSdbg_STATIC`: harness-level static-analysis trace.
    pub static_trace: bool,
    /// `FRENSdbg_PTS`: points-to fixed-point cost (passes, set sizes).
    pub pts: bool,
    /// `FRENSdbg_MEM`: phase-boundary resident memory and graph sizes.
    pub mem: bool,
}

static FLAGS: OnceLock<DebugFlags> = OnceLock::new();

/// `FRENSdbg_CAPS`, kept out of [`DebugFlags`] so adding the flag does not
/// change the shape of that public struct (an additive method instead).
static CAPS: OnceLock<bool> = OnceLock::new();

/// `FRENSdbg_CHECKS`, kept out of [`DebugFlags`] for the same reason.
static CHECKS: OnceLock<bool> = OnceLock::new();

impl DebugFlags {
    /// Install the process-wide flags by querying the caller's lookup for
    /// each `FRENSdbg_*` name. The first install wins; once [`Self::get`]
    /// has cached a value (any earlier call), later installs are ignored -
    /// binaries call this as the first statement of `main`.
    pub fn install_from(lookup: impl Fn(&'static str) -> Option<OsString>) {
        let flags = DebugFlags {
            walk: lookup("FRENSdbg_WALK").is_some(),
            deadend: lookup("FRENSdbg_DEADEND").is_some(),
            unres: lookup("FRENSdbg_UNRES").is_some(),
            is_source: lookup("FRENSdbg_IS_SOURCE").is_some(),
            static_trace: lookup("FRENSdbg_STATIC").is_some(),
            pts: lookup("FRENSdbg_PTS").is_some(),
            mem: lookup("FRENSdbg_MEM").is_some(),
        };
        // The separate flags follow the same first-install-wins rule: do not
        // set them when `get()` already initialized the shared flags.
        if FLAGS.set(flags).is_ok() {
            let _ = CAPS.set(lookup("FRENSdbg_CAPS").is_some());
            let _ = CHECKS.set(lookup("FRENSdbg_CHECKS").is_some());
        }
    }

    /// `FRENSdbg_CAPS`: announce each safety-cap firing once per scan.
    ///
    /// Kept separate from [`DebugFlags::get`] so the public struct keeps its
    /// shape; like the other flags, the first [`Self::install_from`] wins.
    #[must_use]
    pub(crate) fn caps_enabled() -> bool {
        *CAPS.get_or_init(|| false)
    }

    /// `FRENSdbg_CHECKS`: report findings that only one of the two
    /// learned-check evaluation paths produced.
    #[must_use]
    pub(crate) fn checks_enabled() -> bool {
        *CHECKS.get_or_init(|| false)
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
