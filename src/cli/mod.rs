// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

#[cfg(test)]
#[path = "baseline_tests.rs"]
mod baseline_tests;
pub mod options;
pub mod reporting;
pub mod watch;
#[cfg(test)]
mod watch_tests;

pub use options::*;
pub use reporting::*;
pub use watch::{
    FileWatcher, POLL_INTERVAL, format_watch_finding, new_advisories, run_watch_loop,
    snapshot_mtimes,
};
