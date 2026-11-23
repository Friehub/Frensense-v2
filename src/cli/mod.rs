// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

#[cfg(test)]
#[path = "baseline_tests.rs"]
mod baseline_tests;
pub mod engine_setup;
pub mod git;
pub mod options;
pub mod progress;
pub mod reporting;
pub mod watch;
#[cfg(test)]
mod watch_tests;

pub use engine_setup::configure_engine;
pub use options::*;
pub use progress::*;
pub use reporting::*;
pub use watch::{
    FileWatcher, POLL_INTERVAL, format_watch_finding, new_advisories, run_watch_loop,
    snapshot_mtimes,
};
