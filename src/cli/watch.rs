// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Watch mode: poll a directory tree, re-scan files whose mtime changed,
//! and print only findings that are NEW since the previous run.
//!
//! Architecture split (deliberate): the watcher is a CLI delivery feature
//! over the existing scan API. The engine knows nothing about watching —
//! `Engine::run(path)` stays the only analysis entry point, invoked here
//! per changed file. This module owns three concerns, each independently
//! testable without filesystem events or a real engine:
//!
//! 1. [`snapshot_mtimes`] — the observed state (path → mtime seconds) using
//!    the same `collect_files` ignore rules as a normal scan;
//! 2. [`FileWatcher::changed_files`] — the diff between observations;
//! 3. [`new_advisories`] — fingerprint-set diff between scan rounds so a
//!    file whose findings didn't change is silent.
//!
//! Polling (500ms) rather than an inotify/FSEvents dependency: zero new
//! crates, deterministic in tests, and the per-file scan is fast enough
//! that re-stat-ing the tree is not the bottleneck. The upgrade path is
//! swapping [`snapshot_mtimes`] for a notify-debounced event source
//! without touching the loop below.

use crate::engine::files::collect_files;
use crate::Advisory;
use rustc_hash::FxHashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Poll interval between tree observations.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// One tree observation: supported files → mtime (second resolution).
/// Second resolution is deliberate: it matches what filesystems and git
/// guarantee, and sub-second churn within one poll tick collapses into a
/// single change detection on the next tick anyway.
pub fn snapshot_mtimes(
    root: &Path,
    language_filter: Option<&Vec<&'static str>>,
) -> FxHashMap<PathBuf, u64> {
    let mut snap = FxHashMap::default();
    for path in collect_files(root, language_filter) {
        if let Ok(meta) = std::fs::metadata(&path)
            && let Ok(mtime) = meta.modified()
            && let Ok(d) = mtime.duration_since(SystemTime::UNIX_EPOCH)
        {
            snap.insert(path, d.as_secs());
        }
    }
    snap
}

/// Rolling watcher state: the last observation.
#[derive(Default)]
pub struct FileWatcher {
    last: FxHashMap<PathBuf, u64>,
}

impl FileWatcher {
    /// Take the first observation without reporting it as "changed" —
    /// the initial scan is not an edit.
    pub fn prime(&mut self, root: &Path, language_filter: Option<&Vec<&'static str>>) {
        self.last = snapshot_mtimes(root, language_filter);
    }

    /// Observe the tree again; return files that are new or modified since
    /// the previous observation, sorted for deterministic output. Deleted
    /// files drop out of the snapshot silently — their findings age out
    /// through the baseline merge in the loop.
    pub fn changed_files(
        &mut self,
        root: &Path,
        language_filter: Option<&Vec<&'static str>>,
    ) -> Vec<PathBuf> {
        let current = snapshot_mtimes(root, language_filter);
        let mut changed = Vec::new();
        for (path, mtime) in &current {
            match self.last.get(path) {
                None => changed.push(path.clone()),
                Some(prev) if prev != mtime => changed.push(path.clone()),
                Some(_) => {}
            }
        }
        changed.sort();
        self.last = current;
        changed
    }
}

/// Advisories present in `current` whose fingerprint was absent from
/// `previous` — the watch loop prints exactly these, so an edit that
/// doesn't change findings stays silent and a newly introduced bug
/// surfaces immediately. Findings without a fingerprint (should not happen
/// for dataflow advisories) are always treated as new: fail loud, not
/// silent.
pub fn new_advisories(previous: &[Advisory], current: &[Advisory]) -> Vec<Advisory> {
    let seen: std::collections::HashSet<&str> = previous
        .iter()
        .map(|a| a.fingerprint.as_str())
        .collect();
    current
        .iter()
        .filter(|a| !seen.contains(a.fingerprint.as_str()))
        .cloned()
        .collect()
}

/// Render one new advisory as a terminal line (watch mode is a human- and
/// agent-facing stream, not a report file).
pub fn format_watch_finding(adv: &Advisory) -> String {
    let sev = match adv.severity {
        crate::Severity::Critical => "CRITICAL",
        crate::Severity::Warning => "WARNING",
        crate::Severity::Info => "INFO",
    };
    format!(
        "[{sev}] {} ({}:{}) — {}",
        adv.title, adv.file_path, adv.line, adv.observation
    )
}

/// The watch loop. Prime → initial full scan → poll → re-scan changed
/// files → print only new findings. Returns when `should_stop` fires
/// (SIGINT handling in production; tests drive it directly).
///
/// The engine is injected as two closures so tests drive the loop without
/// a real engine; production passes `|| Engine::configured()` and
/// `|e, p| e.run(p)`.
pub fn run_watch_loop<S, B, F>(
    root: &Path,
    language_filter: Option<&Vec<&'static str>>,
    build_engine: B,
    mut scan: F,
    mut should_stop: impl FnMut() -> bool,
) -> crate::Result<()>
where
    B: Fn() -> S,
    F: FnMut(&mut S, &Path) -> crate::Result<Vec<Advisory>>,
{
    let mut watcher = FileWatcher::default();
    watcher.prime(root, language_filter);

    // Initial round: full scan of the root, establishes the baseline
    // fingerprint set so pre-existing findings stay silent.
    let mut engine = build_engine();
    let mut previous = scan(&mut engine, root)?;
    eprintln!(
        "[watch] {} known finding(s) (baseline). Watching {}...",
        previous.len(),
        root.display()
    );

    loop {
        if should_stop() {
            return Ok(());
        }
        std::thread::sleep(POLL_INTERVAL);
        if should_stop() {
            return Ok(());
        }

        let changed = watcher.changed_files(root, language_filter);
        if changed.is_empty() {
            continue;
        }
        eprintln!("[watch] {} file(s) changed", changed.len());

        let mut engine = build_engine();
        let mut round_current: Vec<Advisory> = Vec::new();
        for file in &changed {
            match scan(&mut engine, file) {
                Ok(found) => {
                    round_current.extend(found);
                }
                Err(e) => {
                    // A half-written file can fail to parse; report and
                    // keep watching rather than dying.
                    eprintln!("[watch] scan failed for {}: {e}", file.display());
                }
            }
        }

        let fresh = new_advisories(&previous, &round_current);
        for adv in &fresh {
            println!("{}", format_watch_finding(adv));
        }
        if !fresh.is_empty() {
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        // Merge: the new baseline is old findings from untouched files plus
        // everything this round produced from the changed files. Findings
        // whose file was edited are refreshed wholesale — including ones
        // that disappeared (fixed) or moved lines (refingerprinted).
        let touched: std::collections::HashSet<String> = changed
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let mut merged: Vec<Advisory> = previous
            .into_iter()
            .filter(|a| !touched.contains(a.file_path.as_str()))
            .collect();
        merged.extend(round_current);
        previous = merged;
    }
}
