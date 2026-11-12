// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Progress reporter that outputs real-time scan metrics to stderr.
///
/// Supports two rendering modes:
/// - **Interactive TTY**: animated in-place progress bar using `\r` and ANSI line clearing.
/// - **Non-interactive / Agent / CI**: throttled periodic lines reporting milestone percentages and phases.
pub struct ProgressReporter {
    is_tty: bool,
    enabled: bool,
    last_update: Instant,
    last_percent: usize,
    last_phase: String,
    has_active_line: AtomicBool,
}

impl std::fmt::Debug for ProgressReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressReporter")
            .field("is_tty", &self.is_tty)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Format bytes into human-readable memory string (e.g. "42.5 MB").
#[must_use]
pub fn format_rss(rss_kb: u64) -> String {
    if rss_kb == 0 {
        return "N/A".to_string();
    }
    if rss_kb < 1024 {
        format!("{rss_kb} KB")
    } else if rss_kb < 1024 * 1024 {
        let mb = rss_kb as f64 / 1024.0;
        format!("{mb:.1} MB")
    } else {
        let gb = rss_kb as f64 / (1024.0 * 1024.0);
        format!("{gb:.2} GB")
    }
}

/// Truncate file path to fit inside available character budget.
fn truncate_path(path: &str, max_len: usize) -> String {
    let char_count = path.chars().count();
    if char_count <= max_len {
        path.to_string()
    } else if max_len <= 3 {
        "...".chars().take(max_len).collect()
    } else {
        let keep = max_len - 3;
        let skip = char_count.saturating_sub(keep);
        let suffix: String = path.chars().skip(skip).collect();
        format!("...{suffix}")
    }
}

impl ProgressReporter {
    /// Create a new progress reporter.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        let is_tty = std::io::stderr().is_terminal();
        Self {
            is_tty,
            enabled,
            last_update: Instant::now() - Duration::from_secs(10),
            last_percent: 0,
            last_phase: String::new(),
            has_active_line: AtomicBool::new(false),
        }
    }

    /// Update progress with the current scan status.
    pub fn update(
        &mut self,
        phase: &str,
        completed_files: usize,
        total_files: usize,
        current_file: Option<&str>,
        error_count: usize,
        peak_rss_kb: u64,
    ) {
        if !self.enabled {
            return;
        }

        let percent = if total_files > 0 {
            (completed_files * 100) / total_files
        } else {
            100
        };

        if self.is_tty {
            self.render_tty(phase, completed_files, total_files, percent, current_file, error_count, peak_rss_kb);
        } else {
            self.render_non_tty(phase, completed_files, total_files, percent, error_count, peak_rss_kb);
        }
    }

    fn render_tty(
        &self,
        phase: &str,
        completed_files: usize,
        total_files: usize,
        percent: usize,
        current_file: Option<&str>,
        error_count: usize,
        peak_rss_kb: u64,
    ) {
        let bar_width = 24;
        let filled = (percent * bar_width) / 100;
        let empty = bar_width.saturating_sub(filled);
        let bar = format!("[{}{}]", "=".repeat(filled), " ".repeat(empty));
        let mem = format_rss(peak_rss_kb);

        let err_str = if error_count > 0 {
            format!("{error_count} err")
        } else {
            "0 err".to_string()
        };

        let file_info = match current_file {
            Some(f) => format!(" | {}", truncate_path(f, 30)),
            None => String::new(),
        };

        let mut stderr = std::io::stderr().lock();
        let _ = write!(
            stderr,
            "\r\x1B[2K{phase}: {bar} {completed_files}/{total_files} ({percent}%) | {err_str} | {mem}{file_info}"
        );
        let _ = stderr.flush();
        self.has_active_line.store(true, Ordering::SeqCst);
    }

    fn render_non_tty(
        &mut self,
        phase: &str,
        completed_files: usize,
        total_files: usize,
        percent: usize,
        error_count: usize,
        peak_rss_kb: u64,
    ) {
        let now = Instant::now();
        let phase_changed = phase != self.last_phase;
        let percent_milestone = percent >= self.last_percent + 10 || percent == 100;
        let time_elapsed = now.duration_since(self.last_update) >= Duration::from_secs(2);

        if phase_changed || (percent_milestone && time_elapsed) || percent == 100 {
            self.last_update = now;
            self.last_percent = percent;
            self.last_phase = phase.to_string();

            let mem = format_rss(peak_rss_kb);
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "[frensense] {phase}: {completed_files}/{total_files} ({percent}%) | {error_count} errors | {mem} peak RSS"
            );
            let _ = stderr.flush();
        }
    }

    /// Clear the progress line upon completion.
    pub fn finish(&self) {
        if !self.enabled {
            return;
        }
        if self.is_tty && self.has_active_line.load(Ordering::SeqCst) {
            let mut stderr = std::io::stderr().lock();
            let _ = write!(stderr, "\r\x1B[2K");
            let _ = stderr.flush();
            self.has_active_line.store(false, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_rss_handles_ranges() {
        assert_eq!(format_rss(0), "N/A");
        assert_eq!(format_rss(512), "512 KB");
        assert_eq!(format_rss(1024), "1.0 MB");
        assert_eq!(format_rss(50 * 1024), "50.0 MB");
        assert_eq!(format_rss(2 * 1024 * 1024), "2.00 GB");
    }

    #[test]
    fn truncate_path_respects_budget() {
        assert_eq!(truncate_path("short.rs", 20), "short.rs");
        assert_eq!(truncate_path("path/to/very/long/file/name.rs", 15), "...file/name.rs");
        assert_eq!(truncate_path("path/to/very/long/file/name.rs", 18), "...ng/file/name.rs");
        assert_eq!(truncate_path("path/to/very/long/file/name.rs", 19), "...ong/file/name.rs");
        assert_eq!(truncate_path("hello.rs", 3), "...");
        assert_eq!(truncate_path("hello.rs", 2), "..");
    }

    #[test]
    fn disabled_reporter_does_not_render() {
        let mut r = ProgressReporter::new(false);
        r.update("Testing", 5, 10, Some("file.rs"), 0, 1024);
        assert!(!r.has_active_line.load(Ordering::SeqCst));
        r.finish();
    }
}

