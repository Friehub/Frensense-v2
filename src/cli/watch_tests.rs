// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Watch-mode unit tests: pure functions, no filesystem events or real
//! engine needed (the loop is engine-injected).

use crate::cli::watch::{FileWatcher, format_watch_finding, new_advisories, snapshot_mtimes};
use crate::{Advisory, Severity};
use std::time::Duration;

fn advisory(fp: &str, line: u32) -> Advisory {
    let mut a = Advisory::bare(
        "Path Traversal",
        Severity::Warning,
        crate::FileId(0),
        std::path::Path::new("src/app.py"),
        "flow",
    )
    .with_line(line);
    a.fingerprint = fp.to_string();
    a
}

// ── snapshot / change detection ───────────────────────────────────────

#[test]
fn snapshot_collects_supported_files_only() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();
    std::fs::write(dir.path().join("b.txt"), "ignore me\n").unwrap();
    std::fs::create_dir(dir.path().join("node_modules")).unwrap();
    std::fs::write(dir.path().join("node_modules/c.js"), "var x;\n").unwrap();

    let snap = snapshot_mtimes(dir.path(), None);
    assert!(snap.keys().any(|p| p.ends_with("a.py")));
    assert!(!snap.keys().any(|p| p.ends_with("b.txt")));
    assert!(
        !snap.keys().any(|p| p.ends_with("c.js")),
        "node_modules ignored"
    );
}

#[test]
fn prime_then_unchanged_tree_reports_no_changes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();

    let mut w = FileWatcher::default();
    w.prime(dir.path(), None);
    assert!(w.changed_files(dir.path(), None).is_empty());
}

#[test]
fn modified_and_new_files_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();

    let mut w = FileWatcher::default();
    w.prime(dir.path(), None);

    // mtime resolution is seconds: ensure the modified file's mtime moves.
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(dir.path().join("a.py"), "x = 2\n").unwrap();
    std::fs::write(dir.path().join("new.py"), "y = 1\n").unwrap();

    let changed = w.changed_files(dir.path(), None);
    assert!(changed.iter().any(|p| p.ends_with("a.py")));
    assert!(changed.iter().any(|p| p.ends_with("new.py")));
}

#[test]
fn deleted_files_age_out_silently() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.py"), "x = 1\n").unwrap();

    let mut w = FileWatcher::default();
    w.prime(dir.path(), None);
    std::fs::remove_file(dir.path().join("a.py")).unwrap();
    assert!(w.changed_files(dir.path(), None).is_empty());
    // Snapshot no longer holds the deleted path.
    assert!(w.changed_files(dir.path(), None).is_empty());
}

// ── fingerprint diff ──────────────────────────────────────────────────

#[test]
fn new_advisories_reports_only_unseen_fingerprints() {
    let prev = vec![advisory("fp-1", 10)];
    let current = vec![
        advisory("fp-1", 10), // unchanged finding → silent
        advisory("fp-2", 20), // new bug → reported
    ];
    let fresh = new_advisories(&prev, &current);
    assert_eq!(fresh.len(), 1);
    assert_eq!(fresh[0].fingerprint, "fp-2");
}

#[test]
fn new_advisories_empty_current_is_silent() {
    let prev = vec![advisory("fp-1", 10)];
    assert!(new_advisories(&prev, &[]).is_empty());
}

// ── rendering ─────────────────────────────────────────────────────────

#[test]
fn watch_finding_line_carries_severity_location_message() {
    let line = format_watch_finding(&advisory("fp-9", 7));
    assert!(line.starts_with("[WARNING] "));
    assert!(line.contains("src/app.py:7"));
    assert!(line.contains("Path Traversal"));
}

#[test]
fn watch_finding_severity_labels() {
    let mut a = advisory("fp", 1);
    a.severity = Severity::Critical;
    assert!(format_watch_finding(&a).starts_with("[CRITICAL]"));
    a.severity = Severity::Info;
    assert!(format_watch_finding(&a).starts_with("[INFO]"));
}
