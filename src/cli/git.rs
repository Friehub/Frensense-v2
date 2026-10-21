// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! `git` queries behind `--diff-only`: which files changed since HEAD, and
//! which lines of each one are new.
//!
//! The gate answers one question — *did this change introduce a finding?* —
//! so a finding at an unchanged line is pre-existing and belongs to the
//! baseline (`--compare-baseline`), not to this diff. Scanning whole changed
//! files made the gate fail on bugs nobody in this diff touched, which is
//! both noise and an incentive to stop running it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Added-line ranges of each changed file, keyed by **repo-relative** path.
/// (Advisories carry absolute or repo-prefixed paths; one key space avoids
/// the ambiguity entirely.)
pub type AddedLines = std::collections::BTreeMap<String, Vec<(usize, usize)>>;

/// Files changed since HEAD (added, modified, renamed) that Frensense can
/// scan, as `repo_dir`-prefixed paths in the caller's spelling.
pub fn changed_scan_files(repo_dir: &Path) -> std::result::Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "HEAD"])
        .current_dir(repo_dir)
        .output()
        .map_err(|e| format!("git diff failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| repo_dir.join(l))
        // A deleted file is changed but not scannable (the engine reads it
        // from disk), so it is dropped here rather than erroring mid-scan.
        .filter(|p| p.exists() && crate::parser::is_supported(p))
        .collect())
}

/// Added-line ranges per changed file, from `git diff -U0`. One `git`
/// invocation: the per-file form would be one process per changed file, which
/// on a large diff dominates the scan it is meant to gate.
pub fn added_lines(repo_dir: &Path) -> std::result::Result<AddedLines, String> {
    let output = Command::new("git")
        .args(["diff", "--no-color", "-U0", "HEAD"])
        .current_dir(repo_dir)
        .output()
        .map_err(|e| format!("git diff failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(map_from_patch(&String::from_utf8_lossy(&output.stdout)))
}

/// Parse one `git diff -U0` patch into `repo-relative path -> added lines`.
///
/// Hunk headers carry the new file's line span (`@@ -old,count +start,count
/// @@`); with `-U0` every line inside the span is an added line. Pure: the
/// parser is tested without a repository.
pub fn map_from_patch(patch: &str) -> AddedLines {
    let mut map: AddedLines = AddedLines::new();
    let mut current: Option<&str> = None;
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            current = Some(rest);
            // A deletion-only file still keys an empty entry (no added
            // lines is a different answer from "not in this diff").
            map.entry(rest.to_string()).or_default();
            continue;
        }
        if line.starts_with("diff --git") || line.starts_with("+++ ") {
            // `+++ /dev/null` (a pure deletion) ends the file too.
            if line.starts_with("+++ ") && line.trim_end().ends_with("/dev/null") {
                current = None;
            }
            continue;
        }
        let Some(hunk) = line.strip_prefix("@@ ") else {
            continue;
        };
        // `@@ -old,count +new,count @@ context`: the halves live left of
        // the closing ` @@`; the new-file half is the `+` segment.
        let (halves, _context) = hunk.split_once(" @@").unwrap_or((hunk, ""));
        let Some(new_span) = halves.split_whitespace().find(|p| p.starts_with('+')) else {
            continue;
        };
        let Some((start, count)) = parse_new_span(new_span) else {
            continue;
        };
        let Some(path) = current else {
            continue;
        };
        let ranges = map.entry(path.to_string()).or_default();
        ranges.push((start, start + count.saturating_sub(1)));
    }
    // Merge overlapping ranges so a lookup is a single scan.
    for ranges in map.values_mut() {
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges.drain(..) {
            match merged.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => {
                    last.1 = last.1.max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        *ranges = merged;
    }
    map
}

/// `+start,count` (or `+start`) from a hunk header's new-file half.
fn parse_new_span(span: &str) -> Option<(usize, usize)> {
    let span = span.trim().strip_prefix('+')?;
    let (start, count) = span.split_once(',').unwrap_or((span, "1"));
    let start: usize = start.parse().ok()?;
    let count: usize = count.parse().ok()?;
    // `+0,0` is a deletion-only hunk: no new lines.
    (start > 0 && count > 0).then_some((start, count))
}

/// Is `line` (1-based) on an added line of `file`?
///
/// `file` is the advisory's path in any spelling the engine produces;
/// [`relative_to_repo`] folds it onto the map's repo-relative keys. A path
/// that cannot be matched is unchanged or outside the repo, so its findings
/// are not this diff's.
#[must_use]
pub fn is_added(map: &AddedLines, repo_dir: &Path, file: &str, line: u32) -> bool {
    let key = relative_to_repo(repo_dir, file);
    map.get(key.as_str()).is_some_and(|ranges| {
        ranges
            .iter()
            .any(|(s, e)| line as usize >= *s && line as usize <= *e)
    })
}

/// Fold a scanned path onto the repo-relative spelling git uses.
///
/// The diff scan hands the engine `repo_dir.join(relative)`, but the advisory
/// may echo that path verbatim, `./`-prefixed, or (when `repo_dir` is
/// absolute) absolute, so the prefix is stripped by path, not by string.
#[must_use]
pub fn relative_to_repo(repo_dir: &Path, file: &str) -> String {
    let path = Path::new(file);
    path.strip_prefix(repo_dir)
        .or_else(|_| path.strip_prefix(repo_dir.to_string_lossy().trim_start_matches("./")))
        .unwrap_or(path)
        .to_string_lossy()
        .trim_start_matches("./")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{AddedLines, is_added, map_from_patch, relative_to_repo};
    use std::path::Path;

    const PATCH: &str = "diff --git a/src/lib.rs b/src/lib.rs\nindex 111..222 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -12,0 +13,2 @@ fn added() {\n+    a();\n+    b();\n@@ -40,3 +42,0 @@ fn removed() {\n-    gone();\n-    gone2();\ndiff --git a/docs/mre/app.ts b/docs/mre/app.ts\nsimilarity index 90%\n--- a/docs/mre/app.ts\n+++ b/docs/mre/app.ts\n@@ -7 +7 @@ export function bad() {\n-  exec(req.query.old)\n+  exec(req.query.new)\n";

    #[test]
    fn hunks_map_to_added_lines_only() {
        let map = map_from_patch(PATCH);
        assert_eq!(map["src/lib.rs"], vec![(13, 14)]);
        assert_eq!(map["docs/mre/app.ts"], vec![(7, 7)]);
    }

    #[test]
    fn deletion_only_hunks_add_nothing() {
        let map =
            map_from_patch("--- a/gone.rs\n+++ b/gone.rs\n@@ -3,2 +2,0 @@\n-    x();\n-    y();\n");
        assert_eq!(map["gone.rs"], Vec::new());
    }

    #[test]
    fn adjacent_and_overlapping_ranges_merge() {
        let map = map_from_patch(
            "--- a/x.rs\n+++ b/x.rs\n@@ -10,2 +10,2 @@\n+a\n+b\n@@ -11,3 +11,3 @@\n+c\n-d\n+e\n",
        );
        assert_eq!(map["x.rs"], vec![(10, 13)]);
    }

    #[test]
    fn lookup_answers_for_any_path_spelling_the_engine_uses() {
        let mut map = AddedLines::new();
        map.insert("src/lib.rs".to_string(), vec![(13, 14)]);
        assert!(is_added(&map, Path::new("."), "./src/lib.rs", 13));
        assert!(is_added(&map, Path::new("."), "src/lib.rs", 14));
        assert!(is_added(&map, Path::new("/repo"), "/repo/src/lib.rs", 13));
        assert!(!is_added(&map, Path::new("."), "src/lib.rs", 12));
        assert!(!is_added(&map, Path::new("."), "src/other.rs", 13));
    }

    #[test]
    fn relative_to_repo_strips_the_scan_root() {
        assert_eq!(
            relative_to_repo(Path::new("."), "./src/lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(
            relative_to_repo(Path::new("/repo"), "/repo/src/lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(
            relative_to_repo(Path::new("/repo"), "src/lib.rs"),
            "src/lib.rs"
        );
    }
}
