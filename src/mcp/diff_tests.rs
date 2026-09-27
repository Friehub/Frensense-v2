// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the `frensense_diff` MCP tool: patch parsing (hunks, multi
//! files, no-newline markers), added-line intersection, argument errors,
//! and end-to-end runs against a real temp git repo (dirty + clean
//! changes) plus explicit `diff_text` outside git.

use super::*;
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("frensense-diff-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

const DIFF: &str = "\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,4 +1,6 @@
 import hashlib
+import subprocess
 
 def digest(data):
-    return hashlib.md5(data).hexdigest()
+    h = hashlib.md5(data)
+    return h.hexdigest()
@@ -20,3 +22,4 @@ def tail():
     keep()
+    subprocess.call(cmd, shell=True)
     done()
diff --git a/readme.md b/readme.md
index 3333333..4444444 100644
--- a/readme.md
+++ b/readme.md
@@ -1,2 +1,3 @@
 title
+prose about hashes
";

#[test]
fn tool_definition_shape() {
    let def = tool_definition();
    assert_eq!(def["name"], "frensense_diff");
    assert!(def["description"].as_str().unwrap().contains("added-line"));
    assert!(def["inputSchema"]["properties"]["diff_text"].is_object());
    assert!(def["inputSchema"]["properties"]["repo"].is_object());
}

#[test]
fn parses_added_ranges_across_hunks_and_files() {
    let ranges = added_ranges(DIFF);
    let app = ranges.get("src/app.py").expect("app.py ranges");
    // Hunk 1: `import subprocess` is new line 2; the two replacement
    // lines are new lines 5-6 — the `-` line doesn't advance the new
    // cursor, so the second `+` lands right after the context `def`.
    assert!(app.contains(&AddedRange { start: 2, end: 2 }));
    assert!(app.contains(&AddedRange { start: 5, end: 6 }));
    // Hunk 2 starts at new line 22; `+    subprocess...` is line 23.
    assert!(app.contains(&AddedRange { start: 23, end: 23 }));
    assert_eq!(app.len(), 3);

    // The markdown file is parsed too (it's in the diff; whether it gets
    // scanned is the tool's gating decision, not the parser's).
    assert!(ranges.get("readme.md").is_some());

    // The removed line's old position (3) must NOT be an added range.
    assert!(!app.iter().any(|r| r.contains(3) && r.start == 3 && r.end == 3));
}

#[test]
fn parses_file_paths_in_order() {
    assert_eq!(diff_file_paths(DIFF), vec!["src/app.py", "readme.md"]);
    // /dev/null targets (deleted files) are skipped.
    let d = "diff --git a/gone.py b/gone.py\ndeleted file mode 100644\n+++ /dev/null\n";
    assert!(diff_file_paths(d).is_empty());
}

#[test]
fn intersection_filters_by_file_and_line() {
    let ranges = added_ranges(DIFF);
    let mk = |path: &str, line: u32| {
        Advisory::bare("t", crate::Severity::Warning, crate::FileId(0), Path::new(path), "o")
            .with_line(line)
    };

    // Finding on an added line → kept.
    assert!(in_added_lines(&mk("src/app.py", 2), &ranges));
    // Finding on a context line → dropped.
    assert!(!in_added_lines(&mk("src/app.py", 1), &ranges));
    // Finding on a line only in the old file (removed line) → dropped.
    assert!(!in_added_lines(&mk("src/app.py", 3), &ranges));
    // Findings in untouched files → dropped.
    assert!(!in_added_lines(&mk("src/other.py", 2), &ranges));
    // Absolute engine path matching a diff-relative path → kept.
    assert!(in_added_lines(&mk("/repo/src/app.py", 23), &ranges));
}

#[test]
fn argument_errors() {
    let out = run_diff_tool(&json!({"repo": "/definitely/not/here"}));
    assert!(out["error"].as_str().unwrap().contains("does not exist"));

    // A non-repo directory without diff_text → explicit error.
    let dir = tempdir("norepo");
    let out = run_diff_tool(&json!({"repo": dir.display().to_string()}));
    assert!(out["error"].as_str().unwrap().contains("not a git repository"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn end_to_end_explicit_diff_text() {
    let dir = tempdir("e2e");
    let src = dir.join("app.py");
    std::fs::write(
        &src,
        "import hashlib\nimport subprocess\n\n\ndef digest(data):\n    h = hashlib.md5(data)\n    return h.hexdigest()\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n",
    )
    .unwrap();

    let diff = "\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 import hashlib
+import subprocess
 
 
";
    let (ranges, advisories, scanned) =
        run_diff(&dir, Some(diff), "info", 0.0, None).expect("run_diff");
    assert_eq!(scanned, 1);
    assert!(ranges.contains_key("app.py"));
    // The pre-existing md5 finding is on line 5 — NOT on the added line
    // (2) — so the diff gate must drop it: only findings on added lines
    // survive. No added line introduces a finding here.
    assert!(advisories.is_empty(), "expected clean, got {advisories:?}");

    // Now a diff whose added line IS the finding: the weak-hash call
    // re-added on a new line (engine flags it deterministically).
    std::fs::write(
        &src,
        "import hashlib\nimport subprocess\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n",
    )
    .unwrap();
    let diff2 = "\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -4,2 +5,3 @@
 def digest(data):
+    return hashlib.md5(data).hexdigest()
     pass
";
    let (ranges2, advisories2, _) = run_diff(&dir, Some(diff2), "info", 0.0, None).expect("run_diff 2");
    let expected_line: Vec<u32> = ranges2["app.py"].iter().map(|r| r.start).collect();
    assert_eq!(expected_line, vec![6]);
    assert!(
        advisories2.iter().any(|a| a.line == 6),
        "expected a finding on added line 6, got {advisories2:?}"
    );
}

#[test]
fn end_to_end_git_diff_in_temp_repo() {
    let dir = tempdir("gitrepo");
    run_git(&dir, &["init", "-q"]);
    std::fs::write(dir.join("ok.py"), "x = 1\n").unwrap();
    run_git(&dir, &["add", "."]);
    run_git(&dir, &["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]);

    // Working-tree change that introduces a finding on an added line.
    std::fs::write(dir.join("bad.py"), "import hashlib\n\n\ndef d(x):\n    return hashlib.md5(x).hexdigest()\n").unwrap();

    let (ranges, advisories, _) = run_diff(&dir, None, "info", 0.0, None).expect("git run_diff");
    assert!(ranges.contains_key("bad.py"), "ranges: {ranges:?}");
    assert!(
        advisories.iter().any(|a| a.file_path.ends_with("bad.py")),
        "expected the added weak_hash line to be reported, got {advisories:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn run_git(dir: &Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git spawn");
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}
