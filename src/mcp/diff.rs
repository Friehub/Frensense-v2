// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! `frensense_diff` - scan a patch/diff and report only findings whose
//! reported line falls inside the patch's added-line ranges.
//!
//! Why the range intersection rather than re-parsing the patch into code:
//! the engine's source of truth is the file *on disk* - the working tree
//! already contains the change. Feeding synthetic patch content into the
//! parser would fork the analysis path (patch context, hunk offsets,
//! partial functions). Instead this module observes the patch, computes
//! which line ranges it touched per file, and intersects those ranges
//! with the advisories a normal `Engine::run` produced. One lowering
//! path, one taint engine, zero divergence between "what CI scans" and
//! "what the diff reports".
//!
//! Scope discipline (same doctrine as `scan_file`): this module owns
//! only patch observation and line-range filtering. Language knowledge
//! stays in `frensense-lang`, analysis stays in the engine.

use super::scan_file::is_supported;
use crate::{Advisory, Severity};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

/// What one diff scan produced: the parsed added ranges, the advisories
/// that landed on them, and how many diff files the engine actually ran.
pub type DiffScanOutcome = (BTreeMap<String, Vec<AddedRange>>, Vec<Advisory>, usize);

/// MCP tool definition for `frensense_diff`.
#[must_use]
pub fn tool_definition() -> Value {
    json!({
        "name": "frensense_diff",
        "description": "Scan files touched by a unified diff (git diff/patch format) and report ONLY findings whose line falls inside the diff's added-line ranges. Use this to gate a change: pre-existing findings elsewhere in the touched files are filtered out, so the result answers 'does MY change introduce findings?'. Empty advisories with clean=true means the added lines are invariant-clean. Pass either a diff text (diff_text) or a repo path whose working tree is scanned (repo).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {
                    "type": "string",
                    "description": "Repository root the diff applies to. Files named in the diff are resolved against this directory and scanned there. Defaults to '.'."
                },
                "diff_text": {
                    "type": "string",
                    "description": "Unified diff text (git diff / patch format). Omit to run `git diff HEAD` inside repo."
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": ["critical", "warning", "info"],
                    "default": "info",
                    "description": "Minimum severity to report"
                },
                "min_confidence": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "default": 0.0,
                    "description": "Minimum engine confidence for a finding to be reported"
                },
                "corpus_bundle": {
                    "type": "string",
                    "description": "Optional path to a .frc knowledge bundle whose learned Source/Sink facts extend the built-in tables"
                }
            }
        }
    })
}

/// One added-line range in a file, inclusive on both ends, 1-based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedRange {
    pub start: u32,
    pub end: u32,
}

impl AddedRange {
    fn contains(&self, line: u32) -> bool {
        line >= self.start && line <= self.end
    }
}

/// Extract the `+++ b/<path>` target paths from a unified diff, in order
/// of appearance, deduplicated. Handles `a/`/`b/` prefixes and `/dev/null`
/// (new files whose target we still want - `+++ b/path` form always
/// carries the path). Quoted paths (`"\b/path with spaces"`) are
/// unquoted.
#[must_use]
pub fn diff_file_paths(diff: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for line in diff.lines() {
        let Some(path) = line.strip_prefix("+++ ") else {
            continue;
        };
        let path = path.trim();
        if path == "/dev/null" {
            continue;
        }
        let path = unquote(path);
        let path = path.strip_prefix("b/").unwrap_or(path);
        if seen.insert(path.to_string()) {
            out.push(path.to_string());
        }
    }
    out
}

/// Parse a unified diff into per-file added-line ranges.
///
/// Only `+` lines inside hunks count (context lines and `-` lines do not):
/// a finding belongs to "the change" when its line exists *because* of
/// the patch. Hunk headers (`@@ -l,c +l,c @@`) carry the new-file line
/// numbering; the parser tracks the cursor through each hunk body so
/// multi-hunk files produce disjoint ranges. `No newline at end of file`
/// markers are ignored.
#[must_use]
pub fn added_ranges(diff: &str) -> BTreeMap<String, Vec<AddedRange>> {
    let mut result: BTreeMap<String, Vec<AddedRange>> = BTreeMap::new();
    let mut current_file: Option<String> = None;
    let mut current_line: u32 = 0;
    let mut in_hunk = false;
    // New-side line budget promised by the current hunk header
    // (`@@ -a,b +c,d @@` → d, defaulting to 1 when omitted). Grounds the
    // empty-line ambiguity check below in the patch's own metadata.
    let mut remaining_new: u32 = 0;

    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            let path = path.trim();
            if path != "/dev/null" {
                let p = unquote(path);
                let p = p.strip_prefix("b/").unwrap_or(p).to_string();
                current_file = Some(p);
            }
            in_hunk = false;
            continue;
        }
        if line.starts_with("@@") {
            // @@ -oldStart,oldCount +newStart,newCount @@ ...
            in_hunk = true;
            current_line = parse_new_start(line).unwrap_or(0);
            remaining_new = parse_new_count(line);
            continue;
        }
        if !in_hunk {
            continue;
        }
        if line.starts_with('+') {
            // `diff.lines()` already split on newlines, so each `+` line
            // here is exactly one added line (a bare "+" is an added
            // empty line). Consecutive additions merge into one range:
            // a five-line added block is one finding region, not five.
            let file = current_file.clone().unwrap_or_default();
            let line_no = current_line;
            let ranges = result.entry(file).or_default();
            match ranges.last_mut() {
                Some(last) if last.end + 1 == line_no => last.end = line_no,
                _ => ranges.push(AddedRange {
                    start: line_no,
                    end: line_no,
                }),
            }
            current_line += 1;
            remaining_new = remaining_new.saturating_sub(1);
        } else if line.starts_with('-') || line.starts_with('\\') {
            // Removed lines / "\ No newline": don't advance the new cursor.
        } else if line.starts_with(' ') {
            // Context line.
            current_line += 1;
            remaining_new = remaining_new.saturating_sub(1);
        } else if line.is_empty() {
            // Ambiguous: an empty `.lines()` item is either a context
            // line whose content is empty (git emits it as " \n" which
            // some tools strip the leading space from) or a separator
            // between top-level file sections of a hand-written patch.
            // Distinguish by the hunk's own line budget: track how many
            // new-side lines the header promised; empty input inside
            // that budget is context, anything after it is not.
            if remaining_new > 0 {
                current_line += 1;
                remaining_new -= 1;
            }
        }
    }
    result.retain(|_, ranges| !ranges.is_empty());
    result
}

/// New-side line count from a hunk header; git omits `,1` for
/// single-line hunks, so the default is 1.
fn parse_new_count(header: &str) -> u32 {
    let plus = match header.find('+') {
        Some(i) => i,
        None => return 1,
    };
    let rest = &header[plus + 1..];
    let after_comma = rest.split_once(',').map(|(_, r)| r);
    match after_comma {
        Some(r) => {
            let end = r.find([' ', '@', '\r']).unwrap_or(r.len());
            r[..end].parse().unwrap_or(1)
        }
        None => 1,
    }
}

fn parse_new_start(header: &str) -> Option<u32> {
    // Second +/- span: "@@ -1,3 +2,5 @@"
    let plus = header.find('+')?;
    let rest = &header[plus + 1..];
    let end = rest.find([',', ' ', '@'])?;
    rest[..end].parse().ok()
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// True when the advisory's reported line is inside one of the patch's
/// added ranges for its file. Findings from files the diff doesn't touch
/// never qualify.
#[must_use]
pub fn in_added_lines(adv: &Advisory, ranges: &BTreeMap<String, Vec<AddedRange>>) -> bool {
    let adv_path = normalize(&adv.file_path);
    let file_ranges = ranges
        .iter()
        .find(|(diff_path, _)| path_matches(&adv_path, diff_path))
        .map(|(_, rs)| rs);
    let Some(file_ranges) = file_ranges else {
        return false;
    };
    file_ranges.iter().any(|r| r.contains(adv.line))
}

/// Diff paths are repo-relative; engine advisory paths may be absolute
/// or repo-relative depending on how the repo path was passed. Match on
/// suffix boundaries so `src/foo.py` matches `<repo>/src/foo.py` but not
/// `mysrc/foo.py`.
fn normalize(p: &str) -> String {
    p.replace('\\', "/")
}

fn path_matches(advisory_path: &str, diff_path: &str) -> bool {
    let adv = normalize(advisory_path);
    let d = normalize(diff_path);
    if adv == d {
        return true;
    }
    // Absolute advisory path (`/repo/src/app.py`) vs diff-relative
    // (`src/app.py`): match on a `/`-delimited suffix boundary.
    adv.ends_with(&format!("/{d}")) || d.ends_with(&format!("/{adv}"))
}

/// Severity/confidence filter. Thin wrapper over
/// [`crate::reporting::apply`], the one reporting policy every surface
/// shares.
#[must_use]
pub fn filter_advisories(
    advisories: Vec<Advisory>,
    severity_threshold: &str,
    min_confidence: f64,
) -> Vec<Advisory> {
    crate::reporting::apply(
        advisories,
        min_confidence,
        Some(Severity::parse(severity_threshold)),
    )
}

/// Run `git diff HEAD` in `repo` and append synthetic added-file hunks
/// for untracked files (`git diff` never shows them, but a brand-new
/// file is exactly the change a diff gate must not miss). Returns empty
/// output (not an error) when the repo has no changes.
fn git_diff_head(repo: &Path) -> Result<String, String> {
    let run = |args: &[&str]| -> Result<String, String> {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .map_err(|e| format!("git {args:?} failed: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    };

    let mut diff = run(&["diff", "HEAD"])?;

    let untracked = run(&["ls-files", "--others", "--exclude-standard"])?;
    for file in untracked.lines().filter(|l| !l.trim().is_empty()) {
        match std::fs::read_to_string(repo.join(file)) {
            Ok(content) => {
                diff.push_str(&format!("\ndiff --git a/{file} b/{file}\n"));
                diff.push_str("--- /dev/null\n");
                diff.push_str(&format!("+++ b/{file}\n"));
                diff.push_str(&format!("@@ -0,0 +1,{} @@\n", content.lines().count()));
                for line in content.lines() {
                    diff.push('+');
                    diff.push_str(line);
                    diff.push('\n');
                }
            }
            // Unreadable/unusual untracked file: skip it silently -
            // the engine would skip it too.
            Err(_) => continue,
        }
    }
    Ok(diff)
}

/// Core: scan the files named in the diff via the normal engine path and
/// keep only findings on added lines.
///
/// # Errors
/// Engine failure, unreadable repo, or `git diff` failure (when
/// `diff_text` is None).
pub fn run_diff(
    repo: &Path,
    diff_text: Option<&str>,
    severity_threshold: &str,
    min_confidence: f64,
    corpus_bundle: Option<&str>,
) -> crate::Result<DiffScanOutcome> {
    let diff = match diff_text {
        Some(d) => d.to_string(),
        None => git_diff_head(repo).map_err(crate::FrensenseError::Config)?,
    };
    let ranges = added_ranges(&diff);

    // Scan each file the diff touches with a full engine run of its own
    // directory scope (the file itself). Files the engine can't handle
    // (unsupported ext, deleted files that no longer exist) are skipped
    // by collect_files' own rules.
    let mut all = Vec::new();
    let mut scanned = 0usize;
    let mut engine = super::scan_file::build_engine(min_confidence, corpus_bundle);
    for path in ranges.keys() {
        let abs = repo.join(path);
        if !is_supported(&abs) {
            continue;
        }
        // A file run emits advisories whose file_path is the path we
        // passed; re-point them at the diff-relative name so intersection
        // and output stay diff-scoped.
        if let Ok(found) = engine.run(&abs) {
            scanned += 1;
            for mut adv in found {
                adv.file_path = path.clone();
                all.push(adv);
            }
        }
    }

    let all = filter_advisories(all, severity_threshold, min_confidence);
    let on_added: Vec<Advisory> = all
        .into_iter()
        .filter(|adv| {
            ranges.keys().any(|d| path_matches(&adv.file_path, d)) && in_added_lines(adv, &ranges)
        })
        .collect();
    Ok((ranges, on_added, scanned))
}

/// Build the JSON-RPC `tools/call` result value.
#[must_use]
pub fn result_payload(
    ranges: &BTreeMap<String, Vec<AddedRange>>,
    advisories: &[Advisory],
    scanned: usize,
) -> Value {
    let files: Vec<Value> = ranges
        .iter()
        .map(|(f, rs)| {
            json!({
                "path": f,
                "added_ranges": rs.iter()
                    .map(|r| json!({"start": r.start, "end": r.end}))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "clean": advisories.is_empty(),
        "files_touched": files.len(),
        "files_scanned": scanned,
        "added_ranges": files,
        // Stable IDs of the on-added-line findings: agents gate a change
        // by comparing IDs across iterations of the same change.
        "stable_ids": advisories.iter().map(|a| a.stable_id()).collect::<Vec<_>>(),
        "advisories": advisories,
        "message": if advisories.is_empty() {
            "added lines introduce no findings"
        } else {
            ""
        },
    })
}

/// Full tool invocation: argument parsing, diff sourcing, scanning,
/// filtering, shaping. Returns the `tools/call` result value.
#[must_use]
pub fn run_diff_tool(args: &Value) -> Value {
    let repo_str = args.get("repo").and_then(Value::as_str).unwrap_or(".");
    let repo = Path::new(repo_str);
    if !repo.exists() {
        return json!({
            "clean": false,
            "advisories": [],
            "error": format!("repo path does not exist: {repo_str}")
        });
    }

    let diff_text = args.get("diff_text").and_then(Value::as_str);
    let severity_threshold = args
        .get("severity_threshold")
        .and_then(Value::as_str)
        .unwrap_or("info");
    let min_confidence = args
        .get("min_confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    let corpus_bundle = args.get("corpus_bundle").and_then(Value::as_str);
    if let Some(bundle) = corpus_bundle
        && !Path::new(bundle).exists()
    {
        return json!({
            "clean": false,
            "advisories": [],
            "error": format!("corpus bundle does not exist: {bundle}")
        });
    }

    if diff_text.is_none() {
        // Only hit git when asked to; an explicit diff_text must work
        // outside any repository.
        let probe = std::process::Command::new("git")
            .args(["rev-parse", "--is-inside-work-tree"])
            .current_dir(repo)
            .output();
        match probe {
            Ok(o) if String::from_utf8_lossy(&o.stdout).trim() != "true" => {
                return json!({
                    "clean": false,
                    "advisories": [],
                    "error": "not a git repository: pass diff_text or run inside a repo"
                });
            }
            Err(_) => {
                return json!({
                    "clean": false,
                    "advisories": [],
                    "error": "git unavailable: pass diff_text explicitly"
                });
            }
            _ => {}
        }
    }

    match run_diff(
        repo,
        diff_text,
        severity_threshold,
        min_confidence,
        corpus_bundle,
    ) {
        Ok((ranges, advisories, scanned)) => result_payload(&ranges, &advisories, scanned),
        Err(e) => json!({
            "clean": false,
            "advisories": [],
            "error": format!("analysis error: {e}")
        }),
    }
}

#[cfg(test)]
#[path = "diff_tests.rs"]
mod tests;
