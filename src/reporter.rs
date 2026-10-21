// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::Advisory;
use frensense_engine::analysis::taint::path::{PathStep, TaintPath};
use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;

pub struct Reporter;

impl Reporter {
    /// Generates a Markdown report grouped by severity.
    #[must_use]
    pub fn to_markdown(advisories: &[Advisory], path: &str) -> String {
        let mut md = format!("# Frensense Report for {path}\n\n");
        if advisories.is_empty() {
            md.push_str("**Analysis Complete:** No findings.\n");
            return md;
        }
        for sev in [
            crate::Severity::Critical,
            crate::Severity::Warning,
            crate::Severity::Info,
        ] {
            let filtered: Vec<&Advisory> =
                advisories.iter().filter(|a| a.severity == sev).collect();
            if filtered.is_empty() {
                continue;
            }
            let _ = writeln!(md, "## {:?}", sev);
            for adv in filtered {
                let _ = writeln!(md, "### {}", adv.title);
                let _ = writeln!(md, "- **Location**: `{}:{}`  ", adv.file_path, adv.line);
                let _ = writeln!(md, "- **Observation**: {}  ", adv.observation);
                let _ = writeln!(md, "- **Impact**: {}  ", adv.impact);
                let _ = writeln!(md, "- **Improvement**: {}  \n", adv.improvement);
            }
        }
        md
    }

    /// Generates a SARIF report for CI/CD integration.
    #[must_use]
    pub fn to_sarif(advisories: &[Advisory], _root_path: &Path) -> serde_json::Value {
        // One SARIF rule per stable rule id (never per message): code
        // scanning groups, suppresses and trends findings by it.
        let mut rule_ids: Vec<String> = Vec::new();
        let mut rules_map: std::collections::BTreeMap<String, serde_json::Value> =
            std::collections::BTreeMap::new();
        let mut worst: std::collections::BTreeMap<String, crate::Severity> =
            std::collections::BTreeMap::new();
        for adv in advisories {
            let id = adv.rule_id();
            let entry = worst.entry(id.clone()).or_insert(adv.severity);
            if adv.severity.meets_threshold(*entry) {
                *entry = adv.severity;
            }
            rules_map.entry(id.clone()).or_insert_with(|| {
                let card = frensense_lang::rule_card::card_by_id(&id);
                let title = card.map_or_else(|| adv.title.clone(), |c| c.title.to_string());
                let why = card.map_or_else(|| adv.impact.clone(), |c| c.why.to_string());
                let fix = card.map_or_else(|| adv.improvement.clone(), |c| c.fix.to_string());
                let cwes: Vec<String> = card.map_or_else(
                    || adv.cwe().iter().map(|c| (*c).to_string()).collect(),
                    |c| c.cwe.iter().map(|w| (*w).to_string()).collect(),
                );
                let mut tags: Vec<String> = vec!["security".to_string()];
                tags.extend(
                    cwes.iter()
                        .map(|c| format!("external/cwe/cwe-{}", c.trim_start_matches("CWE-"))),
                );
                let mut rule = serde_json::json!({
                    "id": id,
                    "name": title,
                    "shortDescription": { "text": title },
                    "fullDescription": { "text": why },
                    "help": {
                        "text": format!("{why}\n\nFix: {fix}"),
                        "markdown": format!("{why}\n\n**Fix:** {fix}")
                    },
                    "properties": { "tags": tags, "precision": "high" },
                });
                if let Some(first) = cwes.first() {
                    rule["helpUri"] = serde_json::json!(frensense_lang::rule_card::cwe_url(first));
                }
                rule
            });
        }
        for (id, rule) in &mut rules_map {
            let sev = worst.get(id).copied().unwrap_or(crate::Severity::Warning);
            let (level, score) = match sev {
                crate::Severity::Critical => ("error", "9.0"),
                crate::Severity::Warning => ("warning", "6.0"),
                crate::Severity::Info => ("note", "3.0"),
            };
            rule["defaultConfiguration"] = serde_json::json!({ "level": level });
            rule["properties"]["security-severity"] = serde_json::json!(score);
            rule_ids.push(id.clone());
        }
        let rules_list: Vec<_> = rules_map.into_values().collect();

        serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Frensense",
                        "version": crate::FRENSENSE_VERSION,
                        "informationUri": "https://friehub.com/frensense",
                        "rules": rules_list
                    }
                },
                "results": advisories.iter().map(|adv| {
                    serde_json::json!({
                        "ruleId": adv.rule_id(),
                        "ruleIndex": rule_ids.iter().position(|r| *r == adv.rule_id()),
                        "level": match adv.severity {
                            crate::Severity::Critical => "error",
                            crate::Severity::Warning => "warning",
                            crate::Severity::Info => "note",
                        },
                        "message": { "text": adv.title.clone() },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": { "uri": adv.file_path.clone() },
                                "region": sarif_region(adv),
                            }
                        }],
                        "partialFingerprints": {
                            "primaryLocationLineHash/v1": adv.fingerprint
                        },
                        "codeFlows": [{
                            "threadFlows": [{
                                "locations": adv.taint_steps.iter().map(|(desc, loc)| {
                                    let location = loc.as_ref().and_then(|(file, byte)| {
                                        // SARIF consumers (IDEs, GitHub) want
                                        // line/column regions, not raw byte
                                        // offsets. Resolve from the source
                                        // when the file is readable; fall
                                        // back to the byteOffset-only form.
                                        line_col_for(file, *byte).map(|(l, c)| {
                                            serde_json::json!({
                                                "physicalLocation": {
                                                    "artifactLocation": { "uri": file },
                                                    "region": {
                                                        "startLine": l,
                                                        "startColumn": c,
                                                        "byteOffset": byte
                                                    }
                                                }
                                            })
                                        })
                                    });
                                    serde_json::json!({
                                        "location": location,
                                        "message": { "text": desc }
                                    })
                                }).collect::<Vec<_>>()
                            }]
                        }],
                        "properties": {
                            "confidence": adv.confidence,
                            "requires_human": adv.requires_human,
                            "tags": adv.tags,
                            "cwe": adv.cwe(),
                            "tier": adv.tier.as_str(),
                        }
                    })
                }).collect::<Vec<_>>()
            }]
        })
    }

    /// Generates GitHub Actions workflow-command annotations, one line per
    /// finding:
    ///
    /// `::error file=src/app.py,line=42,col=7,title=SQL Injection::message`
    ///
    /// Printed to stdout inside a workflow step, these render as inline
    /// annotations on the PR's Files Changed tab and in the check-run
    /// summary, no SARIF upload step required. The `file` path is emitted
    /// as given; in a workflow step the working directory is the repo
    /// root, so runner-relative paths resolve naturally.
    ///
    /// Property values are percent-escaped per the workflow-command spec
    /// (`%` → `%25`, `\r` → `%0D`, `\n` → `%0A`, `:` → `%3A`, `,` → `%2C`)
    /// so messages containing commas/colons/newlines cannot inject forged
    /// commands or split into bogus properties. The message body is
    /// data-only after the `::` separator, so newlines there are collapsed
    /// to spaces instead of escaped (GitHub truncates multi-line messages
    /// at the first line break anyway).
    #[must_use]
    pub fn to_github_annotations(advisories: &[Advisory]) -> String {
        let mut out = String::new();
        for adv in advisories {
            let command = match adv.severity {
                crate::Severity::Critical => "error",
                crate::Severity::Warning => "warning",
                crate::Severity::Info => "notice",
            };
            // One-line message: title plus the observation. Taint steps go
            // into the annotation body as a compact flow summary - GitHub
            // renders the body after the `::` separator.
            let mut message = format!("{}: {}", adv.title, adv.observation);
            // The text observation usually embeds the full taint path
            // already; only append the compact flow summary when it
            // doesn't, so annotations don't print the path twice.
            if !adv.taint_steps.is_empty() && !message.contains("Taint path:") {
                let flow: Vec<String> = adv
                    .taint_steps
                    .iter()
                    .take(5)
                    .map(|(desc, _)| desc.clone())
                    .collect();
                message.push_str(&format!(" [flow: {}]", flow.join(" → ")));
            }
            let _ = writeln!(
                out,
                "::{command} file={},line={},col={},title={}::{}",
                escape_workflow_property(&adv.file_path),
                adv.line,
                adv.column,
                escape_workflow_property(&adv.title),
                escape_workflow_message(&message),
            );
        }
        out
    }
}

/// Percent-escape a workflow-command property value (file, title): these
/// sit before the `::` separator where every delimiter is structural.
fn escape_workflow_property(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
        .replace(':', "%3A")
        .replace(',', "%2C")
}

/// Escape a workflow-command message body (after the `::` separator).
/// `%` and line breaks are still structural here; `,` and `:` are not.
fn escape_workflow_message(value: &str) -> String {
    value.replace('%', "%25").replace(['\r', '\n'], " ")
}

/// Deterministic one-line description of one taint-path step.
///
/// Presentation of the engine's structured [`PathStep`] data: the engine
/// records steps, this renders them for text, SARIF codeFlows, and LSP
/// clients. Without the step's source span the wording falls back to SSA
/// variable numbers (`v11`); [`describe_step`] resolves the real expression
/// instead.
#[must_use]
pub fn describe_path_step(step: &PathStep) -> String {
    describe_step(step, None)
}

/// One taint-path step, named from the source text at its span when known.
///
/// The IR names values `v11`; the developer names them `resp.data`. With the
/// step's `(file, byte-range)` the rendered flow shows the expression the
/// step actually moves (`reads `resp.data``), which is the only form that
/// can be matched against the code on screen.
#[must_use]
pub fn describe_step(step: &PathStep, span: Option<&(String, (usize, usize))>) -> String {
    let excerpt = span.and_then(|(file, range)| source_excerpt(file, *range));
    match step {
        PathStep::Source { description } => {
            format!("source: `{description}`")
        }
        PathStep::Phi {
            function,
            variable: _,
        } => {
            let function = short_fn(function);
            match excerpt {
                Some(text) => format!("`{function}`: merge of incoming values (`{text}`)"),
                None => format!("`{function}`: merge of incoming values"),
            }
        }
        PathStep::FieldLoad {
            function,
            base,
            field,
        } => {
            let function = short_fn(function);
            match excerpt {
                Some(text) => format!("`{function}`: reads `{text}`"),
                None if is_ssa_temp(base) => format!("`{function}`: reads field `{field}`"),
                None => format!("`{function}`: reads `{base}.{field}`"),
            }
        }
        PathStep::CallReturn {
            function,
            callee,
            external,
        } => {
            let function = short_fn(function);
            if *external {
                format!("`{function}`: value from unresolvable call `{callee}`")
            } else {
                format!("`{function}`: value returned by `{callee}`")
            }
        }
        PathStep::CallArgument {
            function,
            callee,
            slot,
        } => {
            // The SVFG marks a call's receiver operand (`x.f(..)`), not a
            // positional argument, with the sentinel arg index.
            let function = short_fn(function);
            if *slot == frensense_engine::graph::svfg::RECEIVER_ARG_INDEX {
                format!("`{function}`: passes receiver to `{callee}`")
            } else {
                format!("`{function}`: passes value to `{callee}` (arg {slot})")
            }
        }
        PathStep::FormalParam { function, param } => {
            format!("`{}`: enters as parameter `{param}`", short_fn(function))
        }
        PathStep::ReturnToCaller { caller } => {
            format!("returns into `{}`", short_fn(caller))
        }
        PathStep::Assignment { function, variable } => {
            let function = short_fn(function);
            match excerpt {
                Some(text) => format!("`{function}`: `{text}`"),
                None => format!("`{function}`: flows through v{variable}"),
            }
        }
    }
}

/// Last segment of a qualified function name: the engine keys functions by
/// `file::function`, which repeats what the step's own location line already
/// says.
fn short_fn(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

/// An SSA temporary name (`v11`, `v0`) rather than a source-level identifier.
fn is_ssa_temp(name: &str) -> bool {
    name.strip_prefix('v')
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

/// Source text at `(start, end)`, whitespace-collapsed and length-capped so
/// it fits one line of a flow trace. `None` when the file is unreadable or
/// the range is empty/out of bounds.
fn source_excerpt(file: &str, (start, end): (usize, usize)) -> Option<String> {
    if end <= start {
        return None;
    }
    let text = read_source(file)?;
    let slice = text.get(start..end)?;
    let collapsed = slice.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    Some(if collapsed.chars().count() > MAX_EXCERPT_CHARS {
        collapsed
            .chars()
            .take(MAX_EXCERPT_CHARS)
            .collect::<String>()
            + "\u{2026}"
    } else {
        collapsed
    })
}

/// Longest excerpt shown in a flow step, in characters.
const MAX_EXCERPT_CHARS: usize = 60;

/// Memoized source text per file: one flow trace reads the same file once
/// per step, and multi-finding scans read the same files repeatedly.
fn read_source(file: &str) -> Option<std::rc::Rc<str>> {
    thread_local! {
        static CACHE: std::cell::RefCell<HashMap<String, Option<std::rc::Rc<str>>>> =
            std::cell::RefCell::new(HashMap::new());
    }
    CACHE.with(|cache| {
        cache
            .borrow_mut()
            .entry(file.to_string())
            .or_insert_with(|| std::fs::read_to_string(file).ok().map(std::rc::Rc::from))
            .clone()
    })
}

/// Render a taint path as an indented multi-line text block (CLI output).
#[must_use]
pub fn render_taint_path(path: &TaintPath) -> String {
    let mut out = String::new();
    for (i, step) in path.steps.iter().enumerate() {
        let span = path.spans.get(i).and_then(Option::as_ref);
        let _ = writeln!(out, "  {:>2}. {}", i + 1, describe_step(step, span));
    }
    out
}

/// A source excerpt around a finding: the line before (when present) and
/// the finding's own line, with a caret span under the flagged token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeFrame {
    /// `(1-based line number, text with tabs expanded)`.
    pub lines: Vec<(usize, String)>,
    /// 0-based column of the caret on the last line (tab-expanded).
    pub caret_col: usize,
    /// Number of caret characters (at least 1).
    pub caret_len: usize,
}

const MAX_FRAME_WIDTH: usize = 160;

/// Build the frame for `file:line:column` by reading the file. `None` when
/// the file is unreadable or the line is out of range, so callers fall back
/// to the location-only form.
#[must_use]
pub fn code_frame(file: &str, line: u32, column: u32) -> Option<CodeFrame> {
    if line == 0 {
        return None;
    }
    let text = std::fs::read_to_string(file).ok()?;
    frame_from_source(&text, line as usize, column as usize)
}

fn expand_tabs(s: &str) -> String {
    s.replace('\t', "    ")
}

fn frame_from_source(text: &str, line: usize, column: usize) -> Option<CodeFrame> {
    let all: Vec<&str> = text.lines().collect();
    let target = all.get(line.checked_sub(1)?)?;
    let mut lines = Vec::new();
    if line >= 2
        && let Some(prev) = all.get(line - 2)
        && !prev.trim().is_empty()
    {
        lines.push((line - 1, expand_tabs(prev)));
    }
    // Caret position: columns count characters; tabs expand to four.
    let chars: Vec<char> = target.chars().collect();
    let col0 = column.saturating_sub(1).min(chars.len());
    let tab_extra = chars[..col0].iter().filter(|c| **c == '\t').count() * 3;
    let caret_col = col0 + tab_extra;
    let caret_len = chars[col0..]
        .iter()
        .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | ':' | '$' | '?' | '!'))
        .count()
        .max(1);
    let mut shown = expand_tabs(target);
    if shown.chars().count() > MAX_FRAME_WIDTH {
        shown = shown.chars().take(MAX_FRAME_WIDTH).collect::<String>() + "...";
    }
    lines.push((line, shown));
    Some(CodeFrame {
        lines,
        caret_col,
        caret_len: caret_len.min(MAX_FRAME_WIDTH.saturating_sub(caret_col).max(1)),
    })
}

/// Byte offset → 1-based (line, column) within a file, reading the source
/// from disk. Results are memoized per file for one SARIF render (advisory
/// counts are small; this keeps multi-finding scans from re-reading the
/// same source repeatedly).
/// SARIF region for the finding's own location, with the source line as
/// `snippet` when the file is readable.
fn sarif_region(adv: &Advisory) -> serde_json::Value {
    let mut region = serde_json::json!({
        "startLine": adv.line,
        "startColumn": adv.column,
    });
    if let Some(frame) = code_frame(&adv.file_path, adv.line, adv.column)
        && let Some((_, text)) = frame.lines.last()
    {
        region["snippet"] = serde_json::json!({ "text": text });
        region["endColumn"] = serde_json::json!(adv.column as usize + frame.caret_len);
    }
    region
}

fn line_col_for(file: &str, byte_offset: usize) -> Option<(usize, usize)> {
    thread_local! {
        static SOURCE_CACHE: std::cell::RefCell<HashMap<String, Option<Vec<u8>>>> =
            std::cell::RefCell::new(HashMap::new());
    }
    let source = SOURCE_CACHE.with(|cache| {
        cache
            .borrow_mut()
            .entry(file.to_string())
            .or_insert_with(|| std::fs::read(file).ok())
            .clone()
    })?;
    let end = byte_offset.min(source.len());
    let mut line = 1usize;
    let mut col = 1usize;
    for &b in &source[..end] {
        if b == b'\n' {
            line += 1;
            col = 1;
        } else {
            // UTF-8 continuation bytes are part of the same character.
            if b & 0xC0 != 0x80 {
                col += 1;
            }
        }
    }
    Some((line, col))
}

#[cfg(test)]
mod taint_render_tests {
    use frensense_engine::analysis::taint::path::{PathStep, TaintPath};

    use super::{describe_path_step, describe_step, render_taint_path};

    /// A temporary file plus the byte range of `needle` inside it.
    fn fixture(name: &str, source: &str, needle: &str) -> (String, (usize, usize)) {
        let dir = std::env::temp_dir().join(format!("frensense-step-{name}"));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("app.ts");
        std::fs::write(&file, source).expect("write");
        let start = source.find(needle).expect("needle");
        (
            file.to_string_lossy().into_owned(),
            (start, start + needle.len()),
        )
    }

    /// Steps name the expression the source uses, not `v11`: the IR number is
    /// meaningless to the reader and cannot be matched against the code.
    #[test]
    fn steps_are_named_from_source_text_not_ssa_numbers() {
        let (file, range) = fixture(
            "names",
            "const a = req.body.name\nres.send(a)\n",
            "req.body.name",
        );
        let span = (file, range);
        let step = PathStep::Assignment {
            function: "/repo/src/app.ts::handler".into(),
            variable: 11,
        };
        let text = describe_step(&step, Some(&span));
        assert!(text.contains("`req.body.name`"), "{text}");
        assert!(!text.contains("v11"), "{text}");
        assert!(text.starts_with("`handler`"), "file prefix kept: {text}");
    }

    /// An SSA-named receiver without a readable span must not leak `v7`
    /// either: the field name alone is what the reader can act on.
    #[test]
    fn field_load_without_a_span_drops_the_ssa_receiver() {
        let step = PathStep::FieldLoad {
            function: "handler".into(),
            base: "v7".into(),
            field: "token".into(),
        };
        let text = describe_step(&step, None);
        assert!(text.contains("field `token`"), "{text}");
        assert!(!text.contains('v'), "{text}");
    }

    #[test]
    fn long_or_missing_spans_fall_back_instead_of_panicking() {
        let step = PathStep::Assignment {
            function: "handler".into(),
            variable: 3,
        };
        assert!(
            describe_step(&step, Some(&("/nope/missing.ts".into(), (0, 8))))
                .contains("flows through v3")
        );
        let (file, _) = fixture("range", "x = 1\n", "x");
        assert!(describe_step(&step, Some(&(file, (900, 950)))).contains("flows through v3"));
    }

    /// `render_taint_path` uses each step's own span, so the text report and
    /// the JSON/SARIF flows name the same expressions.
    #[test]
    fn rendered_flow_uses_step_spans() {
        let (file, range) = fixture(
            "path",
            "const p = req.body.path\nread(p)\n",
            "req.body.path",
        );
        let p = TaintPath {
            steps: vec![
                PathStep::Source {
                    description: "req.body.path".into(),
                },
                PathStep::FieldLoad {
                    function: "handler".into(),
                    base: "v4".into(),
                    field: "path".into(),
                },
            ],
            spans: vec![Some((file.clone(), range)), Some((file, range))],
        };
        let text = render_taint_path(&p);
        assert!(text.contains("reads `req.body.path`"), "{text}");
        assert!(!text.contains("v4"), "{text}");
    }

    #[test]
    fn render_text_is_numbered_source_first() {
        let p = TaintPath {
            steps: vec![
                PathStep::Source {
                    description: "req.body".into(),
                },
                PathStep::Assignment {
                    function: "f".into(),
                    variable: 1,
                },
            ],
            spans: vec![None, None],
        };
        let text = render_taint_path(&p);
        assert!(text.contains("1. source:"));
        assert!(text.contains("2. `f`"));
    }

    #[test]
    fn describe_covers_every_step_variant() {
        let steps = [
            PathStep::Source {
                description: "req.body".into(),
            },
            PathStep::Phi {
                function: "f".into(),
                variable: 1,
            },
            PathStep::FieldLoad {
                function: "f".into(),
                base: "obj".into(),
                field: "a".into(),
            },
            PathStep::CallReturn {
                function: "f".into(),
                callee: "g".into(),
                external: false,
            },
            PathStep::CallReturn {
                function: "f".into(),
                callee: "ext".into(),
                external: true,
            },
            PathStep::CallArgument {
                function: "f".into(),
                callee: "g".into(),
                slot: 2,
            },
            PathStep::FormalParam {
                function: "f".into(),
                param: "x".into(),
            },
            PathStep::ReturnToCaller {
                caller: "caller".into(),
            },
            PathStep::Assignment {
                function: "f".into(),
                variable: 7,
            },
        ];
        for step in &steps {
            assert!(!describe_path_step(step).is_empty());
        }
    }
}
#[cfg(test)]
mod sarif_line_mapping_tests {
    use super::{Reporter, code_frame, frame_from_source};
    use crate::Advisory;
    use std::path::Path;

    #[test]
    fn code_frame_marks_the_flagged_call_and_expands_tabs() {
        let src = "a = 1\n\tdb.query(q)\nz = 2\n";
        let f = frame_from_source(src, 2, 2).expect("frame");
        assert_eq!(f.lines.len(), 2);
        assert_eq!(f.lines[1], (2, "    db.query(q)".to_string()));
        assert_eq!(f.caret_col, 4, "tab expands to four columns");
        assert_eq!(f.caret_len, "db.query".len());
    }

    #[test]
    fn code_frame_handles_edges_without_panicking() {
        assert!(frame_from_source("x\n", 0, 1).is_none());
        assert!(frame_from_source("x\n", 9, 1).is_none());
        let f = frame_from_source("x\n", 1, 99).expect("frame");
        assert_eq!(f.lines, vec![(1, "x".to_string())]);
        assert_eq!(f.caret_len, 1);
        assert!(code_frame("/definitely/not/here.rs", 3, 1).is_none());
    }

    fn rule_advisory(msg: &str) -> Advisory {
        let mut a = Advisory::bare(
            format!("SQL injection: `{msg}` reaches `query`"),
            crate::Severity::Critical,
            crate::FileId(0),
            Path::new("app.py"),
            "obs",
        );
        a.rule_id = "taint.sql-injection".to_string();
        a.tags = vec!["taint".into(), "CWE-89".into()];
        a.line = 3;
        a.column = 5;
        a
    }

    #[test]
    fn sarif_groups_findings_by_stable_rule_id_not_message() {
        let advisories = vec![rule_advisory("a"), rule_advisory("b")];
        let sarif = Reporter::to_sarif(&advisories, Path::new("."));
        let run = &sarif["runs"][0];
        let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
        assert_eq!(rules.len(), 1, "two findings, one rule");
        assert_eq!(rules[0]["id"], "taint.sql-injection");
        let tags = rules[0]["properties"]["tags"].as_array().expect("tags");
        assert!(tags.iter().any(|t| t == "external/cwe/cwe-89"), "{tags:?}");
        let results = run["results"].as_array().expect("results");
        assert!(results.iter().all(|r| r["ruleId"] == "taint.sql-injection"));
        assert!(results.iter().all(|r| r["ruleIndex"] == 0));
    }

    #[test]
    fn missing_rule_id_is_derived_from_title_never_raw_text() {
        let mut a = rule_advisory("x");
        a.title = "Unsanitized data from `req.body` reaches sink `send`".to_string();
        a.rule_id.clear();
        let id = a.rule_id();
        assert!(id.starts_with("policy."), "{id}");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'),
            "{id}"
        );
    }

    use super::line_col_for;

    #[test]
    fn maps_byte_offset_to_line_and_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.ts");
        std::fs::write(&path, "const a = 1;\nconst b = 2;\n  const c = a + b;\n").unwrap();
        let file = path.to_str().unwrap();

        // Byte 0 → line 1 col 1.
        assert_eq!(line_col_for(file, 0), Some((1, 1)));
        // Byte offset of `b` on line 2: line 1 is 13 bytes, b at index 6 → 19 → (2, 7).
        assert_eq!(line_col_for(file, 19), Some((2, 7)));
        // Line 3, column 3 (after two spaces): lines 1-2 are 26 bytes, +2 → (3, 3).
        assert_eq!(line_col_for(file, 28), Some((3, 3)));
    }

    #[test]
    fn utf8_characters_count_as_one_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("u.ts");
        // 'é' is 2 bytes; the offset of `x` is line bytes + 2.
        std::fs::write(&path, "const s = \"é\";\nconst x = s;\n").unwrap();
        let file = path.to_str().unwrap();
        let second_line_start = "const s = \"é\";\n".len();
        let offset = second_line_start + "const ".len();
        assert_eq!(line_col_for(file, offset), Some((2, 7)));
    }

    #[test]
    fn unreadable_files_return_none() {
        assert_eq!(line_col_for("/nonexistent/file.ts", 10), None);
    }

    #[test]
    fn offsets_beyond_eof_clamp_to_file_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.ts");
        std::fs::write(&path, "abc\n").unwrap();
        let file = path.to_str().unwrap();
        // Clamped to len 4 → 1 newline → line 2, col 1.
        assert_eq!(line_col_for(file, 999), Some((2, 1)));
    }

    // ── GitHub annotations ────────────────────────────────────────────────

    fn sample_advisory() -> Advisory {
        Advisory::bare(
            "Path Traversal",
            crate::Severity::Critical,
            crate::FileId(0),
            std::path::Path::new("src/app.py"),
            "Unsanitized data reaches open()",
        )
        .with_line(42)
        .with_column(7)
    }

    #[test]
    fn github_annotation_severity_maps_to_commands() {
        let mut critical = sample_advisory();
        critical.severity = crate::Severity::Critical;
        let mut warning = sample_advisory();
        warning.severity = crate::Severity::Warning;
        let mut info = sample_advisory();
        info.severity = crate::Severity::Info;

        let out = Reporter::to_github_annotations(&[critical, warning, info]);
        assert!(out.contains("::error file=src/app.py,line=42,col=7"));
        assert!(out.contains("::warning file=src/app.py,line=42,col=7"));
        assert!(out.contains("::notice file=src/app.py,line=42,col=7"));
        // Every finding is its own line.
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn github_annotation_escapes_structural_characters() {
        let mut adv = sample_advisory();
        adv.title = "Injection, the sequel: harder".into();
        adv.observation = "100% of flows\nreach eval()".into();

        let out = Reporter::to_github_annotations(&[adv]);
        assert_eq!(
            out.lines().count(),
            1,
            "newline in message must be collapsed: {out:?}"
        );
        let line = out.lines().next().unwrap();
        // Property delimiters escaped in the title (before ::).
        assert!(line.contains("title=Injection%2C the sequel%3A harder"));
        // Message body: % escaped, newlines collapsed to spaces.
        assert!(line.contains("100%25 of flows reach eval()"));
    }

    #[test]
    fn github_annotation_empty_findings_is_empty_output() {
        assert_eq!(Reporter::to_github_annotations(&[]), "");
    }

    #[test]
    fn github_annotation_includes_flow_summary() {
        let mut adv = sample_advisory();
        adv.taint_steps = vec![
            ("source: request.args".to_string(), None),
            ("sink: open".to_string(), None),
        ];
        let out = Reporter::to_github_annotations(&[adv]);
        assert!(out.contains("[flow: source: request.args → sink: open]"));
    }
}
