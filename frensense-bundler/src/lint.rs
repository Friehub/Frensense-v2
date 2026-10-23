// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Corpus lint: refuses families that would teach the engine the wrong thing.
//!
//! The replay gate proves that a *fact* separates a family's own pair. It
//! cannot tell whether the pair itself is trustworthy: mislabeled, copied,
//! duplicated, missing provenance, or only passing because the negative uses a
//! meaningless guard. This module checks those properties before the bundler
//! runs, so unattended authors (human or agent) cannot add a bad family
//! quietly.
//!
//! The lint reads the `[frensense]` block of every positive and checks it
//! against a class registry (`bug_classes.json`), the file layout, provenance,
//! cross-family diversity and, optionally, the family's *purpose* against what
//! the bare engine actually does with it - including whether the replay gate
//! would publish any fact from the family at all, with the reason it would
//! not, so a family that teaches nothing cannot pass lint silently.
//!
//! It is self-contained: it walks the corpus with the same naming rules as
//! `extract::group_families` but does not depend on [`FamilyMetadata`], so the
//! metadata struct can evolve independently.
//!
//! [`FamilyMetadata`]: crate::extract::FamilyMetadata

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Metadata keys the lint recognises. Anything else inside a `[frensense]`
/// block is reported (a typo such as `serverity` is otherwise silently lost).
pub const KNOWN_KEYS: &[&str] = &[
    "observation",
    "impact",
    "improvement",
    "cwe",
    "cvss",
    "owasp",
    "severity",
    "check-rule",
    "wrap-max",
    "unbounded-product",
    "package",
    "guard",
    "require-arg-key",
    "check-call",
    "class",
    "purpose",
    "shape",
    "source",
    "expect",
];

/// Keys every training positive must carry.
const REQUIRED_KEYS: &[&str] = &["observation", "impact", "improvement", "cwe", "severity"];

const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "warning", "info"];

const PURPOSES: &[&str] = &["knowledge", "precision", "anchor"];

const SUPPORTED_EXTS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "py", "go", "rs", "c", "cpp", "h", "hpp",
];

/// Calls that are everyday method names. A fact keyed on one of these without
/// a package or receiver fires across unrelated code.
const GENERIC_VERBS: &[&str] = &[
    "get", "set", "put", "post", "delete", "send", "write", "read", "run", "call", "execute",
    "query", "open", "close", "add", "update", "push", "load", "join",
];

/// Names that read as a test double rather than a real API.
const SYNTHETIC_PREFIXES: &[&str] = &[
    "vuln",
    "unsafe_",
    "safe_",
    "insecure_",
    "bad_",
    "good_",
    "fixed_",
    "patched_",
    "fake_",
    "dummy_",
    "sink_",
    "source_",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warn,
}

#[derive(Debug, Clone, Serialize)]
pub struct Issue {
    pub code: &'static str,
    pub level: Level,
    pub family: String,
    pub file: Option<String>,
    pub message: String,
}

/// One accepted-or-not family, for coverage tracking.
#[derive(Debug, Clone, Serialize)]
pub struct FamilyRow {
    pub family: String,
    pub lang: String,
    pub class: Option<String>,
    pub purpose: Option<String>,
    pub has_heldout: bool,
    pub errors: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub issues: Vec<Issue>,
    pub families: Vec<FamilyRow>,
}

impl Report {
    pub fn errors(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.level == Level::Error)
            .count()
    }
    pub fn warnings(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.level == Level::Warn)
            .count()
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Path to `bug_classes.json`. When `None`, looked up next to the corpus
    /// root and then one directory above it.
    pub classes: Option<PathBuf>,
    /// Treat a missing held-out pair as an error instead of a warning.
    pub require_heldout: bool,
    /// Compare each family's declared purpose with the bare engine's verdict.
    pub gate: bool,
    /// Call-set overlap at or above which two same-class, same-language
    /// positives count as near-duplicates.
    pub dup_threshold: f64,
    /// Held-out vs training similarity at or above which the held-out pair is
    /// treated as a copy.
    pub heldout_threshold: f64,
    /// Structural-clone similarity (identifiers and literals abstracted) at or
    /// above which two same-class, same-language positives are renamed copies.
    pub clone_threshold: f64,
    /// Offline advisory index (`advisories.json`); when set, every cited
    /// advisory must exist in it and agree with the family's CWE.
    pub advisories: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            classes: None,
            require_heldout: false,
            gate: true,
            dup_threshold: 0.8,
            heldout_threshold: 0.85,
            clone_threshold: 0.85,
            advisories: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Class registry
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Registry {
    class: Vec<ClassDef>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClassDef {
    pub id: String,
    pub name: String,
    pub cwe: String,
    #[serde(default)]
    pub related_cwe: Vec<String>,
    #[serde(default)]
    pub mechanism: String,
    #[serde(default)]
    pub priority: String,
}

fn load_registry(path: &Path) -> Result<BTreeMap<String, ClassDef>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read class registry {}: {e}", path.display()))?;
    let reg: Registry =
        serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let mut out = BTreeMap::new();
    for c in reg.class {
        if out.insert(c.id.clone(), c.clone()).is_some() {
            return Err(format!("duplicate class id in registry: {}", c.id));
        }
    }
    Ok(out)
}

fn find_registry(corpus: &Path, explicit: &Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        return Ok(p.clone());
    }
    let mut candidates = vec![corpus.join("bug_classes.json")];
    if let Some(parent) = corpus.parent() {
        candidates.push(parent.join("bug_classes.json"));
    }
    candidates.into_iter().find(|c| c.is_file()).ok_or_else(|| {
        "no class registry found: pass --classes <bug_classes.json> or put it next to the corpus"
            .to_string()
    })
}

// ---------------------------------------------------------------------------
// File model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Positive,
    Negative,
    HeldoutPositive,
    HeldoutNegative,
}

#[derive(Debug)]
struct Block {
    start_line: usize,
    entries: Vec<(String, String, usize)>,
}

impl Block {
    fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, v, _)| v.as_str())
    }
}

#[derive(Debug)]
struct Variant {
    rel: String,
    ext: String,
    lang: String,
    kind: Kind,
    source: String,
    block: Option<Block>,
    /// 1-based line of a `[frensense]` marker found anywhere in the file.
    marker_line: Option<usize>,
}

fn comment_prefixes(ext: &str) -> &'static [&'static str] {
    if matches!(ext, "py" | "pyi" | "pyw") {
        &["#", "//"]
    } else {
        &["//", "#"]
    }
}

fn strip_comment<'a>(prefixes: &[&str], line: &'a str) -> Option<&'a str> {
    let t = line.trim();
    prefixes
        .iter()
        .find_map(|p| t.strip_prefix(p))
        .map(str::trim)
}

/// Parse the `[frensense]` block the way the bundler does (first 30 lines,
/// comment lines only, ends at the first non-comment line), but keep unknown
/// keys so they can be reported.
fn parse_block(source: &str, ext: &str) -> (Option<Block>, Option<usize>) {
    let prefixes = comment_prefixes(ext);
    let mut marker_line = None;
    for (i, line) in source.lines().enumerate() {
        if strip_comment(prefixes, line) == Some("[frensense]") {
            marker_line = Some(i + 1);
            break;
        }
    }
    let mut block: Option<Block> = None;
    let mut in_block = false;
    for (i, line) in source.lines().take(30).enumerate() {
        let Some(body) = strip_comment(prefixes, line) else {
            if in_block {
                break;
            }
            continue;
        };
        if body == "[frensense]" {
            in_block = true;
            block = Some(Block {
                start_line: i + 1,
                entries: Vec::new(),
            });
            continue;
        }
        if !in_block {
            continue;
        }
        if let Some((k, v)) = body.split_once(':') {
            let v = v.trim();
            if !v.is_empty() {
                if let Some(b) = block.as_mut() {
                    b.entries
                        .push((k.trim().to_ascii_lowercase(), v.to_string(), i + 1));
                }
            }
        }
    }
    (block, marker_line)
}

fn classify(name: &str) -> Option<(String, Kind)> {
    let (i, positive) = if let Some(i) = name.find("_positive") {
        (i, true)
    } else if let Some(i) = name.find("_negative") {
        (i, false)
    } else {
        return None;
    };
    let stem = &name[..i];
    if let Some(base) = stem.strip_suffix("_heldout") {
        let kind = if positive {
            Kind::HeldoutPositive
        } else {
            Kind::HeldoutNegative
        };
        return Some((base.to_string(), kind));
    }
    Some((
        stem.to_string(),
        if positive {
            Kind::Positive
        } else {
            Kind::Negative
        },
    ))
}

fn walk(corpus: &Path) -> Result<Vec<PathBuf>, String> {
    let mut stack = vec![corpus.to_path_buf()];
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

fn lang_of(ext: &str) -> String {
    frensense_lang::spec_for_ext(ext)
        .map(|s| s.name().to_string())
        .unwrap_or_else(|| ext.to_string())
}

/// Source with comments removed, so a comment-only difference is not a fix.
fn strip_comments(source: &str, ext: &str) -> String {
    let block = Regex::new(r"(?s)/\*.*?\*/").expect("static regex");
    let no_block = block.replace_all(source, " ");
    let hash = matches!(ext, "py" | "pyi" | "pyw");
    let mut out = String::new();
    for line in no_block.lines() {
        let t = line.trim_start();
        if t.starts_with("//") || (hash && t.starts_with('#')) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn tokens(source: &str, ext: &str) -> Vec<String> {
    let re = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*|\d+|\S").expect("static regex");
    re.find_iter(&strip_comments(source, ext))
        .map(|m| m.as_str().to_string())
        .collect()
}

fn shingles(tokens: &[String], n: usize) -> BTreeSet<String> {
    if tokens.len() < n {
        return tokens.iter().cloned().collect();
    }
    tokens.windows(n).map(|w| w.join(" ")).collect()
}

fn jaccard<T: Ord>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    inter / union
}

fn call_set(source: &str, ext: &str) -> BTreeSet<String> {
    const KEYWORDS: &[&str] = &[
        "if", "for", "while", "switch", "return", "sizeof", "catch", "function", "fn", "match",
        "def", "func", "elif", "await", "async", "typeof", "new",
    ];
    let re = Regex::new(r"([A-Za-z_][A-Za-z0-9_.]*)\s*\(").expect("static regex");
    re.captures_iter(&strip_comments(source, ext))
        .map(|c| {
            let full = &c[1];
            full.rsplit('.').next().unwrap_or(full).to_string()
        })
        .filter(|n| !KEYWORDS.contains(&n.as_str()))
        .collect()
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

fn canonical_cwe(raw: &str) -> Option<u32> {
    let re = Regex::new(r"^(?i)CWE-(\d+)$").expect("static regex");
    re.captures(raw.trim())
        .and_then(|c| c[1].parse::<u32>().ok())
}

// ---------------------------------------------------------------------------
// Advisory index (offline provenance check)
// ---------------------------------------------------------------------------

/// One entry of `advisories.json`: `{ "CVE-2026-1": { "cwe": ["CWE-78"] } }`.
/// The index is produced by a separate, networked CI step
/// (`scripts/fetch_advisories.py`); the lint itself never touches the network,
/// so a run is deterministic and reproducible offline.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct Advisory {
    #[serde(default)]
    pub cwe: Vec<String>,
}

fn load_advisories(path: &Path) -> Result<BTreeMap<String, Advisory>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read advisory index {}: {e}", path.display()))?;
    let raw: BTreeMap<String, Advisory> =
        serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k.to_ascii_uppercase(), v))
        .collect())
}

fn advisory_ids(src: &str) -> Vec<String> {
    let re = Regex::new(
        r"(?i)(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|OSV-\d{4}-\d+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d{4}|GO-\d{4}-\d{4})",
    )
    .expect("static regex");
    re.find_iter(src)
        .map(|m| m.as_str().to_ascii_uppercase())
        .collect()
}

// ---------------------------------------------------------------------------
// Structural skeleton (rename-proof clone detection)
// ---------------------------------------------------------------------------

/// Token stream with identifiers, strings and numbers abstracted, keeping only
/// control keywords and called names. Two files that differ only by variable,
/// parameter, function or literal renames have the same skeleton, which the
/// call-name overlap cannot see when a copy is padded with extra calls.
fn skeleton(source: &str, ext: &str) -> Vec<String> {
    const KEYWORDS: &[&str] = &[
        "if", "else", "for", "while", "switch", "case", "return", "try", "catch", "except",
        "finally", "function", "fn", "def", "func", "match", "await", "async", "const", "let",
        "var", "new", "throw", "raise", "defer", "go", "struct", "class", "import", "from",
        "unsafe", "with", "yield", "break", "continue", "null", "nil", "None", "true", "false",
    ];
    let re = Regex::new(
        r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`|[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|\S"#,
    )
    .expect("static regex");
    let text = strip_comments(source, ext);
    let toks: Vec<&str> = re.find_iter(&text).map(|m| m.as_str()).collect();
    let mut out = Vec::with_capacity(toks.len());
    for (i, t) in toks.iter().enumerate() {
        let first = t.chars().next().unwrap_or(' ');
        let next_is_call = toks.get(i + 1) == Some(&"(");
        if matches!(first, '"' | '\'' | '`') {
            out.push("STR".to_string());
        } else if first.is_ascii_digit() {
            out.push("NUM".to_string());
        } else if first.is_alphabetic() || first == '_' {
            if KEYWORDS.contains(t) || next_is_call {
                out.push((*t).to_string());
            } else {
                out.push("ID".to_string());
            }
        } else {
            out.push((*t).to_string());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Lint driver
// ---------------------------------------------------------------------------

struct Ctx<'a> {
    issues: Vec<Issue>,
    family: &'a str,
}

impl Ctx<'_> {
    fn push(&mut self, code: &'static str, level: Level, file: Option<&str>, msg: String) {
        self.issues.push(Issue {
            code,
            level,
            family: self.family.to_string(),
            file: file.map(str::to_string),
            message: msg,
        });
    }
    fn err(&mut self, code: &'static str, file: Option<&str>, msg: impl Into<String>) {
        self.push(code, Level::Error, file, msg.into());
    }
    fn warn(&mut self, code: &'static str, file: Option<&str>, msg: impl Into<String>) {
        self.push(code, Level::Warn, file, msg.into());
    }
}

struct FamilyGroup {
    stem: String,
    lang: String,
    variants: Vec<Variant>,
}

impl FamilyGroup {
    fn of(&self, kind: Kind) -> Vec<&Variant> {
        self.variants.iter().filter(|v| v.kind == kind).collect()
    }
}

/// Run the lint over `corpus`.
pub fn run(corpus: &Path, opts: &Options) -> Result<Report, String> {
    let registry = load_registry(&find_registry(corpus, &opts.classes)?)?;

    // 1. Collect and group variants by (stem, language).
    let mut groups: BTreeMap<(String, String), FamilyGroup> = BTreeMap::new();
    for path in walk(corpus)? {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();
        if !SUPPORTED_EXTS.contains(&ext.as_str()) {
            continue;
        }
        let Some((stem, kind)) = classify(name) else {
            continue;
        };
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let (block, marker_line) = parse_block(&source, &ext);
        let lang = lang_of(&ext);
        let rel = path
            .strip_prefix(corpus)
            .unwrap_or(&path)
            .display()
            .to_string();
        groups
            .entry((stem.clone(), lang.clone()))
            .or_insert_with(|| FamilyGroup {
                stem,
                lang: lang.clone(),
                variants: Vec::new(),
            })
            .variants
            .push(Variant {
                rel,
                ext,
                lang,
                kind,
                source,
                block,
                marker_line,
            });
    }

    let mut report = Report::default();

    // Same stem across languages: the bundler would silently split it.
    let mut by_stem: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for g in groups.values() {
        by_stem.entry(&g.stem).or_default().push(&g.lang);
    }
    for (stem, langs) in &by_stem {
        if langs.len() > 1 {
            report.issues.push(Issue {
                code: "S006",
                level: Level::Error,
                family: (*stem).to_string(),
                file: None,
                message: format!(
                    "stem is used by several languages ({}): prefix it with the language so each family is unambiguous",
                    langs.join(", ")
                ),
            });
        }
    }

    let advisories = match &opts.advisories {
        Some(p) => Some(load_advisories(p)?),
        None => None,
    };
    let mut cited: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    // 2. Optional engine verdicts, keyed by (stem, lang).
    let verdicts = if opts.gate {
        bare_engine_verdicts(corpus)
    } else {
        BTreeMap::new()
    };
    let baselines: BTreeMap<(String, String), (bool, bool)> = verdicts
        .iter()
        .map(|(k, v)| (k.clone(), (v.pos, v.neg)))
        .collect();

    // 3. Per-family checks.
    let mut rows: Vec<(
        String,
        String,
        Option<String>,
        BTreeSet<String>,
        String,
        String,
    )> = Vec::new(); // (stem, lang, class, shapes, ext, positive source) for cross-family checks
    for ((stem, lang), g) in &groups {
        let mut cx = Ctx {
            issues: Vec::new(),
            family: stem,
        };
        let positives = g.of(Kind::Positive);
        let negatives = g.of(Kind::Negative);
        let held_pos = g.of(Kind::HeldoutPositive);
        let held_neg = g.of(Kind::HeldoutNegative);

        // --- structure ---
        if positives.is_empty() && !negatives.is_empty() {
            cx.err("S002", None, "negative file(s) without a positive");
        }
        if negatives.is_empty() && !positives.is_empty() {
            cx.err("S001", None, "positive file(s) without a negative");
        }
        if positives.is_empty() && (!held_pos.is_empty() || !held_neg.is_empty()) {
            cx.err(
                "S003",
                None,
                "held-out file(s) without a training pair: there is nothing to generalize from",
            );
        }
        let has_heldout = !held_pos.is_empty() && !held_neg.is_empty();
        if held_pos.is_empty() != held_neg.is_empty() {
            cx.err(
                "S005",
                None,
                "held-out pair is incomplete: it needs both a held-out positive and a held-out negative",
            );
        } else if !has_heldout && !positives.is_empty() {
            let msg = "no held-out pair: a family without one makes no generalization claim";
            if opts.require_heldout {
                cx.err("S004", None, msg);
            } else {
                cx.warn("S004", None, msg);
            }
        }

        // --- marker placement ---
        for v in negatives.iter().chain(&held_pos).chain(&held_neg) {
            if v.marker_line.is_some() {
                let what = if v.kind == Kind::Negative {
                    "negative"
                } else {
                    "held-out"
                };
                cx.err(
                    "S010",
                    Some(&v.rel),
                    format!("{what} file carries a [frensense] block; only training positives may"),
                );
            }
        }
        for v in &positives {
            match (&v.block, v.marker_line) {
                (None, None) => cx.err(
                    "S012",
                    Some(&v.rel),
                    "positive has no [frensense] metadata block",
                ),
                (None, Some(line)) => cx.err(
                    "S013",
                    Some(&v.rel),
                    format!(
                        "[frensense] marker at line {line} is outside the first 30 lines or after code, so the bundler ignores it"
                    ),
                ),
                _ => {}
            }
        }

        // --- metadata: every positive is linted; the first one with a block
        // is what the bundler reads, and the others must agree with it ---
        let mut class_id: Option<String> = None;
        let mut purpose: Option<String> = None;
        let mut shapes: BTreeSet<String> = BTreeSet::new();
        let mut first_cwe: Option<String> = None;
        let mut first_file: Option<String> = None;
        for v in &positives {
            let Some(b) = v.block.as_ref() else { continue };
            let file = Some(v.rel.as_str());
            let is_first = first_file.is_none();
            let (mut c2, mut p2, mut s2) = (None, None, BTreeSet::new());
            if is_first {
                lint_metadata(
                    &mut cx,
                    file,
                    b,
                    &registry,
                    stem,
                    &mut class_id,
                    &mut purpose,
                    &mut shapes,
                    advisories.as_ref(),
                );
                first_cwe = b.get("cwe").map(|c| c.trim().to_ascii_uppercase());
                first_file = Some(v.rel.clone());
            } else {
                lint_metadata(
                    &mut cx,
                    file,
                    b,
                    &registry,
                    stem,
                    &mut c2,
                    &mut p2,
                    &mut s2,
                    advisories.as_ref(),
                );
                let first = first_file.clone().unwrap_or_default();
                if c2 != class_id {
                    cx.err(
                        "M008",
                        file,
                        format!("class differs from `{first}`; one family is one class"),
                    );
                }
                if p2 != purpose {
                    cx.err("M008", file, format!("purpose differs from `{first}`"));
                }
                if b.get("cwe").map(|c| c.trim().to_ascii_uppercase()) != first_cwe {
                    cx.err("M008", file, format!("cwe differs from `{first}`"));
                }
            }

            // Trigger naming.
            if let Some(call) = b.get("check-call") {
                let lower = call.to_ascii_lowercase();
                if SYNTHETIC_PREFIXES.iter().any(|p| lower.starts_with(p)) {
                    cx.warn(
                        "D005",
                        file,
                        format!(
                            "check-call `{call}` reads like a test double; use the real API name"
                        ),
                    );
                }
                if GENERIC_VERBS.contains(&lower.as_str()) && b.get("package").is_none() {
                    cx.err(
                        "E040",
                        file,
                        format!(
                            "check-call `{call}` is an everyday method name; add `package:` so it does not fire on unrelated code"
                        ),
                    );
                }
            }
            if let Some(src) = b.get("source") {
                for id in advisory_ids(src) {
                    cited.entry(id).or_default().insert(stem.clone());
                }
            }
        }

        // --- tautology / copy checks ---
        if let (Some(p), Some(n)) = (positives.first(), negatives.first()) {
            if tokens(&p.source, &p.ext)
                .iter()
                .zip(tokens(&n.source, &n.ext).iter())
                .all(|(a, b)| a == b)
                && tokens(&p.source, &p.ext).len() == tokens(&n.source, &n.ext).len()
            {
                cx.err(
                    "D003",
                    Some(&n.rel),
                    "negative is identical to the positive once comments are removed: it contains no fix",
                );
            }
        }
        if let Some(h) = held_pos.first() {
            let hs = shingles(&tokens(&h.source, &h.ext), 3);
            for p in &positives {
                let sim = jaccard(&hs, &shingles(&tokens(&p.source, &p.ext), 3));
                if sim >= opts.heldout_threshold {
                    cx.err(
                        "D004",
                        Some(&h.rel),
                        format!(
                            "held-out positive is {:.0}% similar to `{}`; it must be structurally different (different sink, wrapper depth, source or control flow)",
                            sim * 100.0,
                            p.rel
                        ),
                    );
                }
            }
        }

        // --- purpose versus the bare engine ---
        if let (Some(purpose), Some(&(pos_alerts, neg_alerts))) = (
            purpose.as_deref(),
            baselines.get(&(stem.clone(), lang.clone())),
        ) {
            let anchor = pos_alerts && !neg_alerts;
            match purpose {
                "anchor" if !anchor => cx.err(
                    "PU002",
                    None,
                    format!(
                        "declared anchor but the bare engine does not separate the pair (positive alerts: {pos_alerts}, negative alerts: {neg_alerts}); it teaches something, so declare knowledge or precision"
                    ),
                ),
                "knowledge" if pos_alerts => cx.err(
                    "PU001",
                    None,
                    "declared knowledge but the bare engine already alerts on the positive; it adds no fact, so declare anchor (or fix the positive so it exercises a gap)",
                ),
                "precision" if !neg_alerts => cx.err(
                    "PU003",
                    None,
                    "declared precision but the bare engine already leaves the negative silent; there is no false positive to remove",
                ),
                _ => {}
            }
        }

        // --- teachability versus the replay gate ---
        // A family can satisfy every purpose check and still contribute
        // nothing: the premise holds (knowledge/positive silent, or
        // precision/negative noisy) yet no proposed fact separates the pair,
        // so the gate publishes nothing from it and the bundle scans both
        // twins as the bare engine did. Anchors are exempt - teaching nothing
        // is their whole point - and the two purpose errors above already
        // cover the states where the declared premise is false.
        if let (Some(declared), Some(v)) = (
            purpose.as_deref(),
            verdicts.get(&(stem.clone(), lang.clone())),
        ) {
            let premise_holds = match declared {
                "knowledge" => !v.pos,
                "precision" => v.neg,
                _ => false,
            };
            if premise_holds {
                if let Some(why) = v.teachability_gap() {
                    cx.warn(
                        "PU004",
                        None,
                        format!(
                            "declared {declared} but the bundle would learn nothing from this family: {why}"
                        ),
                    );
                }
            }
        }

        let errors = cx.issues.iter().filter(|i| i.level == Level::Error).count();
        report.families.push(FamilyRow {
            family: stem.clone(),
            lang: lang.clone(),
            class: class_id.clone(),
            purpose: purpose.clone(),
            has_heldout,
            errors,
        });
        if let Some(p) = positives.first() {
            rows.push((
                stem.clone(),
                lang.clone(),
                class_id,
                shapes,
                p.ext.clone(),
                p.source.clone(),
            ));
        }
        report.issues.extend(cx.issues);
    }

    // 4. Cross-family diversity within (class, language).
    let mut seen: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
    for (i, r) in rows.iter().enumerate() {
        if let Some(c) = &r.2 {
            seen.entry((c.clone(), r.1.clone())).or_default().push(i);
        }
    }
    for ((class, lang), idxs) in &seen {
        for (n, &j) in idxs.iter().enumerate() {
            for &i in &idxs[..n] {
                let (a, b) = (&rows[i], &rows[j]);
                let mut cx = Ctx {
                    issues: Vec::new(),
                    family: &b.0,
                };
                if !a.3.is_empty() && a.3 == b.3 {
                    cx.err(
                        "D002",
                        None,
                        format!(
                            "same shape tags as `{}` in class {class} ({lang}); a second copy of one shape is one family, not two",
                            a.0
                        ),
                    );
                }
                let (ca, cb) = (call_set(&a.5, &a.4), call_set(&b.5, &b.4));
                if ca.len() >= 4 && cb.len() >= 4 {
                    let sim = jaccard(&ca, &cb);
                    if sim >= opts.dup_threshold {
                        cx.err(
                            "D001",
                            None,
                            format!(
                                "positive shares {:.0}% of its calls with `{}` in class {class} ({lang}); near-duplicates make a fact look `confirmed` without independent evidence",
                                sim * 100.0,
                                a.0
                            ),
                        );
                    }
                }
                let (ka, kb) = (
                    shingles(&skeleton(&a.5, &a.4), 4),
                    shingles(&skeleton(&b.5, &b.4), 4),
                );
                if ka.len() >= 8 && kb.len() >= 8 {
                    let sim = jaccard(&ka, &kb);
                    if sim >= opts.clone_threshold {
                        cx.err(
                            "D008",
                            None,
                            format!(
                                "positive is a {:.0}% structural clone of `{}` in class {class} ({lang}) once names and literals are abstracted: a renamed copy",
                                sim * 100.0,
                                a.0
                            ),
                        );
                    }
                }
                report.issues.extend(cx.issues);
            }
        }
    }

    // 5. Semantic duplicates: families that propose the same facts teach the
    // same thing no matter how different the code looks. Compared across
    // classes, because a fact does not know which class it was filed under.
    let mut by_lang: BTreeMap<&str, Vec<(&str, &BTreeSet<String>)>> = BTreeMap::new();
    for ((stem, lang), v) in &verdicts {
        if !v.taught.is_empty() {
            by_lang.entry(lang).or_default().push((stem, &v.taught));
        }
    }
    for (lang, fams) in &by_lang {
        for (n, (b, fb)) in fams.iter().enumerate() {
            for (a, fa) in &fams[..n] {
                let (code, level, what) = if fa == fb {
                    ("D006", Level::Error, "teaches exactly the same facts as")
                } else if fb.is_subset(fa) {
                    ("D007", Level::Warn, "teaches nothing beyond")
                } else if fa.is_subset(fb) {
                    // Report against the smaller family.
                    report.issues.push(Issue {
                        code: "D007",
                        level: Level::Warn,
                        family: (*a).to_string(),
                        file: None,
                        message: format!(
                            "teaches nothing beyond `{b}` ({lang}); its facts are a subset"
                        ),
                    });
                    continue;
                } else {
                    continue;
                };
                report.issues.push(Issue {
                    code,
                    level,
                    family: (*b).to_string(),
                    file: None,
                    message: format!("{what} `{a}` ({lang}): the replay gate will credit one fact to two families"),
                });
            }
        }
    }
    // The same advisory behind several families is allowed (variants), but
    // it is evidence of one bug, not several.
    for (id, stems) in &cited {
        if stems.len() > 1 {
            for stem in stems {
                report.issues.push(Issue {
                    code: "P008",
                    level: Level::Warn,
                    family: stem.clone(),
                    file: None,
                    message: format!(
                        "{id} is also cited by {}; one advisory is one bug, so these count as one source of evidence",
                        stems.iter().filter(|s| *s != stem).cloned().collect::<Vec<_>>().join(", ")
                    ),
                });
            }
        }
    }

    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn lint_metadata(
    cx: &mut Ctx<'_>,
    file: Option<&str>,
    b: &Block,
    registry: &BTreeMap<String, ClassDef>,
    stem: &str,
    class_out: &mut Option<String>,
    purpose_out: &mut Option<String>,
    shapes_out: &mut BTreeSet<String>,
    advisories: Option<&BTreeMap<String, Advisory>>,
) {
    // Required keys.
    for k in REQUIRED_KEYS {
        if b.get(k).is_none() {
            cx.err("M001", file, format!("missing required key `{k}`"));
        }
    }
    // Unknown and duplicate keys.
    let mut seen_keys: BTreeSet<&str> = BTreeSet::new();
    for (k, _, line) in &b.entries {
        if !KNOWN_KEYS.contains(&k.as_str()) {
            let hint = KNOWN_KEYS
                .iter()
                .filter(|known| edit_distance(k, known) <= 2)
                .min_by_key(|known| edit_distance(k, known));
            let msg = match hint {
                Some(h) => format!("unknown key `{k}` at line {line}; did you mean `{h}`?"),
                None => format!("unknown key `{k}` at line {line}"),
            };
            cx.err("M004", file, msg);
        }
        if !seen_keys.insert(k.as_str()) && !matches!(k.as_str(), "guard" | "require-arg-key") {
            cx.warn("M007", file, format!("key `{k}` appears more than once"));
        }
    }
    // Prose quality.
    for k in ["observation", "impact", "improvement"] {
        if let Some(v) = b.get(k) {
            if v.len() < 20 || v.contains("TODO") || v.contains('<') {
                cx.err(
                    "M005",
                    file,
                    format!("`{k}` is a placeholder or too short to be advisory text: {v:?}"),
                );
            }
        }
    }
    // Severity and numeric fields.
    if let Some(s) = b.get("severity") {
        if !SEVERITIES.contains(&s.to_ascii_lowercase().as_str()) {
            cx.err(
                "M003",
                file,
                format!("severity `{s}` is not one of {}", SEVERITIES.join(", ")),
            );
        }
    }
    if let Some(v) = b.get("cvss") {
        match v.parse::<f32>() {
            Ok(n) if (0.0..=10.0).contains(&n) => {}
            _ => cx.err("M006", file, format!("cvss `{v}` is not a number in 0..10")),
        }
    }

    // CWE.
    let cwe_raw = b.get("cwe");
    let cwe_num = cwe_raw.and_then(canonical_cwe);
    if let Some(raw) = cwe_raw {
        match cwe_num {
            None => cx.err(
                "M002",
                file,
                format!("cwe `{raw}` is not of the form CWE-<number>"),
            ),
            Some(n) => {
                if raw.trim() != format!("CWE-{n}") {
                    cx.warn(
                        "M002",
                        file,
                        format!("cwe `{raw}` is not canonical; write CWE-{n}"),
                    );
                }
            }
        }
    }

    // Class.
    match b.get("class") {
        None => cx.err(
            "C001",
            file,
            "missing `class:`; every family maps to exactly one class id",
        ),
        Some(id) => match registry.get(id) {
            None => {
                let hint = registry
                    .keys()
                    .min_by_key(|k| edit_distance(id, k))
                    .filter(|k| edit_distance(id, k) <= 3);
                let msg = match hint {
                    Some(h) => format!("unknown class `{id}`; did you mean `{h}`?"),
                    None => format!("unknown class `{id}` (not in the class registry)"),
                };
                cx.err("C002", file, msg);
            }
            Some(def) => {
                *class_out = Some(id.to_string());
                if let Some(n) = cwe_num {
                    let allowed: Vec<u32> = std::iter::once(def.cwe.as_str())
                        .chain(def.related_cwe.iter().map(String::as_str))
                        .filter_map(canonical_cwe)
                        .collect();
                    if !allowed.contains(&n) {
                        cx.err(
                            "C003",
                            file,
                            format!(
                                "CWE-{n} does not belong to class `{id}` (expects {}{})",
                                def.cwe,
                                if def.related_cwe.is_empty() {
                                    String::new()
                                } else {
                                    format!(", related {}", def.related_cwe.join(", "))
                                }
                            ),
                        );
                    }
                }
            }
        },
    }

    // Purpose.
    match b.get("purpose") {
        None => cx.err(
            "C005",
            file,
            "missing `purpose:` (knowledge, precision or anchor)",
        ),
        Some(p) => {
            let p = p.to_ascii_lowercase();
            if PURPOSES.contains(&p.as_str()) {
                *purpose_out = Some(p);
            } else {
                cx.err(
                    "C005",
                    file,
                    format!("purpose `{p}` is not one of {}", PURPOSES.join(", ")),
                );
            }
        }
    }

    // Shape tags: required for knowledge families, recommended otherwise.
    if let Some(s) = b.get("shape") {
        for t in s.split(',') {
            let t = t.trim().to_ascii_lowercase();
            if !t.is_empty() {
                shapes_out.insert(t);
            }
        }
    }
    if shapes_out.is_empty() {
        if purpose_out.as_deref() == Some("knowledge") {
            cx.err(
                "C006",
                file,
                "knowledge families must declare `shape:` tags so diversity can be checked",
            );
        } else {
            cx.warn("C006", file, "no `shape:` tags");
        }
    }

    // Provenance.
    lint_source(cx, file, b.get("source"), stem, advisories, cwe_num);
}

fn lint_source(
    cx: &mut Ctx<'_>,
    file: Option<&str>,
    source: Option<&str>,
    stem: &str,
    advisories: Option<&BTreeMap<String, Advisory>>,
    cwe_num: Option<u32>,
) {
    let Some(src) = source else {
        cx.err(
            "P001",
            file,
            "missing `source:`; give `<advisory id>, <https url>, <SPDX license>` or `synthetic: <reason>`",
        );
        return;
    };
    if let Some(reason) = src
        .strip_prefix("synthetic:")
        .or_else(|| src.strip_prefix("Synthetic:"))
    {
        if reason.trim().len() < 10 {
            cx.err(
                "P002",
                file,
                "`synthetic:` needs a reason of at least 10 characters",
            );
        }
        return;
    }
    let id_re = Regex::new(
        r"(?i)(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|OSV-\d{4}-\d+|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d{4}|GO-\d{4}-\d{4})",
    )
    .expect("static regex");
    if !id_re.is_match(src) {
        cx.err(
            "P002",
            file,
            format!("`source` has no recognizable advisory id: {src:?}"),
        );
    }
    if !src.contains("https://") {
        cx.err(
            "P002",
            file,
            "`source` has no https:// link to the advisory or fix commit",
        );
    }
    if src.split(',').count() < 3 || src.split(',').nth(2).is_none_or(|l| l.trim().is_empty()) {
        cx.warn(
            "P003",
            file,
            "`source` has no license; add the SPDX license of the code the repro was modeled on",
        );
    }
    // Link host must fit the advisory database the id belongs to.
    for id in advisory_ids(src) {
        let host_ok = |hosts: &[&str]| hosts.iter().any(|h| src.contains(h));
        if id.starts_with("GHSA-") && !host_ok(&["github.com"]) {
            cx.warn(
                "P007",
                file,
                format!("{id} should link to github.com/advisories"),
            );
        }
        if id.starts_with("RUSTSEC-") && !host_ok(&["rustsec.org", "github.com"]) {
            cx.warn("P007", file, format!("{id} should link to rustsec.org"));
        }
        // Offline verification against the advisory index.
        if let Some(index) = advisories {
            match index.get(&id) {
                None => cx.err(
                    "P005",
                    file,
                    format!("{id} is not in the advisory index; it may not exist, or the index is stale"),
                ),
                Some(adv) => {
                    let listed: Vec<u32> = adv.cwe.iter().filter_map(|c| canonical_cwe(c)).collect();
                    if let (Some(n), false) = (cwe_num, listed.is_empty()) {
                        if !listed.contains(&n) {
                            cx.err(
                                "P006",
                                file,
                                format!(
                                    "{id} is filed under {} but the family claims CWE-{n}",
                                    adv.cwe.join(", ")
                                ),
                            );
                        }
                    }
                }
            }
        }
    }
    // A stem that names a CVE must be backed by the same CVE.
    let stem_re = Regex::new(r"(?i)cve_(\d{4})_(\d{4,})").expect("static regex");
    if let Some(c) = stem_re.captures(stem) {
        let want = format!("CVE-{}-{}", &c[1], &c[2]);
        if !src.to_ascii_uppercase().contains(&want) {
            cx.err(
                "P004",
                file,
                format!("family name claims {want} but `source` does not cite it"),
            );
        }
    }
}

/// What the bare engine makes of one family, and what the replay gate would
/// make of the facts it proposes.
struct Verdict {
    pos: bool,
    neg: bool,
    /// Candidate fact keys the family proposes.
    taught: BTreeSet<String>,
    /// Each proposed fact trialled against this family alone:
    /// `(key, positive alerts, negative alerts)`. Left empty when the bare
    /// engine already separates the pair, since a separating pair needs no
    /// fact (an anchor) and a `knowledge`/`precision` family that still
    /// separates is already reported by the purpose checks.
    trials: Vec<(String, bool, bool)>,
}

impl Verdict {
    /// Why the bundle would learn nothing from this family, or `None` when at
    /// least one proposed fact separates its own pair.
    ///
    /// The replay gate publishes a fact only when some voting family
    /// separates under it. A family whose every candidate leaves the twins as
    /// they are contributes neither vocabulary nor evidence, and the failure
    /// is otherwise silent: lint passes, the bundle builds, and the binary
    /// scans both files exactly as before. This names the closest candidate
    /// and the engine verdict that sank it, so the author can act.
    fn teachability_gap(&self) -> Option<String> {
        if self.pos && !self.neg {
            return None;
        }
        if self.trials.iter().any(|t| t.1 && !t.2) {
            return None;
        }
        if self.trials.is_empty() {
            return Some(
                "it proposes no fact at all: the twins differ in no source, sink, sanitizer, \
                 guard or check call, so the bundle would scan both exactly as it does today"
                    .to_string(),
            );
        }
        // The closest attempt: a candidate whose fact at least alerts on the
        // positive shows the shape was seen; only the negative did not go
        // quiet. Fall back to the first trial when nothing alerts at all.
        let (key, pos_alerts, neg_alerts) =
            self.trials.iter().find(|t| t.1).unwrap_or(&self.trials[0]);
        let why = match (pos_alerts, neg_alerts) {
            (true, true) => {
                "the positive alerts but so does the negative, so the gate rejects \
                             the fact as a false positive waiting to happen"
            }
            (false, true) => {
                "the positive stays silent while the negative alerts, so the fact \
                              fixes nothing"
            }
            _ => "both sides stay silent, so the fact changes no verdict",
        };
        Some(format!(
            "none of its {} proposed fact(s) separates the pair; closest is `{key}` \
             (positive_alerts={pos_alerts}, negative_alerts={neg_alerts}): {why}",
            self.trials.len()
        ))
    }
}

/// `(stem, language) -> (positive alerts, negative alerts)` under the bare
/// engine tables, exactly as the bundler's replay gate computes its baseline.
fn bare_engine_verdicts(corpus: &Path) -> BTreeMap<(String, String), Verdict> {
    use crate::extract::{
        apply_candidate, fact_key, family_tables, group_families, propose, Candidate,
        PreparedFamily,
    };
    let key = |c: &Candidate| {
        let (a, b) = fact_key(&c.to_learned_entry());
        format!("{a}:{b}")
    };
    let mut out = BTreeMap::new();
    let Ok(families) = group_families(corpus) else {
        return out;
    };
    for f in families {
        let (cfg, facts) = family_tables(&f);
        let Ok(p) = PreparedFamily::new(&f, &facts) else {
            continue;
        };
        let (pos, neg) = p.alert_flags(&cfg, &facts);
        // What the bundler would try to teach: the candidate facts the
        // pos/neg delta yields, before the replay gate prunes them.
        let cands = propose(&f, &cfg, &facts);
        let taught: BTreeSet<String> = cands.iter().map(key).collect();
        // What each of those would actually do: trial it against this family
        // on its own, the way the gate's per-family vote does, so a family
        // that cannot teach anything says so before the bundle is built.
        let trials: Vec<(String, bool, bool)> = if pos && !neg {
            Vec::new()
        } else {
            cands
                .iter()
                .map(|c| {
                    let mut trial = facts.clone();
                    apply_candidate(&mut trial, c);
                    let (pa, na) = p.alert_flags(&cfg, &trial);
                    (key(c), pa, na)
                })
                .collect()
        };
        let flags = Verdict {
            pos,
            neg,
            taught,
            trials,
        };
        // Family ids are the stem, or `stem (language)` after a collision.
        let (stem, lang) = match f.id.split_once(" (") {
            Some((s, l)) => (s.to_string(), l.trim_end_matches(')').to_string()),
            None => (f.id.clone(), f.language().unwrap_or("").to_string()),
        };
        out.insert((stem, lang), flags);
    }
    out
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Class x language coverage: `families / knowledge / with held-out`, counting
/// only families with no errors.
pub fn coverage_table(report: &Report) -> String {
    let mut cells: BTreeMap<(String, String), (usize, usize, usize)> = BTreeMap::new();
    for f in report.families.iter().filter(|f| f.errors == 0) {
        let Some(c) = &f.class else { continue };
        let e = cells.entry((c.clone(), f.lang.clone())).or_default();
        e.0 += 1;
        e.1 += usize::from(f.purpose.as_deref() == Some("knowledge"));
        e.2 += usize::from(f.has_heldout);
    }
    let mut out = String::from("class | language | families / knowledge / held-out\n");
    for ((c, l), (n, k, h)) in &cells {
        out.push_str(&format!("{c} | {l} | {n} / {k} / {h}\n"));
    }
    out
}

pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    let mut by_family: BTreeMap<&str, Vec<&Issue>> = BTreeMap::new();
    for i in &report.issues {
        by_family.entry(&i.family).or_default().push(i);
    }
    for (fam, issues) in by_family {
        out.push_str(&format!("{fam}\n"));
        for i in issues {
            let lvl = match i.level {
                Level::Error => "error",
                Level::Warn => "warn ",
            };
            let loc = i
                .file
                .as_deref()
                .map(|f| format!(" [{f}]"))
                .unwrap_or_default();
            out.push_str(&format!("  {lvl} {}{loc}: {}\n", i.code, i.message));
        }
    }
    out.push_str(&format!(
        "\n{} families, {} errors, {} warnings\n",
        report.families.len(),
        report.errors(),
        report.warnings()
    ));
    out
}

const USAGE: &str = "\
Usage: frensense lint <corpus_dir> [options]
       frensense-bundler lint <corpus_dir> [options]   (same entry point)

Checks every family against the class registry, file layout, provenance,
cross-family diversity and (by default) the bare engine's verdict on its
declared purpose, plus whether the replay gate could learn a fact from the
family at all (PU004, with the candidate and engine verdict that block it).
Exits 1 when any error is found.

Options:
  --classes <file>        bug_classes.json (default: next to or above the corpus)
  --advisories <file>     offline advisory index; cited ids must exist and match the CWE
  --strict                treat warnings as errors
  --require-heldout       a family without a held-out pair is an error
  --no-gate               skip the bare-engine purpose check (no scan)
  --dup-threshold <0..1>  near-duplicate call overlap (default 0.8)
  --json                  machine-readable report on stdout
  --coverage              print the class x language coverage table
  -h, --help              this help";

/// CLI entry: `args` are the arguments after `lint`. Returns the exit code.
pub fn cli(args: &[String]) -> i32 {
    let mut corpus: Option<PathBuf> = None;
    let mut opts = Options::default();
    let (mut strict, mut json, mut coverage) = (false, false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return 0;
            }
            "--strict" => strict = true,
            "--json" => json = true,
            "--coverage" => coverage = true,
            "--require-heldout" => opts.require_heldout = true,
            "--no-gate" => opts.gate = false,
            "--classes" => match it.next() {
                Some(v) => opts.classes = Some(PathBuf::from(v)),
                None => return usage_error("missing value for --classes"),
            },
            "--advisories" => match it.next() {
                Some(v) => opts.advisories = Some(PathBuf::from(v)),
                None => return usage_error("missing value for --advisories"),
            },
            "--dup-threshold" => match it.next().and_then(|v| v.parse::<f64>().ok()) {
                Some(v) if (0.0..=1.0).contains(&v) => opts.dup_threshold = v,
                _ => return usage_error("--dup-threshold needs a number in 0..1"),
            },
            other if other.starts_with('-') => {
                return usage_error(&format!("unknown flag: {other}"))
            }
            other => {
                if corpus.is_some() {
                    return usage_error(&format!("unexpected extra argument: {other}"));
                }
                corpus = Some(PathBuf::from(other));
            }
        }
    }
    let Some(corpus) = corpus else {
        return usage_error("missing <corpus_dir>");
    };
    let report = match run(&corpus, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            return 2;
        }
    };
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("Error: {e}");
                return 2;
            }
        }
    } else {
        print!("{}", render_text(&report));
        if coverage {
            println!("\n{}", coverage_table(&report));
        }
    }
    let failed = report.errors() > 0 || (strict && report.warnings() > 0);
    i32::from(failed)
}

fn usage_error(msg: &str) -> i32 {
    eprintln!("Error: {msg}\n{USAGE}");
    2
}

#[cfg(test)]
#[path = "lint_tests.rs"]
mod tests;
