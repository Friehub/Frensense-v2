// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Shape fingerprints, shape cells, and the diversity quota.
//!
//! A corpus family is one *shape cell*: one defect mechanism, in one class,
//! in one language, written with one call structure. Two families that differ
//! only in identifier names, literals, comments or formatting teach the same
//! fact, so they are one witness, not two. Without that rule a wave of
//! generated families turns a single witness into `support >= 2` and publishes
//! an over-broad sink.
//!
//! The fingerprint is syntactic, not an AST dump: the normalizer keeps the
//! call structure (callee names and argument counts), keywords and punctuation,
//! and erases everything that carries no teaching signal - local identifiers,
//! literals, comments, whitespace. It is deliberately language-agnostic so all
//! corpus languages share one rule.

use rustc_hash::FxHashMap;

use super::family::Family;
use super::trial_cache;

/// Words that describe control flow or a declaration, not a value: they stay
/// in the fingerprint because they shape the code path taint takes.
const KEYWORDS: &[&str] = &[
    "if",
    "else",
    "elif",
    "for",
    "while",
    "loop",
    "match",
    "switch",
    "case",
    "default",
    "return",
    "break",
    "continue",
    "let",
    "const",
    "var",
    "mut",
    "static",
    "fn",
    "def",
    "function",
    "class",
    "struct",
    "enum",
    "impl",
    "trait",
    "interface",
    "type",
    "new",
    "pub",
    "use",
    "import",
    "from",
    "export",
    "async",
    "await",
    "try",
    "catch",
    "except",
    "finally",
    "throw",
    "raise",
    "yield",
    "defer",
    "go",
    "select",
    "unsafe",
    "as",
    "in",
    "of",
    "not",
    "and",
    "or",
    "is",
    "null",
    "None",
    "true",
    "false",
    "self",
    "this",
];

/// Keywords after which an identifier is a *declared name*, not a call.
const DECLARATIONS: &[&str] = &[
    "fn",
    "def",
    "function",
    "class",
    "struct",
    "enum",
    "trait",
    "interface",
    "type",
    "impl",
];

/// How many families may share one shape cell before the extras stop voting.
/// Three keeps a second witness available (the `confirmed` rule needs two
/// distinct cells, not three copies of one) without letting a generated wave
/// fill a cell.
pub(super) const MAX_PER_CELL: usize = 3;

/// How many shape cells one `(class, language)` pair may contribute. A class
/// is taught once per language by a handful of shapes; beyond that the
/// families are variants of a mechanism already covered.
pub(super) const MAX_PER_CLASS_LANGUAGE: usize = 16;

/// One family's diversity coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Cell {
    /// Hashed `(class, language, shape)` identity: equal ids are the same
    /// witness for every fact the family votes on.
    pub(super) id: String,
    /// Declared `class:` (`bug_classes.json` id), when the family has one.
    pub(super) class: Option<String>,
    /// Language name derived from the variant extensions.
    pub(super) language: Option<String>,
    /// The hashed call/control-flow shape shared by equivalent families.
    pub(super) shape: String,
}

/// Normalize source text to its teaching shape.
///
/// Kept tokens: callee identifiers (an identifier immediately followed by
/// `(`), keywords, and punctuation. Everything else - local identifiers,
/// numbers, string contents, comments, whitespace - collapses, so
/// `exec(req.query.cmd)` and `exec(input)` are the same shape while
/// `exec(x)` and `spawn(x)` are not.
#[must_use]
pub(super) fn shape_of(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len() / 2);
    let mut last = String::new();
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while chars.get(i).is_some_and(|x| *x != '\n') {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while chars.get(i).is_some()
                && !(chars.get(i) == Some(&'*') && chars.get(i + 1) == Some(&'/'))
            {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            continue;
        }
        // Python/shell line comment. Rust attributes (`#[`, `#![`) are code.
        if c == '#' && !matches!(chars.get(i + 1), Some('[') | Some('!')) {
            while chars.get(i).is_some_and(|x| *x != '\n') {
                i += 1;
            }
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            i += 1;
            while let Some(&ch) = chars.get(i) {
                if ch == '\\' {
                    i += 2;
                    continue;
                }
                if ch == c {
                    i += 1;
                    break;
                }
                i += 1;
            }
            push_token(&mut out, &mut last, "s");
            continue;
        }
        if c.is_ascii_digit() {
            while chars
                .get(i)
                .is_some_and(|x| x.is_ascii_alphanumeric() || *x == '.' || *x == '_' || *x == 'x')
            {
                i += 1;
            }
            push_token(&mut out, &mut last, "0");
            continue;
        }
        if c.is_alphabetic() || c == '_' || c == '$' {
            let start = i;
            while chars
                .get(i)
                .is_some_and(|x| x.is_alphanumeric() || *x == '_' || *x == '$')
            {
                i += 1;
            }
            let word: String = chars
                .get(start..i)
                .map(|s| s.iter().collect())
                .unwrap_or_default();
            let mut j = i;
            while chars.get(j).is_some_and(|x| x.is_whitespace()) {
                j += 1;
            }
            let callee = chars.get(j) == Some(&'(');
            // A declared name is not a callee: `function run(` and
            // `function handler(` are the same shape.
            let declared = DECLARATIONS.contains(&last.as_str());
            if KEYWORDS.contains(&word.as_str()) || (callee && !declared) {
                push_token(&mut out, &mut last, &word);
            } else {
                push_token(&mut out, &mut last, "_");
            }
            continue;
        }
        push_token(&mut out, &mut last, &c.to_string());
        i += 1;
    }
    out
}

fn push_token(out: &mut String, last: &mut String, token: &str) {
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(token);
    last.clear();
    last.push_str(token);
}

/// The family's shape: the sorted normalized variants, hashed.
///
/// Sorted because a family's variant count and file order carry no meaning;
/// only the set of shapes it demonstrates does.
#[must_use]
pub(super) fn family_shape(f: &Family) -> String {
    let mut shards: Vec<String> = f
        .positives
        .iter()
        .chain(f.negatives.iter())
        .map(|(_, src, _)| shape_of(src))
        .collect();
    shards.sort();
    trial_cache::hash_str(&shards.join("\u{1f}"))
}

/// The family's shape cell: class, language and shape, hashed.
#[must_use]
pub(super) fn family_cell(f: &Family) -> Cell {
    let shape = family_shape(f);
    let class = f.metadata.class.clone();
    let language = f.language().map(str::to_string);
    let id = trial_cache::hash_str(&format!(
        "{}|{}|{}",
        class.as_deref().unwrap_or(""),
        language.as_deref().unwrap_or(""),
        shape
    ));
    Cell {
        id,
        class,
        language,
        shape,
    }
}

/// Families that exceed the quota, with the reason.
///
/// Allocation is deterministic: families are considered in id order, so the
/// same corpus always keeps the same witnesses and bundle bytes never depend
/// on directory iteration order. An over-quota family is not a bad family -
/// it is a duplicate witness, and it stops voting (it can still be prepared
/// and baselined, so its separation evidence stays in the report).
#[must_use]
pub(super) fn quota_exclusions(families: &[Family], cells: &[Cell]) -> FxHashMap<String, String> {
    let mut order: Vec<usize> = (0..families.len().min(cells.len())).collect();
    order.sort_by(|a, b| {
        let left = families.get(*a);
        let right = families.get(*b);
        left.map(|f| &f.id).cmp(&right.map(|f| &f.id))
    });

    let mut per_cell: FxHashMap<&str, usize> = FxHashMap::default();
    let mut per_class: FxHashMap<(String, String), usize> = FxHashMap::default();
    let mut excluded: FxHashMap<String, String> = FxHashMap::default();

    for idx in order {
        let (Some(family), Some(cell)) = (families.get(idx), cells.get(idx)) else {
            continue;
        };
        let class = cell.class.clone().unwrap_or_default();
        let language = cell.language.clone().unwrap_or_default();

        let cell_count = per_cell.entry(cell.id.as_str()).or_insert(0);
        if *cell_count >= MAX_PER_CELL {
            let short: String = cell.id.chars().take(8).collect();
            excluded.insert(
                family.id.clone(),
                format!(
                    "shape cell {short} already has {} families (cap {MAX_PER_CELL})",
                    *cell_count
                ),
            );
            continue;
        }

        if !class.is_empty() {
            let key = (class.clone(), language.clone());
            let class_count = per_class.entry(key).or_insert(0);
            if *class_count >= MAX_PER_CLASS_LANGUAGE {
                excluded.insert(
                    family.id.clone(),
                    format!(
                        "class `{class}` in `{language}` already has {} families (cap {MAX_PER_CLASS_LANGUAGE})",
                        *class_count
                    ),
                );
                continue;
            }
            *class_count += 1;
        }
        *cell_count += 1;
    }
    excluded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::family::FamilyMetadata;

    fn family(id: &str, class: &str, pos: &str, neg: &str) -> Family {
        Family {
            id: id.to_string(),
            positives: vec![("p.ts".into(), pos.into(), "ts".into())],
            negatives: vec![("n.ts".into(), neg.into(), "ts".into())],
            declared_check_call: None,
            metadata: FamilyMetadata {
                class: Some(class.to_string()),
                ..FamilyMetadata::default()
            },
        }
    }

    #[test]
    fn renaming_and_reformatting_keep_the_shape() {
        let a = "function run(req) { const cmd = req.query.cmd; return exec(cmd); }";
        let b = "function handler(input) {\n  // different names and layout\n  const command = input.body.value;\n  return exec(command);\n}";
        assert_eq!(shape_of(a), shape_of(b));
    }

    #[test]
    fn a_different_callee_is_a_different_shape() {
        let a = "function run(req) { return exec(req.query.cmd); }";
        let b = "function run(req) { return spawn(req.query.cmd); }";
        assert_ne!(shape_of(a), shape_of(b));
    }

    #[test]
    fn literals_do_not_split_a_cell_but_guards_do() {
        let a = "function run(x) { return query(\"select 1\"); }";
        let b = "function run(y) { return query('select 2'); }";
        let c = "function run(x) { return escape(query(x)); }";
        assert_eq!(shape_of(a), shape_of(b));
        assert_ne!(shape_of(a), shape_of(c));
    }

    #[test]
    fn cell_identity_covers_class_and_language() {
        let src_pos = "function run(req) { return exec(req.query.cmd); }";
        let src_neg = "function run(req) { return exec(escape(req.query.cmd)); }";
        let a = family("a", "inj.command", src_pos, src_neg);
        let b = family("b", "inj.sql", src_pos, src_neg);
        assert_ne!(family_cell(&a).id, family_cell(&b).id);
        assert_eq!(
            family_cell(&a).id,
            family_cell(&family("c", "inj.command", src_pos, src_neg)).id
        );
    }

    #[test]
    fn quota_keeps_the_first_witnesses_and_drops_the_copies() {
        let src_pos = "function run(req) { return exec(req.query.cmd); }";
        let src_neg = "function run(req) { return exec(escape(req.query.cmd)); }";
        let families: Vec<Family> = (0..MAX_PER_CELL + 2)
            .map(|n| family(&format!("f{n}"), "inj.command", src_pos, src_neg))
            .collect();
        let cells: Vec<Cell> = families.iter().map(family_cell).collect();
        let excluded = quota_exclusions(&families, &cells);
        assert_eq!(excluded.len(), 2);
        assert!(excluded.contains_key(&format!("f{}", MAX_PER_CELL)));
    }
}
