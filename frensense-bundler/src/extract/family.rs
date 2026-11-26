// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

use frensense_engine::analysis::taint::facts::LearnedFactEntry;
use rustc_hash::FxHashMap;
use std::path::Path;

pub use super::metadata::FamilyMetadata;

/// A published learned fact with its provenance.
#[derive(Debug, Clone)]
pub struct LearnedFact {
    /// The fact itself, bundle-ready.
    pub entry: LearnedFactEntry,
    /// Sanitizer class scope (`bug_classes.json` ids) the voting families
    /// proved. Published in the payload's `sanitizer_scopes` table, not
    /// inside the fact, so the engine's `SanitizerFact` keeps its published
    /// shape. Empty for every non-sanitizer fact.
    pub classes: Vec<String>,
    /// Corpus family that taught the fact, for suppression provenance.
    pub family: Option<String>,
    /// Number of corpus variants that voted for this fact.
    pub support: u32,
    /// Number of independent shape cells among those voters. Two families
    /// that differ only in names, literals or formatting share a cell and
    /// count once.
    pub cells: u32,
    /// `confirmed` (two independent cells) or `provisional` (one cell).
    pub status: String,
    /// Families that voted for this fact.
    pub families: Vec<String>,
}

/// One corpus family: id + variant files.
#[derive(Debug)]
pub struct Family {
    pub id: String,
    /// (file name, source text, ext)
    pub positives: Vec<(String, String, String)>,
    pub negatives: Vec<(String, String, String)>,
    /// Declared check trigger from the positive's `[frensense]` metadata
    /// (`check-call: name`). When present, Check proposals are restricted
    /// to this call, the family authors declare which call is the
    /// privileged action; the gate still validates the claim.
    pub declared_check_call: Option<String>,
    /// Advisory text from the positive's `[frensense]` block, baked into
    /// the bundle as a `BundlePattern`.
    pub metadata: FamilyMetadata,
}

impl Family {
    /// The language name of this family, derived from its variant extensions.
    pub fn language(&self) -> Option<&'static str> {
        self.positives
            .first()
            .or_else(|| self.negatives.first())
            .and_then(|(_, _, ext)| frensense_lang::spec_for_ext(ext))
            .map(|s| s.name())
    }
}

/// Group a corpus directory into families by filename convention
/// (`<family>_positive*.ts`, `<family>_negative*.ts`).
pub fn group_families(corpus_dir: &Path) -> Result<Vec<Family>, String> {
    let mut families: FxHashMap<String, Family> = FxHashMap::default();

    // Recursive walk: the corpus is organized as a manifest tree
    // (`<lang>/<CWE>/<family>/<stem>_<variant>.<ext>`), with flat files
    // still supported at the root of `corpus_dir`. Family identity is the
    // file stem before `_positive`/`_negative`; directory structure is
    // metadata (recorded in each family's manifest.json), never part of
    // the id, so moving a family between CWE directories preserves its
    // learned facts.
    // Two-phase grouping: collect (family stem, language, variant, file)
    // records first, THEN bucket them into families. The extra language
    // dimension exists because learned facts are language-blind (call
    // matching is by last segment), so a family must never mix languages:
    // a `foo_positive.py` and `foo_negative.ts` under the same stem would
    // vote as one family and the replay gate could publish a fact no
    // single-language pair supports. When a stem collides across
    // languages, each language gets its own sub-family (`foo (python)`,
    // `foo (typescript)`) and a warning names the affected files.
    let mut stack = vec![corpus_dir.to_path_buf()];
    let mut all_paths: Vec<std::path::PathBuf> = Vec::new();
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                all_paths.push(path);
            }
        }
    }
    all_paths.sort();

    /// One scanned file's grouping inputs (before language disambiguation).
    struct Grouped {
        stem: String,
        lang: &'static str,
        variant: &'static str,
        name: String,
        ext: String,
        source: String,
        declared_check_call: Option<String>,
        metadata: FamilyMetadata,
    }

    let mut records: Vec<Grouped> = Vec::new();
    for path in all_paths {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();
        if !matches!(
            ext.as_str(),
            "ts" | "tsx" | "js" | "jsx" | "py" | "go" | "rs" | "c" | "cpp" | "h" | "hpp"
        ) {
            continue;
        }

        let (family, variant) = if let Some(i) = name.find("_positive") {
            (name[..i].to_string(), "positive")
        } else if let Some(i) = name.find("_negative") {
            (name[..i].to_string(), "negative")
        } else {
            continue;
        };
        // Held-out blind-verification variants never contribute to
        // extraction: the bundle must be learned from the training pair
        // alone so `test_bundles.sh` can scan these files afterward as
        // proof of generalization. The `_heldout_` infix marks them
        // (e.g. `<family>_heldout_positive.c`).
        if family.ends_with("_heldout") {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        // Declared check trigger: `// check-call: <name>` inside the
        // `[frensense]` metadata block of a positive variant. The comment
        // prefix follows the language: `#` for Python/shell-family files,
        // `//` everywhere else, so every supported language can declare a
        // trigger in its own comment syntax.
        let comment_prefix: &[&str] = if ext == "py" || ext == "pyi" || ext == "pyw" {
            &["# check-call:", "// check-call:"]
        } else {
            &["// check-call:", "# check-call:"]
        };
        // Advisory metadata: parsed from every variant's head (positives
        // are the ones that carry the block); later records for the same
        // family overwrite earlier ones, so a positive's block wins.
        let metadata = FamilyMetadata::parse(&source, &ext, 30);
        let declared_check_call = if variant == "positive" {
            source
                .lines()
                .take(30)
                .find_map(|l| {
                    let t = l.trim();
                    comment_prefix
                        .iter()
                        .find_map(|p| t.strip_prefix(p))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                })
                // An author may name the identity instead of the call:
                // `expect: policy_<call>` declares the rule, and the rule
                // name carries the trigger.
                .or_else(|| metadata.declared_policy_call())
        } else {
            None
        };
        // Language identity comes from the registry, same name the specs
        // use for fingerprints; unknown extensions fall back to the raw
        // extension so the collision check still distinguishes them.
        let lang = frensense_lang::spec_for_ext(&ext)
            .map(|s| s.name())
            .unwrap_or(leaked_ext(&ext));
        records.push(Grouped {
            stem: family,
            lang,
            variant,
            name: name.to_string(),
            ext,
            source,
            declared_check_call,
            metadata,
        });
    }

    // Language-mixing detector: which stems carry more than one language?
    let mut langs_by_stem: FxHashMap<&str, std::collections::BTreeSet<&'static str>> =
        FxHashMap::default();
    for r in &records {
        langs_by_stem
            .entry(r.stem.as_str())
            .or_default()
            .insert(r.lang);
    }
    let mixed: FxHashMap<&str, ()> = langs_by_stem
        .into_iter()
        .filter(|(_, langs)| langs.len() > 1)
        .map(|(stem, _)| (stem, ()))
        .collect();
    // File names per colliding stem, for the actionable follow-up warning.
    let mut mixed_files: FxHashMap<&str, Vec<String>> =
        mixed.keys().map(|s| (*s, Vec::new())).collect();
    for stem in mixed.keys() {
        eprintln!(
            "[facts] WARNING: family stem '{stem}' mixes languages; splitting into \
             per-language sub-families so votes never cross language boundaries"
        );
    }

    for r in &records {
        // Mixed stems are disambiguated with the language name; clean stems
        // keep the bare id so existing family ids are stable.
        let family = if mixed.contains_key(r.stem.as_str()) {
            format!("{} ({})", r.stem, r.lang)
        } else {
            r.stem.clone()
        };
        if let Some(files) = mixed_files.get_mut(r.stem.as_str()) {
            files.push(r.name.clone());
        }
        let f = families.entry(family.clone()).or_insert_with(|| Family {
            id: family.clone(),
            positives: Vec::new(),
            negatives: Vec::new(),
            declared_check_call: None,
            metadata: FamilyMetadata::default(),
        });
        if r.declared_check_call.is_some() {
            f.declared_check_call = r.declared_check_call.clone();
        }
        // Positives' metadata wins over negatives' (negatives should not
        // carry a block, but parse defensively): only overwrite from a
        // non-default parse.
        if r.variant == "positive" && r.metadata != FamilyMetadata::default() {
            f.metadata = r.metadata.clone();
        }
        let slot = match r.variant {
            "positive" => &mut f.positives,
            _ => &mut f.negatives,
        };
        slot.push((r.name.clone(), r.source.clone(), r.ext.clone()));
    }

    // Name the colliding files once, after grouping, so the warning is
    // actionable (which files ended up in which sub-family).
    for stem in mixed.keys() {
        let files = mixed_files
            .get(stem)
            .map(|v| v.join(", "))
            .unwrap_or_default();
        eprintln!("[facts]   stem '{stem}' files: {files}");
    }

    let mut out: Vec<Family> = families.into_values().collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Leak the raw extension as a `'static` fallback for unregistered
/// extensions (at most a handful of small strings per run; acceptable for
/// a build-time tool).
fn leaked_ext(ext: &str) -> &'static str {
    Box::leak(ext.to_string().into_boxed_str())
}
