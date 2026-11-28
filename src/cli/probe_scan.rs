// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Reading and scanning one family: header, training pair, per-side scan.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use frensense_bundler::format::{LoadedBundle, default_pack};
use frensense_engine::analysis::taint::facts::LearnedFactEntry;
use frensense_lang::rule_card::{all_cards, card_by_id, cwe_url, taint_card, taint_class_for_cwe};
use frensense_lang::severity::SinkRole;
use serde_json::{Value, json};

use super::Side;
use crate::engine::Engine;

/// The `[frensense]` block fields the probe needs.
#[derive(Debug, Default)]
pub(super) struct Header {
    pub(super) class: Option<String>,
    pub(super) cwe: Option<String>,
    pub(super) purpose: Option<String>,
}

/// Read `class`, `cwe` and `purpose` from the leading comment block.
///
/// Deliberately minimal: this is the family's own declaration, and the lint
/// owns the full schema. A missing marker yields an empty header.
pub(super) fn parse_header(source: &str) -> Header {
    let mut header = Header::default();
    let mut in_block = false;
    for line in source.lines().take(40) {
        let trimmed = line.trim();
        let body = ["#", "//", "--"]
            .iter()
            .find_map(|prefix| trimmed.strip_prefix(prefix))
            .map(str::trim);
        let Some(body) = body else {
            if in_block {
                break;
            }
            continue;
        };
        if body == "[frensense]" {
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        let Some((key, value)) = body.split_once(':') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim() {
            "class" => header.class = Some(value),
            "cwe" => header.cwe = Some(value),
            "purpose" => header.purpose = Some(value),
            _ => {}
        }
    }
    header
}

/// Language key for an extension, from the registry.
pub(super) fn language_of(ext: &str) -> String {
    frensense_lang::all_specs()
        .find(|spec| spec.extensions().contains(&ext))
        .map_or_else(|| ext.to_string(), |spec| spec.fact_language().to_string())
}

/// Find the training pair inside `dir`: `*_positive.*` / `*_negative.*`,
/// excluding held-out variants.
pub(super) fn training_pair(dir: &Path) -> Result<(PathBuf, Option<PathBuf>), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read family directory {}: {e}", dir.display()))?;
    let mut positive = None;
    let mut negative = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if stem.contains("heldout") {
            continue;
        }
        if stem.ends_with("_positive") && positive.is_none() {
            positive = Some(path);
        } else if stem.ends_with("_negative") && negative.is_none() {
            negative = Some(path);
        }
    }
    match positive {
        Some(positive) => Ok((positive, negative)),
        None => Err(format!(
            "no *_positive.* file in {} (pass the family directory)",
            dir.display()
        )),
    }
}

/// Scan one file under the shipped fact table plus an optional bundle.
pub(super) fn scan_side(path: &Path, bundle: Option<&Path>) -> Result<Side, String> {
    let mut engine = Engine::new();
    engine.set_explain(true);
    if let Some(bundle) = bundle {
        engine.set_corpus_bundle_path(bundle.to_path_buf());
    }
    let advisories = engine
        .run(path)
        .map_err(|e| format!("scan {}: {e}", path.display()))?;
    let coverage = engine.take_coverage();
    let explain = engine.take_explain();

    let mut sinks_recognised = BTreeSet::new();
    let mut advisory_json = Vec::new();
    for advisory in &advisories {
        let card = card_by_id(&advisory.rule_id);
        let cwe = card
            .and_then(|c| c.cwe.first().copied())
            .unwrap_or_default();
        advisory_json.push(json!({
            "rule": advisory.rule_id,
            "cwe": cwe,
            "severity": advisory.severity,
            "line": advisory.line,
            "steps": advisory.taint_steps.len(),
        }));
    }
    let mut explain_json = Vec::new();
    for record in &explain {
        sinks_recognised.insert(record.sink.clone());
        let sites: Vec<Value> = record
            .cut_sites
            .iter()
            .map(|site| {
                json!({
                    "kind": site.kind,
                    "detail": site.detail,
                    "file": site.file,
                    "line": site.line,
                })
            })
            .collect();
        explain_json.push(json!({
            "sink": record.sink,
            "line": record.line,
            "verdict": record.verdict,
            "reason": record.reason,
            "cut_reasons": record.cut_reasons,
            "cut_sites": sites,
            "suppressed_by": record
                .suppressed_by
                .iter()
                .map(|fact| json!({"call": fact.call, "classes": fact.classes}))
                .collect::<Vec<_>>(),
        }));
    }

    Ok(Side {
        path: path.to_path_buf(),
        advisories: advisory_json,
        sinks_recognised,
        explain: explain_json,
        coverage: json!({
            "files_found": coverage.files_found,
            "files_analyzed": coverage.files_analyzed,
            "sink_sites": coverage.sink_sites,
            "unresolved_sites": coverage.unresolved_sites,
        }),
    })
}

/// Does the pack model this sink call for this language?
///
/// The answer is what makes the difference between "add a vocabulary row"
/// and "the dataflow is the problem".
#[must_use]
pub fn pack_models(language: &str, sink: &str) -> bool {
    let pack: &'static LoadedBundle = default_pack();
    let last = sink.rsplit('.').next().unwrap_or(sink);
    pack.learned_facts.iter().any(|entry| match entry {
        LearnedFactEntry::LanguageSink {
            language: lang,
            call,
            ..
        } => {
            (lang == language || lang == "*")
                && (call == sink || call.rsplit('.').next() == Some(last))
        }
        LearnedFactEntry::LanguageSinkSlots {
            language: lang,
            call,
            ..
        } => (lang == language || lang == "*") && call.rsplit('.').next() == Some(last),
        _ => false,
    })
}

pub(super) fn expressible_for(cwe: Option<&str>) -> Value {
    let Some(cwe) = cwe else {
        return json!({"expressible": Value::Null, "reason": "no cwe declared"});
    };
    match taint_class_for_cwe(cwe) {
        Some((role, slug)) => {
            let card = taint_card(Some(slug), role, false);
            json!({
                "expressible": true,
                "via": card.id,
                "role": match role {
                    SinkRole::Execution => "execution",
                    SinkRole::Resource => "resource",
                    SinkRole::Storage => "storage",
                    SinkRole::Crypto => "crypto",
                    SinkRole::Response => "response",
                    SinkRole::Xss => "xss",
                    SinkRole::Validation => "validation",
                    SinkRole::Other => "other",
                },
                "url": cwe_url(cwe),
            })
        }
        None => {
            let check =
                all_cards().find(|card| card.cwe.iter().any(|id| id.eq_ignore_ascii_case(cwe)));
            if let Some(card) = check {
                json!({"expressible": true, "via": card.id, "url": cwe_url(cwe)})
            } else {
                json!({
                    "expressible": false,
                    "reason": "no built-in card names this CWE",
                    "url": cwe_url(cwe),
                })
            }
        }
    }
}
