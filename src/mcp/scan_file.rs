// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! `frensense_scan_file` — single-file scan tool for the MCP surface.
//!
//! Exists because agents working in an editor loop need a *focused*
//! question answered — "is THIS file clean?" — not a directory audit.
//! `frensense_audit` answers "is this tree clean" and reports findings
//! tree-wide; `frensense_scan_file` answers only about the one file and
//! labels every advisory with it, so the agent can associate fixes with
//! the buffer it is editing.
//!
//! Architecture split (same doctrine as the CLI): this module is a thin
//! delivery adapter. All language knowledge lives in `frensense-lang`
//! specs and the engine does all analysis via `Engine::run(path)`; the
//! only mechanism added here is the supported-file gate
//! ([`is_supported`], itself backed by the specs) and result shaping.

use crate::{Advisory, Engine, Severity};
use serde_json::{Value, json};
use std::path::Path;

/// MCP tool definition for `frensense_scan_file`.
#[must_use]
pub fn tool_definition() -> Value {
    json!({
        "name": "frensense_scan_file",
        "description": "Scan ONE source file with deterministic dataflow analysis. Returns advisories found in that file only, each labeled with the file path, line, and column. An empty advisories array with clean=true means the file satisfies all invariants. Use this over frensense_audit when checking a single file you just wrote or edited; it is faster and scoped. Non-source files (or unsupported extensions) return unsupported_file instead of an error.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the single file to scan"
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": ["critical", "warning", "info"],
                    "default": "info",
                    "description": "Minimum severity to report (default: report everything)"
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
                    "description": "Optional path to a .frc knowledge bundle whose learned Source/Sink facts extend the built-in tables (framework-specific taint sources etc.)"
                }
            },
            "required": ["path"]
        }
    })
}

/// Files the specs don't handle are a tool-level "unsupported" outcome,
/// not an RPC error: the agent can act on it (skip the file) without a
/// round-trip of exception handling.
#[must_use]
pub fn is_supported(path: &Path) -> bool {
    crate::parser::is_supported(path)
}

/// Severity ranking shared with `frensense_audit`'s filtering.
#[must_use]
pub fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 3,
        Severity::Warning => 2,
        Severity::Info => 1,
    }
}

fn threshold_floor(severity_threshold: &str) -> Severity {
    match severity_threshold {
        "critical" => Severity::Critical,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Filter advisories by severity threshold and minimum confidence.
/// No language filter here — the file's own extension decides what runs.
#[must_use]
pub fn filter_advisories(
    advisories: Vec<Advisory>,
    severity_threshold: &str,
    min_confidence: f64,
) -> Vec<Advisory> {
    let floor = severity_rank(threshold_floor(severity_threshold));
    advisories
        .into_iter()
        .filter(|a| severity_rank(a.severity) >= floor)
        .filter(|a| a.confidence >= min_confidence)
        .collect()
}

/// Core single-file scan. All analysis goes through `Engine::run` —
/// no parallel code path, no re-implemented lowering. Errors from the
/// engine surface as `Err` and are rendered by the caller as a
/// tool-level `error` field, matching `frensense_audit`'s convention.
///
/// # Errors
/// Propagates engine failures (unreadable file, internal analysis error).
pub fn scan_file(
    path: &Path,
    min_confidence: f64,
    corpus_bundle: Option<&str>,
) -> crate::Result<Vec<Advisory>> {
    let mut engine = build_engine(min_confidence, corpus_bundle);
    engine.run(path)
}

/// Engine construction shared by every MCP tool. The CLI wires the same
/// three knobs; the MCP surface must not drift from it (learned `.frc`
/// facts are part of a scan's meaning, not an optional extra).
pub(crate) fn build_engine(min_confidence: f64, corpus_bundle: Option<&str>) -> Engine {
    let mut engine = Engine::new();
    engine.set_min_confidence(min_confidence);
    if let Some(bundle) = corpus_bundle {
        engine.set_corpus_bundle_path(std::path::PathBuf::from(bundle));
    }
    engine
}

/// Build the JSON-RPC `tools/call` result payload.
#[must_use]
pub fn result_payload(path: &Path, advisories: &[Advisory]) -> Value {
    let clean = advisories.is_empty();
    let mut payload = json!({
        "clean": clean,
        "file": path.display().to_string(),
        // Stable IDs (shift-resistant fingerprints) for agents tracking
        // "did I fix THIS finding yet" across edit cycles: ID unchanged
        // means the bug is still there; ID gone means fixed. The `id`
        // field of each advisory carries the same value.
        "stable_ids": advisories.iter().map(|a| a.stable_id()).collect::<Vec<_>>(),
        "advisories": advisories,
    });
    if clean {
        payload["message"] = json!("no findings");
    }
    payload
}

/// Full tool invocation: argument parsing, gating, scanning, shaping.
/// Returns the JSON-RPC `tools/call` result value (same shape as
/// `frensense_audit`).
#[must_use]
pub fn run_scan_file(args: &Value) -> Value {
    let path_str = args
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if path_str.is_empty() {
        return json!({
            "clean": false,
            "advisories": [],
            "error": "missing required argument: path"
        });
    }

    let path = Path::new(path_str);
    if !path.exists() {
        return json!({
            "clean": false,
            "advisories": [],
            "error": format!("file does not exist: {path_str}")
        });
    }
    if !is_supported(path) {
        return json!({
            "clean": false,
            "advisories": [],
            "file": path_str,
            "unsupported_file": true,
            "error": format!("unsupported file type: {path_str}")
        });
    }

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

    match scan_file(path, min_confidence, corpus_bundle) {
        Ok(advisories) => {
            let filtered = filter_advisories(advisories, severity_threshold, min_confidence);
            result_payload(path, &filtered)
        }
        Err(e) => json!({
            "clean": false,
            "advisories": [],
            "error": format!("analysis error: {e}")
        }),
    }
}

#[cfg(test)]
#[path = "scan_file_tests.rs"]
mod tests;
