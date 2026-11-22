// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! `frensense_scan_file` - single-file scan tool for the MCP surface.
//!
//! Exists because agents working in an editor loop need a *focused*
//! question answered - "what did this file report?" - not a directory audit.
//! `frensense_audit` reports findings tree-wide; `frensense_scan_file`
//! answers only about the one file and labels every advisory with it, so the
//! agent can associate fixes with the buffer it is editing.
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
        "description": "Scan ONE source file with deterministic dataflow analysis. Returns advisories found in that file only, each labeled with the file path, line, and column. There is no boolean that means the file is safe: read `advisories` for reported findings and `analysis.coverage` for the denominator, the recognized `sink_sites` (0 means an empty advisory list is a statement about engine vocabulary, not about the code), and the sites it could not decide. Use this over frensense_audit when checking a single file you just wrote or edited; it is faster and scoped. Non-source files (or unsupported extensions) return unsupported_file instead of an error.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the single file to scan"
                },
                "severity_threshold": {
                    "type": "string",
                    "enum": frensense_lang::severity::SEVERITY_LABELS,
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

/// Filter advisories by severity threshold and minimum confidence.
/// No language filter here - the file's own extension decides what runs.
///
/// Thin wrapper over [`crate::policy::apply`], the one reporting
/// policy every surface shares. The caller resolves the threshold with
/// [`crate::policy::severity_from_label`], so an unknown label is rejected
/// before any work is done.
#[must_use]
pub fn filter_advisories(
    advisories: Vec<Advisory>,
    severity_floor: Severity,
    min_confidence: f64,
) -> Vec<Advisory> {
    crate::policy::apply(advisories, min_confidence, Some(severity_floor))
}

/// A single-file scan plus what it actually covered.
///
/// `advisories` answers "did anything fire?"; `coverage` answers "did the
/// engine inspect anything at all, and was every file it found actually
/// analyzed?". The second is what keeps an empty advisory list falsifiable:
/// a file with no recognized sink is silent for a reason that has nothing to
/// do with the code being safe.
#[derive(Debug)]
pub(crate) struct FileScan {
    pub advisories: Vec<Advisory>,
    pub coverage: crate::policy::Coverage,
    pub telemetry: frensense_engine::telemetry::ScanTelemetry,
    pub incomplete: Vec<frensense_engine::scan::IncompleteFunction>,
}

/// Core single-file scan, retaining coverage and telemetry.
///
/// # Errors
/// Propagates engine failures (unreadable file, internal analysis error).
pub(crate) fn scan_file_detailed(
    path: &Path,
    min_confidence: f64,
    corpus_bundle: Option<&str>,
) -> crate::Result<FileScan> {
    let mut engine = build_engine(min_confidence, corpus_bundle);
    let advisories = engine.run(path)?;
    Ok(FileScan {
        advisories,
        coverage: engine.take_coverage(),
        telemetry: engine.take_telemetry(),
        incomplete: engine.take_incomplete(),
    })
}

/// Core single-file scan. All analysis goes through `Engine::run` -
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
    Ok(scan_file_detailed(path, min_confidence, corpus_bundle)?.advisories)
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
    result_payload_detailed(path, advisories, None, None, &[])
}

/// The `analysis` object every MCP tool reports.
///
/// One implementation for `scan_file`, `audit` and `diff`: all three expose
/// the same coverage shape, so a prompt or a script can read one shape
/// everywhere. There is deliberately no `clean` boolean: an empty
/// `advisories` array plus `analysis.coverage` is the honest answer, and a
/// single flag must not stand in for a safety claim.
pub(crate) fn mcp_analysis(
    coverage: &crate::policy::Coverage,
    telemetry: &frensense_engine::telemetry::ScanTelemetry,
    incomplete: &[frensense_engine::scan::IncompleteFunction],
) -> Value {
    let status = crate::cli::reporting::status_with_coverage(telemetry, incomplete, Some(coverage));
    json!({
        "status": status,
        "coverage": {
            "files_found": coverage.files_found,
            "files_analyzed": coverage.files_analyzed,
            "files_not_analyzed": coverage.files_not_analyzed(),
            "files_unsupported": coverage.files_unsupported,
            "files_failed": coverage.files_failed,
            "sink_sites": coverage.sink_sites,
            "files_with_sink_sites": coverage.files_with_sink_sites,
            "files_without_sink_sites": coverage.files_without_sink_sites,
            "no_sink_files": coverage.no_sink_files,
            "unresolved_sites": coverage.unresolved_sites,
            "unresolved_sample": coverage.unresolved_sample.iter().map(|s| json!({
                "file": s.file,
                "line": s.line,
                "sink": s.sink,
            })).collect::<Vec<Value>>(),
        },
        "functions": telemetry.input.functions,
        "parse_partial": telemetry.input.parse_partial,
    })
}

/// Build the JSON-RPC `tools/call` result payload with coverage.
///
/// The payload has no `clean` flag. An empty `advisories` array is a fact
/// about this report, not a safety verdict; `analysis` carries the coverage
/// numbers either way, so an agent can see when an empty answer came from a
/// file where the engine recognized nothing or left a site undecided.
#[must_use]
pub(crate) fn result_payload_detailed(
    path: &Path,
    advisories: &[Advisory],
    coverage: Option<&crate::policy::Coverage>,
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    incomplete: &[frensense_engine::scan::IncompleteFunction],
) -> Value {
    let empty_telem = frensense_engine::telemetry::ScanTelemetry::default();
    let telem = telemetry.unwrap_or(&empty_telem);
    let cov = coverage.cloned().unwrap_or_default();
    let analysis = mcp_analysis(&cov, telem, incomplete);
    let message = if !advisories.is_empty() {
        None
    } else if !cov.recognized_anything() {
        Some(
            "no findings reported; no sink site was recognized in this file, so findings there cannot be ruled out"
                .to_string(),
        )
    } else if telem
        .suppressed
        .iter()
        .any(|s| s.reason == "below-confidence" && s.count > 0)
    {
        Some(
            "no findings reported; potential finding(s) were dropped below confidence threshold"
                .to_string(),
        )
    } else if !cov.fully_resolved() {
        Some(format!(
            "no findings reported; {} sink site(s) could not be decided",
            cov.unresolved_sites
        ))
    } else if cov.files_not_analyzed() > 0 {
        Some(format!(
            "no findings reported; only {}/{} source file(s) were analyzed, so the rest cannot be ruled out",
            cov.files_analyzed, cov.files_found
        ))
    } else {
        Some("no findings reported".to_string())
    };

    let mut payload = json!({
        "file": path.display().to_string(),
        // Stable IDs (shift-resistant fingerprints) for agents tracking
        // "did I fix THIS finding yet" across edit cycles: ID unchanged
        // means the bug is still there; ID gone means fixed. The `id`
        // field of each advisory carries the same value.
        "stable_ids": advisories.iter().map(|a| a.stable_id()).collect::<Vec<_>>(),
        "advisories": advisories,
        // What the answer rests on. `coverage.sink_sites == 0` means the
        // engine found nothing it models as dangerous in this file, so an
        // empty advisory list is a statement about engine vocabulary, not
        // about the code.
        "analysis": analysis,
    });
    if let (Some(msg), Some(map)) = (message, payload.as_object_mut()) {
        map.insert("message".to_string(), json!(msg));
    }
    payload
}

/// Full tool invocation: argument parsing, gating, scanning, shaping.
/// Returns the JSON-RPC `tools/call` result value (same shape as
/// `frensense_audit`).
#[must_use]
pub fn run_scan_file(args: &Value) -> Value {
    let path_str = args.get("path").and_then(Value::as_str).unwrap_or_default();
    if path_str.is_empty() {
        return json!({
            "advisories": [],
            "error": "missing required argument: path"
        });
    }

    let path = Path::new(path_str);
    if !path.exists() {
        return json!({
            "advisories": [],
            "error": format!("file does not exist: {path_str}")
        });
    }
    if !is_supported(path) {
        return json!({
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
    let severity_floor = match crate::policy::severity_from_label(severity_threshold) {
        Ok(floor) => floor,
        Err(error) => {
            return json!({
                "advisories": [],
                "error": error
            });
        }
    };
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
            "advisories": [],
            "error": format!("corpus bundle does not exist: {bundle}")
        });
    }

    match scan_file_detailed(path, min_confidence, corpus_bundle) {
        Ok(scan) => {
            let filtered = filter_advisories(scan.advisories, severity_floor, min_confidence);
            result_payload_detailed(
                path,
                &filtered,
                Some(&scan.coverage),
                Some(&scan.telemetry),
                &scan.incomplete,
            )
        }
        Err(e) => json!({
            "advisories": [],
            "error": format!("analysis error: {e}")
        }),
    }
}

#[cfg(test)]
#[path = "scan_file_tests.rs"]
mod tests;
