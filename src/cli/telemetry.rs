// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The telemetry contract: one shape for what a scan measured.
//!
//! Frensense collects telemetry **on the machine that runs the scan** and
//! writes it nowhere else. There is no upload path in this crate: no HTTP
//! client, no background sender, no retry queue. The word "telemetry" here
//! means the accounting a report carries about its own scan - what was read,
//! what was skipped, which safety valve truncated, how long a phase took - so
//! that "no findings" can be checked instead of trusted.
//!
//! One builder produces that shape for every surface: the `analysis` object of
//! a JSON report, the `--profile-out` document and the MCP `analysis` block.
//! Before this module each of the three assembled its own object with its own
//! key names, which is how a schema drifts without anyone deciding to change
//! it.
//!
//! Two rules keep the payload reviewable:
//!
//! 1. **Counts are bare, samples are `_sample`.** A count is a `usize`; an
//!    array of names is capped (`COVERAGE_SAMPLE`, `PARTIAL_SAMPLE`,
//!    `SLOW_SAMPLE`, `MISSED_CALLEE_SAMPLE`) and says so in its key.
//! 2. **Every path goes through [`PathPolicy`].** A report names the files it
//!    could not analyze and the functions that cost the most time, so it
//!    carries user paths and symbols by design. `FRENSENSE_TELEMETRY_PATHS`
//!    chooses how much of a path a report keeps, because a profile attached to
//!    a bug report is read by someone else.
//!
//! [`crate::identity::producer`] identifies the build; [`TELEMETRY_SCHEMA_VERSION`]
//! versions this payload independently of the report envelope. A new field is
//! additive; a rename or a semantic change moves the version, and
//! [`tests::the_payload_keys_are_committed`] fails until the committed key list
//! is updated with it.

use std::path::Path;

use serde_json::{Value, json};

use frensense_engine::scan::IncompleteFunction;
use frensense_engine::telemetry::{GraphSize, ScanTelemetry, TaintFunnel};

use crate::Result;
use crate::cli::reporting::{skipped_unsupported_json, status_with_coverage};
use crate::engine::files::UnsupportedSourceFile;
use crate::policy::{Coverage, Exclusions};

/// Version of the telemetry payload, independent of the report envelope.
///
/// `1`: the first published shape. Bumped when a key is renamed, removed or
/// changes meaning; adding a key does not move it.
pub const TELEMETRY_SCHEMA_VERSION: u32 = 1;

/// Environment variable choosing how much of a path a report keeps.
pub const PATHS_ENV: &str = "FRENSENSE_TELEMETRY_PATHS";

/// How much of a path the payload keeps.
///
/// Absolute paths are the default because a report is read to debug a scan on
/// the machine that produced it. The other two modes exist for the case where
/// the report leaves that machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathPolicy {
    /// The path as the scan saw it.
    Absolute,
    /// Relative to the current directory when the path is under it, otherwise
    /// unchanged.
    Relative,
    /// Only the final component (`index.ts`), which loses directory
    /// context but also loses the customer layout.
    Basename,
}

impl PathPolicy {
    /// Parse the value of [`PATHS_ENV`]; anything unrecognized is
    /// [`PathPolicy::Absolute`], so a typo cannot silently widen redaction.
    #[must_use]
    pub(crate) fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "relative" => Self::Relative,
            "basename" => Self::Basename,
            _ => Self::Absolute,
        }
    }

    /// The policy this process was started with.
    #[must_use]
    pub(crate) fn from_env() -> Self {
        super::env_config::telemetry_paths().map_or(Self::Absolute, |raw| Self::parse(&raw))
    }

    /// The value this policy is reported as, i.e. what a reader sees in
    /// `redaction.paths`.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Absolute => "absolute",
            Self::Relative => "relative",
            Self::Basename => "basename",
        }
    }

    /// One path, under this policy.
    #[must_use]
    pub(crate) fn apply(self, path: &str) -> String {
        let p = Path::new(path);
        match self {
            Self::Absolute => path.to_string(),
            Self::Basename => p
                .file_name()
                .map_or_else(|| path.to_string(), |name| name.to_string_lossy().into()),
            Self::Relative => match std::env::current_dir() {
                Ok(cwd) => p
                    .strip_prefix(&cwd)
                    .map_or_else(|_| path.to_string(), |rest| rest.display().to_string()),
                Err(_) => path.to_string(),
            },
        }
    }
}

/// The one `analysis` object every surface reports.
///
/// `coverage` is optional so the compatibility entry points still produce the
/// shape; without it the input accounting from `telemetry` supplies the
/// denominator, which keeps `files_not_analyzed` honest even then.
#[must_use]
pub(crate) fn analysis_payload(
    telemetry: Option<&ScanTelemetry>,
    coverage: Option<&Coverage>,
    skipped: &[UnsupportedSourceFile],
    exclusions: Option<&Exclusions>,
    incomplete: &[IncompleteFunction],
    target: Option<&str>,
) -> Value {
    let empty_telem = ScanTelemetry::default();
    let telem = telemetry.unwrap_or(&empty_telem);
    let status = status_with_coverage(telem, incomplete, coverage);
    let cov = coverage.cloned().unwrap_or_default();
    let empty_exclusions = Exclusions::default();
    let exclusions = exclusions.unwrap_or(&empty_exclusions);
    let policy = PathPolicy::from_env();

    // Without engine-derived coverage (the compatibility entry points), fall
    // back to the input accounting so the denominator is still honest about
    // unsupported inputs and read failures.
    let (files_found, files_not_analyzed, files_unsupported) = match coverage {
        Some(c) => (c.files_found, c.files_not_analyzed(), c.files_unsupported),
        None => {
            let unsupported = skipped.len().max(telem.input.unsupported);
            let found = telem.input.submitted + unsupported;
            (
                found,
                found.saturating_sub(telem.input.scanned),
                unsupported,
            )
        }
    };

    let analysis_obj = json!({
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "collection": "local",
        "redaction": {
            "paths": policy.as_str(),
        },
        "status": status,
        "target": target.map(|t| policy.apply(t)),
        "coverage": {
            "files_found": files_found,
            "files_submitted": telem.input.submitted,
            "files_analyzed": telem.input.scanned,
            "files_not_analyzed": files_not_analyzed,
            "files_unsupported": files_unsupported,
            "files_excluded": cov.files_excluded(),
            "excluded_by_reason": exclusions.by_reason,
            "excluded_sample": exclusions.sample.iter().map(|e| json!({
                "path": policy.apply(&e.path),
                "reason": e.reason,
                "source_files": e.source_files,
            })).collect::<Vec<Value>>(),
            "files_failed": telem.input.failed,
            "failed_files_sample": telem.input.failed_files.iter().map(|f| policy.apply(f)).collect::<Vec<String>>(),
            "unsupported_inputs": telem.input.unsupported,
            "unsupported_source_files": skipped_unsupported_json(skipped),
            "files_partial": telem.input.parse_partial,
            "partial_files_sample": telem.input.parse_partial_files.iter().map(|f| policy.apply(f)).collect::<Vec<String>>(),
            "functions": telem.input.functions,
            // What the scan recognized: the denominator behind "no findings".
            // `files_without_sink_sites` names the files where the engine found
            // nothing it models as dangerous, so a reader can tell "inspected
            // and no finding" from "nothing recognized".
            "sink_sites": cov.sink_sites,
            "files_with_sink_sites": cov.files_with_sink_sites,
            "files_without_sink_sites": cov.files_without_sink_sites,
            "no_sink_files_sample": cov.no_sink_files.iter().map(|f| policy.apply(f)).collect::<Vec<String>>(),
            "unresolved_sites": cov.unresolved_sites,
            "unresolved_sample": cov.unresolved_sample.iter().map(|s| json!({
                "file": policy.apply(&s.file),
                "line": s.line,
                "sink": s.sink,
            })).collect::<Vec<Value>>(),
        },
        "errors": telem.errors,
        "suppressed": telem.suppressed.iter().map(|s| json!({
            "reason": s.reason,
            "count": s.count,
        })).collect::<Vec<Value>>(),
        "verdicts": {
            "vulnerable": telem.taint.vulnerable,
            "sanitized": telem.taint.sanitized,
            "unknown": telem.taint.unknown,
            // No "clean" verdict: this counts sink arguments whose backward
            // walk found no source, which is a statement about the walk, not
            // about the code.
            "no_source": telem.taint.clean,
        },
        "graph": graph_json(&telem.graph),
        "funnel": funnel_json(&telem.funnel),
        "caps": telem.caps.iter().map(|c| json!({
            "cap": c.cap,
            "hits": c.hits,
            "effect": c.effect,
        })).collect::<Vec<Value>>(),
        "checks": telem.checks.iter().map(|c| json!({
            "id": c.id,
            "scope": c.scope,
            "ran": c.ran,
            "findings": c.findings,
            "millis": c.millis,
            "outcome": match &c.outcome {
                frensense_engine::telemetry::CheckOutcome::Ok => "ok".into(),
                frensense_engine::telemetry::CheckOutcome::Panicked(p) => format!("panicked: {p}"),
                frensense_engine::telemetry::CheckOutcome::Skipped(s) => format!("skipped: {s}"),
            },
        })).collect::<Vec<Value>>(),
        "phases": telem.phases.iter().map(|p| json!({
            "phase": p.phase,
            "ms": p.ms,
        })).collect::<Vec<Value>>(),
        "slowest_files": telem.slowest_files.iter().map(|f| json!({
            "file": policy.apply(&f.file),
            "ms": f.ms,
            "functions": f.functions,
        })).collect::<Vec<Value>>(),
        "slowest_functions": telem.slowest_functions.iter().map(|f| json!({
            "function": f.function,
            "file": policy.apply(&f.file),
            "ms": f.ms,
            "sink_args": f.sink_args,
        })).collect::<Vec<Value>>(),
    });

    analysis_obj
}

/// The `--profile-out` document: the same payload, wrapped with the producer
/// that wrote it.
///
/// The wrapper exists so a file found on disk can be attributed and versioned
/// without the report envelope around it; the payload inside is byte-identical
/// to a report's `analysis` object.
#[must_use]
pub(crate) fn profile_document(
    telemetry: Option<&ScanTelemetry>,
    coverage: Option<&Coverage>,
    skipped: &[UnsupportedSourceFile],
    exclusions: Option<&Exclusions>,
    incomplete: &[IncompleteFunction],
    target: Option<&str>,
) -> Value {
    json!({
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "kind": "scan-telemetry",
        "collection": "local",
        "producer": crate::identity::producer(),
        "telemetry": analysis_payload(telemetry, coverage, skipped, exclusions, incomplete, target),
    })
}

/// Write [`profile_document`] to `path`.
///
/// # Errors
///
/// Returns [`crate::FrensenseError::Config`] when the document cannot be
/// serialized or the file cannot be written (missing directory, permissions,
/// full disk).
pub fn write_profile(
    path: &Path,
    telemetry: Option<&ScanTelemetry>,
    coverage: Option<&Coverage>,
    skipped: &[UnsupportedSourceFile],
    exclusions: Option<&Exclusions>,
    incomplete: &[IncompleteFunction],
    target: Option<&str>,
) -> Result<()> {
    let doc = profile_document(telemetry, coverage, skipped, exclusions, incomplete, target);
    let text = serde_json::to_string_pretty(&doc)
        .map_err(|e| crate::FrensenseError::Config(e.to_string()))?;
    std::fs::write(path, text).map_err(|e| {
        crate::FrensenseError::Config(format!(
            "Failed to write profile to {}: {e}",
            path.display()
        ))
    })
}

/// A path for a surface outside [`analysis_payload`] (the report's
/// `analysis_incomplete` list), under the same policy and env switch.
#[must_use]
pub(crate) fn path_in_payload(path: &str) -> String {
    PathPolicy::from_env().apply(path)
}

/// The `analysis.graph` block: the sizes of the program the taint phase
/// actually walked.
fn graph_json(graph: &GraphSize) -> Value {
    json!({
        "functions": graph.functions,
        "nodes": graph.nodes,
        "edges": graph.edges,
        "cross_edges": graph.cross_edges,
    })
}

/// The `analysis.funnel` block: where the call sites left the taint phase,
/// including the busiest callees that matched no sink fact.
fn funnel_json(f: &TaintFunnel) -> Value {
    json!({
        "calls_examined": f.calls_examined,
        "skipped_local_callable": f.skipped_local_callable,
        "skipped_program_local": f.skipped_program_local,
        "skipped_receiver_only_verb": f.skipped_receiver_only_verb,
        "not_a_sink": f.not_a_sink,
        "sink_calls": f.sink_calls,
        "unmatched_callees_sample": f.top_unmatched().iter().map(|entry| json!({
            "callee": entry.callee,
            "calls": entry.calls,
        })).collect::<Vec<Value>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::{PathPolicy, TELEMETRY_SCHEMA_VERSION, analysis_payload, profile_document};

    fn payload() -> serde_json::Value {
        analysis_payload(None, None, &[], None, &[], None)
    }

    /// The committed inventory: adding a field is a reviewed diff, and a
    /// rename cannot land without this list moving with it.
    #[test]
    fn the_payload_keys_are_committed() {
        let mut keys: Vec<String> = payload()
            .as_object()
            .expect("payload is an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "caps",
                "checks",
                "collection",
                "coverage",
                "errors",
                "funnel",
                "graph",
                "phases",
                "redaction",
                "schema_version",
                "slowest_files",
                "slowest_functions",
                "status",
                "suppressed",
                "target",
                "verdicts",
            ],
            "the telemetry payload gained or lost a top-level key"
        );

        let mut coverage: Vec<String> = payload()["coverage"]
            .as_object()
            .expect("coverage is an object")
            .keys()
            .cloned()
            .collect();
        coverage.sort();
        assert_eq!(
            coverage,
            vec![
                "excluded_by_reason",
                "excluded_sample",
                "failed_files_sample",
                "files_analyzed",
                "files_excluded",
                "files_failed",
                "files_found",
                "files_not_analyzed",
                "files_partial",
                "files_submitted",
                "files_unsupported",
                "files_with_sink_sites",
                "files_without_sink_sites",
                "functions",
                "no_sink_files_sample",
                "partial_files_sample",
                "sink_sites",
                "unresolved_sample",
                "unresolved_sites",
                "unsupported_inputs",
                "unsupported_source_files",
            ],
            "the coverage block gained or lost a key"
        );
    }

    /// The payload says, in the payload, that it was collected locally and how
    /// much of a path it kept: a reader must not have to find a doc page to
    /// learn either.
    #[test]
    fn the_payload_declares_where_it_stays_and_how_paths_are_kept() {
        let p = payload();
        assert_eq!(p["schema_version"], TELEMETRY_SCHEMA_VERSION);
        assert_eq!(p["collection"], "local");
        assert_eq!(p["redaction"]["paths"], "absolute");
    }

    /// The profile document wraps the same payload rather than restating it.
    #[test]
    fn the_profile_document_embeds_the_report_payload() {
        let doc = profile_document(None, None, &[], None, &[], None);
        assert_eq!(doc["kind"], "scan-telemetry");
        assert_eq!(doc["collection"], "local");
        assert!(doc["producer"]["version"].is_string());
        assert_eq!(doc["telemetry"], payload());
    }

    /// Every mode is reachable by name, and an unknown name cannot widen what
    /// the report keeps.
    #[test]
    fn path_policies_are_named_and_typos_fall_back_to_absolute() {
        assert_eq!(PathPolicy::parse("absolute"), PathPolicy::Absolute);
        assert_eq!(PathPolicy::parse("relative"), PathPolicy::Relative);
        assert_eq!(PathPolicy::parse(" Basename "), PathPolicy::Basename);
        assert_eq!(PathPolicy::parse("nonsense"), PathPolicy::Absolute);
        assert_eq!(PathPolicy::Absolute.as_str(), "absolute");
        assert_eq!(PathPolicy::Relative.as_str(), "relative");
        assert_eq!(PathPolicy::Basename.as_str(), "basename");
    }

    /// The switch does what the notice says: a basename policy drops the
    /// directory layout and nothing else.
    #[test]
    fn a_basename_policy_keeps_only_the_file_name() {
        assert_eq!(
            PathPolicy::Basename.apply("/home/ana/customer/app/index.ts"),
            "index.ts"
        );
        assert_eq!(
            PathPolicy::Absolute.apply("/home/ana/customer/app/index.ts"),
            "/home/ana/customer/app/index.ts"
        );
        // A path with no final component survives unchanged rather than
        // becoming an empty string.
        assert_eq!(PathPolicy::Basename.apply(""), "");
    }
}
