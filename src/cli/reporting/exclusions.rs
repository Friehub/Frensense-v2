// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

#![allow(clippy::too_many_arguments)]

//! Report entry points that name the paths the default exclusion rules
//! skipped.
//!
//! The counts a report shows live on [`Coverage`]; the reasons and the sample
//! travel in [`Exclusions`]. Keeping those entry points here means
//! `reporting.rs` gains no length, and the compatibility entry points there
//! remain byte-for-byte the same public API.

use crate::Advisory;
use crate::Result;
use crate::engine::files::UnsupportedSourceFile;
use crate::policy::{Coverage, Exclusions};

use super::{json_report_with_coverage_impl, print_results_impl, print_scan_summary_detailed_impl};

/// Text lines naming what the default exclusion rules skipped and how to
/// opt back in. Empty when nothing source-bearing was excluded.
pub(super) fn excluded_lines(exclusions: &Exclusions) -> Vec<String> {
    if exclusions.files_excluded == 0 {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "Excluded by default rules: {}",
        exclusions
            .by_reason
            .iter()
            .map(|(reason, n)| format!("{reason} x{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    )];
    lines.push(
        "Scan them with --include-dir <name>, or everything with --no-default-excludes."
            .to_string(),
    );
    lines
}

/// Prints the scan summary, including what the walk skipped by default.
pub fn print_scan_summary_detailed_with_coverage_and_exclusions(
    advisories: &[Advisory],
    input_path: &std::path::Path,
    duration: std::time::Duration,
    output_path: Option<&std::path::Path>,
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    coverage: Option<&Coverage>,
    exclusions: &Exclusions,
) {
    print_scan_summary_detailed_impl(
        advisories,
        input_path,
        duration,
        output_path,
        telemetry,
        incomplete,
        coverage,
        Some(exclusions),
    );
}

/// The compatibility summary entry point: same numbers, without the names of
/// the skipped paths. A consumer that wants those passes [`Exclusions`] to
/// [`print_scan_summary_detailed_with_coverage_and_exclusions`].
pub fn print_scan_summary_detailed_with_coverage(
    advisories: &[Advisory],
    input_path: &std::path::Path,
    duration: std::time::Duration,
    output_path: Option<&std::path::Path>,
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    coverage: Option<&Coverage>,
) {
    print_scan_summary_detailed_impl(
        advisories,
        input_path,
        duration,
        output_path,
        telemetry,
        incomplete,
        coverage,
        None,
    );
}

/// The scan report as JSON, with the reasons and sample for every path the
/// default exclusion rules skipped.
#[must_use]
pub fn json_report_with_coverage_and_exclusions(
    advisories: &[Advisory],
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    skipped: &[UnsupportedSourceFile],
    coverage: Option<&Coverage>,
    exclusions: &Exclusions,
) -> serde_json::Value {
    json_report_with_coverage_impl(
        advisories,
        incomplete,
        telemetry,
        skipped,
        coverage,
        Some(exclusions),
        None,
    )
}

/// The compatibility JSON entry point: the counts are the same, the
/// `excluded_by_reason` map and `excluded_sample` list are empty.
#[must_use]
pub fn json_report_with_coverage(
    advisories: &[Advisory],
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    skipped: &[UnsupportedSourceFile],
    coverage: Option<&Coverage>,
) -> serde_json::Value {
    json_report_with_coverage_impl(
        advisories, incomplete, telemetry, skipped, coverage, None, None,
    )
}

/// Prints the results, including the paths the default exclusion rules
/// skipped.
///
/// # Errors
/// Returns an error when the report cannot be serialized or written.
pub fn print_results_with_coverage_and_exclusions(
    advisories: &[Advisory],
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    skipped: &[UnsupportedSourceFile],
    coverage: Option<&Coverage>,
    format: &str,
    input_path: &std::path::Path,
    duration: Option<std::time::Duration>,
    output_path: Option<&std::path::Path>,
    exclusions: &Exclusions,
) -> Result<()> {
    print_results_impl(
        advisories,
        incomplete,
        telemetry,
        skipped,
        coverage,
        format,
        input_path,
        duration,
        output_path,
        Some(exclusions),
    )
}

/// The compatibility results entry point: the counts are the same, the
/// excluded paths are not named.
///
/// # Errors
/// Returns an error when the report cannot be serialized or written.
pub fn print_results_with_coverage(
    advisories: &[Advisory],
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    skipped: &[UnsupportedSourceFile],
    coverage: Option<&Coverage>,
    format: &str,
    input_path: &std::path::Path,
    duration: Option<std::time::Duration>,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    print_results_impl(
        advisories,
        incomplete,
        telemetry,
        skipped,
        coverage,
        format,
        input_path,
        duration,
        output_path,
        None,
    )
}
