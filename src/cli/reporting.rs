// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::engine::files::UnsupportedSourceFile;
use crate::explain::{ExplainRecord, slot_label};
use crate::policy::Coverage;
use crate::reporter::Reporter;
use crate::{Advisory, FrensenseError, Result};
use std::collections::HashSet;

/// How many skipped-file paths a report embeds. The counts are complete; the
/// path list is a sample so a generated-source tree cannot bloat the JSON.
pub const UNSUPPORTED_SAMPLE: usize = 25;

/// One language for which the engine skipped source files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedLanguage {
    /// Language name shown to the user (`Ruby`, `PHP`, ...).
    pub language: String,
    /// How many files of that language were skipped.
    pub files: usize,
}

/// Per-language counts for skipped source files, ordered by count (largest
/// first, then name) so the report is deterministic regardless of walk order.
#[must_use]
pub fn skipped_language_counts(skipped: &[UnsupportedSourceFile]) -> Vec<SkippedLanguage> {
    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for file in skipped {
        *counts.entry(file.language).or_default() += 1;
    }
    let mut languages: Vec<SkippedLanguage> = counts
        .into_iter()
        .map(|(language, files)| SkippedLanguage {
            language: language.to_string(),
            files,
        })
        .collect();
    languages.sort_by(|a, b| {
        b.files
            .cmp(&a.files)
            .then_with(|| a.language.cmp(&b.language))
    });
    languages
}

/// The `unsupported_source_files` object shared by the CLI JSON report and
/// the MCP audit result: a full count, a full per-language breakdown, and a
/// bounded path sample.
#[must_use]
pub fn skipped_unsupported_json(skipped: &[UnsupportedSourceFile]) -> serde_json::Value {
    serde_json::json!({
        "count": skipped.len(),
        "languages": skipped_language_counts(skipped)
            .into_iter()
            .map(|entry| serde_json::json!({
                "language": entry.language,
                "files": entry.files,
            }))
            .collect::<Vec<_>>(),
        "files": skipped
            .iter()
            .take(UNSUPPORTED_SAMPLE)
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
    })
}

/// Print a banner at the start of a scan when running in interactive human mode.
pub fn print_scan_banner(
    input_path: &std::path::Path,
    bundle_path: Option<&std::path::Path>,
    language_filter: Option<&str>,
    output_path: Option<&std::path::Path>,
) {
    println!("Frensense Security Scanner v{}", crate::FRENSENSE_VERSION);
    println!("Target:        {}", input_path.display());
    if let Some(bundle) = bundle_path {
        println!("Rule Bundle:   {}", bundle.display());
    }
    if let Some(lang) = language_filter {
        println!("Language:      {}", lang);
    }
    if let Some(out) = output_path {
        println!("Report Output: {}", out.display());
    }
    println!();
}

/// Overall outcome of the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    /// Every file parsed cleanly, no checks panicked, no safety caps hit.
    Complete,
    /// Scan completed with caveats: caps fired, syntax parse partial, or degraded functions.
    Partial,
    /// All files failed to analyze or critical crash.
    Failed,
}

impl ScanStatus {
    #[must_use]
    pub fn compute(
        telemetry: &frensense_engine::telemetry::ScanTelemetry,
        incomplete: &[frensense_engine::scan::IncompleteFunction],
    ) -> Self {
        if (telemetry.input.submitted > 0
            && (telemetry.input.scanned == 0
                || telemetry.input.failed >= telemetry.input.submitted))
            || (telemetry.input.scanned == 0 && telemetry.input.unsupported > 0)
        {
            return ScanStatus::Failed;
        }
        if telemetry.is_complete() && incomplete.is_empty() {
            ScanStatus::Complete
        } else {
            ScanStatus::Partial
        }
    }

    /// The report's answer to "is this clean?".
    ///
    /// `true` only when nothing was reported, the machinery completed, every
    /// file the walk found was analyzed, and every sink site the scan
    /// recognized was decided. An *undecided* site makes a scan unclean: "I
    /// could not decide" is not "clean". So does a file the engine never
    /// looked at - a clean verdict over an unanalyzed tree is the one thing a
    /// clean verdict must never mean.
    ///
    /// A coverage gap (an analyzed file where no sink site was recognized)
    /// does not by itself make the scan unclean, because [`Coverage`] reports
    /// it separately - forcing every utility module to look like a failure
    /// would train readers to ignore the status.
    #[must_use]
    pub fn clean(self, advisories_empty: bool, coverage: &Coverage) -> bool {
        advisories_empty
            && self == ScanStatus::Complete
            && coverage.fully_resolved()
            && coverage.files_not_analyzed() == 0
    }
}

/// The one-line answer the summary prints.
///
/// `Clean` is reserved for a scan that ran completely, analyzed every file
/// it found, recognized at least one sink site somewhere, and decided every
/// site it recognized. Every other combination says what qualified it.
fn status_label(
    status: ScanStatus,
    findings: usize,
    coverage: Option<&Coverage>,
    telem: Option<&frensense_engine::telemetry::ScanTelemetry>,
) -> String {
    match status {
        ScanStatus::Failed => "Failed analysis".to_string(),
        ScanStatus::Partial if findings == 0 => "No findings (partial analysis)".to_string(),
        ScanStatus::Partial => format!("Findings reported ({findings}, partial analysis)"),
        ScanStatus::Complete if findings > 0 => "Findings reported".to_string(),
        ScanStatus::Complete => {
            if let Some(t) = telem {
                let below_conf: usize = t
                    .suppressed
                    .iter()
                    .filter(|s| s.reason == "below-confidence")
                    .map(|s| s.count)
                    .sum();
                if below_conf > 0 {
                    return format!(
                        "No findings ({below_conf} dropped below confidence threshold)"
                    );
                }
            }
            match coverage {
                Some(c) if !c.recognized_anything() => {
                    "No findings (nothing recognized)".to_string()
                }
                Some(c) if c.files_not_analyzed() > 0 => format!(
                    "No findings ({} of {} source files analyzed)",
                    c.files_analyzed, c.files_found
                ),
                Some(c) if !c.fully_resolved() => {
                    format!("No findings ({} site(s) undecided)", c.unresolved_sites)
                }
                _ => "Clean".to_string(),
            }
        }
    }
}

/// Prints the scan summary block, including what the scan actually covered.
///
/// The coverage line is the denominator behind "no findings": without it a
/// scan that analyzed 3 of 40 files is indistinguishable from one that
/// analyzed all 40 and found nothing.
pub fn print_scan_summary_detailed_with_coverage(
    advisories: &[Advisory],
    input_path: &std::path::Path,
    duration: std::time::Duration,
    output_path: Option<&std::path::Path>,
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    coverage: Option<&Coverage>,
) {
    let mut critical = 0;
    let mut warning = 0;
    let mut info = 0;

    for a in advisories {
        match a.severity {
            crate::Severity::Critical => critical += 1,
            crate::Severity::Warning => warning += 1,
            crate::Severity::Info => info += 1,
        }
    }

    let empty_telem = frensense_engine::telemetry::ScanTelemetry::default();
    let telem = telemetry.unwrap_or(&empty_telem);
    let status = ScanStatus::compute(telem, incomplete);

    println!("============================= Scan Summary =============================");
    println!("Target:             {}", input_path.display());
    println!("Scan Duration:      {:.2}s", duration.as_secs_f64());
    let peak_rss = crate::cli::progress::peak_rss_kb();
    if peak_rss > 0 {
        println!(
            "Peak Memory (RSS):  {}",
            crate::cli::progress::format_rss(peak_rss)
        );
    }
    // The honest denominator: files found, not files the engine chose to
    // submit. On a polyglot tree the two differ, and only the first tells a
    // reader that 380 of 400 files were never analyzed.
    match coverage {
        Some(c) if c.files_found > 0 => {
            println!("Files Scanned:      {}/{}", c.files_analyzed, c.files_found);
            if c.files_not_analyzed() > 0 {
                println!(
                    "Not Analyzed:       {} ({} unsupported language, {} failed)",
                    c.files_not_analyzed(),
                    c.files_unsupported,
                    c.files_failed
                );
            }
        }
        _ if telem.input.submitted > 0 => {
            let errs = telem.input.failed + telem.errors.len();
            if errs > 0 {
                println!(
                    "Files Scanned:      {}/{} ({errs} failed/errors)",
                    telem.input.scanned, telem.input.submitted
                );
            } else {
                println!(
                    "Files Scanned:      {}/{}",
                    telem.input.scanned, telem.input.submitted
                );
            }
        }
        _ => {}
    }
    // The denominator behind "no findings". Without it, a scan that
    // recognized nothing is indistinguishable from a clean one; with it, a
    // reader can falsify the verdict themselves.
    // CWE coverage split: dataflow rules and structural policies are not the
    // same claim. Counting them together let cheap policy rules inflate the
    // CWE total, so the summary states each contribution separately.
    let mut dataflow_cwes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut policy_cwes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for a in advisories {
        let target = if a.rule_id().starts_with("taint.") {
            &mut dataflow_cwes
        } else {
            &mut policy_cwes
        };
        target.extend(a.cwe().iter().map(|c| c.to_string()));
    }
    if !dataflow_cwes.is_empty() || !policy_cwes.is_empty() {
        println!(
            "CWE Coverage:       {} via dataflow · {} via structural policies",
            dataflow_cwes.len(),
            policy_cwes.len()
        );
    }
    if let Some(c) = coverage {
        println!(
            "Sink Sites:         {} recognized in {} file(s)",
            c.sink_sites, c.files_with_sink_sites
        );
        if c.files_without_sink_sites > 0 {
            println!(
                "Not Recognized:     {} file(s) contained no sink site the engine models",
                c.files_without_sink_sites
            );
        }
        if c.unresolved_sites > 0 {
            println!(
                "Undecided:          {} sink site(s) the analysis could not resolve",
                c.unresolved_sites
            );
        }
    }
    if telem.input.submitted > 0 {
        // Not `print!`: the stage ledger is one block, written in one go so it
        // cannot interleave with the progress output on the same stream.
        use std::io::Write as _;
        let _ = write!(
            std::io::stdout(),
            "{}",
            render_stages(telem, advisories.len())
        );
    }
    println!("Findings Breakdown:");
    println!("  - Critical:       {critical}");
    println!("  - Warning:        {warning}");
    println!("  - Info:           {info}");
    println!("Total Findings:     {}", advisories.len());
    println!(
        "Status:             {}",
        status_label(status, advisories.len(), coverage, Some(telem))
    );
    if let Some(out) = output_path {
        println!("Report File:        {}", out.display());
    }
    println!("========================================================================");
    let coverage_gap = coverage.is_some_and(|c| {
        !c.fully_resolved() || !c.recognized_anything() || c.files_not_analyzed() > 0
    });
    if status != ScanStatus::Complete {
        println!("Caveat: Analysis status is {status:?}; results may be partial.");
        let caps_count = telem.caps.iter().map(|c| c.hits).sum::<usize>();
        println!(
            "        {} cap truncation(s), {} partial parse file(s), {} degraded function(s).",
            caps_count,
            telem.input.parse_partial,
            incomplete.len()
        );
    }
    if status != ScanStatus::Complete || coverage_gap {
        if status == ScanStatus::Complete {
            // The headline has to match the gap: a scan that read every file
            // but recognized nothing has a coverage gap, not a file it never
            // opened.
            match coverage {
                Some(c) if c.files_not_analyzed() > 0 => {
                    println!("Caveat: the analysis did not analyze every file.");
                }
                Some(_) => println!("Caveat: the analysis is qualified."),
                None => println!("Caveat: the analysis did not cover every file."),
            }
        }
        if let Some(c) = coverage {
            if c.files_not_analyzed() > 0 {
                println!(
                    "        {} of {} source file(s) were not analyzed ({} unsupported",
                    c.files_not_analyzed(),
                    c.files_found,
                    c.files_unsupported
                );
                println!(
                    "        language, {} failed); findings there cannot be ruled out.",
                    c.files_failed
                );
            }
            if !c.recognized_anything() {
                println!("        No sink site was recognized in any scanned file: this scan says");
                println!("        nothing about whether the code is safe.");
            } else if c.files_without_sink_sites > 0 {
                // Subsumed by the line above when nothing was recognized at
                // all; here it names the files that were silent among the
                // ones that were not.
                println!(
                    "        {} of {} analyzed file(s) yielded no recognized sink; a finding",
                    c.files_without_sink_sites, c.files_analyzed
                );
                println!("        there cannot be ruled out. `analysis.coverage.no_sink_files`");
                println!("        names a sample.");
            }
            if !c.fully_resolved() {
                println!(
                    "        {} sink site(s) reached no verdict. Run with --explain to see where",
                    c.unresolved_sites
                );
                println!("        the backward walk stopped.");
            }
        }
        println!("        Run with --json to inspect the full `analysis` telemetry object.");
        println!("========================================================================");
    }
}

/// The one-line headline above the summary when the scan reported nothing.
///
/// "Analysis Complete: No findings." was printed for every empty result,
/// including scans that recognized no sink at all. A reader has no way to
/// tell those apart, so the headline now carries the qualification.
fn no_findings_headline(
    status: ScanStatus,
    coverage: Option<&Coverage>,
    telem: Option<&frensense_engine::telemetry::ScanTelemetry>,
) -> String {
    if let Some(t) = telem {
        let below_conf: usize = t
            .suppressed
            .iter()
            .filter(|s| s.reason == "below-confidence")
            .map(|s| s.count)
            .sum();
        if below_conf > 0 {
            return format!(
                "No findings - {below_conf} potential finding(s) dropped below confidence threshold."
            );
        }
    }
    match (status, coverage) {
        (ScanStatus::Complete, Some(c)) if !c.recognized_anything() => {
            "No findings - no sink site was recognized, so this scan does not show the code is safe."
                .to_string()
        }
        (ScanStatus::Complete, Some(c)) if c.files_not_analyzed() > 0 => format!(
            "No findings - only {} of {} source file(s) were analyzed; the rest were not scanned.",
            c.files_analyzed, c.files_found
        ),
        (ScanStatus::Complete, Some(c)) if !c.fully_resolved() => {
            format!(
                "No findings - {} sink site(s) were left undecided.",
                c.unresolved_sites
            )
        }
        (ScanStatus::Complete, _) => "Analysis Complete: No findings.".to_string(),
        (ScanStatus::Partial, _) => "No findings (analysis incomplete).".to_string(),
        (ScanStatus::Failed, _) => "Analysis failed.".to_string(),
    }
}

/// The JSON report envelope including the source files the scan skipped
/// because the engine has no spec for their language. The extra object is
/// additive (`analysis.coverage.unsupported_source_files`), so the schema
/// version does not move; consumers that ignore it keep working.
#[must_use]
pub fn json_report_with_skips(
    advisories: &[Advisory],
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    skipped: &[UnsupportedSourceFile],
) -> serde_json::Value {
    json_report_with_coverage(advisories, incomplete, telemetry, skipped, None)
}

/// The `analysis.graph` block: the sizes of the program the taint phase
/// actually walked.
fn graph_json(graph: &frensense_engine::telemetry::GraphSize) -> serde_json::Value {
    serde_json::json!({
        "functions": graph.functions,
        "nodes": graph.nodes,
        "edges": graph.edges,
        "cross_edges": graph.cross_edges,
    })
}

/// The `analysis.funnel` block: where the call sites left the taint phase,
/// including the busiest callees that matched no sink fact.
fn funnel_json(f: &frensense_engine::telemetry::TaintFunnel) -> serde_json::Value {
    serde_json::json!({
        "calls_examined": f.calls_examined,
        "skipped_local_callable": f.skipped_local_callable,
        "skipped_program_local": f.skipped_program_local,
        "skipped_receiver_only_verb": f.skipped_receiver_only_verb,
        "not_a_sink": f.not_a_sink,
        "sink_calls": f.sink_calls,
        "unmatched_callees": f.top_unmatched().iter().map(|entry| serde_json::json!({
            "callee": entry.callee,
            "calls": entry.calls,
        })).collect::<Vec<_>>(),
    })
}

/// [`json_report_with_skips`] plus what the scan actually covered.
///
/// Adds `analysis.clean` and the recognition/denominator fields under
/// `analysis.coverage`, so a consumer that reads only `status` cannot mistake
/// "we recognized nothing" for "we inspected and found nothing".
#[must_use]
pub fn json_report_with_coverage(
    advisories: &[Advisory],
    incomplete: &[frensense_engine::scan::IncompleteFunction],
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
    skipped: &[UnsupportedSourceFile],
    coverage: Option<&Coverage>,
) -> serde_json::Value {
    let empty_telem = frensense_engine::telemetry::ScanTelemetry::default();
    let telem = telemetry.unwrap_or(&empty_telem);
    let status = ScanStatus::compute(telem, incomplete);
    let cov = coverage.cloned().unwrap_or_default();
    let below_confidence = telem
        .suppressed
        .iter()
        .any(|s| s.reason == "below-confidence" && s.count > 0);
    let clean = status.clean(advisories.is_empty(), &cov) && !below_confidence;
    // Without engine-derived coverage (the compatibility entry points),
    // fall back to the input accounting so the denominator is still honest
    // about unsupported inputs and read failures.
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

    let analysis_obj = serde_json::json!({
        "status": status,
        "clean": clean,
        "coverage": {
            "files_found": files_found,
            "files_submitted": telem.input.submitted,
            "files_scanned": telem.input.scanned,
            "files_not_analyzed": files_not_analyzed,
            "files_unsupported": files_unsupported,
            "files_failed": telem.input.failed,
            "failed_files": telem.input.failed_files,
            "unsupported_inputs": telem.input.unsupported,
            "unsupported_source_files": skipped_unsupported_json(skipped),
            "files_partial": telem.input.parse_partial,
            "partial_files": telem.input.parse_partial_files,
            "functions": telem.input.functions,
            // What the scan recognized: the denominator behind "no
            // findings". `files_without_sink_sites` names the files where
            // the engine found nothing it models as dangerous, so a reader
            // can tell "inspected and clean" from "nothing recognized".
            "sink_sites": cov.sink_sites,
            "files_with_sink_sites": cov.files_with_sink_sites,
            "files_without_sink_sites": cov.files_without_sink_sites,
            "no_sink_files": cov.no_sink_files,
            "unresolved_sites": cov.unresolved_sites,
            "unresolved_sample": cov.unresolved_sample.iter().map(|s| serde_json::json!({
                "file": s.file,
                "line": s.line,
                "sink": s.sink,
            })).collect::<Vec<serde_json::Value>>(),
        },
        "errors": telem.errors,
        "suppressed": telem.suppressed.iter().map(|s| serde_json::json!({
            "reason": s.reason,
            "count": s.count,
        })).collect::<Vec<_>>(),
        "verdicts": {
            "vulnerable": telem.taint.vulnerable,
            "sanitized": telem.taint.sanitized,
            "unknown": telem.taint.unknown,
            "clean": telem.taint.clean,
        },
        // The sizes and call-site accounting behind the summary's graph and
        // taint lines, so a JSON consumer sees the same numbers.
        "graph": graph_json(&telem.graph),
        "funnel": funnel_json(&telem.funnel),
        "truncations": telem.caps.iter().map(|c| serde_json::json!({
            "cap": c.cap,
            "hits": c.hits,
            "effect": c.effect,
        })).collect::<Vec<_>>(),
        "checks": telem.checks.iter().map(|c| serde_json::json!({
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
        })).collect::<Vec<_>>(),
        "timings": telem.phases.iter().map(|p| serde_json::json!({
            "phase": p.phase,
            "ms": p.ms,
        })).collect::<Vec<_>>(),
        "slowest_files": telem.slowest_files.iter().map(|f| serde_json::json!({
            "file": f.file,
            "ms": f.ms,
            "functions": f.functions,
        })).collect::<Vec<_>>(),
        "slowest_functions": telem.slowest_functions.iter().map(|f| serde_json::json!({
            "function": f.function,
            "file": f.file,
            "ms": f.ms,
            "sink_args": f.sink_args,
        })).collect::<Vec<_>>(),
    });

    serde_json::json!({
        "schema_version": crate::REPORT_SCHEMA_VERSION,
        "producer": crate::identity::producer(),
        "clean": clean,
        "advisory_count": advisories.len(),
        "analysis_incomplete": incomplete
            .iter()
            .map(|f| serde_json::json!({
                "function": f.function,
                "file": f.file,
            }))
            .collect::<Vec<serde_json::Value>>(),
        "analysis": analysis_obj,
        "advisories": advisories,
    })
}

/// Prints the findings and the scan summary, including what the scan could recognize.
///
/// `coverage` is the denominator behind "no findings": a report that prints
/// "Clean" without it cannot be falsified, because a scan that recognized no
/// sink at all looks exactly like an inspected-clean one.
#[allow(clippy::too_many_arguments)]
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
    if !skipped.is_empty() {
        let languages = skipped_language_counts(skipped)
            .iter()
            .map(|entry| format!("{} ({})", entry.language, entry.files))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "Warning: {} source file(s) in unsupported languages were not scanned: {languages}.",
            skipped.len(),
        );
        eprintln!(
            "  Supported languages: {}.",
            crate::parser::language_names_help()
        );
        for file in skipped.iter().take(10) {
            eprintln!("  {} ({})", file.path, file.language);
        }
        if skipped.len() > 10 {
            eprintln!("  ... and {} more", skipped.len() - 10);
        }
    }
    if !incomplete.is_empty() {
        eprintln!(
            "Warning: {} function(s) exceeded the per-function analysis budget and were \
             analyzed in degraded form (see `analysis_incomplete` in the JSON report):",
            incomplete.len()
        );
        for f in incomplete.iter().take(20) {
            eprintln!("  {} ({})", f.function, f.file);
        }
        if incomplete.len() > 20 {
            eprintln!("  ... and {} more", incomplete.len() - 20);
        }
    }
    if let Some(telem) = telemetry
        && !telem.is_complete()
    {
        eprintln!(
            "Warning: scan is incomplete: {} submitted, {} scanned, {} failed, {} unsupported, {} partial-parse file(s), {} safety-cap event(s).",
            telem.input.submitted,
            telem.input.scanned,
            telem.input.failed,
            telem.input.unsupported,
            telem.input.parse_partial,
            telem.caps.iter().map(|c| c.hits).sum::<usize>(),
        );
        for error in telem.errors.iter().take(10) {
            eprintln!("  {error}");
        }
    }
    // The one coverage warning worth stderr: a scan that recognized no sink
    // at all proves nothing, and a `--output` report reader may never see
    // the summary block.
    if let Some(c) = coverage
        && !c.recognized_anything()
    {
        eprintln!(
            "Warning: no sink site was recognized in any of the {} analyzed file(s): this scan does not show the code is safe.",
            c.files_analyzed
        );
    }
    match format {
        "json" => {
            let rendered = serde_json::to_string_pretty(&json_report_with_coverage(
                advisories, incomplete, telemetry, skipped, coverage,
            ))
            .map_err(|e| FrensenseError::Config(format!("JSON error: {e}")))?;
            if let Some(out) = output_path {
                std::fs::write(out, rendered).map_err(|e| {
                    FrensenseError::Config(format!(
                        "Failed to write report to {}: {e}",
                        out.display()
                    ))
                })?;
                if let Some(d) = duration {
                    print_scan_summary_detailed_with_coverage(
                        advisories,
                        input_path,
                        d,
                        Some(out),
                        telemetry,
                        incomplete,
                        coverage,
                    );
                }
                println!("JSON report written to: {}", out.display());
            } else {
                println!("{rendered}");
            }
        }
        "sarif" => {
            let sarif = Reporter::to_sarif_with_coverage(
                advisories, input_path, telemetry, incomplete, coverage,
            );
            let rendered = serde_json::to_string_pretty(&sarif)
                .map_err(|e| FrensenseError::Config(format!("JSON error: {e}")))?;
            if let Some(out) = output_path {
                std::fs::write(out, rendered).map_err(|e| {
                    FrensenseError::Config(format!(
                        "Failed to write report to {}: {e}",
                        out.display()
                    ))
                })?;
                if let Some(d) = duration {
                    print_scan_summary_detailed_with_coverage(
                        advisories,
                        input_path,
                        d,
                        Some(out),
                        telemetry,
                        incomplete,
                        coverage,
                    );
                }
                println!("SARIF report written to: {}", out.display());
            } else {
                println!("{rendered}");
            }
        }
        "github" => {
            let rendered = Reporter::to_github_annotations(advisories);
            if let Some(out) = output_path {
                std::fs::write(out, &rendered).map_err(|e| {
                    FrensenseError::Config(format!(
                        "Failed to write report to {}: {e}",
                        out.display()
                    ))
                })?;
                if let Some(d) = duration {
                    print_scan_summary_detailed_with_coverage(
                        advisories,
                        input_path,
                        d,
                        Some(out),
                        telemetry,
                        incomplete,
                        coverage,
                    );
                }
                println!("GitHub annotations written to: {}", out.display());
            } else {
                print!("{rendered}");
            }
        }
        _ => {
            let cwd = std::env::current_dir().ok();
            let empty_telem = frensense_engine::telemetry::ScanTelemetry::default();
            let status = ScanStatus::compute(telemetry.unwrap_or(&empty_telem), incomplete);
            let headline = no_findings_headline(status, coverage, telemetry);
            if let Some(out) = output_path {
                let mut buf = Vec::new();
                if advisories.is_empty() {
                    buf.extend_from_slice(format!("{headline}\n").as_bytes());
                } else {
                    buf.extend_from_slice(
                        format!("Analysis: {}\n\n", input_path.display()).as_bytes(),
                    );
                    for v in advisories {
                        buf.extend_from_slice(
                            format!("{}\n", format_advisory_clean(v, input_path, cwd.as_deref()))
                                .as_bytes(),
                        );
                    }
                    buf.extend_from_slice(
                        format!("Total Findings: {}\n", advisories.len()).as_bytes(),
                    );
                }
                std::fs::write(out, buf).map_err(|e| {
                    FrensenseError::Config(format!(
                        "Failed to write report to {}: {e}",
                        out.display()
                    ))
                })?;

                if let Some(d) = duration {
                    print_scan_summary_detailed_with_coverage(
                        advisories,
                        input_path,
                        d,
                        Some(out),
                        telemetry,
                        incomplete,
                        coverage,
                    );
                }
                println!("Text report written to: {}", out.display());
            } else {
                if advisories.is_empty() {
                    println!("{headline}");
                    if let Some(d) = duration {
                        println!();
                        print_scan_summary_detailed_with_coverage(
                            advisories, input_path, d, None, telemetry, incomplete, coverage,
                        );
                    }
                } else {
                    println!("Analysis: {}", input_path.display());
                    println!();
                    for v in advisories {
                        println!("{}", format_advisory_clean(v, input_path, cwd.as_deref()));
                    }
                    println!("Total Findings: {}", advisories.len());
                    if let Some(d) = duration {
                        println!();
                        print_scan_summary_detailed_with_coverage(
                            advisories, input_path, d, None, telemetry, incomplete, coverage,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Helper to format hidden finding count by tier for `--explain`.
#[must_use]
pub fn format_hidden_summary(tier: crate::RuleTier, count: usize) -> String {
    let noun = if count == 1 { "finding" } else { "findings" };
    format!(
        "{} {} {} hidden; use --profile {}",
        count,
        tier.as_str(),
        noun,
        tier.required_profile()
    )
}

/// The stage ledger shown in every human-format scan summary: one line per
/// stage a scan went through, so a slow or empty stage is visible without a
/// flag. Pure over the telemetry, which `--json` consumers also receive.
fn render_stages(telem: &frensense_engine::telemetry::ScanTelemetry, reported: usize) -> String {
    use std::fmt::Write as _;
    let ms = |name: &str| {
        telem
            .phases
            .iter()
            .find(|p| p.phase == name)
            .map_or(0, |p| p.ms)
    };
    let (i, g, f, t) = (&telem.input, &telem.graph, &telem.funnel, &telem.taint);
    let dropped: usize = telem.suppressed.iter().map(|s| s.count).sum();
    let mut out = String::from("Stages:\n");
    let _ = writeln!(
        out,
        "  parse+lower  {:>6} ms  {} file(s) given, {} lowered, {} failed -> {} function(s)",
        ms("lower"),
        i.submitted,
        i.scanned,
        i.failed,
        i.functions
    );
    let _ = writeln!(
        out,
        "  graph        {:>6} ms  {} function(s), {} value-flow node(s), {} edge(s), {} cross-function edge(s)",
        ms("graph"),
        g.functions,
        g.nodes,
        g.edges,
        g.cross_edges
    );
    let _ = writeln!(
        out,
        "  checks       {:>6} ms  {} check(s), {} finding(s)",
        ms("checks"),
        telem.checks.len(),
        telem.checks.iter().map(|c| c.findings).sum::<usize>()
    );
    let _ = writeln!(
        out,
        "  taint        {:>6} ms  {} call(s) -> {} sink call(s) -> {} argument(s) walked ({} vulnerable)",
        ms("taint"),
        f.calls_examined,
        f.sink_calls,
        t.sink_args_explored,
        t.vulnerable
    );
    let _ = writeln!(
        out,
        "  report                  {reported} reported, {dropped} dropped at the reporting gate"
    );
    out
}

/// Where the taint phase's call sites left the pipeline: the numbers behind
/// the summary's taint line, printed by `--explain`.
fn render_funnel(telem: &frensense_engine::telemetry::ScanTelemetry) -> String {
    use std::fmt::Write as _;
    let f = &telem.funnel;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Pipeline: where {} call(s) left the engine",
        f.calls_examined
    );
    let _ = writeln!(
        out,
        "  skipped before matching   {:>6}   (local callable {}, program-local callee {}, receiver-only verb {})",
        f.skipped(),
        f.skipped_local_callable,
        f.skipped_program_local,
        f.skipped_receiver_only_verb
    );
    let _ = writeln!(
        out,
        "  matched no sink fact      {:>6}   <- vocabulary the engine never walks",
        f.not_a_sink
    );
    let top = f.top_unmatched();
    if !top.is_empty() {
        let _ = writeln!(
            out,
            "  most-called callees with no sink fact   ({} name(s) tracked, busiest first):",
            f.unmatched_callees.len()
        );
        for entry in top {
            let _ = writeln!(out, "    {:<26}{:>5}", entry.callee, entry.calls);
        }
    }
    let _ = writeln!(out, "  matched a sink fact       {:>6}", f.sink_calls);
    for s in &telem.suppressed {
        let _ = writeln!(out, "  reporting gate: {:<24}{:>6}", s.reason, s.count);
    }
    out
}

/// Print the `--explain` section: every explored sink argument that did
/// NOT become an advisory, with the reason the engine stayed silent, as well
/// as counts of findings hidden by profile tiers.
/// Written to stderr so it never contaminates the report on stdout.
pub fn print_explain(
    records: &[ExplainRecord],
    hidden_by_tier: &std::collections::BTreeMap<crate::RuleTier, usize>,
) {
    eprintln!();
    eprintln!(
        "Explain: {} silent sink argument(s) explored (no advisory)",
        records.len()
    );
    for (tier, &count) in hidden_by_tier {
        if count > 0 {
            eprintln!("  {}", format_hidden_summary(*tier, count));
        }
    }
    if records.is_empty() {
        eprintln!("  (none - every explored sink argument either reported or was not a sink)");
        return;
    }
    eprintln!();
    let mut sorted: Vec<&ExplainRecord> = records.iter().collect();
    sorted.sort_by(|a, b| {
        (&a.file, a.line, &a.sink, a.arg_slot).cmp(&(&b.file, b.line, &b.sink, b.arg_slot))
    });
    for r in sorted {
        eprintln!(
            "  {:<14} {}:{}  {}({})",
            r.verdict,
            r.file,
            r.line,
            r.sink,
            slot_label(r.arg_slot)
        );
        eprintln!("      why: {}", r.reason);
        for c in &r.cut_sites {
            let passed = c.kind == "passed-through";
            let what = match (passed, c.detail.is_empty()) {
                (true, _) => format!("`{}`", c.detail),
                (false, true) => c.kind.to_string(),
                (false, false) => format!("{} `{}`", c.kind, c.detail),
            };
            let verb = if passed {
                "flowed through"
            } else {
                "stopped at"
            };
            eprintln!(
                "      {verb}: {what} in {} ({}:{})",
                c.function, c.file, c.line
            );
        }
        if let Some(src) = &r.source_desc {
            eprintln!("      source: {src}");
        }
    }
}

/// Print the `--explain` coverage lists: every source file the scan did not
/// analyze (and why), the analyzed files where no sink site was recognized,
/// and the sink sites that reached no verdict.
///
/// `--explain` already answers "why did the engine stay silent about a sink
/// it saw"; this answers the prior question, "which files did it never see".
/// Written to stderr, like the rest of `--explain`.
pub fn print_explain_coverage(
    coverage: &Coverage,
    skipped: &[UnsupportedSourceFile],
    telemetry: Option<&frensense_engine::telemetry::ScanTelemetry>,
) {
    eprintln!();
    eprintln!(
        "Coverage: {}/{} source file(s) analyzed ({} not analyzed: {} unsupported language, {} failed)",
        coverage.files_analyzed,
        coverage.files_found,
        coverage.files_not_analyzed(),
        coverage.files_unsupported,
        coverage.files_failed,
    );
    if !skipped.is_empty() {
        eprintln!("  unsupported language (not scanned):");
        for entry in skipped_language_counts(skipped) {
            eprintln!("    {:<16} {}", entry.language, entry.files);
        }
        for file in skipped.iter().take(10) {
            eprintln!("    - {} ({})", file.path, file.language);
        }
        if skipped.len() > 10 {
            eprintln!("    ... and {} more", skipped.len() - 10);
        }
    }
    if let Some(telem) = telemetry
        && !telem.input.failed_files.is_empty()
    {
        eprintln!("  failed to read, parse, or lower (not analyzed):");
        for file in &telem.input.failed_files {
            eprintln!("    - {file}");
        }
        if telem.input.failed > telem.input.failed_files.len() {
            eprintln!(
                "    ... and {} more",
                telem.input.failed - telem.input.failed_files.len()
            );
        }
    }
    if coverage.files_without_sink_sites > 0 {
        eprintln!(
            "  analyzed, no sink site the engine models ({} of {} analyzed file(s)):",
            coverage.files_without_sink_sites, coverage.files_analyzed
        );
        for file in &coverage.no_sink_files {
            eprintln!("    - {file}");
        }
        if coverage.files_without_sink_sites > coverage.no_sink_files.len() {
            eprintln!(
                "    ... and {} more",
                coverage.files_without_sink_sites - coverage.no_sink_files.len()
            );
        }
    }
    if coverage.unresolved_sites > 0 {
        eprintln!(
            "  sink site(s) the backward walk could not decide ({}):",
            coverage.unresolved_sites
        );
        for site in &coverage.unresolved_sample {
            eprintln!("    - {}:{}  {}", site.file, site.line, site.sink);
        }
        if coverage.unresolved_sites > coverage.unresolved_sample.len() {
            eprintln!(
                "    ... and {} more",
                coverage.unresolved_sites - coverage.unresolved_sample.len()
            );
        }
    }
    if let Some(telem) = telemetry {
        // One block, written in one go so it cannot interleave with the
        // rest of the explain output on the same stream.
        use std::io::Write as _;
        let _ = write!(std::io::stderr(), "\n{}", render_funnel(telem));
    }
}

/// Format an advisory cleanly for human consumption.
fn format_advisory_clean(
    v: &Advisory,
    input_path: &std::path::Path,
    cwd: Option<&std::path::Path>,
) -> String {
    let mut out = String::new();
    let severity_label = match v.severity {
        crate::Severity::Critical => "[CRITICAL]",
        crate::Severity::Warning => "[WARNING]",
        crate::Severity::Info => "[INFO]",
    };

    let file_path = std::path::Path::new(&v.file_path);
    let rel_path = if file_path == input_path
        || (input_path.is_file() && file_path.file_name() == input_path.file_name())
    {
        input_path
    } else if let Ok(stripped) = file_path.strip_prefix(input_path) {
        stripped
    } else if let Some(c) = cwd
        && let Ok(stripped) = file_path.strip_prefix(c)
    {
        stripped
    } else if let Ok(stripped) = file_path.strip_prefix(".") {
        stripped
    } else {
        file_path
    };

    let clean_title = if let Some(ref func) = v.enclosing_symbol {
        v.title
            .strip_suffix(&format!(" ({func})"))
            .unwrap_or(&v.title)
    } else {
        &v.title
    };

    let clean_title = clean_title
        .strip_prefix("Policy violation: policy_")
        .map(|sink| format!("Policy violation: {sink}"))
        .unwrap_or_else(|| clean_title.to_string());

    out.push_str(&format!("{severity_label} {clean_title}\n"));
    if let Some(ref func) = v.enclosing_symbol {
        out.push_str(&format!(
            "  --> {}:{}:{} (in `{func}`)\n",
            rel_path.display(),
            v.line,
            v.column
        ));
    } else {
        out.push_str(&format!(
            "  --> {}:{}:{}\n",
            rel_path.display(),
            v.line,
            v.column
        ));
    }
    out.push('\n');

    // Code frame: the offending line (and the one before it) with a caret
    // under the flagged call, so the developer sees the bug without
    // opening the file.
    if let Some(frame) = crate::reporter::code_frame(&v.file_path, v.line, v.column) {
        let width = frame
            .lines
            .iter()
            .map(|(n, _)| n.to_string().len())
            .max()
            .unwrap_or(1);
        out.push_str(&format!("  {:>width$} |\n", ""));
        for (n, text) in &frame.lines {
            out.push_str(&format!("  {n:>width$} | {text}\n"));
        }
        if v.column > 0 {
            out.push_str(&format!(
                "  {:>width$} | {}{}\n",
                "",
                " ".repeat(frame.caret_col),
                "^".repeat(frame.caret_len)
            ));
        }
        out.push_str(&format!("  {:>width$} |\n", ""));
    }

    // Rule identity: stable id and CWE ids with their reference.
    let cwes = v.cwe();
    if cwes.is_empty() {
        out.push_str(&format!("  = rule: {}\n", v.rule_id()));
    } else {
        out.push_str(&format!(
            "  = rule: {}  ({})\n",
            v.rule_id(),
            cwes.join(", ")
        ));
    }
    if !v.impact.is_empty() {
        out.push_str(&format!("  = why:  {}\n", v.impact));
    }
    if !v.improvement.is_empty() {
        out.push_str(&format!("  = fix:  {}\n", v.improvement));
    }

    // Observation & taint steps. For taint findings the first line only
    // restates the title, so it is shown for non-dataflow findings, whose
    // observation carries the specific prose.
    let is_taint = v.rule_id().starts_with("taint.");
    let sanitized_obs = crate::engine::project::runner::sanitize_corpus_provenance(&v.observation);
    let mut lines = sanitized_obs.lines();
    if let Some(summary) = lines.next()
        && !is_taint
        && !summary.trim().is_empty()
    {
        out.push_str(&format!("  = note: {}\n", summary.trim()));
    }
    let mut in_path = false;
    let mut step_idx = 0usize;
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "Taint path:" {
            in_path = true;
            out.push_str("  = flow:\n");
            continue;
        }
        if in_path {
            let location = v
                .taint_steps
                .get(step_idx)
                .and_then(|(_, loc)| loc.as_ref())
                .and_then(|(file, byte)| line_for(file, *byte));
            step_idx += 1;
            match location {
                Some(loc) => out.push_str(&format!("      {}  [{loc}]\n", trimmed)),
                None => out.push_str(&format!("      {}\n", trimmed)),
            }
        } else if !trimmed.is_empty() {
            out.push_str(&format!("          {}\n", trimmed));
        }
    }
    out
}

/// Byte offset → 1-based line number for a file, reading it once per call
/// site (advisory counts are small; a global cache is unnecessary).
fn line_for(file: &str, byte_offset: usize) -> Option<String> {
    let source = std::fs::read(file).ok()?;
    let end = byte_offset.min(source.len());
    let line = source[..end].iter().filter(|&&b| b == b'\n').count() + 1;
    let name = std::path::Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.to_string());
    Some(format!("{name}:{line}"))
}

/// Save the current findings as a baseline.
///
/// # Errors
/// Returns an error if the baseline file cannot be written.
pub fn save_baseline(advisories: &[Advisory], path: &str) -> Result<()> {
    let content = serde_json::to_string_pretty(advisories)
        .map_err(|e| FrensenseError::Config(format!("JSON error: {e}")))?;
    std::fs::write(path, content)
        .map_err(|e| FrensenseError::Config(format!("Failed to write baseline: {e}")))?;
    println!("[SUCCESS] Captured baseline to {path}");
    Ok(())
}

/// Compare the current findings against a baseline.
///
/// # Errors
/// Returns an error if the baseline file cannot be read or parsed.
pub fn compare_baseline(advisories: &[Advisory], path: &str) -> Result<bool> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| FrensenseError::Config(format!("Failed to read baseline: {e}")))?;
    let baseline: Vec<Advisory> = serde_json::from_str(&content)
        .map_err(|e| FrensenseError::Config(format!("Failed to parse baseline: {e}")))?;

    // Identity is the semantic fingerprint (file + rule/sink + function
    // + source), stable across line shifts: a finding that moves lines
    // after an unrelated edit is the SAME finding, not a regression.
    // Baselines captured before the fingerprint scheme changed carry
    // line-seeded hashes; those still compare (the hash just never
    // matches after a shift), so the migration path is: regenerate the
    // baseline once, then enjoy shift-stable comparisons.
    let baseline_ids: HashSet<&str> = baseline.iter().map(|a| a.identity()).collect();
    let mut new_advisories: Vec<&Advisory> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    for adv in advisories {
        if baseline_ids.contains(adv.identity()) || !seen.insert(adv.identity()) {
            continue;
        }
        new_advisories.push(adv);
    }

    let regression_detected = !new_advisories.is_empty();
    if regression_detected {
        println!(
            "\n[REGRESSION] {} new advisories detected!",
            new_advisories.len()
        );
        for adv in &new_advisories {
            println!(
                "  + {} {}:{} ({})",
                adv.stable_id(),
                adv.file_path,
                adv.line,
                adv.title
            );
        }
    } else {
        println!("\n[OK] No new advisories compared to baseline.");
    }
    Ok(regression_detected)
}

/// `frensense explain <rule-id>`: what one built-in rule means and how to fix
/// it, rendered from its card so the CLI cannot drift from the report.
///
/// `None` when no built-in rule has that id (the caller exits non-zero);
/// bundle-learned and user policy rules have prose of their own and no card.
#[must_use]
pub fn explain_rule(id: &str) -> Option<String> {
    use frensense_lang::rule_card::{RuleCard, card_by_id, checker_key, cwe_url};

    let card: &RuleCard = card_by_id(id)?;
    let mut out = format!("{}  {}\n", card.id, card.title);
    let cwes: Vec<String> = card
        .cwe
        .iter()
        .map(|c| format!("{c}  {}", cwe_url(c)))
        .collect();
    out.push_str(&format!("  CWE:  {}\n", cwes.join(", ")));
    if let Some(key) = checker_key(card.id) {
        out.push_str(&format!(
            "  tier: {}\n",
            frensense_lang::severity::checker_rule_tier(key).as_str()
        ));
    }
    out.push_str(&format!("  why:  {}\n", card.why));
    out.push_str(&format!("  fix:  {}\n", card.fix));
    Some(out)
}

/// Every built-in rule, one line each: id, CWE, title. Printed by
/// `frensense explain` with no argument so the ids are discoverable without
/// reading the source.
#[must_use]
pub fn rule_index() -> String {
    use frensense_lang::rule_card::all_cards;

    let mut out = String::from("Built-in rules (use `frensense explain <rule-id>`):\n\n");
    for card in all_cards() {
        out.push_str(&format!(
            "  {:<32} {:<18} {}\n",
            card.id,
            card.cwe.join(", "),
            card.title
        ));
    }
    out
}

/// The finding-id form (`policy.redirect-challenge`) of a learned rule's
/// raw name (`policy_redirect_challenge`), mirroring the advisory path in
/// the scan runner so `explain` accepts exactly the id a finding prints.
fn policy_id(rule: &str) -> String {
    format!(
        "policy.{}",
        rule.trim_start_matches("policy_").replace('_', "-")
    )
}

/// Does a learned fact's raw `rule` name answer to the typed id? Accepts
/// the printed form (`policy.foo-bar`) and the raw rule, since users copy
/// whichever they saw.
fn learned_rule_matches(rule: &str, id: &str) -> bool {
    policy_id(rule) == id || rule == id
}

/// One `PolicyRequirement` in prose, for the `requires:` line of a learned
/// policy's card.
fn describe_requirement(
    req: &frensense_engine::analysis::taint::facts::PolicyRequirement,
) -> String {
    use frensense_engine::analysis::taint::facts::PolicyRequirement as R;
    fn quoted(values: &[String]) -> String {
        values
            .iter()
            .map(|v| format!("`{v}`"))
            .collect::<Vec<_>>()
            .join(", ")
    }
    match req {
        R::GuardCall { call } => format!("guard call `{call}` is present"),
        R::NotCall { call } => format!("no call to `{call}`"),
        R::RangeCheck { ops } => {
            format!(
                "an argument is compared to a literal bound ({})",
                ops.join(", ")
            )
        }
        R::RequireCall { any_of } => {
            format!("one of {} is called", quoted(any_of))
        }
        R::BannedArgLiteral { slot, values } => {
            format!("argument {slot} is not one of {}", quoted(values))
        }
        R::RequiredArgLiteral { slot, values } => {
            format!("argument {slot} is one of {}", quoted(values))
        }
        R::RequireArgKey { slot, keys } => {
            let subject = if *slot == usize::MAX {
                "an argument".to_string()
            } else {
                format!("argument {slot}")
            };
            format!("{subject} carries key {}", quoted(keys))
        }
        R::RequireNamedArgLiteral { name, values } => {
            format!("named argument `{name}` is one of {}", quoted(values))
        }
        R::BannedNamedArgLiteral { name, values } => {
            format!("named argument `{name}` is not one of {}", quoted(values))
        }
    }
}

/// `frensense explain <rule-id>` for rules whose knowledge lives in data
/// rather than a card: learned policies/checks and per-family advisory
/// patterns. `None` when no source carries the id (the caller exits 2).
///
/// A learned rule has no built-in card BY DESIGN - its semantics are the
/// trigger, requirements and message the bundle taught - so the bundle that
/// taught it is its documentation. This renders exactly that data; no CWE
/// or prose is invented for a rule that has none.
#[must_use]
pub fn explain_learned_rule(
    id: &str,
    sources: &[(&str, &frensense_bundler::format::LoadedBundle)],
) -> Option<String> {
    use frensense_engine::analysis::taint::facts::{AuthoredPolicyEntry, LearnedFactEntry as E};

    let mut out = String::new();
    for (label, bundle) in sources {
        // Per-family advisory metadata, joined back to findings by
        // `BundlePattern::rules` (the finding identities the family's
        // facts publish).
        for pat in &bundle.patterns {
            let joined = pat.rules.iter().any(|r| r == id);
            if !joined && pat.id != id {
                continue;
            }
            out.push_str(&format!("{id}  Advisory pattern (from {label})\n"));
            if let Some(cwe) = &pat.cwe {
                out.push_str(&format!("  CWE:  {cwe}\n"));
            }
            if let Some(sev) = &pat.severity {
                out.push_str(&format!("  severity: {sev}\n"));
            }
            if let Some(owasp) = &pat.owasp {
                out.push_str(&format!("  owasp: {owasp}\n"));
            }
            if let Some(text) = &pat.observation {
                out.push_str(&format!("  why:  {text}\n"));
            }
            if let Some(text) = &pat.impact {
                out.push_str(&format!("  impact: {text}\n"));
            }
            if let Some(text) = &pat.improvement {
                out.push_str(&format!("  fix:  {text}\n"));
            }
        }

        for fact in &bundle.learned_facts {
            match fact {
                E::Policy {
                    rule,
                    when_call,
                    require,
                    scope,
                    message,
                    severity,
                    ..
                }
                | E::PolicyScoped {
                    rule,
                    when_call,
                    require,
                    scope,
                    message,
                    severity,
                    ..
                } if learned_rule_matches(rule, id) => {
                    out.push_str(&format!(
                        "{}  Learned policy (from {label})\n",
                        policy_id(rule)
                    ));
                    out.push_str(&format!("  severity: {severity}\n"));
                    out.push_str(&format!("  trigger:  call to `{when_call}`\n"));
                    out.push_str(&format!(
                        "  scope:    {}\n",
                        match scope {
                            frensense_engine::analysis::taint::facts::PolicyScope::Function =>
                                "same function",
                            frensense_engine::analysis::taint::facts::PolicyScope::Module =>
                                "any function in the scanned program",
                        }
                    ));
                    if require.is_empty() {
                        out.push_str(
                            "  requires: nothing else - the trigger alone is the violation\n",
                        );
                    } else {
                        let reqs: Vec<String> = require.iter().map(describe_requirement).collect();
                        out.push_str(&format!("  requires: {}\n", reqs.join("; ")));
                    }
                    out.push_str(&format!("  why:  {message}\n"));
                }
                E::Check {
                    rule,
                    call,
                    message,
                    severity,
                    unless_guard,
                    unless_range_check,
                } if learned_rule_matches(rule, id) => {
                    out.push_str(&format!(
                        "{}  Learned check (from {label})\n",
                        policy_id(rule)
                    ));
                    out.push_str(&format!("  severity: {severity}\n"));
                    out.push_str(&format!("  trigger:  call to `{call}`\n"));
                    if let Some(guard) = unless_guard {
                        out.push_str(&format!("  unless:   guard `{guard}` is present\n"));
                    }
                    if let Some(ops) = unless_range_check {
                        out.push_str(&format!(
                            "  unless:   an argument is compared to a literal bound ({})\n",
                            ops.join(", ")
                        ));
                    }
                    out.push_str(&format!("  why:  {message}\n"));
                }
                _ => {}
            }
        }

        // Hand-authored policy entries a bundle may also carry.
        for entry in &bundle.policy_pack {
            match entry {
                AuthoredPolicyEntry::Policy(pf) if learned_rule_matches(&pf.rule, id) => {
                    out.push_str(&format!(
                        "{}  Authored policy (from {label})\n",
                        policy_id(&pf.rule)
                    ));
                    out.push_str(&format!("  severity: {}\n", pf.severity));
                    out.push_str(&format!("  trigger:  call to `{}`\n", pf.when_call));
                    if pf.require.is_empty() {
                        out.push_str(
                            "  requires: nothing else - the trigger alone is the violation\n",
                        );
                    } else {
                        let reqs: Vec<String> =
                            pf.require.iter().map(describe_requirement).collect();
                        out.push_str(&format!("  requires: {}\n", reqs.join("; ")));
                    }
                    out.push_str(&format!("  why:  {}\n", pf.message));
                }
                AuthoredPolicyEntry::IntegerOverflowRule {
                    rule,
                    wrap_threshold,
                    severity,
                    message,
                } if learned_rule_matches(rule, id) => {
                    out.push_str(&format!(
                        "{}  Authored overflow rule (from {label})\n",
                        policy_id(rule)
                    ));
                    out.push_str(&format!("  severity: {severity}\n"));
                    out.push_str(&format!(
                        "  wraps when an operand exceeds {wrap_threshold} (or is unbounded)\n"
                    ));
                    out.push_str(&format!("  why:  {message}\n"));
                }
                _ => {}
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// One line per learned rule a bundle publishes: id, kind+severity, first
/// line of its message. Printed by `frensense explain --list-rules -b
/// <bundle>` so bundle-taught ids are as discoverable as built-in ones.
#[must_use]
pub fn bundle_rule_index(bundle: &frensense_bundler::format::LoadedBundle) -> String {
    use frensense_engine::analysis::taint::facts::LearnedFactEntry as E;

    let mut rows: Vec<(String, String, String)> = Vec::new();
    for pat in &bundle.patterns {
        let message = pat.observation.clone().unwrap_or_default();
        let kind = pat
            .cwe
            .as_deref()
            .map_or_else(|| "advisory".to_string(), |c| format!("advisory, {c}"));
        if pat.rules.is_empty() {
            rows.push((pat.id.clone(), kind, message));
        } else {
            for rule in &pat.rules {
                rows.push((rule.clone(), kind.clone(), message.clone()));
            }
        }
    }
    for fact in &bundle.learned_facts {
        match fact {
            E::Policy {
                rule,
                message,
                severity,
                ..
            }
            | E::PolicyScoped {
                rule,
                message,
                severity,
                ..
            } => rows.push((
                policy_id(rule),
                format!("policy, {severity}"),
                message.clone(),
            )),
            E::Check {
                rule,
                message,
                severity,
                ..
            } => rows.push((
                policy_id(rule),
                format!("check, {severity}"),
                message.clone(),
            )),
            _ => {}
        }
    }
    if rows.is_empty() {
        return String::new();
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.dedup_by(|a, b| a.0 == b.0);

    let mut out = String::from(
        "\nBundle-learned rules (describe one: `frensense explain <rule-id> -b <bundle>`):\n\n",
    );
    for (id, kind, message) in rows {
        let first = message.lines().next().unwrap_or("");
        out.push_str(&format!("  {id:<40} {kind:<24} {first}\n"));
    }
    out
}

#[cfg(test)]
mod explain_rule_tests {
    use super::{explain_rule, rule_index};

    #[test]
    fn explains_a_taint_rule_with_its_cwe_and_advice() {
        let text = explain_rule("taint.sql-injection").expect("card");
        assert!(text.contains("taint.sql-injection"), "{text}");
        assert!(text.contains("CWE-89"), "{text}");
        assert!(
            text.contains("https://cwe.mitre.org/data/definitions/89.html"),
            "{text}"
        );
        assert!(text.contains("bound parameter"), "{text}");
    }

    #[test]
    fn explains_a_checker_rule_with_its_tier() {
        let text = explain_rule("check.weak-hash").expect("card");
        assert!(text.contains("CWE-328"), "{text}");
        assert!(text.contains("tier: stable"), "{text}");
        let hygiene = explain_rule("check.cookie-httponly-missing").expect("card");
        assert!(hygiene.contains("tier: hygiene"), "{hygiene}");
    }

    #[test]
    fn unknown_ids_are_not_invented() {
        assert!(explain_rule("taint.not-a-rule").is_none());
        assert!(explain_rule("policy.my_learned_rule").is_none());
    }

    #[test]
    fn the_index_lists_every_built_in_rule() {
        let index = rule_index();
        for card in frensense_lang::rule_card::all_cards() {
            assert!(index.contains(card.id), "{} missing", card.id);
        }
    }
}

/// Golden shape of the JSON report envelope: the `schema_version` and
/// `producer` identity block are asserted field-by-field so a silent change
/// (a rename, a dropped key, a type change) fails here until
/// `REPORT_SCHEMA_VERSION` and this test move together.
#[cfg(test)]
mod json_report_schema_tests {
    use super::json_report_with_coverage;
    use crate::Advisory;
    use crate::engine::files::UnsupportedSourceFile;
    use frensense_engine::telemetry::{GraphSize, ScanTelemetry, TaintFunnel};
    use std::path::Path;

    fn sorted_keys(obj: &serde_json::Map<String, serde_json::Value>) -> Vec<&str> {
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        keys
    }

    fn adv() -> Advisory {
        Advisory::bare(
            "SQL injection",
            crate::Severity::Critical,
            crate::FileId(0),
            Path::new("app.py"),
            "obs",
        )
    }

    #[test]
    fn envelope_carries_schema_version_and_producer() {
        let report = json_report_with_coverage(&[adv()], &[], None, &[], None);
        assert_eq!(report["schema_version"], crate::REPORT_SCHEMA_VERSION);
        assert_eq!(report["clean"], false);
        assert_eq!(report["advisory_count"], 1);
        assert_eq!(report["advisories"].as_array().unwrap().len(), 1);

        let p = &report["producer"];
        assert_eq!(p["name"], "frensense");
        assert_eq!(p["version"], crate::FRENSENSE_VERSION);
        assert_eq!(p["report_schema"], crate::REPORT_SCHEMA_VERSION);
        let fp = p["fact_vocabulary_fingerprint"].as_str().unwrap();
        assert!(fp.starts_with("0x") && fp.len() == 18, "{fp}");
        assert_eq!(p["default_pack_blake3"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn clean_report_still_has_the_envelope() {
        let report = json_report_with_coverage(&[], &[], None, &[], None);
        assert_eq!(report["clean"], true);
        assert_eq!(report["advisory_count"], 0);
        // The producer block is present even with no findings - a consumer
        // can always attribute the report.
        assert!(report["producer"]["version"].is_string());
    }

    #[test]
    fn analysis_envelope_has_required_keys() {
        let report = json_report_with_coverage(&[], &[], None, &[], None);
        let analysis = &report["analysis"];
        // All top-level keys must be present.
        assert!(analysis["status"].is_string(), "analysis.status missing");
        assert!(
            analysis["coverage"].is_object(),
            "analysis.coverage missing"
        );
        assert!(
            analysis["verdicts"].is_object(),
            "analysis.verdicts missing"
        );
        assert!(
            analysis["truncations"].is_array(),
            "analysis.truncations missing"
        );
        assert!(analysis["checks"].is_array(), "analysis.checks missing");
        assert!(analysis["timings"].is_array(), "analysis.timings missing");
        assert!(
            analysis["slowest_files"].is_array(),
            "analysis.slowest_files missing"
        );
        assert!(
            analysis["slowest_functions"].is_array(),
            "analysis.slowest_functions missing"
        );
        assert!(analysis["graph"].is_object(), "analysis.graph missing");
        assert!(analysis["funnel"].is_object(), "analysis.funnel missing");
    }

    /// Every key a consumer reads the measured graph and taint numbers from,
    /// pinned with its value: a rename, a drop or a type change fails here.
    #[test]
    fn analysis_graph_and_funnel_keys_are_pinned() {
        // 1 + 2 + 0 skipped + 6 unmatched + 2 sinks = 11 examined. Four
        // unmatched came from the constructor, two from `record_unmatched`.
        let mut funnel = TaintFunnel::new(11, (1, 2, 0), 4, 2);
        funnel.record_unmatched("read");
        funnel.record_unmatched("read");
        let telem = ScanTelemetry {
            graph: GraphSize::new(3, 10, 12, 2),
            funnel,
            ..ScanTelemetry::default()
        };

        let report = json_report_with_coverage(&[], &[], Some(&telem), &[], None);
        let analysis = &report["analysis"];

        let graph = analysis["graph"].as_object().expect("analysis.graph");
        assert_eq!(
            sorted_keys(graph),
            ["cross_edges", "edges", "functions", "nodes"]
        );
        assert_eq!(graph["functions"], 3);
        assert_eq!(graph["nodes"], 10);
        assert_eq!(graph["edges"], 12);
        assert_eq!(graph["cross_edges"], 2);

        let funnel = analysis["funnel"].as_object().expect("analysis.funnel");
        assert_eq!(
            sorted_keys(funnel),
            [
                "calls_examined",
                "not_a_sink",
                "sink_calls",
                "skipped_local_callable",
                "skipped_program_local",
                "skipped_receiver_only_verb",
                "unmatched_callees",
            ]
        );
        assert_eq!(funnel["calls_examined"], 11);
        assert_eq!(funnel["skipped_local_callable"], 1);
        assert_eq!(funnel["skipped_program_local"], 2);
        assert_eq!(funnel["skipped_receiver_only_verb"], 0);
        assert_eq!(funnel["not_a_sink"], 6);
        assert_eq!(funnel["sink_calls"], 2);

        let callees = funnel["unmatched_callees"]
            .as_array()
            .expect("analysis.funnel.unmatched_callees");
        assert_eq!(callees.len(), 1, "{report}");
        let entry = callees[0].as_object().expect("unmatched callee entry");
        assert_eq!(sorted_keys(entry), ["callee", "calls"]);
        assert_eq!(entry["callee"], "read");
        assert_eq!(entry["calls"], 2);
    }

    #[test]
    fn analysis_status_reflects_scan_telemetry() {
        // No engine telemetry supplied → legacy API treats it as complete.
        let report = json_report_with_coverage(&[], &[], None, &[], None);
        assert_eq!(report["analysis"]["status"], "complete");

        // With a partial-parse file recorded → Partial.
        let mut telem = ScanTelemetry::default();
        telem.input.scanned = 1;
        telem.input.parse_partial = 1;
        telem.input.parse_partial_files.push("bad.py".into());
        let report = json_report_with_coverage(&[], &[], Some(&telem), &[], None);
        assert_eq!(report["analysis"]["status"], "partial");
    }

    #[test]
    fn coverage_names_unsupported_source_languages() {
        let skipped = vec![
            UnsupportedSourceFile {
                path: "src/a.rb".into(),
                language: "Ruby",
            },
            UnsupportedSourceFile {
                path: "src/b.rb".into(),
                language: "Ruby",
            },
            UnsupportedSourceFile {
                path: "web/App.java".into(),
                language: "Java",
            },
        ];
        let report = json_report_with_coverage(&[], &[], None, &skipped, None);
        let coverage = &report["analysis"]["coverage"]["unsupported_source_files"];
        assert_eq!(coverage["count"], 3);
        assert_eq!(coverage["languages"][0]["language"], "Ruby");
        assert_eq!(coverage["languages"][0]["files"], 2);
        assert_eq!(coverage["languages"][1]["language"], "Java");
        assert_eq!(coverage["files"][0], "src/a.rb");
    }

    #[test]
    fn reports_without_skips_keep_an_empty_unsupported_object() {
        let report = json_report_with_coverage(&[], &[], None, &[], None);
        let coverage = &report["analysis"]["coverage"]["unsupported_source_files"];
        assert_eq!(coverage["count"], 0);
        assert_eq!(coverage["languages"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn coverage_denominator_counts_unsupported_sources_and_blocks_clean() {
        let mut telem = frensense_engine::telemetry::ScanTelemetry::default();
        telem.input.submitted = 1;
        telem.input.scanned = 1;
        let skipped = vec![UnsupportedSourceFile {
            path: "worker.rb".into(),
            language: "Ruby",
        }];
        let coverage = crate::policy::Coverage {
            files_found: 2,
            files_analyzed: 1,
            files_unsupported: 1,
            files_with_sink_sites: 1,
            sink_sites: 1,
            ..crate::policy::Coverage::default()
        };
        let report = json_report_with_coverage(&[], &[], Some(&telem), &skipped, Some(&coverage));
        let c = &report["analysis"]["coverage"];
        assert_eq!(c["files_found"], 2, "{report}");
        assert_eq!(c["files_not_analyzed"], 1, "{report}");
        assert_eq!(c["files_unsupported"], 1, "{report}");
        assert_eq!(
            report["analysis"]["clean"], false,
            "a source file left unanalyzed is not clean: {report}"
        );
    }
}

#[cfg(test)]
mod scan_status_tests {
    use super::ScanStatus;
    use frensense_engine::{scan::IncompleteFunction, telemetry::ScanTelemetry};

    fn incomplete(name: &str) -> IncompleteFunction {
        IncompleteFunction {
            function: name.to_string(),
            file: "f.rs".to_string(),
        }
    }

    #[test]
    fn complete_on_clean_zero_files() {
        let telem = ScanTelemetry::default();
        assert_eq!(ScanStatus::compute(&telem, &[]), ScanStatus::Complete);
    }

    fn clean_coverage() -> crate::policy::Coverage {
        crate::policy::Coverage {
            files_found: 1,
            files_analyzed: 1,
            files_with_sink_sites: 1,
            sink_sites: 1,
            ..crate::policy::Coverage::default()
        }
    }

    #[test]
    fn clean_requires_every_recognized_site_decided() {
        let mut coverage = clean_coverage();
        assert!(ScanStatus::Complete.clean(true, &coverage));
        coverage.unresolved_sites = 1;
        assert!(
            !ScanStatus::Complete.clean(true, &coverage),
            "an undecided sink site is not clean"
        );
    }

    #[test]
    fn clean_requires_every_found_file_analyzed() {
        let mut coverage = clean_coverage();
        coverage.files_found = 2;
        coverage.files_unsupported = 1;
        assert!(
            !ScanStatus::Complete.clean(true, &coverage),
            "a file never analyzed is not clean"
        );
    }

    #[test]
    fn clean_still_requires_no_findings_and_a_complete_status() {
        let coverage = clean_coverage();
        assert!(!ScanStatus::Partial.clean(true, &coverage));
        assert!(!ScanStatus::Complete.clean(false, &coverage));
    }

    #[test]
    fn status_label_flags_findings_dropped_below_confidence() {
        use frensense_engine::telemetry::SuppressionCount;
        let mut telem = ScanTelemetry::default();
        telem.suppressed.push(SuppressionCount {
            reason: "below-confidence".to_string(),
            count: 2,
        });
        let coverage = clean_coverage();
        let label = super::status_label(ScanStatus::Complete, 0, Some(&coverage), Some(&telem));
        assert!(
            label.contains("dropped below confidence"),
            "got label: {label}"
        );
    }

    #[test]
    fn complete_when_telemetry_is_clean_and_no_incomplete_functions() {
        let mut telem = ScanTelemetry::default();
        telem.input.scanned = 5;
        assert_eq!(ScanStatus::compute(&telem, &[]), ScanStatus::Complete);
    }

    #[test]
    fn partial_when_incomplete_functions_present() {
        let telem = ScanTelemetry::default();
        assert_eq!(
            ScanStatus::compute(&telem, &[incomplete("fn_a")]),
            ScanStatus::Partial
        );
    }

    #[test]
    fn partial_when_parse_partial_files_present() {
        let mut telem = ScanTelemetry::default();
        telem.input.scanned = 1;
        telem.input.parse_partial = 1;
        telem.input.parse_partial_files.push("bad.ts".into());
        assert_eq!(ScanStatus::compute(&telem, &[]), ScanStatus::Partial);
    }

    #[test]
    fn failed_when_all_submitted_inputs_fail() {
        let mut telem = ScanTelemetry::default();
        telem.input.submitted = 1;
        telem.input.failed = 1;
        telem.input.failed_files.push("crash.c".into());
        assert_eq!(ScanStatus::compute(&telem, &[]), ScanStatus::Failed);
    }

    #[test]
    fn failed_when_inputs_were_submitted_but_none_scanned() {
        let mut telem = ScanTelemetry::default();
        telem.input.submitted = 2;
        telem.input.failed = 1;
        telem.input.failed_files.push("crash.c".into());
        assert_eq!(ScanStatus::compute(&telem, &[]), ScanStatus::Failed);
    }

    #[test]
    fn partial_when_some_inputs_failed_but_others_scanned() {
        let mut telem = ScanTelemetry::default();
        telem.input.submitted = 2;
        telem.input.scanned = 1;
        telem.input.failed = 1;
        assert_eq!(ScanStatus::compute(&telem, &[]), ScanStatus::Partial);
    }
}

#[cfg(test)]
mod explain_learned_rule_tests {
    use super::{bundle_rule_index, explain_learned_rule};
    use frensense_bundler::format::{BundleHeader, LoadedBundle};
    use frensense_engine::analysis::taint::facts::{
        LearnedFactEntry, PolicyRequirement, PolicyScope,
    };

    /// A hand-built bundle carrying one learned policy (raw rule name), one
    /// check, and one advisory pattern joined to a sink name - enough to
    /// exercise every learned card shape.
    fn bundle() -> LoadedBundle {
        LoadedBundle {
            header: BundleHeader {
                magic: *frensense_bundler::format::BUNDLE_MAGIC,
                version: 6,
                pattern_count: 1,
                checksum: [0; 32],
                // v6 header: pre-Phase-6, so no compatibility metadata.
                vocabulary: None,
                requires_engine: None,
                built_by_engine: None,
                trust: frensense_bundler::format::BundleTrust::Community,
            },
            sanitizer_scopes: Vec::new(),
            policy_meta: Vec::new(),
            patterns: vec![frensense_bundler::format::BundlePattern {
                id: "family-sqli".to_string(),
                observation: Some("raw query string reaches the driver".to_string()),
                impact: Some("full database read".to_string()),
                improvement: Some("use a bound parameter".to_string()),
                cwe: Some("CWE-89".to_string()),
                cvss: None,
                owasp: None,
                severity: Some("Critical".to_string()),
                rules: vec!["pg_query_raw".to_string()],
            }],
            learned_facts: vec![
                LearnedFactEntry::Policy {
                    rule: "policy_redirect_challenge".to_string(),
                    when_call: "redirect".to_string(),
                    require: vec![PolicyRequirement::GuardCall {
                        call: "challenge_ok".to_string(),
                    }],
                    scope: PolicyScope::Function,
                    message: "open redirects bypass the challenge".to_string(),
                    severity: "warning".to_string(),
                },
                LearnedFactEntry::Check {
                    rule: "policy_weak_cookie_flag".to_string(),
                    call: "set_cookie".to_string(),
                    message: "session cookies need Secure".to_string(),
                    severity: "info".to_string(),
                    unless_guard: Some("secure_flag".to_string()),
                    unless_range_check: None,
                },
            ],
            policy_pack: Vec::new(),
        }
    }

    fn sources(bundle: &LoadedBundle) -> Vec<(&str, &LoadedBundle)> {
        vec![("test bundle", bundle)]
    }

    #[test]
    fn explains_a_learned_policy_by_its_printed_id() {
        let b = bundle();
        let text = explain_learned_rule("policy.redirect-challenge", &sources(&b)).expect("card");
        assert!(text.contains("Learned policy"), "{text}");
        assert!(text.contains("`redirect`"), "{text}");
        assert!(text.contains("challenge_ok"), "{text}");
        assert!(text.contains("open redirects"), "{text}");
        assert!(text.contains("same function"), "{text}");
        assert!(text.contains("test bundle"), "{text}");
    }

    #[test]
    fn explains_a_learned_policy_by_its_raw_rule_name() {
        let b = bundle();
        let text = explain_learned_rule("policy_redirect_challenge", &sources(&b)).expect("card");
        assert!(text.contains("policy.redirect-challenge"), "{text}");
    }

    #[test]
    fn explains_a_learned_check_with_its_unless_guard() {
        let b = bundle();
        let text = explain_learned_rule("policy.weak-cookie-flag", &sources(&b)).expect("card");
        assert!(text.contains("Learned check"), "{text}");
        assert!(text.contains("secure_flag"), "{text}");
        assert!(text.contains("session cookies"), "{text}");
    }

    #[test]
    fn explains_an_advisory_pattern_by_its_joined_sink_rule() {
        let b = bundle();
        let text = explain_learned_rule("pg_query_raw", &sources(&b)).expect("card");
        assert!(text.contains("Advisory pattern"), "{text}");
        assert!(text.contains("CWE-89"), "{text}");
        assert!(text.contains("bound parameter"), "{text}");
    }

    #[test]
    fn unknown_ids_stay_none_even_with_a_bundle() {
        let b = bundle();
        assert!(explain_learned_rule("policy.not_taught", &sources(&b)).is_none());
        assert!(explain_learned_rule("taint.sql-injection", &sources(&b)).is_none());
    }

    #[test]
    fn the_bundle_index_lists_each_learned_rule_once() {
        let b = bundle();
        let index = bundle_rule_index(&b);
        assert!(index.contains("policy.redirect-challenge"), "{index}");
        assert!(index.contains("policy.weak-cookie-flag"), "{index}");
        assert!(index.contains("pg_query_raw"), "{index}");
        assert!(index.contains("CWE-89"), "{index}");
        assert_eq!(
            index
                .lines()
                .filter(|l| l.contains("policy.redirect-challenge"))
                .count(),
            1,
            "{index}"
        );
    }

    #[test]
    fn an_empty_bundle_indexes_nothing() {
        let mut b = bundle();
        b.patterns.clear();
        b.learned_facts.clear();
        assert!(bundle_rule_index(&b).is_empty());
    }
}

#[cfg(test)]
mod stage_report_tests {
    use super::{render_funnel, render_stages};
    use frensense_engine::telemetry::{
        GraphSize, PhaseTiming, ScanTelemetry, SuppressionCount, TaintFunnel,
    };

    /// Collapse runs of whitespace so column alignment is not asserted.
    fn squash(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn telemetry() -> ScanTelemetry {
        let phase = |name: &str, ms| PhaseTiming {
            phase: name.to_string(),
            ms,
        };
        let mut t = ScanTelemetry {
            phases: vec![
                phase("lower", 12),
                phase("graph", 4),
                phase("checks", 2),
                phase("taint", 7),
            ],
            ..ScanTelemetry::default()
        };
        t.input.submitted = 14;
        t.input.scanned = 13;
        t.input.failed = 1;
        t.input.functions = 25;
        t.graph = GraphSize::new(25, 760, 865, 4);
        // 3 local callable + 2 program-local + 2 receiver-only + 40 matched
        // no sink + 25 armed a sink = 72 examined. Three of the 40 were
        // recorded by name (`read` twice, `noop` once).
        t.funnel = TaintFunnel::new(72, (3, 2, 2), 37, 25);
        t.funnel.record_unmatched("read");
        t.funnel.record_unmatched("read");
        t.funnel.record_unmatched("noop");
        t.taint.sink_args_explored = 30;
        t.taint.vulnerable = 1;
        t.suppressed = vec![SuppressionCount {
            reason: "not-reportable".to_string(),
            count: 15,
        }];
        t
    }

    #[test]
    fn the_stage_ledger_has_one_line_per_stage() {
        let text = render_stages(&telemetry(), 3);
        for needle in [
            "parse+lower 12 ms 14 file(s) given, 13 lowered, 1 failed -> 25 function(s)",
            "graph 4 ms 25 function(s), 760 value-flow node(s), 865 edge(s), 4 cross-function edge(s)",
            "taint 7 ms 72 call(s) -> 25 sink call(s) -> 30 argument(s) walked (1 vulnerable)",
            "report 3 reported, 15 dropped at the reporting gate",
        ] {
            assert!(
                squash(&text).contains(&squash(needle)),
                "missing `{needle}` in:\n{text}"
            );
        }
    }

    #[test]
    fn the_funnel_partitions_the_call_sites() {
        let telem = telemetry();
        let text = render_funnel(&telem);
        assert_eq!(
            telem.funnel.calls_examined,
            telem.funnel.skipped() + telem.funnel.not_a_sink + telem.funnel.sink_calls,
            "the counters must partition the call sites"
        );
        for needle in [
            "Pipeline: where 72 call(s) left the engine",
            "skipped before matching 7 (local callable 3, program-local callee 2, receiver-only verb 2)",
            "matched no sink fact 40",
            "most-called callees with no sink fact (2 name(s) tracked, busiest first): read 2 noop 1",
            "matched a sink fact 25",
            "reporting gate: not-reportable 15",
        ] {
            assert!(
                squash(&text).contains(&squash(needle)),
                "missing `{needle}` in:\n{text}"
            );
        }
    }
}
