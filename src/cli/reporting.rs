// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::options::CliOptions;
use crate::reporter::Reporter;
use crate::{Advisory, FrensenseError, Result};
use std::collections::HashSet;

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

/// Print a structured scan summary block.
pub fn print_scan_summary(
    advisories: &[Advisory],
    input_path: &std::path::Path,
    duration: std::time::Duration,
    output_path: Option<&std::path::Path>,
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

    println!("============================= Scan Summary =============================");
    println!("Target:             {}", input_path.display());
    println!("Scan Duration:      {:.2}s", duration.as_secs_f64());
    println!("Findings Breakdown:");
    println!("  - Critical:       {critical}");
    println!("  - Warning:        {warning}");
    println!("  - Info:           {info}");
    println!("Total Findings:     {}", advisories.len());
    let status_label = if advisories.is_empty() {
        "PASSED (Clean)"
    } else {
        "FAILED (Security gate violated)"
    };
    println!("Security Gate:      {status_label}");
    if let Some(out) = output_path {
        println!("Report File:        {}", out.display());
    }
    println!("========================================================================");
}

/// Print results in the requested format.
///
/// If `output_path` is provided, writes the formatted report to that destination
/// and prints status summary to stdout.
///
/// # Errors
/// Returns an error if serialization or file writing fails.
pub fn print_results(
    advisories: &[Advisory],
    format: &str,
    input_path: &std::path::Path,
    duration: Option<std::time::Duration>,
    output_path: Option<&std::path::Path>,
) -> Result<()> {
    match format {
        "json" => {
            let wrapper = serde_json::json!({
                "clean": advisories.is_empty(),
                "advisory_count": advisories.len(),
                "advisories": advisories,
            });
            let rendered = serde_json::to_string_pretty(&wrapper)
                .map_err(|e| FrensenseError::Config(format!("JSON error: {e}")))?;
            if let Some(out) = output_path {
                std::fs::write(out, rendered).map_err(|e| {
                    FrensenseError::Config(format!(
                        "Failed to write report to {}: {e}",
                        out.display()
                    ))
                })?;
                if let Some(d) = duration {
                    print_scan_summary(advisories, input_path, d, Some(out));
                }
                println!("JSON report written to: {}", out.display());
            } else {
                println!("{rendered}");
            }
        }
        "sarif" => {
            let sarif = Reporter::to_sarif(advisories, input_path);
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
                    print_scan_summary(advisories, input_path, d, Some(out));
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
                    print_scan_summary(advisories, input_path, d, Some(out));
                }
                println!("GitHub annotations written to: {}", out.display());
            } else {
                print!("{rendered}");
            }
        }
        _ => {
            let cwd = std::env::current_dir().ok();
            if let Some(out) = output_path {
                let mut buf = Vec::new();
                if advisories.is_empty() {
                    buf.extend_from_slice(b"Analysis Complete: No findings.\n");
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
                    print_scan_summary(advisories, input_path, d, Some(out));
                }
                println!("Text report written to: {}", out.display());
            } else {
                if advisories.is_empty() {
                    println!("Analysis Complete: No findings.");
                    if let Some(d) = duration {
                        println!();
                        print_scan_summary(advisories, input_path, d, None);
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
                        print_scan_summary(advisories, input_path, d, None);
                    }
                }
            }
        }
    }
    Ok(())
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

    // Observation & Taint Steps
    let sanitized_obs = crate::engine::project::runner::sanitize_corpus_provenance(&v.observation);
    let mut lines = sanitized_obs.lines();
    if let Some(summary) = lines.next() {
        out.push_str(&format!("  Details:     {}\n", summary.trim()));
    }
    let mut in_path = false;
    let mut step_idx = 0usize;
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "Taint path:" {
            in_path = true;
            out.push_str("  Taint Flow:\n");
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
                Some(loc) => out.push_str(&format!("    {}  [{loc}]\n", trimmed)),
                None => out.push_str(&format!("    {}\n", trimmed)),
            }
        } else if !trimmed.is_empty() {
            out.push_str(&format!("               {}\n", trimmed));
        }
    }

    out.push_str(&format!("  Impact:      {}\n", v.impact));
    out.push_str(&format!("  Remediation: {}\n", v.improvement));
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

/// Apply CLI filters to advisories.
pub fn apply_filters(advisories: &mut [Advisory], options: &CliOptions) {
    let _ = (advisories, options);
}
