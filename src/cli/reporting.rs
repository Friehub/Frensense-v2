// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::options::CliOptions;
use crate::explain::ExplainRecord;
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
        "Clean"
    } else {
        "Findings reported"
    };
    println!("Status:             {status_label}");
    if let Some(out) = output_path {
        println!("Report File:        {}", out.display());
    }
    println!("========================================================================");
}

/// The JSON report envelope: `schema_version` + `producer` identity block,
/// then the finding payload.
///
/// Extracted so the shape is testable (and golden-assertable) without a
/// filesystem. Bump [`crate::REPORT_SCHEMA_VERSION`] when a key here is
/// renamed, removed, or changes type.
#[must_use]
pub fn json_report(advisories: &[Advisory]) -> serde_json::Value {
    serde_json::json!({
        "schema_version": crate::REPORT_SCHEMA_VERSION,
        "producer": crate::identity::producer(),
        "clean": advisories.is_empty(),
        "advisory_count": advisories.len(),
        "advisories": advisories,
    })
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
            let rendered = serde_json::to_string_pretty(&json_report(advisories))
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
            "  {:<14} {}:{}  {}(arg {})",
            r.verdict, r.file, r.line, r.sink, r.arg_slot
        );
        eprintln!("      why: {}", r.reason);
        if let Some(src) = &r.source_desc {
            eprintln!("      source: {src}");
        }
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

/// Apply CLI filters to advisories.
pub fn apply_filters(advisories: &mut [Advisory], options: &CliOptions) {
    let _ = (advisories, options);
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
    use super::json_report;
    use crate::Advisory;
    use std::path::Path;

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
        let report = json_report(&[adv()]);
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
        let report = json_report(&[]);
        assert_eq!(report["clean"], true);
        assert_eq!(report["advisory_count"], 0);
        // The producer block is present even with no findings - a consumer
        // can always attribute the report.
        assert!(report["producer"]["version"].is_string());
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
            },
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
