// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! `capabilities` and `probe`: the engine-as-decider command surface.
//!
//! Both are read-only: `capabilities` reports what the shipped fact table can
//! model, `probe` says whether one corpus family lies inside that model. The
//! reports themselves are built in `frensense::cli`; this module owns argv,
//! printing and exit codes.
//!
//! Output goes through [`out`]/[`err`] rather than `println!`: a closed pipe
//! (`frensense capabilities | head`) must not panic the process, and the
//! binary keeps its print-site count where the lint ratchet expects it.

use std::io::Write as _;

/// Write one line to stdout, ignoring a closed pipe.
fn out(text: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{text}");
}

/// Write one line to stderr, ignoring a closed pipe.
fn err(text: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{text}");
}

const CAPABILITIES_USAGE: &str = "\
Usage: frensense capabilities [options]

Report what the engine can model, without scanning anything: the embedded
default pack's sinks, sources, sanitizers and propagators per language, the
built-in class catalogue with its CWE ids, and which CWEs a built-in card can
express at all. This is the deciding input for corpus curation: a family
whose sink call is not here cannot teach the engine anything.

Options:
  --json          machine-readable report on stdout
  --cwe <id>      print only this CWE's expressibility and exit
  -h, --help      this help";

const PROBE_USAGE: &str = "\
Usage: frensense probe <family_dir> [options]

Scan one corpus family's training pair under the shipped fact table and
report which sink models matched, whether a path was found, and what blocked
it (the engine's own --explain verdict, cut reasons and cut sites). Ends in
one disposition: class-not-expressible, no-sink-recognised,
no-source-recognised, flow-not-proven, sanitized-before-sink,
fact-does-not-separate, or separated.

Exits 0 when the engine separates the pair, 1 when it does not (the family
needs a fix, a vocabulary row, or a ledger entry), 2 on a usage error.

Options:
  -b, --bundle <file.frc>  also load this bundle
  --json                   machine-readable report on stdout
  -h, --help               this help";

pub(crate) fn handle_capabilities(args: &[String]) -> i32 {
    let mut json = false;
    let mut cwe: Option<String> = None;
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                out(CAPABILITIES_USAGE);
                return 0;
            }
            "--cwe" => match it.next() {
                Some(value) => cwe = Some(value.clone()),
                None => {
                    err(&format!(
                        "Error: missing value for --cwe\n{CAPABILITIES_USAGE}"
                    ));
                    return 2;
                }
            },
            other => {
                err(&format!(
                    "Error: unknown argument: {other}\n{CAPABILITIES_USAGE}"
                ));
                return 2;
            }
        }
    }

    let report = frensense::cli::capabilities::report();
    if let Some(cwe) = cwe {
        let entry = frensense::cli::capabilities::cwe_entry(&report, &cwe);
        if json {
            match serde_json::to_string_pretty(&entry) {
                Ok(text) => out(&text),
                Err(e) => {
                    err(&format!("Error: {e}"));
                    return 2;
                }
            }
        } else {
            out(&render_cwe_entry(&entry));
        }
        return 0;
    }

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => out(&text),
            Err(e) => {
                err(&format!("Error: {e}"));
                return 2;
            }
        }
    } else {
        let rendered = frensense::cli::capabilities::render(&report);
        let mut stdout = std::io::stdout().lock();
        let _ = write!(stdout, "{rendered}");
    }
    0
}

/// One line for `--cwe`: either where it is expressible, or why it is not.
fn render_cwe_entry(entry: &serde_json::Value) -> String {
    let cwe = entry
        .get("cwe")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    if entry
        .get("expressible")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        let via = entry
            .get("via")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let class = entry
            .get("class")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(via);
        let role = entry
            .get("role")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        format!("{cwe}: expressible via {class} (role {role})")
    } else {
        let reason = entry
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("not expressible");
        format!("{cwe}: not expressible - {reason}")
    }
}

pub(crate) fn handle_probe(args: &[String]) -> i32 {
    let mut json = false;
    let mut bundle: Option<std::path::PathBuf> = None;
    let mut family: Option<std::path::PathBuf> = None;
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                out(PROBE_USAGE);
                return 0;
            }
            "-b" | "--bundle" => match it.next() {
                Some(value) => bundle = Some(std::path::PathBuf::from(value)),
                None => {
                    err(&format!("Error: missing value for {arg}\n{PROBE_USAGE}"));
                    return 2;
                }
            },
            other if other.starts_with('-') => {
                err(&format!("Error: unknown argument: {other}\n{PROBE_USAGE}"));
                return 2;
            }
            other => {
                if family.is_some() {
                    err(&format!(
                        "Error: unexpected extra argument: {other}\n{PROBE_USAGE}"
                    ));
                    return 2;
                }
                family = Some(std::path::PathBuf::from(other));
            }
        }
    }
    let Some(family) = family else {
        err(&format!("Error: missing <family_dir>\n{PROBE_USAGE}"));
        return 2;
    };

    match frensense::cli::probe::probe(&family, bundle.as_deref()) {
        Ok(report) => {
            if json {
                match serde_json::to_string_pretty(&report.to_json()) {
                    Ok(text) => out(&text),
                    Err(e) => {
                        err(&format!("Error: {e}"));
                        return 2;
                    }
                }
            } else {
                let rendered = report.render();
                let mut stdout = std::io::stdout().lock();
                let _ = write!(stdout, "{rendered}");
            }
            i32::from(!report.verdict.accepted())
        }
        Err(e) => {
            err(&format!("Probe error: {e}"));
            2
        }
    }
}
