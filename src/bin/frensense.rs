// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
#![warn(clippy::unwrap_used)]

//! The frensense CLI: collect files → compiler scan → report.

use frensense::cli::{
    CliOptions, compare_baseline, get_input_paths, parse_options, print_results, save_baseline,
};
use frensense::engine::Engine;
use frensense::{FRENSENSE_VERSION, Result};

fn print_help() {
    println!("Frensense v{FRENSENSE_VERSION}, deterministic dataflow security scanner.");
    println!();
    println!("Usage: frensense [path] [options]");
    println!("       frensense watch [path] [options]   Re-scan on file changes, print new findings");
    println!();
    println!("Options:");
    println!("  --json                     Output findings as JSON");
    println!("  --sarif                    Output findings in SARIF format");
    println!("  --github                   GitHub Actions annotations (::error/::warning/::notice)");
    println!("  --strict                   Exit with code 1 if any findings");
    println!("  --severity <level>         Minimum severity: critical, warning, info");
    println!("  --language <lang>          Language filter (rust, typescript, javascript, python)");
    println!("  --min-confidence <0-1>     Minimum confidence threshold");
    println!("  --corpus-bundle <file>     .frc bundle whose learned facts teach the engine");
    println!("  --diff-only                Only scan files changed since the last git commit");
    println!("  --emit-baseline <file>     Save current findings as a baseline");
    println!("  --compare-baseline <file>  Fail on new findings vs. baseline");
}

fn handle_early_args(args: &[String]) -> bool {
    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        std::process::exit(0);
    }
    if args.iter().any(|a| a == "--version") {
        println!("frensense {FRENSENSE_VERSION}");
        std::process::exit(0);
    }
    false
}

/// Watch mode entry: parse the remaining args like a one-shot scan, build
/// the engine from the same options, then enter the poll loop. Ctrl-C
/// kills the process (default handler); `should_stop` here also honors a
/// stop-file (`frensense-watch.stop` in the watched root) so scripts and
/// tests can end the loop deterministically.
fn run_watch(args: Vec<String>) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let input_paths = get_input_paths(&args);
    let input_path = input_paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let options: CliOptions = parse_options(&args);

    let language_filter: Option<Vec<&'static str>> = options
        .language_filter
        .as_ref()
        .and_then(|l| frensense::parser::extensions_for(l))
        .map(|exts| exts.to_vec());
    let corpus_bundle = options.corpus_bundle_path.clone();
    let severity = options.severity_filter;
    let min_confidence = options.min_confidence;

    // Stop-file: polled by a detached thread, lets scripts/tests end the
    // loop deterministically without signaling machinery. SIGINT keeps the
    // default handler (process exit).
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_file = input_path.join("frensense-watch.stop");
    {
        let stop_flag = Arc::clone(&stop_flag);
        std::thread::spawn(move || loop {
            if stop_file.exists() {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = std::fs::remove_file(&stop_file);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
    }

    let root = input_path;
    let stop = Arc::new(AtomicBool::new(false));
    frensense::cli::run_watch_loop(
        &root,
        language_filter.as_ref(),
        || {
            let mut engine = frensense::engine::Engine::new();
            if let Some(ref p) = corpus_bundle {
                engine.set_corpus_bundle_path(p.clone());
            }
            engine.set_severity_filter(severity);
            engine.set_min_confidence(min_confidence);
            engine
        },
        |engine, path| engine.run(path),
        || stop.load(Ordering::SeqCst) || stop_flag.load(Ordering::SeqCst),
    )
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if handle_early_args(&args) {
        return Ok(());
    }

    // Watch subcommand: poll-loop delivery mode, everything else shared
    // with the one-shot path (same options, same engine config).
    if args.iter().any(|a| a == "watch") {
        return run_watch(
            args.iter()
                .filter(|a| a.as_str() != "watch")
                .cloned()
                .collect::<Vec<_>>(),
        );
    }

    let input_paths = get_input_paths(&args);
    let input_path = input_paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let options: CliOptions = parse_options(&args);

    let mut engine = Engine::new();
    if let Some(ref path) = options.corpus_bundle_path {
        engine.set_corpus_bundle_path(path.clone());
    }
    if let Some(ref lang) = options.language_filter
        && let Some(exts) = frensense::parser::extensions_for(lang)
    {
        engine.set_language_filter(exts.to_vec());
    }
    engine.set_severity_filter(options.severity_filter);
    engine.set_min_confidence(options.min_confidence);

    let advisories = if options.diff_only {
        let repo_dir = if input_path.is_dir() {
            input_path.clone()
        } else {
            input_path.parent().unwrap_or(&input_path).to_path_buf()
        };
        let output = std::process::Command::new("git")
            .args(["diff", "--name-only", "HEAD"])
            .current_dir(&repo_dir)
            .output()
            .map_err(|e| frensense::FrensenseError::Config(format!("git diff failed: {e}")))?;
        if !output.status.success() {
            return Err(frensense::FrensenseError::Config(format!(
                "git diff failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let diff_files: Vec<std::path::PathBuf> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| repo_dir.join(l))
            .filter(|p| frensense::parser::is_supported(p))
            .collect();
        if diff_files.is_empty() {
            eprintln!("No changed files to scan.");
            Vec::new()
        } else {
            eprintln!(
                "Diff-only: scanning {} changed file(s)...",
                diff_files.len()
            );
            // Diff mode: scan each changed file individually.
            let mut all = Vec::new();
            for f in &diff_files {
                let mut e2 = Engine::new();
                if let Some(ref path) = options.corpus_bundle_path {
                    e2.set_corpus_bundle_path(path.clone());
                }
                all.extend(e2.run(f)?);
            }
            all
        }
    } else {
        // Scan every positional input path; findings merge across them.
        let mut all = Vec::new();
        for p in &input_paths {
            all.extend(engine.run(p)?);
        }
        all
    };

    print_results(&advisories, &options.format, &input_path)?;

    if let Some(path) = &options.emit_baseline_path {
        save_baseline(&advisories, path)?;
    }

    let mut regression_detected = false;
    if let Some(path) = &options.compare_baseline_path {
        regression_detected = compare_baseline(&advisories, path)?;
    }

    if regression_detected || (options.is_strict && !advisories.is_empty()) {
        std::process::exit(1);
    }

    Ok(())
}
