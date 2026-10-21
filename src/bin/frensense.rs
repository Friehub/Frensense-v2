// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
#![warn(clippy::unwrap_used)]

//! The frensense CLI: collect files → compiler scan → report.

use frensense::cli::{
    compare_baseline, parse_options, print_explain, print_results, print_scan_banner, save_baseline,
};
use frensense::engine::Engine;
use frensense::{FRENSENSE_VERSION, Result};
use frensense_engine::analysis::taint::facts::LearnedFactEntry;

/// Tokens of an `explain` invocation: the rule id (if any), the bundle
/// path (if any), and whether the rule index was requested. Pure so the
/// subcommand/flag resolution is testable without a filesystem.
///
/// Both spellings parse alike: the subcommand form (`frensense explain
/// <rule-id> -b <bundle>`) and the flag form (`--explain-rule <id>` /
/// `--list-rules`), which cannot collide with a scan path.
#[derive(Debug, PartialEq)]
struct ExplainArgs {
    id: Option<String>,
    bundle: Option<std::path::PathBuf>,
    list: bool,
}

fn parse_explain_args(args: &[String]) -> ExplainArgs {
    let subcommand = args.get(1).map(String::as_str) == Some("explain");
    let mut out = ExplainArgs {
        id: None,
        bundle: None,
        list: args.iter().any(|a| a == "--list-rules"),
    };
    // Skip the program name, and the `explain` token in subcommand form;
    // a positional is only an id there - a plain scan's path is not.
    let start = if subcommand { 2 } else { 1 };
    let mut it = args.iter().skip(start);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-b" | "--bundle" | "--corpus-bundle" => {
                if let Some(val) = it.next()
                    && out.bundle.is_none()
                {
                    out.bundle = Some(std::path::PathBuf::from(val));
                }
            }
            "--explain-rule" => {
                if out.id.is_none()
                    && let Some(val) = it.next()
                {
                    out.id = Some(val.clone());
                }
            }
            "--list-rules" => {}
            other if subcommand && !other.starts_with('-') && out.id.is_none() => {
                out.id = Some(other.to_string());
            }
            _ => {}
        }
    }
    out
}

/// Outcome of `frensense explain ...` argument handling.
enum ExplainOutcome {
    /// Not an explain invocation: continue with normal option parsing.
    NotApplicable,
    /// Explained (or listed) rules; done.
    Handled,
    /// `explain` resolved to a filesystem path (a directory literally named
    /// `explain`, or an unknown-rule argument that names a real path):
    /// rescan with these arguments instead.
    ScanInstead(Vec<String>),
}

/// `frensense explain [<rule-id>]`, plus the flag forms `--list-rules` and
/// `--explain-rule <id>` (unambiguous even when a path named `explain`
/// exists). `-b <bundle>` (also `--bundle`/`--corpus-bundle`) teaches
/// `explain` the bundle's learned and policy rules, which have no built-in
/// card by design - their knowledge lives in the bundle, so the bundle is
/// their documentation. Unknown ids exit 2: they are typed by hand and a
/// silent fallback would report confidence in a rule that does not exist.
///
/// Subcommand resolution: a rule id wins over a same-named path (paths can
/// be disambiguated with `./`); with no rule id, a path literally named
/// `explain` wins and gets scanned, and the rule index stays reachable via
/// `--list-rules`.
fn handle_explain_command(args: &[String]) -> ExplainOutcome {
    let parsed = parse_explain_args(args);
    let subcommand = args.get(1).map(String::as_str) == Some("explain");
    let flag_form = args
        .iter()
        .any(|a| a == "--list-rules" || a == "--explain-rule");
    if !subcommand && !flag_form {
        return ExplainOutcome::NotApplicable;
    }

    // The bundle (user-supplied) documents learned rules; the embedded
    // default pack documents the ones every scan already ships with.
    let loaded = match parsed.bundle.as_deref() {
        None => None,
        Some(path) => {
            let bytes = std::fs::read(path)
                .map_err(|e| format!("failed to read bundle {}: {e}", path.display()));
            match bytes.and_then(|b| frensense_bundler::format::load_bundle(&b)) {
                Ok(loaded) => Some(loaded),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(2);
                }
            }
        }
    };
    let mut sources: Vec<(&str, &frensense_bundler::format::LoadedBundle)> = vec![(
        "built-in vocabulary",
        frensense_bundler::format::default_pack(),
    )];
    if let Some(bundle) = &loaded {
        sources.push(("this bundle", bundle));
    }

    let Some(id) = parsed.id else {
        // Bare `explain`: a path with that name is a scan target, unless an
        // explicit flag asked for the index.
        if subcommand && !parsed.list && std::path::Path::new("explain").exists() {
            return ExplainOutcome::NotApplicable;
        }
        let mut text = frensense::cli::reporting::rule_index();
        if let Some(bundle) = &loaded {
            text.push_str(&frensense::cli::reporting::bundle_rule_index(bundle));
        }
        println!("{text}");
        return ExplainOutcome::Handled;
    };

    if let Some(text) = frensense::cli::reporting::explain_rule(&id) {
        println!("{text}");
        return ExplainOutcome::Handled;
    }
    if let Some(text) = frensense::cli::reporting::explain_learned_rule(&id, &sources) {
        println!("{text}");
        return ExplainOutcome::Handled;
    }
    // An unknown id that names a real path is a scan target, not a rule.
    if !flag_form && std::path::Path::new(&id).exists() {
        let mut rescanned = vec![args[0].clone()];
        rescanned.extend(args.iter().skip(2).cloned());
        return ExplainOutcome::ScanInstead(rescanned);
    }
    eprintln!("Error: unknown rule id `{id}`");
    eprintln!("Run `frensense explain` to list every built-in rule.");
    if parsed.bundle.is_none() {
        eprintln!("Bundle-learned rules need their bundle: add `-b <file.frc>`.");
    }
    std::process::exit(2);
}

fn print_help() {
    println!("Frensense v{FRENSENSE_VERSION}, deterministic dataflow security scanner.");
    println!();
    println!("Usage: frensense [path] [options]");
    println!(
        "       frensense bundle [<corpus_dir>] [output.frc] [-c/-o]  Compile corpus pairs into a .frc bundle"
    );
    println!(
        "       frensense bundle info <file.frc>             Inspect metadata and facts of a .frc bundle"
    );
    println!(
        "       frensense watch [path] [options]            Re-scan on file changes, print new findings"
    );
    println!(
        "       frensense mcp                               Run the Model Context Protocol (MCP) server"
    );
    println!(
        "       frensense lsp                               Run the Language Server Protocol (LSP) server"
    );
    println!(
        "       frensense explain [<rule-id>]               Describe a built-in rule (no id: list them all)"
    );
    println!(
        "       frensense --mcp                             Run the MCP server (unambiguous form)"
    );
    println!();
    println!("Paths vs subcommands:");
    println!("  A path named like a subcommand wins: `frensense mcp` scans ./mcp when it exists");
    println!(
        "  (`frensense --mcp` starts the server), `frensense watch` scans ./watch (`frensense"
    );
    println!("  watch <path>` watches), and `frensense bundle` scans ./bundle (`frensense bundle");
    println!("  <corpus> [out.frc]` compiles). `lsp` is always the server - editors run it.");
    println!();
    println!("Options:");
    println!("  -o, --output <file>        Write report to file (text, json, sarif, or github)");
    println!("  --json                     Output findings as JSON");
    println!("  --sarif                    Output findings in SARIF format");
    println!(
        "  --github                   GitHub Actions annotations (::error/::warning/::notice)"
    );
    println!("  -f, --format <format>      Report format: text, json, sarif, github");
    println!("  --strict                   Exit with code 1 if any findings");
    println!(
        "  -s, --severity <level>     Minimum severity: critical, warning, info (default: warning)"
    );
    // Generated from the lang registry so help, docs and MCP descriptions
    // agree on one list (WI-56); see `frensense::parser::language_names_help`.
    println!(
        "  -l, --language <lang>      Language filter: {}",
        frensense::parser::language_names_help()
    );
    println!(
        "  -b, --bundle <file>        .frc rules bundle (download: https://frensense.friehub.cloud/bundles)"
    );
    println!(
        "  --diff-only                Only report findings on lines changed since the last git commit"
    );
    println!("  --emit-baseline <file>     Save current findings as a baseline");
    println!("  --compare-baseline <file>  Fail on new findings vs. baseline");
    println!(
        "  --show-flows               Also embed the source->sink taint flow in text output (JSON/SARIF always carry the path)"
    );
    println!("  -h, --help                 Print this help");
    println!("  -v, --version              Print version");
    println!();
    println!("Rule Bundles (.frc):");
    println!("  Community and commercial rule bundles: https://frensense.friehub.cloud/bundles");
}

fn print_bundle_help() {
    println!("Frensense Bundle Compiler & Inspector: compile or inspect .frc facts bundles.");
    println!();
    println!("Usage: frensense bundle [<corpus_dir>] [output.frc] [-c <dir>] [-o <file>]");
    println!("       frensense bundle info <file.frc>");
    println!();
    println!("Arguments:");
    println!(
        "  <corpus_dir>  Directory containing vulnerability families organized as paired variants:"
    );
    println!(
        "                '<id>_positive.<ext>' (vulnerable) and '<id>_negative.<ext>' (safe/fixed)."
    );
    println!(
        "  [output.frc]  Destination file for compiled facts bundle (default: frensense-corpus.frc)."
    );
    println!(
        "  info <file>   Inspect .frc binary header, version, checksum, and fact distributions."
    );
    println!();
    println!("Options:");
    println!("  -c, --corpus <dir>   Set the corpus directory (alternative to <corpus_dir>)");
    println!("  -o, --output <file>  Set the output path (alternative to [output.frc])");
    println!("  -h, --help           Print this help");
    println!();
    println!("Workflow:");
    println!("  1. Author a vulnerability concept as a pair of source files in <corpus_dir>:");
    println!("       - <id>_positive.<ext>: contains the vulnerable flow or unguarded call");
    println!(
        "       - <id>_negative.<ext>: contains the safe/remediated pattern (with // SAFE: comment)"
    );
    println!("  2. (Optional) In the positive file, open with a '[frensense]' metadata block:");
    println!("       // [frensense]");
    println!("       // observation: description of the flaw");
    println!("       // impact: potential security impact");
    println!("       // improvement: recommended remediation");
    println!("       // cwe: CWE-xxx");
    println!("       // severity: Critical | Warning | Info");
    println!(
        "  3. Run 'frensense bundle <corpus_dir> [output.frc]' to compile and replay-verify the facts."
    );
    println!("  4. Run 'frensense bundle info <output.frc>' to inspect the compiled bundle.");
    println!(
        "  5. Run 'frensense <path> --corpus-bundle <output.frc>' to scan using the learned bundle."
    );
}

fn print_bundle_info(bundle_path: &std::path::Path) -> std::result::Result<(), String> {
    let bytes = std::fs::read(bundle_path)
        .map_err(|e| format!("failed to read bundle {}: {e}", bundle_path.display()))?;
    let loaded = frensense_bundler::format::load_bundle(&bytes)
        .map_err(|e| format!("failed to deserialize bundle: {e}"))?;

    let magic_str = std::str::from_utf8(&loaded.header.magic).unwrap_or("????");
    let checksum_hex: String = loaded
        .header
        .checksum
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let mut sources = 0;
    let mut sinks = 0;
    let mut sanitizers = 0;
    let mut policies = 0;
    let mut checks = 0;
    let mut memory_contracts = 0;
    let mut other = 0;

    for fact in &loaded.learned_facts {
        match fact {
            LearnedFactEntry::Source { .. } | LearnedFactEntry::LanguageSource { .. } => {
                sources += 1
            }
            LearnedFactEntry::Sink { .. }
            | LearnedFactEntry::LanguageSink { .. }
            | LearnedFactEntry::LanguageSinkSlots { .. } => sinks += 1,
            LearnedFactEntry::Sanitizer { .. } | LearnedFactEntry::LanguageSanitizer { .. } => {
                sanitizers += 1
            }
            LearnedFactEntry::Policy { .. } | LearnedFactEntry::PolicyScoped { .. } => {
                policies += 1
            }
            LearnedFactEntry::Check { .. } => checks += 1,
            LearnedFactEntry::MemoryContract { .. }
            | LearnedFactEntry::Allocator { .. }
            | LearnedFactEntry::Deallocator { .. } => memory_contracts += 1,
            _ => other += 1,
        }
    }

    println!("============================= Bundle Details =============================");
    println!("Path:               {}", bundle_path.display());
    println!("Magic:              {magic_str}");
    println!("Format Version:     v{}", loaded.header.version);
    println!("Payload Size:       {} bytes", bytes.len());
    println!("BLAKE3 Checksum:    {checksum_hex}");
    println!("Pattern Count:      {}", loaded.patterns.len());
    println!("Learned Facts:      {}", loaded.learned_facts.len());
    println!("  - Taint Sources:  {sources}");
    println!("  - Taint Sinks:    {sinks}");
    println!("  - Sanitizers:     {sanitizers}");
    println!("  - Co-occurrence:  {policies}");
    println!("  - Checks:         {checks}");
    if memory_contracts > 0 {
        println!("  - Memory Facts:   {memory_contracts}");
    }
    if other > 0 {
        println!("  - Other Facts:    {other}");
    }
    if !loaded.policy_pack.is_empty() {
        println!("Authored Policies:  {}", loaded.policy_pack.len());
    }
    println!("==========================================================================");

    if !loaded.patterns.is_empty() {
        println!();
        println!("Advisory Patterns:");
        for pat in &loaded.patterns {
            let cwe = pat.cwe.as_deref().unwrap_or("N/A");
            let sev = pat.severity.as_deref().unwrap_or("Unspecified");
            println!("  - [{}] {} (Severity: {})", pat.id, cwe, sev);
            if !pat.rules.is_empty() {
                println!("      Rules: {}", pat.rules.join(", "));
            }
        }
    }

    Ok(())
}

/// Parse arguments following the `bundle` subcommand: positionals fill the
/// corpus/output slots left-to-right, `-c`/`-o` set them explicitly, and any
/// other `-` argument is an error. `Ok(None)` means print help and exit 0
/// (no arguments after `bundle`, or `-h`/`--help`).
fn parse_bundle_args(
    args: &[String],
) -> std::result::Result<Option<(std::path::PathBuf, std::path::PathBuf)>, String> {
    if args.len() <= 2 {
        return Ok(None);
    }
    let mut corpus: Option<std::path::PathBuf> = None;
    let mut output: Option<std::path::PathBuf> = None;
    let mut it = args.iter().skip(2);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "-c" | "--corpus" => {
                if corpus.is_some() {
                    return Err(format!("corpus specified twice ({arg})"));
                }
                let value = it
                    .next()
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                corpus = Some(std::path::PathBuf::from(value));
            }
            "-o" | "--output" => {
                if output.is_some() {
                    return Err(format!("output specified twice ({arg})"));
                }
                let value = it
                    .next()
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                output = Some(std::path::PathBuf::from(value));
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag: {other}"));
            }
            other => {
                if corpus.is_none() {
                    corpus = Some(std::path::PathBuf::from(other));
                } else if output.is_none() {
                    output = Some(std::path::PathBuf::from(other));
                } else {
                    return Err(format!("unexpected extra argument: {other}"));
                }
            }
        }
    }
    let corpus = corpus.ok_or("missing corpus directory")?;
    Ok(Some((
        corpus,
        output.unwrap_or_else(|| std::path::PathBuf::from("frensense-corpus.frc")),
    )))
}

fn handle_bundle_command(args: &[String]) -> Result<bool> {
    if args.get(1).map(|s| s.as_str()) != Some("bundle") {
        return Ok(false);
    }
    if let Some(sub) = args.get(2)
        && (sub == "info" || sub == "inspect")
    {
        if args.get(3).map(|s| s.as_str()) == Some("-h")
            || args.get(3).map(|s| s.as_str()) == Some("--help")
        {
            println!("Frensense Bundle Inspector: inspect metadata and facts of a .frc bundle.");
            println!();
            println!("Usage: frensense bundle info <file.frc>");
            std::process::exit(0);
        }
        let bundle_path = match args.get(3) {
            Some(p) => std::path::PathBuf::from(p),
            None => {
                eprintln!("Error: missing bundle file path");
                eprintln!("Usage: frensense bundle info <file.frc>");
                std::process::exit(2);
            }
        };
        if let Err(e) = print_bundle_info(&bundle_path) {
            eprintln!("Bundle inspection error: {e}");
            std::process::exit(1);
        }
        return Ok(true);
    }
    match parse_bundle_args(args) {
        Ok(None) => {
            print_bundle_help();
            std::process::exit(0);
        }
        Ok(Some((corpus_dir, output_path))) => {
            if let Err(e) = frensense_bundler::run_facts_pipeline(&corpus_dir, &output_path) {
                eprintln!("Bundle compilation error: {e}");
                std::process::exit(1);
            }
            Ok(true)
        }
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Usage: frensense bundle [<corpus_dir>] [output.frc] [-c <dir>] [-o <file>]");
            eprintln!("       frensense bundle info <file.frc>");
            std::process::exit(2);
        }
    }
}

/// Which entry point argv describes.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Scan,
    Mcp,
    Lsp,
    Watch,
    Bundle,
}

/// Resolve argv[1] to a mode. A subcommand token yields to a path of the
/// same name: a repo can legitimately contain `watch/`, `bundle/` or `mcp/`,
/// and `frensense explain` already resolves that way (a known id wins, else
/// an existing path scans). Arguments that only the subcommand understands
/// keep it claimed (`frensense watch src`, `frensense bundle corpus/`), and
/// `--mcp` is the unambiguous form of the argument-less server mode.
///
/// `lsp` stays literal on purpose: editor integrations run `frensense lsp`
/// non-interactively, where silently scanning a `lsp/` directory would break
/// the editor rather than present an ambiguity a human can resolve.
///
/// `path_exists` is injected so the rule is testable without a filesystem.
fn resolve_mode(args: &[String], path_exists: &dyn Fn(&str) -> bool) -> Mode {
    if args.iter().any(|a| a == "--mcp") {
        return Mode::Mcp;
    }
    let token = args.get(1).map(String::as_str);
    let extra = args.len() > 2;
    match token {
        Some("mcp") if !path_exists("mcp") => Mode::Mcp,
        Some("lsp") => Mode::Lsp,
        Some("watch") if extra || !path_exists("watch") => Mode::Watch,
        Some("bundle") if extra || !path_exists("bundle") => Mode::Bundle,
        _ => Mode::Scan,
    }
}

fn handle_early_args(args: &[String]) -> bool {
    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        std::process::exit(0);
    }
    if args.iter().any(|a| a == "--version" || a == "-v") {
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let options = parse_options(&args).map_err(frensense::FrensenseError::Config)?;
    let input_path = options
        .paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let language_filter: Option<Vec<&'static str>> = options
        .language_filter
        .as_ref()
        .and_then(|l| frensense::parser::extensions_for(l))
        .map(|exts| exts.to_vec());
    let corpus_bundle = options.corpus_bundle_path.clone();
    let severity = options.severity_filter;

    // Stop-file: polled by a detached thread, lets scripts/tests end the
    // loop deterministically without signaling machinery. SIGINT keeps the
    // default handler (process exit).
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_file = input_path.join("frensense-watch.stop");
    {
        let stop_flag = Arc::clone(&stop_flag);
        std::thread::spawn(move || {
            loop {
                if stop_file.exists() {
                    stop_flag.store(true, Ordering::SeqCst);
                    let _ = std::fs::remove_file(&stop_file);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
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
            engine
        },
        |engine, path| engine.run(path),
        || stop.load(Ordering::SeqCst) || stop_flag.load(Ordering::SeqCst),
    )
}

fn run_mcp() -> Result<()> {
    use frensense::mcp::handler::handle_request;
    use frensense::mcp::protocol::{JsonRpcRequest, RequestId, rpc_error, write_response};
    use std::io::{self, BufRead};

    eprintln!("frensense-mcp v{FRENSENSE_VERSION} starting");
    eprintln!("frensense-mcp: cwd={:?}", std::env::current_dir().ok());

    let stdin = io::stdin();
    let reader = stdin.lock();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("frensense-mcp: stdin read error: {e}");
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = rpc_error(RequestId::Absent, -32700, format!("parse error: {e}"));
                write_response(&err_resp);
                continue;
            }
        };

        if req.method == "exit" {
            break;
        }

        let resp = handle_request(req);
        if resp.id.is_some() {
            write_response(&resp);
        }
    }

    eprintln!("frensense-mcp: exiting");
    Ok(())
}

fn run_lsp() -> Result<()> {
    let bundle = std::env::var("FRENSENSE_CORPUS_BUNDLE")
        .ok()
        .filter(|p| !p.is_empty());
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    if let Err(e) = frensense::lsp::server::run_server(&mut reader, &mut writer, bundle.as_deref())
    {
        eprintln!("frensense-lsp: fatal transport error: {e}");
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> Result<()> {
    frensense_engine::debug_flags::DebugFlags::install_from(std::env::var_os);
    let mut args: Vec<String> = std::env::args().collect();
    if handle_early_args(&args) {
        return Ok(());
    }

    match resolve_mode(&args, &|p| std::path::Path::new(p).exists()) {
        Mode::Mcp => return run_mcp(),
        Mode::Lsp => return run_lsp(),
        Mode::Watch => {
            // Drop only the `watch` token (argv[1]): a path named `watch`
            // later in the line is a real watch target.
            let mut watch_args = args.clone();
            watch_args.remove(1);
            return run_watch(watch_args);
        }
        Mode::Bundle => {
            if handle_bundle_command(&args)? {
                return Ok(());
            }
        }
        Mode::Scan => {}
    }

    match handle_explain_command(&args) {
        ExplainOutcome::NotApplicable => {}
        ExplainOutcome::Handled => return Ok(()),
        ExplainOutcome::ScanInstead(rescanned) => {
            args = rescanned;
        }
    }

    let options = match parse_options(&args) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Run 'frensense --help' for usage information");
            std::process::exit(2);
        }
    };

    let input_paths = options.paths.clone();
    let input_path = input_paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::path::PathBuf::from("."));

    let is_machine_format = matches!(options.format.as_str(), "json" | "sarif" | "github")
        && options.output_path.is_none();
    if !is_machine_format {
        print_scan_banner(
            &input_path,
            options.corpus_bundle_path.as_deref(),
            options.language_filter.as_deref(),
            options.output_path.as_deref(),
        );
    }

    let start_time = std::time::Instant::now();

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
    engine.set_profile(options.profile);
    engine.set_explain(options.explain);
    engine.set_show_flows(options.show_flows);

    let mut explain_records = Vec::new();
    let mut hidden_by_tier = std::collections::BTreeMap::new();
    let advisories = if options.diff_only {
        let repo_dir = if input_path.is_dir() {
            input_path.clone()
        } else {
            input_path.parent().unwrap_or(&input_path).to_path_buf()
        };
        let diff_files = frensense::cli::git::changed_scan_files(&repo_dir)
            .map_err(frensense::FrensenseError::Config)?;
        if diff_files.is_empty() {
            eprintln!("No changed files to scan.");
            Vec::new()
        } else {
            let added = frensense::cli::git::added_lines(&repo_dir)
                .map_err(frensense::FrensenseError::Config)?;
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
                e2.set_profile(options.profile);
                e2.set_explain(options.explain);
                e2.set_show_flows(options.show_flows);
                all.extend(e2.run(f)?);
                if options.explain {
                    explain_records.extend(e2.take_explain());
                    for (tier, count) in e2.take_hidden_by_tier() {
                        *hidden_by_tier.entry(tier).or_insert(0) += count;
                    }
                }
            }
            // The gate answers one question - did THIS change introduce a
            // finding? Whole files are scanned (a change can make an old
            // line reachable), but a finding whose span touches no added
            // line predates the diff: it belongs to the baseline
            // (--compare-baseline), not to this gate.
            let (on_diff, pre_existing): (Vec<_>, Vec<_>) = all.into_iter().partition(|a| {
                (a.line..=a.end_line.max(a.line))
                    .any(|ln| frensense::cli::git::is_added(&added, &repo_dir, &a.file_path, ln))
            });
            if !pre_existing.is_empty() {
                eprintln!(
                    "Diff-only: suppressed {} pre-existing finding(s) at unchanged lines (run without --diff-only to see them).",
                    pre_existing.len()
                );
            }
            on_diff
        }
    } else {
        // Scan every positional input path; findings merge across them.
        let mut all = Vec::new();
        for p in &input_paths {
            all.extend(engine.run(p)?);
        }
        if options.explain {
            explain_records = engine.take_explain();
            hidden_by_tier = engine.take_hidden_by_tier();
        }
        all
    };

    if options.explain {
        print_explain(&explain_records, &hidden_by_tier);
    }

    print_results(
        &advisories,
        &options.format,
        &input_path,
        Some(start_time.elapsed()),
        options.output_path.as_deref(),
    )?;

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

#[cfg(test)]
mod tests {
    use super::{Mode, parse_bundle_args, parse_explain_args, resolve_mode};

    fn argv(rest: &[&str]) -> Vec<String> {
        std::iter::once("frensense".to_string())
            .chain(rest.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn explain_subcommand_parses_id_and_bundle() {
        let parsed = parse_explain_args(&argv(&[
            "explain",
            "policy.redirect-challenge",
            "-b",
            "learned.frc",
        ]));
        assert_eq!(
            parsed.id.as_deref(),
            Some("policy.redirect-challenge"),
            "{parsed:?}"
        );
        assert_eq!(
            parsed.bundle.as_deref(),
            Some(std::path::Path::new("learned.frc")),
            "{parsed:?}"
        );
        assert!(!parsed.list, "{parsed:?}");
    }

    #[test]
    fn explain_flag_forms_parse_without_the_subcommand() {
        let rule = parse_explain_args(&argv(&["--explain-rule", "taint.sql-injection"]));
        assert_eq!(rule.id.as_deref(), Some("taint.sql-injection"), "{rule:?}");
        let list = parse_explain_args(&argv(&["--list-rules", "-b", "x.frc"]));
        assert!(list.list, "{list:?}");
        assert_eq!(list.bundle.as_deref(), Some(std::path::Path::new("x.frc")));
    }

    #[test]
    fn explain_bare_and_non_explain_args_parse_empty() {
        let bare = parse_explain_args(&argv(&["explain"]));
        assert_eq!(bare.id, None, "{bare:?}");
        assert!(!bare.list, "{bare:?}");
        let scan = parse_explain_args(&argv(&[".", "--strict"]));
        // A scan path after the program name is not an explain id: the
        // subcommand slot (argv[1]) is where ids are read from.
        assert_eq!(scan.id, None, "{scan:?}");
    }

    #[test]
    fn subcommands_yield_to_a_same_named_path() {
        let mcp = argv(&["mcp"]);
        assert_eq!(resolve_mode(&mcp, &|_| false), Mode::Mcp);
        assert_eq!(resolve_mode(&mcp, &|p| p == "mcp"), Mode::Scan);

        let watch = argv(&["watch"]);
        assert_eq!(resolve_mode(&watch, &|_| false), Mode::Watch);
        assert_eq!(resolve_mode(&watch, &|p| p == "watch"), Mode::Scan);

        let bundle = argv(&["bundle"]);
        assert_eq!(resolve_mode(&bundle, &|_| false), Mode::Bundle);
        assert_eq!(resolve_mode(&bundle, &|p| p == "bundle"), Mode::Scan);
    }

    #[test]
    fn subcommand_arguments_keep_the_subcommand_claimed() {
        // `watch <path>` and `bundle <corpus>` can only mean the subcommand,
        // whatever paths exist.
        assert_eq!(
            resolve_mode(&argv(&["watch", "src"]), &|p| p == "watch"),
            Mode::Watch
        );
        assert_eq!(
            resolve_mode(&argv(&["bundle", "corpus/"]), &|p| p == "bundle"),
            Mode::Bundle
        );
        assert_eq!(
            resolve_mode(&argv(&["bundle", "info", "x.frc"]), &|p| p == "bundle"),
            Mode::Bundle
        );
    }

    #[test]
    fn mcp_flag_is_the_unambiguous_server_form() {
        assert_eq!(resolve_mode(&argv(&["--mcp"]), &|p| p == "mcp"), Mode::Mcp);
    }

    #[test]
    fn tokens_outside_the_subcommand_slot_are_paths() {
        // Only argv[1] names a subcommand; `frensense . mcp` scans both.
        assert_eq!(resolve_mode(&argv(&[".", "mcp"]), &|_| true), Mode::Scan);
        assert_eq!(resolve_mode(&argv(&["src/mcp"]), &|_| false), Mode::Scan);
        assert_eq!(resolve_mode(&argv(&["."]), &|_| true), Mode::Scan);
    }

    #[test]
    fn lsp_stays_literal_for_editor_integrations() {
        assert_eq!(resolve_mode(&argv(&["lsp"]), &|_| true), Mode::Lsp);
    }

    fn args(rest: &[&str]) -> Vec<String> {
        std::iter::once("frensense".to_string())
            .chain(std::iter::once("bundle".to_string()))
            .chain(rest.iter().map(|s| s.to_string()))
            .collect()
    }

    fn paths(
        result: Result<Option<(std::path::PathBuf, std::path::PathBuf)>, String>,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        result.expect("parse").expect("expected paths, got help")
    }

    #[test]
    fn bare_bundle_and_help_print_help() {
        assert!(parse_bundle_args(&args(&[])).expect("parse").is_none());
        assert!(
            parse_bundle_args(&args(&["--help"]))
                .expect("parse")
                .is_none()
        );
        assert!(
            parse_bundle_args(&args(&["-c", "dir", "-h"]))
                .expect("parse")
                .is_none()
        );
    }

    #[test]
    fn positional_pair_parses() {
        let (corpus, output) = paths(parse_bundle_args(&args(&["mycorpus", "my.frc"])));
        assert_eq!(corpus, std::path::PathBuf::from("mycorpus"));
        assert_eq!(output, std::path::PathBuf::from("my.frc"));
    }

    #[test]
    fn flag_form_parses() {
        let (corpus, output) = paths(parse_bundle_args(&args(&[
            "-c",
            "corpus/targets",
            "-o",
            "frensense-corpus.frc",
        ])));
        assert_eq!(corpus, std::path::PathBuf::from("corpus/targets"));
        assert_eq!(output, std::path::PathBuf::from("frensense-corpus.frc"));
    }

    #[test]
    fn long_flag_form_parses() {
        let (corpus, output) = paths(parse_bundle_args(&args(&[
            "--corpus", "dir", "--output", "file.frc",
        ])));
        assert_eq!(corpus, std::path::PathBuf::from("dir"));
        assert_eq!(output, std::path::PathBuf::from("file.frc"));
    }

    #[test]
    fn flag_corpus_with_positional_output() {
        let (corpus, output) = paths(parse_bundle_args(&args(&["-c", "dir", "file.frc"])));
        assert_eq!(corpus, std::path::PathBuf::from("dir"));
        assert_eq!(output, std::path::PathBuf::from("file.frc"));
    }

    #[test]
    fn default_output_applies() {
        let (corpus, output) = paths(parse_bundle_args(&args(&["mycorpus"])));
        assert_eq!(corpus, std::path::PathBuf::from("mycorpus"));
        assert_eq!(output, std::path::PathBuf::from("frensense-corpus.frc"));
    }

    #[test]
    fn missing_corpus_is_rejected() {
        let err = parse_bundle_args(&args(&["-o", "file.frc"])).expect_err("reject");
        assert!(err.contains("missing corpus directory"), "{err}");
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let err =
            parse_bundle_args(&args(&["mycorpus", "--policy", "p.toml"])).expect_err("reject");
        assert!(err.contains("unknown flag: --policy"), "{err}");
    }

    #[test]
    fn missing_flag_value_is_rejected() {
        let err = parse_bundle_args(&args(&["-c"])).expect_err("reject");
        assert!(err.contains("missing value for -c"), "{err}");
    }

    #[test]
    fn duplicate_flag_is_rejected() {
        let err = parse_bundle_args(&args(&["-c", "a", "-c", "b"])).expect_err("reject");
        assert!(err.contains("corpus specified twice"), "{err}");
    }

    #[test]
    fn extra_positional_is_rejected() {
        let err = parse_bundle_args(&args(&["a", "b", "c"])).expect_err("reject");
        assert!(err.contains("unexpected extra argument: c"), "{err}");
    }
}
