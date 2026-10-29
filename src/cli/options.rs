// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::Severity;
use std::path::PathBuf;

/// CLI options for the deterministic dataflow compiler scan.
///
/// `#[non_exhaustive]`: an evolving options DTO. New flags (e.g. `explain` in
/// 0.8.0) are added as minor releases; construct via [`super::parse_options`],
/// not literals.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CliOptions {
    /// Positional scan target paths (files or directories).
    pub paths: Vec<PathBuf>,
    /// Report format: "text", "json", "sarif", "github".
    pub format: String,
    /// Optional output file to write the report to.
    pub output_path: Option<PathBuf>,
    /// Fail with exit code 1 if any findings are found.
    pub is_strict: bool,
    /// Minimum severity floor: critical, warning, info. Default: warning.
    pub severity_filter: Option<Severity>,
    /// Language filter (e.g., rust, go, typescript, javascript, python, c).
    pub language_filter: Option<String>,
    /// .frc bundle providing learned facts and advisory patterns.
    pub corpus_bundle_path: Option<PathBuf>,
    /// Save current findings as a baseline JSON artifact.
    pub emit_baseline_path: Option<String>,
    /// Compare findings against a baseline and fail on new findings.
    pub compare_baseline_path: Option<String>,
    /// Only scan files modified relative to git HEAD.
    pub diff_only: bool,
    /// Record every silent sink argument (why the engine stayed quiet).
    pub explain: bool,
    /// Include the taint-path flow (source→sink SSA steps) in the text
    /// observation. JSON/SARIF always carry the path (`taint_steps` / SARIF
    /// `codeFlows`); `--show-flows` additionally embeds it in the text
    /// observation for terminal reports.
    pub show_flows: bool,
    /// Precision profile: default (stable), recommended (stable + beta),
    /// or strict (all tiers, including hygiene and experimental).
    pub profile: crate::Profile,
    /// Report code hygiene rules (e.g. function complexity) under any profile.
    pub enable_hygiene: bool,
    /// Maximum cyclomatic complexity ceiling before emitting function_complexity.
    pub max_complexity: Option<usize>,
    /// Exit with code 2 if the scan was incomplete, degraded, or had errors.
    pub fail_on_incomplete: bool,
    /// Destination path to write profiling/telemetry JSON.
    pub profile_output: Option<PathBuf>,
    /// Initialize tracing subscriber for spans and logs.
    pub trace: bool,
}

/// Parse CLI arguments into structured scan options.
pub fn parse_options(args: &[String]) -> std::result::Result<CliOptions, String> {
    let mut options = CliOptions {
        paths: Vec::new(),
        format: "text".to_string(),
        output_path: None,
        is_strict: false,
        severity_filter: Some(Severity::Warning),
        language_filter: None,
        corpus_bundle_path: None,
        emit_baseline_path: None,
        compare_baseline_path: None,
        diff_only: false,
        explain: false,
        show_flows: false,
        profile: crate::Profile::Default,
        enable_hygiene: false,
        max_complexity: None,
        fail_on_incomplete: false,
        profile_output: None,
        trace: false,
    };

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-o" | "--output" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                options.output_path = Some(PathBuf::from(val));
                i += 1;
            }
            "--json" => options.format = "json".to_string(),
            "--sarif" => options.format = "sarif".to_string(),
            "--github" | "--github-annotations" => {
                options.format = "github".to_string();
            }
            "-f" | "--format" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                match val.to_lowercase().as_str() {
                    "text" | "json" | "sarif" | "github" => {
                        options.format = val.to_lowercase();
                    }
                    other => {
                        return Err(format!(
                            "unknown format '{other}' (expected: text, json, sarif, github)"
                        ));
                    }
                }
                i += 1;
            }
            "--strict" => options.is_strict = true,
            "--diff-only" => options.diff_only = true,
            "--explain" => options.explain = true,
            "--show-flows" => options.show_flows = true,
            "--hygiene" => options.enable_hygiene = true,
            "--max-complexity" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                let n = val.parse::<usize>().map_err(|_| {
                    format!("invalid value for {arg}: '{val}' must be a positive integer")
                })?;
                options.max_complexity = Some(n);
                options.enable_hygiene = true;
                i += 1;
            }
            "--fail-on-incomplete" => options.fail_on_incomplete = true,
            "--trace" => options.trace = true,
            "--profile-out" | "--profile-output" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                options.profile_output = Some(PathBuf::from(val));
                i += 1;
            }
            "-p" | "--profile" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                if val.ends_with(".json") {
                    options.profile_output = Some(PathBuf::from(val));
                } else {
                    options.profile = crate::Profile::parse(val)?;
                }
                i += 1;
            }
            "-s" | "--severity" => {
                let level = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                options.severity_filter = match level.to_lowercase().as_str() {
                    "critical" => Some(Severity::Critical),
                    "warning" => Some(Severity::Warning),
                    "info" => Some(Severity::Info),
                    other => {
                        return Err(format!(
                            "unknown severity level '{other}' (expected: critical, warning, info)"
                        ));
                    }
                };
                i += 1;
            }
            "-l" | "--lang" | "--language" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                options.language_filter = Some(val.clone());
                i += 1;
            }
            "-b" | "--bundle" | "--corpus-bundle" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                options.corpus_bundle_path = Some(PathBuf::from(val));
                i += 1;
            }
            "--emit-baseline" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                options.emit_baseline_path = Some(val.clone());
                i += 1;
            }
            "--compare-baseline" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                options.compare_baseline_path = Some(val.clone());
                i += 1;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag: {other}"));
            }
            pos => {
                let p = PathBuf::from(pos);
                if p.exists() {
                    options.paths.push(p);
                } else {
                    return Err(format!(
                        "path '{pos}' does not exist - specify a valid file or directory"
                    ));
                }
            }
        }
        i += 1;
    }

    if options.paths.is_empty() {
        options.paths.push(PathBuf::from("."));
    }

    Ok(options)
}

/// All positional input paths: extracted from parsed options.
#[must_use]
pub fn get_input_paths(args: &[String]) -> Vec<PathBuf> {
    parse_options(args)
        .map(|opts| opts.paths)
        .unwrap_or_else(|_| vec![std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))])
}

/// Back-compat single-path accessor (first positional input).
#[must_use]
pub fn get_input_path(args: &[String]) -> PathBuf {
    get_input_paths(args)
        .into_iter()
        .next()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_args(strs: &[&str]) -> Vec<String> {
        std::iter::once("frensense".to_string())
            .chain(strs.iter().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn defaults_and_single_positional() {
        let opts = parse_options(&to_args(&["Cargo.toml"])).expect("parse");
        assert_eq!(opts.format, "text");
        assert_eq!(opts.severity_filter, Some(Severity::Warning));
        assert!(opts.output_path.is_none());
        assert!(!opts.is_strict);
        assert_eq!(opts.paths.len(), 1);
        assert!(opts.paths[0].ends_with("Cargo.toml"));
    }

    #[test]
    fn format_flags_work() {
        let opts = parse_options(&to_args(&["--json"])).expect("parse");
        assert_eq!(opts.format, "json");

        let opts = parse_options(&to_args(&["--sarif"])).expect("parse");
        assert_eq!(opts.format, "sarif");

        let opts = parse_options(&to_args(&["--github"])).expect("parse");
        assert_eq!(opts.format, "github");

        let opts = parse_options(&to_args(&["-f", "sarif"])).expect("parse");
        assert_eq!(opts.format, "sarif");
    }

    #[test]
    fn output_flag_parses() {
        let opts = parse_options(&to_args(&["-o", "report.sarif"])).expect("parse");
        assert_eq!(opts.output_path, Some(PathBuf::from("report.sarif")));

        let opts = parse_options(&to_args(&["--output", "report.json"])).expect("parse");
        assert_eq!(opts.output_path, Some(PathBuf::from("report.json")));
    }

    #[test]
    fn severity_and_language_flags() {
        let opts = parse_options(&to_args(&["-s", "critical", "-l", "typescript"])).expect("parse");
        assert_eq!(opts.severity_filter, Some(Severity::Critical));
        assert_eq!(opts.language_filter.as_deref(), Some("typescript"));

        let opts =
            parse_options(&to_args(&["--severity", "info", "--language", "rust"])).expect("parse");
        assert_eq!(opts.severity_filter, Some(Severity::Info));
        assert_eq!(opts.language_filter.as_deref(), Some("rust"));
    }

    #[test]
    fn bundle_flag_parses() {
        let opts = parse_options(&to_args(&["-b", "bundle.frc"])).expect("parse");
        assert_eq!(opts.corpus_bundle_path, Some(PathBuf::from("bundle.frc")));

        let opts = parse_options(&to_args(&["--corpus-bundle", "bundle.frc"])).expect("parse");
        assert_eq!(opts.corpus_bundle_path, Some(PathBuf::from("bundle.frc")));
    }

    #[test]
    fn unknown_flag_rejected() {
        let err = parse_options(&to_args(&["--unknown"])).expect_err("should reject");
        assert!(err.contains("unknown flag: --unknown"));
    }

    #[test]
    fn explain_flag_parses() {
        let opts = parse_options(&to_args(&["--explain"])).expect("parse");
        assert!(opts.explain);
        let opts = parse_options(&to_args(&["Cargo.toml"])).expect("parse");
        assert!(!opts.explain);
    }

    #[test]
    fn show_flows_flag_parses() {
        let opts = parse_options(&to_args(&["--show-flows"])).expect("parse");
        assert!(opts.show_flows);
        let opts = parse_options(&to_args(&["Cargo.toml"])).expect("parse");
        assert!(!opts.show_flows, "show_flows defaults to off");
    }

    #[test]
    fn missing_value_rejected() {
        let err = parse_options(&to_args(&["-o"])).expect_err("should reject");
        assert!(err.contains("missing value for -o"));
    }

    #[test]
    fn non_existent_path_rejected() {
        let err = parse_options(&to_args(&["this_file_does_not_exist_at_all.xyz"]))
            .expect_err("should reject");
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn profile_flag_parses() {
        let opts = parse_options(&to_args(&["Cargo.toml"])).expect("parse");
        assert_eq!(opts.profile, crate::Profile::Default);

        let opts =
            parse_options(&to_args(&["--profile", "recommended", "Cargo.toml"])).expect("parse");
        assert_eq!(opts.profile, crate::Profile::Recommended);

        let opts = parse_options(&to_args(&["-p", "strict", "Cargo.toml"])).expect("parse");
        assert_eq!(opts.profile, crate::Profile::Strict);

        let err = parse_options(&to_args(&["--profile", "invalid", "Cargo.toml"]))
            .expect_err("should reject");
        assert!(err.contains("unknown profile 'invalid'"));
    }

    #[test]
    fn hygiene_flag_parses() {
        let opts = parse_options(&to_args(&["--hygiene"])).expect("parse");
        assert!(opts.enable_hygiene);
        assert_eq!(opts.max_complexity, None);

        let opts = parse_options(&to_args(&["Cargo.toml"])).expect("parse");
        assert!(!opts.enable_hygiene);
    }

    #[test]
    fn max_complexity_flag_parses() {
        let opts = parse_options(&to_args(&["--max-complexity", "15"])).expect("parse");
        assert_eq!(opts.max_complexity, Some(15));
        assert!(
            opts.enable_hygiene,
            "setting max-complexity should automatically enable hygiene"
        );

        let err = parse_options(&to_args(&["--max-complexity"])).expect_err("should reject");
        assert!(err.contains("missing value for --max-complexity"));

        let err = parse_options(&to_args(&["--max-complexity", "abc"])).expect_err("should reject");
        assert!(err.contains("must be a positive integer"));
    }

    #[test]
    fn fail_on_incomplete_flag_parses() {
        let opts = parse_options(&to_args(&["--fail-on-incomplete"])).expect("parse");
        assert!(opts.fail_on_incomplete);

        // Must be false by default.
        let opts = parse_options(&to_args(&["Cargo.toml"])).expect("parse");
        assert!(!opts.fail_on_incomplete);
    }

    #[test]
    fn trace_flag_parses() {
        let opts = parse_options(&to_args(&["--trace"])).expect("parse");
        assert!(opts.trace);

        // Must be false by default.
        let opts = parse_options(&to_args(&["Cargo.toml"])).expect("parse");
        assert!(!opts.trace);
    }

    #[test]
    fn profile_output_flag_parses() {
        // Long form
        let opts = parse_options(&to_args(&["--profile-output", "profile.json"])).expect("parse");
        assert_eq!(opts.profile_output, Some(PathBuf::from("profile.json")));
        // Short alias
        let opts = parse_options(&to_args(&["--profile-out", "out.json"])).expect("parse");
        assert_eq!(opts.profile_output, Some(PathBuf::from("out.json")));
    }

    #[test]
    fn profile_flag_with_json_extension_sets_profile_output() {
        // --profile <path.json> must route to profile_output, not precision profile.
        let opts =
            parse_options(&to_args(&["--profile", "timing.json", "Cargo.toml"])).expect("parse");
        assert_eq!(opts.profile_output, Some(PathBuf::from("timing.json")));
        // The precision profile must remain at its default.
        assert_eq!(opts.profile, crate::Profile::Default);
    }
}
