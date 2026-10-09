// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Frensense bundler CLI: builds a `.frc` facts bundle from positive/negative
//! corpus pairs.
//!
//! Usage: frensense-bundler [<corpus_dir>] [<output.frc>] [-c <dir>] [-o <file>]

use std::env;
use std::path::PathBuf;

const USAGE: &str = "\
Usage: frensense-bundler [<corpus_dir>] [<output.frc>] [options]

Options:
  -c, --corpus <dir>   Corpus directory (default: <workspace>/corpus/targets)
  -o, --output <file>  Output bundle path (default: <workspace>/frensense-corpus.frc)
  -h, --help           Print this help";

#[derive(Debug)]
enum Parsed {
    Help,
    Paths { corpus: PathBuf, output: PathBuf },
}

/// Parse bundler CLI arguments: positional args fill the corpus and output
/// slots left-to-right, `-c`/`-o` (long forms included) set them explicitly,
/// and anything else beginning with `-` is an error. `release.yml` invokes
/// the binary as `-- -c corpus/targets -o frensense-corpus.frc`, so flag
/// handling is load-bearing for release runners.
fn parse_args(
    args: &[String],
    default_corpus: PathBuf,
    default_output: PathBuf,
) -> Result<Parsed, String> {
    let mut corpus: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-c" | "--corpus" => {
                if corpus.is_some() {
                    return Err(format!("corpus specified twice ({arg})"));
                }
                let value = it
                    .next()
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                corpus = Some(PathBuf::from(value));
            }
            "-o" | "--output" => {
                if output.is_some() {
                    return Err(format!("output specified twice ({arg})"));
                }
                let value = it
                    .next()
                    .ok_or_else(|| format!("missing value for {arg}"))?;
                output = Some(PathBuf::from(value));
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag: {other}"));
            }
            other => {
                if corpus.is_none() {
                    corpus = Some(PathBuf::from(other));
                } else if output.is_none() {
                    output = Some(PathBuf::from(other));
                } else {
                    return Err(format!("unexpected extra argument: {other}"));
                }
            }
        }
    }
    Ok(Parsed::Paths {
        corpus: corpus.unwrap_or(default_corpus),
        output: output.unwrap_or(default_output),
    })
}

fn main() {
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").map_or_else(|_| env::current_dir().unwrap(), PathBuf::from);
    let workspace_root = manifest_dir.parent().unwrap();

    let args: Vec<String> = env::args().collect();
    let (corpus_dir, output_path) = match parse_args(
        &args,
        workspace_root.join("corpus").join("targets"),
        workspace_root.join("frensense-corpus.frc"),
    ) {
        Ok(Parsed::Help) => {
            println!("{USAGE}");
            return;
        }
        Ok(Parsed::Paths { corpus, output }) => (corpus, output),
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };

    if let Err(e) = frensense_bundler::run_facts_pipeline(&corpus_dir, &output_path) {
        eprintln!("Error in facts pipeline: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(rest: &[&str]) -> Vec<String> {
        std::iter::once("frensense-bundler".to_string())
            .chain(rest.iter().map(|s| s.to_string()))
            .collect()
    }

    fn defaults() -> (PathBuf, PathBuf) {
        (
            PathBuf::from("/ws/corpus/targets"),
            PathBuf::from("/ws/frensense-corpus.frc"),
        )
    }

    fn paths(parsed: Result<Parsed, String>) -> (PathBuf, PathBuf) {
        match parsed.expect("parse") {
            Parsed::Paths { corpus, output } => (corpus, output),
            Parsed::Help => panic!("expected paths, got help"),
        }
    }

    #[test]
    fn no_args_uses_workspace_defaults() {
        let (d_corpus, d_output) = defaults();
        let (corpus, output) = paths(parse_args(&args(&[]), d_corpus, d_output));
        assert_eq!(corpus, PathBuf::from("/ws/corpus/targets"));
        assert_eq!(output, PathBuf::from("/ws/frensense-corpus.frc"));
    }

    #[test]
    fn positional_pair_maps_to_corpus_and_output() {
        let (d_corpus, d_output) = defaults();
        let (corpus, output) = paths(parse_args(
            &args(&["mycorpus", "my.frc"]),
            d_corpus,
            d_output,
        ));
        assert_eq!(corpus, PathBuf::from("mycorpus"));
        assert_eq!(output, PathBuf::from("my.frc"));
    }

    #[test]
    fn release_ci_flag_form_parses() {
        let (d_corpus, d_output) = defaults();
        let (corpus, output) = paths(parse_args(
            &args(&["-c", "corpus/targets", "-o", "frensense-corpus.frc"]),
            d_corpus,
            d_output,
        ));
        assert_eq!(corpus, PathBuf::from("corpus/targets"));
        assert_eq!(output, PathBuf::from("frensense-corpus.frc"));
    }

    #[test]
    fn long_flag_forms_parse() {
        let (d_corpus, d_output) = defaults();
        let (corpus, output) = paths(parse_args(
            &args(&["--corpus", "dir", "--output", "file.frc"]),
            d_corpus,
            d_output,
        ));
        assert_eq!(corpus, PathBuf::from("dir"));
        assert_eq!(output, PathBuf::from("file.frc"));
    }

    #[test]
    fn flag_corpus_with_positional_output() {
        let (d_corpus, d_output) = defaults();
        let (corpus, output) = paths(parse_args(
            &args(&["-c", "dir", "file.frc"]),
            d_corpus,
            d_output,
        ));
        assert_eq!(corpus, PathBuf::from("dir"));
        assert_eq!(output, PathBuf::from("file.frc"));
    }

    #[test]
    fn positionals_fill_remaining_slots() {
        let (d_corpus, d_output) = defaults();
        let (corpus, output) = paths(parse_args(
            &args(&["-o", "file.frc", "dir"]),
            d_corpus,
            d_output,
        ));
        assert_eq!(corpus, PathBuf::from("dir"));
        assert_eq!(output, PathBuf::from("file.frc"));
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let (d_corpus, d_output) = defaults();
        let err = parse_args(&args(&["--facts"]), d_corpus, d_output).unwrap_err();
        assert!(err.contains("unknown flag: --facts"), "{err}");
    }

    #[test]
    fn missing_flag_value_is_rejected() {
        let (d_corpus, d_output) = defaults();
        let err = parse_args(&args(&["-c"]), d_corpus, d_output).unwrap_err();
        assert!(err.contains("missing value for -c"), "{err}");
    }

    #[test]
    fn duplicate_flag_is_rejected() {
        let (d_corpus, d_output) = defaults();
        let err = parse_args(&args(&["-c", "a", "-c", "b"]), d_corpus, d_output).unwrap_err();
        assert!(err.contains("corpus specified twice"), "{err}");
    }

    #[test]
    fn extra_positional_is_rejected() {
        let (d_corpus, d_output) = defaults();
        let err = parse_args(&args(&["a", "b", "c"]), d_corpus, d_output).unwrap_err();
        assert!(err.contains("unexpected extra argument: c"), "{err}");
    }

    #[test]
    fn help_flag_wins() {
        let (d_corpus, d_output) = defaults();
        assert!(matches!(
            parse_args(&args(&["--help"]), d_corpus, d_output),
            Ok(Parsed::Help)
        ));
        let (d_corpus, d_output) = defaults();
        assert!(matches!(
            parse_args(&args(&["-c", "dir", "-h"]), d_corpus, d_output),
            Ok(Parsed::Help)
        ));
    }
}
