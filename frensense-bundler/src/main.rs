// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Frensense bundler CLI: builds a `.frc` facts bundle from positive/negative
//! corpus pairs.
//!
//! Usage: frensense-bundler <corpus_dir> <output.frc> [--facts]

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").map_or_else(|_| env::current_dir().unwrap(), PathBuf::from);
    let workspace_root = manifest_dir.parent().unwrap();

    let args: Vec<String> = env::args().collect();
    let corpus_dir = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("corpus").join("targets"));
    let output_path = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root.join("frensense-corpus.frc"));

    if let Err(e) = frensense_bundler::run_facts_pipeline(&corpus_dir, &output_path) {
        eprintln!("Error in facts pipeline: {e}");
        std::process::exit(1);
    }
}
