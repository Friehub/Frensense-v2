// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! packgen: generate the frensense default `.frc` pack asset.
//!
//! `packgen --check`  Regenerate in memory and compare against the
//!                    committed asset; exit 1 with a drift report when
//!                    stale (the CI gate).
//! `packgen --out [<path>]`
//!                    Write the regenerated asset (default:
//!                    `frensense-bundler/assets/frensense-default.frc`).
//!                    Use after changing generator-owned vocabularies.

use std::path::PathBuf;

use frensense_bundler::format::{load_bundle, LoadedBundle};

const DEFAULT_ASSET: &str = "frensense-bundler/assets/frensense-default.frc";

fn asset_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(DEFAULT_ASSET)
}

/// First differing entry between the generated and the committed fact
/// lists, for a readable `--check` failure message.
fn first_drift(
    generated: &[frensense_engine::analysis::taint::facts::LearnedFactEntry],
    committed: &[frensense_engine::analysis::taint::facts::LearnedFactEntry],
) -> Option<(usize, String, String)> {
    let n = generated.len().max(committed.len());
    for i in 0..n {
        match (generated.get(i), committed.get(i)) {
            (None, Some(c)) => return Some((i, "missing".to_string(), format!("{c:?}"))),
            (Some(g), None) => return Some((i, format!("{g:?}"), "missing".to_string())),
            (Some(g), Some(c)) if g != c => return Some((i, format!("{g:?}"), format!("{c:?}"))),
            _ => {}
        }
    }
    None
}

fn check() -> i32 {
    let path = asset_path();
    let generated = frensense_packgen::build_default_bundle();
    let committed = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!(
                "packgen: cannot read committed asset {}: {e}",
                path.display()
            );
            return 1;
        }
    };
    if generated == committed {
        println!(
            "packgen: committed asset is up to date ({} bytes)",
            committed.len()
        );
        return 0;
    }
    eprintln!(
        "packgen: {} is out of date (committed {} bytes, generated {} bytes)",
        path.display(),
        committed.len(),
        generated.len()
    );
    // Best-effort readable diff: compare the decoded fact lists.
    let gen = load_bundle(&generated);
    let com = load_bundle(&committed);
    if let (Ok(g), Ok(c)) = (gen, com) {
        let (g, c): (&LoadedBundle, &LoadedBundle) = (&g, &c);
        eprintln!(
            "packgen: facts committed {} vs generated {}",
            c.learned_facts.len(),
            g.learned_facts.len()
        );
        if let Some((i, gv, cv)) = first_drift(&g.learned_facts, &c.learned_facts) {
            eprintln!("packgen: first drift at fact #{i}:");
            eprintln!("packgen:   generated: {gv}");
            eprintln!("packgen:   committed: {cv}");
        }
    }
    eprintln!("packgen: regenerate with `cargo run -p frensense-packgen -- --out`");
    1
}

fn out(path: Option<&str>) -> i32 {
    let path = path.map_or_else(asset_path, PathBuf::from);
    let bytes = frensense_packgen::build_default_bundle();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&path, &bytes) {
        Ok(()) => {
            println!("packgen: wrote {} ({} bytes)", path.display(), bytes.len());
            0
        }
        Err(e) => {
            eprintln!("packgen: cannot write {}: {e}", path.display());
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        None | Some("--check") => check(),
        Some("--out") => out(args.get(1).map(String::as_str)),
        Some(flag) => {
            eprintln!("packgen: unknown flag {flag}; usage: packgen [--check | --out [<path>]]");
            2
        }
    };
    std::process::exit(code);
}
