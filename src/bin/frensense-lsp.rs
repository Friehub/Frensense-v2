// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//! `frensense-lsp` — Language Server Protocol adapter (stdio).
//!
//! Thin entry point: framing + dispatch live in `frensense::lsp`. Edit
//! this file only to change process-level concerns (env, logging).

fn main() {
    let bundle = std::env::var("FRENSENSE_CORPUS_BUNDLE").ok().filter(|p| !p.is_empty());
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    if let Err(e) = frensense::lsp::server::run_server(&mut reader, &mut writer, bundle.as_deref()) {
        eprintln!("frensense-lsp: fatal transport error: {e}");
        std::process::exit(1);
    }
}
