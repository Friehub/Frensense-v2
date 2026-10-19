// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Modular Dataflow Consistency Probe Test Harness.
//!
//! Submodules cover the frontier diagnostic domains:
//! - `path_sensitivity_tests`: Guard dominance, early returns, branch feasibility
//! - `async_concurrency_tests`: EventEmitter, timers, microtask queues
//! - `multi_lang_tests`: Go channels/structs and Rust Command/Result
//! - `sanitizer_matrix_tests`: Multi-step pipelines and regex bypasses
//! - `cve_reproductions_tests`: Minimal reproductions of historic CVE signatures
//! - `framework_ioc_tests`: Express, Flask, and NestJS route entrypoints

use crate::analysis::taint::engine::BackwardVerdict;
use crate::analysis::taint::facts::seeded_tables;
use crate::scan::{ScanResult, scan};

pub fn scan_files(files: &[(&str, &str, &str)]) -> ScanResult {
    // Scope the fact tables to the languages under test, exactly as the CLI
    // does for the files it is given. Merging EVERY language's vocabulary
    // instead drags in same-named facts from unrelated ecosystems - the JS
    // sanitizer `format` (knex/pg SQL parameterization) cut Rust `format!`
    // flows - which no real scan would ever do, so a probe could fail on
    // vocabulary the product never applies to that file.
    let exts: Vec<&str> = files.iter().map(|(_, _, e)| *e).collect();
    let (config, facts) = seeded_tables(exts);
    let file_tuples: Vec<(String, String, String)> = files
        .iter()
        .map(|(p, s, e)| (p.to_string(), s.to_string(), e.to_string()))
        .collect();
    scan(&file_tuples, &config, &facts)
}

pub fn scan_ts(src: &str) -> ScanResult {
    scan_files(&[("app/probe.ts", src, "ts")])
}

pub fn scan_py(src: &str) -> ScanResult {
    scan_files(&[("app/probe.py", src, "py")])
}

#[allow(dead_code)]
pub fn scan_c(src: &str) -> ScanResult {
    scan_files(&[("app/probe.c", src, "c")])
}

pub fn scan_go(src: &str) -> ScanResult {
    scan_files(&[("app/probe.go", src, "go")])
}

pub fn scan_rust(src: &str) -> ScanResult {
    scan_files(&[("app/probe.rs", src, "rs")])
}

pub fn assert_detected(res: &ScanResult, probe_name: &str, expected_sink: &str) {
    let found = res.located.iter().any(|l| {
        l.finding.sink.contains(expected_sink) && l.finding.verdict == BackwardVerdict::Vulnerable
    });
    assert!(
        found,
        "PROBE FAILED: [{probe_name}] expected vulnerable sink '{expected_sink}' not detected.\nFindings: {:?}",
        res.located
            .iter()
            .map(|l| (&l.file, &l.finding.sink, l.line, l.finding.verdict.clone()))
            .collect::<Vec<_>>()
    );
}

pub fn assert_clean(res: &ScanResult, probe_name: &str) {
    let vulnerable: Vec<_> = res
        .located
        .iter()
        .filter(|l| l.finding.verdict == BackwardVerdict::Vulnerable)
        .collect();
    assert!(
        vulnerable.is_empty(),
        "PROBE FAILED (FALSE POSITIVE): [{probe_name}] expected clean, but detected:\nFindings: {:?}",
        vulnerable
            .iter()
            .map(|l| (&l.file, &l.finding.sink, l.line))
            .collect::<Vec<_>>()
    );
}

mod async_concurrency_tests;
mod cve_reproductions_tests;
mod extractor_source_tests;
mod financial_enterprise_tests;
mod framework_ioc_tests;
mod multi_lang_tests;
mod path_sensitivity_tests;
mod sanitizer_matrix_tests;
mod sink_identity_tests;
