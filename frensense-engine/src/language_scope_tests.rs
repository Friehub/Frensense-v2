// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Language scoping of the default pack's provider vocabulary.
//!
//! A bare call name is not portable across languages. The pack declares
//! `create` for Rust (`File::create`, path traversal) and `update` for
//! TypeScript (mongoose), `input` as a TypeScript request-parameter source
//! and `std::env::var` as a Rust one. Installing those into one shared name
//! space made every one of them apply to every file: adding a single `.rs`
//! file to a TypeScript-only package turned a clean scan into dozens of
//! `prisma.model.create(...)` findings, and a TypeScript-only source name
//! seeded taint in Rust.
//!
//! These fixtures scan a *mixed-language* program (the shape that used to
//! leak) and assert both directions:
//!
//! 1. Nothing crosses over: the Rust `create` signature does not arm a
//!    TypeScript `create`, and a TypeScript source name does not seed a Rust
//!    flow.
//! 2. Recall is kept: every language still reports its own flows.
//!
//! They run against the real default pack, so the vocabulary cannot drift
//! out from under the assertions.

#[cfg(test)]
#[allow(clippy::module_inception)] // test file convention: module name repeats parent path segment
pub mod language_scope_tests {
    use crate::analysis::taint::engine::SinkFinding;
    use crate::analysis::taint::facts::seeded_tables;
    use crate::scan::{prepare, scan_prepared};

    /// TypeScript: `prisma.order.create(...)` (not a sink anywhere) beside a
    /// real `fetch` sink, so the same file also proves TypeScript detection
    /// still works in a mixed-language scan.
    const TS_SOURCE: &str = r#"
export async function handler(req: any, prisma: any) {
  await prisma.order.create({ data: { ref: req.body.ref } });
  return fetch(req.body.url);
}
"#;

    /// Rust: `File::create` fed by a process environment variable - the
    /// language's own sink and its own source.
    const RUST_SINK_FLOW: &str = r#"
use std::fs::File;

pub fn open_target() {
    let path = std::env::var("TARGET").unwrap();
    let _f = File::create(path);
}
"#;

    /// Rust: a parameter that happens to be named `input` - a TypeScript
    /// request-parameter name and a meaningless one in Rust.
    const RUST_NAMED_INPUT: &str = r#"
use std::fs::File;

pub fn open_target(input: String) {
    let _f = File::create(input);
}
"#;

    fn scan(files: &[(&str, &str, &str)]) -> Vec<SinkFinding> {
        let files: Vec<(String, String, String)> = files
            .iter()
            .map(|(p, s, e)| ((*p).to_string(), (*s).to_string(), (*e).to_string()))
            .collect();
        let exts: Vec<&str> = files.iter().map(|(_, _, ext)| ext.as_str()).collect();
        let (config, facts) = seeded_tables(exts);
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts).findings
    }

    fn sinks_on(findings: &[SinkFinding], file_sink: &str) -> Vec<String> {
        findings
            .iter()
            .filter(|f| f.sink == file_sink)
            .map(|f| f.sink.clone())
            .collect()
    }

    /// `create` is a Rust sink (path traversal). A TypeScript
    /// `prisma.order.create(...)` must not match it just because the scan
    /// also contains Rust code.
    #[test]
    fn rust_sink_does_not_fire_in_typescript_file() {
        let ts_only = scan(&[("api.ts", TS_SOURCE, "ts")]);
        let mixed = scan(&[
            ("api.ts", TS_SOURCE, "ts"),
            ("tool.rs", RUST_SINK_FLOW, "rs"),
        ]);

        assert!(
            sinks_on(&ts_only, "create").is_empty(),
            "TypeScript-only baseline must not flag create; got {ts_only:?}"
        );
        assert!(
            sinks_on(&mixed, "create").is_empty(),
            "adding a Rust file must not arm `create` in TypeScript; got {mixed:?}"
        );
        assert!(
            mixed.iter().any(|f| f.sink == "fetch"),
            "the TypeScript sink in the same mixed scan must still fire; got {mixed:?}"
        );
    }

    /// The same `create` call in Rust is the language's own sink and must
    /// keep firing after scoping (the fix must not cost recall).
    #[test]
    fn rust_sink_still_fires_in_rust_file() {
        let findings = scan(&[("tool.rs", RUST_SINK_FLOW, "rs")]);
        assert!(
            findings.iter().any(|f| f.sink.contains("create")),
            "Rust File::create must stay armed for Rust code; got {findings:?}"
        );
    }

    /// `input` is a TypeScript request-parameter source. In Rust it is an
    /// ordinary parameter: a bare name must not seed taint across languages.
    ///
    /// The call still surfaces as an unresolved (Unknown) sink argument,
    /// which is reported as coverage; what must not happen is a Proven flow
    /// whose source is the borrowed name.
    #[test]
    fn typescript_source_name_does_not_seed_rust_taint() {
        let findings = scan(&[("tool.rs", RUST_NAMED_INPUT, "rs")]);
        let seeded: Vec<&SinkFinding> = findings
            .iter()
            .filter(|f| f.verdict == crate::analysis::taint::engine::BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            seeded.is_empty(),
            "a Rust parameter named `input` is not attacker data; got {seeded:?}"
        );
        assert!(
            findings.iter().all(|f| f.source_desc.is_none()),
            "no source may be borrowed from another language; got {findings:?}"
        );
    }

    /// The fact table itself keeps the sections apart: the language-agnostic
    /// lane holds neither language's `create`, and each language's own lane
    /// resolves it.
    #[test]
    fn language_sections_are_kept_apart() {
        let (_, facts) = seeded_tables(["ts", "rs"]);

        assert!(
            !facts.sink_signatures.contains_key("create"),
            "a language-keyed sink must not be published to the shared name space"
        );
        assert!(
            facts
                .sink_signature_for_language("create", Some("rust"))
                .is_some(),
            "Rust's create must resolve under the Rust key"
        );
        assert!(
            facts
                .sink_signature_for_language("create", Some("typescript"))
                .is_none(),
            "TypeScript must not inherit Rust's create"
        );

        // `req.query` is a TypeScript request accessor; a Rust parameter is
        // never named that. (The bare name `input` used to stand here, but
        // it is no longer a JavaScript request-parameter source: every
        // variable called `input` was treated as attacker data, a
        // false-discovery class the pack dropped. The language-separation
        // guarantee needs a name that is unambiguously language-specific.)
        let ts_sources = facts
            .language_sources("typescript")
            .expect("TypeScript source section");
        assert!(
            ts_sources.contains("req.query"),
            "ts sources: {ts_sources:?}"
        );
        assert!(
            !facts
                .language_sources("rust")
                .is_some_and(|s| s.contains("req.query")),
            "Rust must not inherit TypeScript's request-parameter names"
        );
    }
}
