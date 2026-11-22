// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Config-declared sinks (`sinks:` in `TaintConfig`) carry no vocabulary
//! label at taint time. A class-scoped sanitizer must still match them via a
//! conservative name->class fallback, and must still refuse a different class.

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{FactTable, SanitizerFact};

fn config() -> TaintConfig {
    TaintConfig {
        sources: ["req.body", "req.query"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        sinks: ["query", "execute", "eval"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        sanitizers: Default::default(),
    }
}

/// One fact table with the guard-style `isSafeQuery` sanitizer installed and,
/// when `classes` is non-empty, re-scoped to exactly those sink classes (the
/// same `scope_sanitizer` call a consumer bundle makes after installing the
/// fact).
fn table(classes: &[&str]) -> FactTable {
    let mut facts = FactTable::from_config(&config());
    facts.sanitizer_facts.insert(
        "isSafeQuery".to_string(),
        SanitizerFact {
            call: "isSafeQuery".to_string(),
            package: None,
            kind: "allowlist".to_string(),
            sanitizes_args: Default::default(),
            guard_style: true,
        },
    );
    if !classes.is_empty() {
        let classes: Vec<String> = classes.iter().map(|c| c.to_string()).collect();
        assert!(facts.scope_sanitizer("isSafeQuery", None, &classes));
    }
    facts
}

const POS: &str =
    "function handler(req: any) {\n    const id = req.body.id;\n    db.query(id);\n}\n";
const NEG: &str = "function handler(req: any) {\n    const id = req.body.id;\n    if (isSafeQuery(id)) {\n        db.query(id);\n    }\n}\n";

fn scan(
    src: &str,
    facts: &FactTable,
) -> Vec<frensense_engine::analysis::taint::engine::BackwardVerdict> {
    frensense_engine::scan::scan(
        &[("a.ts".to_string(), src.to_string(), "ts".to_string())],
        &config(),
        facts,
    )
    .findings
    .iter()
    .map(|f| f.verdict.clone())
    .collect()
}

#[test]
fn config_sink_is_class_matched() {
    use frensense_engine::analysis::taint::engine::BackwardVerdict::Vulnerable;

    let sql = table(&["inj.sql"]);
    assert!(
        scan(POS, &sql).contains(&Vulnerable),
        "positive must still alert"
    );
    assert!(
        !scan(NEG, &sql).contains(&Vulnerable),
        "negative must be silenced by the class-scoped guard"
    );

    // A fact scoped to another class must NOT silence a SQL sink.
    let command = table(&["inj.command"]);
    assert!(
        scan(NEG, &command).contains(&Vulnerable),
        "a command-class fact must not silence a SQL sink"
    );

    // A wildcard scope covers every class.
    let wildcard = table(&["*"]);
    assert!(
        !scan(NEG, &wildcard).contains(&Vulnerable),
        "a wildcard scope must silence the SQL sink"
    );
}

/// A guard-style cut must be auditable like a call-style one: the finding
/// carries the sanitizer fact that silenced it and the classes it was proven
/// for, so `--show-suppressed` can name it. Before this, a guard silenced the
/// walk and left no trace, which made a poisoned guard invisible.
#[test]
fn guard_cut_records_the_fact_that_made_it() {
    let facts = table(&["inj.sql"]);
    let out = frensense_engine::scan::scan(
        &[("a.ts".to_string(), NEG.to_string(), "ts".to_string())],
        &config(),
        &facts,
    );
    let suppressions: Vec<_> = out
        .findings
        .iter()
        .flat_map(|f| f.suppressions.iter())
        .collect();
    assert!(
        suppressions
            .iter()
            .any(|s| s.call == "isSafeQuery" && s.classes == ["inj.sql"]),
        "guard suppression not recorded: {suppressions:?}"
    );

    // A guard proven for another class cuts nothing, so records nothing.
    let other = table(&["inj.command"]);
    let out = frensense_engine::scan::scan(
        &[("a.ts".to_string(), NEG.to_string(), "ts".to_string())],
        &config(),
        &other,
    );
    assert!(
        out.findings.iter().all(|f| f.suppressions.is_empty()),
        "a guard that did not cut must not be reported as suppressing"
    );
}
