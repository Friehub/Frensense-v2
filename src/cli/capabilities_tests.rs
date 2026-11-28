// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Tests for `frensense capabilities`: the report must describe the pack that
//! is actually embedded, and CWE expressibility must come from the shipped
//! rule cards, not from a hand-written list.

use super::capabilities::{cwe_entry, render, report};

#[test]
fn report_describes_the_embedded_pack() {
    let report = report();
    let facts = report
        .pointer("/engine/default_pack/facts")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    assert!(facts > 1_000, "default pack carries {facts} facts");

    let languages = report["languages"]
        .as_object()
        .expect("languages is an object");
    assert!(
        languages.len() >= 4,
        "expected at least four languages, got {:?}",
        languages.keys().collect::<Vec<_>>()
    );

    let python = languages.get("python").expect("python vocabulary");
    assert!(
        python["sinks"]["total"].as_u64().unwrap_or(0) > 50,
        "python sinks: {python}"
    );
    assert!(
        python["sources"]["total"].as_u64().unwrap_or(0) > 10,
        "python sources: {python}"
    );
    assert!(
        python["sanitizers"]["total"].as_u64().unwrap_or(0) > 5,
        "python sanitizers: {python}"
    );
}

#[test]
fn every_sink_is_grouped_under_a_known_role() {
    let report = report();
    let known = [
        "execution",
        "resource",
        "storage",
        "crypto",
        "response",
        "xss",
        "validation",
        "other",
    ];
    let languages = report["languages"].as_object().expect("languages");
    for (name, vocab) in languages {
        let Some(roles) = vocab["sinks"]["by_role"].as_object() else {
            continue;
        };
        for role in roles.keys() {
            assert!(
                known.contains(&role.as_str()),
                "{name} sink role `{role}` is not a SinkRole name"
            );
        }
    }
}

#[test]
fn every_class_reports_its_role_vocabulary_per_language() {
    let report = report();
    let languages = report["languages"].as_object().expect("languages");
    let classes = report["classes"].as_array().expect("classes");
    let mut dataflow = 0;
    for class in classes {
        let Some(role) = class["role"].as_str() else {
            assert_eq!(
                class["sinks_by_language"],
                serde_json::json!({}),
                "check rules consume no sink role: {class}"
            );
            continue;
        };
        let counts = class["sinks_by_language"]
            .as_object()
            .unwrap_or_else(|| panic!("class {class} has no per-language counts"));
        assert_eq!(
            counts.len(),
            languages.len(),
            "one column per language: {class}"
        );
        for (name, vocab) in languages {
            let expected = vocab["sinks"]["by_role"][role]["total"]
                .as_u64()
                .unwrap_or(0);
            assert_eq!(
                counts[name].as_u64(),
                Some(expected),
                "{name} `{role}` count disagrees with the language block"
            );
        }
        dataflow += 1;
    }
    assert!(
        dataflow > 10,
        "expected many dataflow classes, got {dataflow}"
    );

    let sql = classes
        .iter()
        .find(|c| c["id"] == serde_json::json!("taint.sql-injection"))
        .expect("sql-injection class");
    assert!(
        sql["sinks_by_language"]["python"].as_u64().unwrap_or(0) > 0,
        "sql-injection must see sinks in python: {sql}"
    );
}

#[test]
fn text_class_table_shows_the_joined_counts() {
    let text = render(&report());
    let row = text
        .lines()
        .find(|line| line.trim_start().starts_with("taint.sql-injection"))
        .expect("sql-injection row");
    let numbers = row
        .split_whitespace()
        .filter(|token| token.parse::<u64>().is_ok())
        .count();
    assert!(numbers >= 4, "row carries per-language sink counts: {row}");
}

#[test]
fn a_cwe_a_built_in_card_names_is_expressible() {
    let report = report();
    let entry = cwe_entry(&report, "CWE-89");
    assert_eq!(entry["expressible"], serde_json::json!(true), "{entry}");
    assert_eq!(entry["via"], serde_json::json!("taint"), "{entry}");
    assert_eq!(
        entry["class"],
        serde_json::json!("taint.sql-injection"),
        "{entry}"
    );
    assert_eq!(entry["role"], serde_json::json!("execution"), "{entry}");
}

#[test]
fn a_cwe_no_card_names_is_not_expressible() {
    let report = report();
    let entry = cwe_entry(&report, "cwe-99999");
    assert_eq!(entry["expressible"], serde_json::json!(false), "{entry}");
    assert!(
        entry["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "{entry}"
    );
    assert_eq!(entry["cwe"], serde_json::json!("CWE-99999"), "{entry}");
}

#[test]
fn text_render_names_the_vocabulary_and_classes() {
    let text = render(&report());
    assert!(text.contains("Language vocabulary"), "{text}");
    assert!(text.contains("python"), "{text}");
    assert!(text.contains("taint.sql-injection"), "{text}");
}
