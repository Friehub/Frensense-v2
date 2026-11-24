// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Text rendering for `frensense capabilities`.

use serde_json::Value;

/// Column label for a language in the class table.
fn short_language(name: &str) -> &str {
    match name {
        "javascript" => "js",
        "typescript" => "ts",
        "python" => "py",
        "rust" => "rs",
        "ruby" => "rb",
        other => other,
    }
}

fn num(value: &Value, path: &[&str]) -> u64 {
    let mut cursor = value;
    for key in path {
        match cursor.get(key) {
            Some(next) => cursor = next,
            None => return 0,
        }
    }
    cursor.as_u64().unwrap_or(0)
}

/// Render the report as text. Kept separate from `report` so the library
/// returns a string and the binary owns printing.
#[must_use]
pub fn render(report: &Value) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let version = report
        .pointer("/engine/version")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let blake3 = report
        .pointer("/engine/default_pack/blake3")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let _ = writeln!(
        out,
        "frensense {version} · default pack {blake3} · {} facts",
        num(report, &["engine", "default_pack", "facts"])
    );
    let _ = writeln!(
        out,
        "  sinks {} · sources {} · sanitizers {} · checks {} · memory {} · propagators {}",
        num(report, &["engine", "default_pack", "sinks"]),
        num(report, &["engine", "default_pack", "sources"]),
        num(report, &["engine", "default_pack", "sanitizers"]),
        num(report, &["engine", "default_pack", "checks"]),
        num(report, &["engine", "default_pack", "memory_contracts"]),
        num(report, &["engine", "default_pack", "propagators"]),
    );

    if let Some(languages) = report.get("languages").and_then(Value::as_object) {
        let _ = writeln!(out, "\nLanguage vocabulary");
        let _ = writeln!(
            out,
            "  {:<12} {:>7} {:>9} {:>12} {:>8}",
            "language", "sinks", "sources", "sanitizers", "route"
        );
        for (name, vocab) in languages {
            let _ = writeln!(
                out,
                "  {name:<12} {:>7} {:>9} {:>12} {:>8}",
                num(vocab, &["sinks", "total"]),
                num(vocab, &["sources", "total"]),
                num(vocab, &["sanitizers", "total"]),
                num(vocab, &["routes"]),
            );
        }
    }

    let classes = report
        .get("classes")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let taint = classes
        .iter()
        .filter(|c| c.get("kind").and_then(Value::as_str) == Some("taint"))
        .count();
    // Each class already carries its role's sink counts per language, so the
    // table below is the answer to "what can this class see in Python?"
    // without the reader joining `classes` to `languages` by hand.
    let columns: Vec<(String, &str)> = report
        .get("languages")
        .and_then(Value::as_object)
        .map(|langs| {
            langs
                .keys()
                .map(|name| (short_language(name).to_string(), name.as_str()))
                .collect()
        })
        .unwrap_or_default();
    let _ = writeln!(out, "\nClasses ({taint} dataflow, {} total)", classes.len());
    let _ = write!(out, "  {:<32} {:<17} {:<13}", "class", "cwe", "role");
    for (short, _) in &columns {
        let _ = write!(out, " {short:>3}");
    }
    let _ = writeln!(out);
    for class in classes {
        let id = class.get("id").and_then(Value::as_str).unwrap_or("?");
        let role = class.get("role").and_then(Value::as_str).unwrap_or("-");
        let cwe = class
            .get("cwe")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let _ = write!(out, "  {id:<32} {cwe:<17} {role:<13}");
        for (_, language) in &columns {
            match class
                .get("sinks_by_language")
                .and_then(Value::as_object)
                .and_then(|counts| counts.get(*language))
                .and_then(Value::as_u64)
            {
                Some(count) => {
                    let _ = write!(out, " {count:>3}");
                }
                None => out.push_str("   -"),
            }
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(
        out,
        "\n  counts are the sinks of each class's role in that language."
    );

    let cwe_count = report
        .get("cwe")
        .and_then(Value::as_object)
        .map_or(0, serde_json::Map::len);
    let _ = writeln!(
        out,
        "\n{}/1000 CWE ids are expressible by a built-in card today; \
         `--cwe <id>` checks one.",
        cwe_count.min(1000)
    );
    out
}
