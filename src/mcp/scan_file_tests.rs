// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the `frensense_scan_file` MCP tool. Coverage mirrors the
//! delivery-adapter surface: gating, argument handling, filtering, and
//! one end-to-end scan through the real engine (deterministic weak-hash
//! fixture, no bundle needed).

use super::*;
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("frensense-scanfile-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[test]
fn tool_definition_shape() {
    let def = tool_definition();
    assert_eq!(def["name"], "frensense_scan_file");
    assert_eq!(def["inputSchema"]["required"][0], "path");
    assert!(def["description"].as_str().unwrap().contains("ONE source file"));
    // Distinct from the directory-audit tool.
    assert_ne!(def["name"], audit_tool_name());
}

fn audit_tool_name() -> String {
    super::super::audit::tool_definition()["name"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn supported_gate_follows_specs() {
    assert!(is_supported(Path::new("foo.py")));
    assert!(is_supported(Path::new("foo.ts")));
    assert!(is_supported(Path::new("foo.rs")));
    assert!(!is_supported(Path::new("foo.txt")));
    assert!(!is_supported(Path::new("foo.md")));
    assert!(!is_supported(Path::new("noext")));
}

#[test]
fn filter_respects_severity_and_confidence() {
    use crate::Severity;
    let mk = |sev: Severity, conf: f64| {
        let mut a = Advisory::bare(
            "t",
            sev,
            crate::FileId(0),
            Path::new("f.py"),
            "obs",
        );
        a.confidence = conf;
        a
    };
    let all = vec![
        mk(Severity::Critical, 0.9),
        mk(Severity::Warning, 0.5),
        mk(Severity::Info, 0.2),
    ];
    assert_eq!(filter_advisories(all.clone(), "info", 0.0).len(), 3);
    assert_eq!(filter_advisories(all.clone(), "warning", 0.0).len(), 2);
    assert_eq!(filter_advisories(all.clone(), "critical", 0.0).len(), 1);
    // Confidence floor drops the 0.2-confidence info finding.
    assert_eq!(filter_advisories(all, "info", 0.3).len(), 2);
}

#[test]
fn missing_and_nonexistent_path_errors() {
    let out = run_scan_file(&serde_json::json!({}));
    assert_eq!(out["error"], "missing required argument: path");

    let out = run_scan_file(&serde_json::json!({"path": "/definitely/not/here.py"}));
    assert!(out["error"].as_str().unwrap().contains("does not exist"));
}

#[test]
fn unsupported_extension_is_tool_level_outcome() {
    let dir = tempdir("unsupported");
    let f = dir.join("notes.txt");
    std::fs::write(&f, "hello").unwrap();
    let out = run_scan_file(&serde_json::json!({ "path": f.display().to_string() }));
    assert_eq!(out["unsupported_file"], true);
    assert!(out["advisories"].as_array().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn end_to_end_finds_and_reports_clean() {
    let dir = tempdir("e2e");
    let dirty = dir.join("bug.py");
    std::fs::write(
        &dirty,
        "import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();
    let clean = dir.join("ok.py");
    std::fs::write(&clean, "x = 1\n").unwrap();

    let out = run_scan_file(&serde_json::json!({ "path": dirty.display().to_string() }));
    assert_eq!(out["clean"], false);
    assert_eq!(out["file"], dirty.display().to_string());
    let advs = out["advisories"].as_array().unwrap();
    assert_eq!(advs.len(), 1);
    assert_eq!(advs[0]["file_path"], dirty.display().to_string());
    assert!(advs[0]["line"].as_u64().unwrap() >= 1);

    let out = run_scan_file(&serde_json::json!({ "path": clean.display().to_string() }));
    assert_eq!(out["clean"], true);
    assert_eq!(out["message"], "no findings");
    assert!(out["advisories"].as_array().unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn result_payload_labels_file() {
    let p = Path::new("/tmp/x.py");
    let payload = result_payload(p, &[]);
    assert_eq!(payload["file"], "/tmp/x.py");
    assert_eq!(payload["clean"], true);
}

#[test]
fn corpus_bundle_extends_fact_tables() {
    // A bundle whose learned facts (Source: random.randint,
    // Sink: codecs.open) fire on a file the built-in tables don't flag.
    let dir = tempdir("bundle");
    let file = dir.join("flow.py");
    std::fs::write(
        &file,
        "import codecs\nimport random\n\n\ndef read_user(path):\n    n = random.randint(0, 99)\n    f = codecs.open(path + str(n), \"r\", \"utf-8\")\n    return f.read()\n",
    )
    .unwrap();

    // No bundle → clean (built-in tables don't know random.randint or
    // codecs.open in these roles).
    let out = run_scan_file(&json!({ "path": file.display().to_string() }));
    assert_eq!(out["clean"], true, "no bundle: expected clean");

    // With a bundle → the learned source/sink pair fires. The bundle
    // bytes are generated by the bundler example; if it's not available
    // in the test environment the pre-check below fails loudly rather
    // than passing vacuously.
    let bundle = bundle_fixture_path();
    let out = run_scan_file(&json!({
        "path": file.display().to_string(),
        "corpus_bundle": bundle.display().to_string(),
    }));
    assert_eq!(out["clean"], false, "with bundle: expected findings");
    let advs = out["advisories"].as_array().unwrap();
    assert!(
        advs.iter().any(|a| a["title"].as_str().unwrap().contains("random.randint")),
        "expected a learned-source finding, got {advs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Path to the fixture bundle, generated on demand by the bundler's
/// `make_test_bundle` example (writes /tmp/cwe-bundle.frc).
fn bundle_fixture_path() -> PathBuf {
    let path = std::path::PathBuf::from("/tmp/cwe-bundle.frc");
    if !path.exists() {
        let out = std::process::Command::new("cargo")
            .args(["build", "--release", "--example", "make_test_bundle", "-p", "frensense-bundler"])
            .output()
            .expect("spawn cargo");
        assert!(out.status.success(), "build bundle example failed");
        let out = std::process::Command::new(
            concat!(env!("CARGO_MANIFEST_DIR"), "/target/release/examples/make_test_bundle"),
        )
        .output()
        .expect("run make_test_bundle");
        assert!(out.status.success(), "generate bundle failed");
    }
    path
}

#[test]
fn missing_corpus_bundle_is_a_tool_error() {
    let dir = tempdir("missingbundle");
    let file = dir.join("ok.py");
    std::fs::write(&file, "x = 1\n").unwrap();
    let out = run_scan_file(&json!({
        "path": file.display().to_string(),
        "corpus_bundle": "/definitely/not/here.frc",
    }));
    assert!(out["error"].as_str().unwrap().contains("corpus bundle does not exist"));
    let _ = std::fs::remove_dir_all(&dir);
}
