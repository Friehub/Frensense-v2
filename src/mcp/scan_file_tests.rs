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
