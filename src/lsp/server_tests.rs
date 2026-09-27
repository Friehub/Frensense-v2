// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the LSP server: URI conversion, advisory→diagnostic
//! mapping, and full protocol round-trips over in-memory streams with
//! the real engine.

use super::*;
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("frensense-lsp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[test]
fn uri_conversion_round_trips() {
    assert_eq!(uri_to_path("file:///tmp/x.py"), "/tmp/x.py");
    assert_eq!(uri_to_path("file:///a%20b/c.py"), "/a b/c.py");
    assert_eq!(uri_to_path("/plain/path.rs"), "/plain/path.rs");
    assert_eq!(path_to_uri("/tmp/x.py"), "file:///tmp/x.py");
    assert_eq!(path_to_uri("/a b/c.py"), "file:///a%20b/c.py");
    // Round trip.
    assert_eq!(
        uri_to_path(&path_to_uri("/dir with space/f.py")),
        "/dir with space/f.py"
    );
}

#[test]
fn severity_mapping_matches_lsp_codes() {
    assert_eq!(severity_code(Severity::Critical), 1);
    assert_eq!(severity_code(Severity::Warning), 2);
    assert_eq!(severity_code(Severity::Info), 3);
}

#[test]
fn diagnostic_range_is_zero_based_and_code_is_stable_id() {
    let mut adv = Advisory::bare(
        "Policy violation: weak_hash (digest)",
        Severity::Warning,
        crate::FileId(0),
        std::path::Path::new("/t/app.py"),
        "Weak hash function `md5`",
    )
    .with_line(5)
    .with_column(12);
    adv.fingerprint = "abcd1234abcd1234".into();
    let d = diagnostic_from_advisory(&adv);
    assert_eq!(d["range"]["start"]["line"], 4);
    assert_eq!(d["range"]["start"]["character"], 11);
    assert_eq!(d["severity"], 2);
    assert_eq!(d["source"], "frensense");
    assert_eq!(d["code"], adv.stable_id());
    assert!(d["message"].as_str().unwrap().contains("md5"));
}

#[test]
fn diagnostics_from_real_scan_and_unsupported_clearing() {
    let dir = tempdir("diag");
    let file = dir.join("app.py");
    std::fs::write(
        &file,
        "import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();

    let mut engine = Engine::new();
    let diags = diagnostics_for_file(&mut engine, &file).expect("scan");
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0]["range"]["start"]["line"], 4);

    // Unsupported extension → empty array (clears), not an error.
    let txt = dir.join("notes.txt");
    std::fs::write(&txt, "hello").unwrap();
    let diags = diagnostics_for_file(&mut engine, &txt).expect("scan txt");
    assert!(diags.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn protocol_round_trip_open_save_close() {
    let dir = tempdir("proto");
    let file = dir.join("app.py");
    std::fs::write(
        &file,
        "import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();
    let uri = path_to_uri(&file.display().to_string());

    // Drive the server with a scripted client session.
    let mut input = Vec::new();
    for msg in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","method":"initialized","params":{}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":uri,"languageId":"python","version":1,"text":"x"}}}),
        json!({"jsonrpc":"2.0","method":"textDocument/didClose","params":{"textDocument":{"uri":uri}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"shutdown"}),
        json!({"jsonrpc":"2.0","method":"exit"}),
    ] {
        write_message(&mut input, &msg.to_string()).unwrap();
    }
    let mut reader: &[u8] = &input;
    let mut output = Vec::new();
    run_server(&mut reader, &mut output, None).expect("server run");

    // Parse the framed output stream.
    let mut out_reader: &[u8] = &output;
    let mut messages = Vec::new();
    while let Some(body) = read_message(&mut out_reader).unwrap() {
        messages.push(serde_json::from_str::<Value>(&body).unwrap());
    }

    // initialize response.
    assert_eq!(messages[0]["id"], 1);
    assert_eq!(messages[0]["result"]["serverInfo"]["name"], "frensense-lsp");
    assert_eq!(
        messages[0]["result"]["capabilities"]["textDocumentSync"]["change"],
        1
    );

    // didOpen → publishDiagnostics with the md5 finding.
    let publish = &messages[1];
    assert_eq!(publish["method"], "textDocument/publishDiagnostics");
    assert_eq!(publish["params"]["uri"], uri);
    let diags = publish["params"]["diagnostics"].as_array().unwrap();
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0]["range"]["start"]["line"], 4);
    assert!(diags[0]["code"].as_str().unwrap().starts_with("FRN-"));

    // didClose → publishDiagnostics with an empty array.
    let cleared = &messages[2];
    assert_eq!(cleared["method"], "textDocument/publishDiagnostics");
    assert!(
        cleared["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // shutdown response.
    assert_eq!(messages[3]["id"], 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_request_gets_method_not_found() {
    let mut input = Vec::new();
    for msg in [
        json!({"jsonrpc":"2.0","id":7,"method":"textDocument/hover","params":{}}),
        json!({"jsonrpc":"2.0","method":"exit"}),
    ] {
        write_message(&mut input, &msg.to_string()).unwrap();
    }
    let mut reader: &[u8] = &input;
    let mut output = Vec::new();
    run_server(&mut reader, &mut output, None).unwrap();
    let mut out_reader: &[u8] = &output;
    let body = read_message(&mut out_reader).unwrap().unwrap();
    let resp: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["id"], 7);
    assert_eq!(resp["error"]["code"], -32601);
}
