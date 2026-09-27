// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

#![allow(clippy::print_stderr)]

//! LSP server loop: request dispatch + diagnostics generation.
//!
//! The diagnostics pipeline is one pure function
//! ([`diagnostics_for_file`]): file → engine run → LSP `Diagnostic`
//! array. Everything the protocol needs (severity mapping, range
//! computation, stable `code`) is derived from the `Advisory`, so the
//! editor displays exactly what the CLI and MCP report.

use super::framing::{read_message, write_message};
use crate::{Advisory, Engine, Severity};
use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;

/// One diagnostic, JSON-shaped per LSP 3.17. A struct would be overkill:
/// the shape is fixed by the protocol and `json!` keeps the mapping
/// (advisory → diagnostic) visible in one place.
pub type DiagnosticItem = Value;

/// `publishDiagnostics` params for one file.
pub type PublishParams = Value;

/// URI ↔ path conversion. LSP uses `file:///` URIs; the engine wants
/// paths. Non-`file` schemes are passed through (the server only scans
/// disk files; other schemes never produce diagnostics anyway).
#[must_use]
pub fn uri_to_path(uri: &str) -> String {
    let Some(rest) = uri.strip_prefix("file://") else {
        return uri.to_string();
    };
    // Strip a localhost authority (`file:///path` → empty authority).
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    // Percent-decode the minimal set editors actually emit.
    let bytes = rest.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(b) = u8::from_str_radix(&rest[i + 1..i + 3], 16)
        {
            out.push(b);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[must_use]
pub fn path_to_uri(path: &str) -> String {
    if path.starts_with("file://") {
        return path.to_string();
    }
    let mut out = String::from("file://");
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'.' | b'_' | b'-' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Advisory severity → LSP DiagnosticSeverity.
#[must_use]
pub fn severity_code(s: Severity) -> u8 {
    match s {
        Severity::Critical => 1, // Error
        Severity::Warning => 2,  // Warning
        Severity::Info => 3,     // Information
    }
}

/// Advisory → LSP Diagnostic. 0-based ranges from the 1-based advisory
/// line/column. `code` carries the stable finding ID so editor UIs and
/// the CLI identify the same bug identically; `source` is `frensense`.
#[must_use]
pub fn diagnostic_from_advisory(adv: &Advisory) -> DiagnosticItem {
    let line = adv.line.saturating_sub(1);
    let col = adv.column.saturating_sub(1);
    let end_line = adv.end_line.max(adv.line).saturating_sub(1);
    json!({
        "range": {
            "start": { "line": line, "character": col },
            "end": { "line": end_line, "character": col }
        },
        "severity": severity_code(adv.severity),
        "code": adv.stable_id(),
        "source": "frensense",
        "message": if adv.observation.is_empty() {
            adv.title.clone()
        } else {
            adv.observation.clone()
        },
        "data": {
            "fingerprint": adv.fingerprint,
            "tags": adv.tags,
        }
    })
}

/// The whole diagnostics pipeline for one file: scan through the
/// per-file engine path and map to LSP diagnostics. Unsupported or
/// missing files yield an empty array (clears stale diagnostics rather
/// than erroring — closing a tab for a deleted file should not spam).
///
/// # Errors
/// Propagates engine failure (real transport-level problems, e.g. an
/// unreadable bundle) so the server can log and continue with empty
/// diagnostics.
pub fn diagnostics_for_file(
    engine: &mut Engine,
    path: &std::path::Path,
) -> crate::Result<Vec<DiagnosticItem>> {
    if !crate::parser::is_supported(path) {
        return Ok(Vec::new());
    }
    let advisories = engine.run(path)?;
    Ok(advisories.iter().map(diagnostic_from_advisory).collect())
}

/// `publishDiagnostics` notification params.
#[must_use]
pub fn publish_params(uri: &str, diagnostics: &[DiagnosticItem]) -> PublishParams {
    json!({
        "uri": uri,
        "diagnostics": diagnostics,
    })
}

/// Build the `initialize` result: diagnostics-only capability surface.
#[must_use]
pub fn initialize_result() -> Value {
    json!({
        "capabilities": {
            "textDocumentSync": { "openClose": true, "change": 1, "save": true },
            "positionEncoding": "utf-16"
        },
        "serverInfo": {
            "name": "frensense-lsp",
            "version": crate::FRENSENSE_VERSION
        }
    })
}

fn notification(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": method, "params": params })
}

fn response(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Server loop over framed stdio. Returns when the client closes the
/// stream or sends `shutdown`/`exit`.
///
/// # Errors
/// Fatal transport failures (malformed framing, broken pipe) propagate;
/// per-message analysis errors degrade to empty diagnostics, keeping the
/// editor alive.
pub fn run_server(
    input: &mut impl std::io::BufRead,
    output: &mut impl Write,
    corpus_bundle: Option<&str>,
) -> std::io::Result<()> {
    let mut engine = Engine::new();
    if let Some(bundle) = corpus_bundle {
        engine.set_corpus_bundle_path(PathBuf::from(bundle));
    }

    loop {
        let Some(body) = read_message(input)? else {
            return Ok(()); // client closed the stream
        };
        let msg: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                let err = error_response(&Value::Null, -32700, &format!("parse error: {e}"));
                write_message(output, &err.to_string())?;
                continue;
            }
        };
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let params = msg.get("params").cloned().unwrap_or(json!({}));

        match method {
            "initialize" => {
                write_message(output, &response(&id, initialize_result()).to_string())?;
            }
            "initialized" | "textDocument/didChange" | "$/setTrace" | "$/cancelRequest" => {
                // Notifications we acknowledge silently.
            }
            "textDocument/didOpen" | "textDocument/didSave" => {
                let uri = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let path = uri_to_path(uri);
                let diagnostics =
                    match diagnostics_for_file(&mut engine, std::path::Path::new(&path)) {
                        Ok(d) => d,
                        Err(e) => {
                            eprintln!("frensense-lsp: scan failed for {path}: {e}");
                            Vec::new()
                        }
                    };
                let note = notification(
                    "textDocument/publishDiagnostics",
                    publish_params(uri, &diagnostics),
                );
                write_message(output, &note.to_string())?;
            }
            "textDocument/didClose" => {
                // Clear diagnostics for the closed file.
                let uri = params
                    .pointer("/textDocument/uri")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let note =
                    notification("textDocument/publishDiagnostics", publish_params(uri, &[]));
                write_message(output, &note.to_string())?;
            }
            "shutdown" => {
                write_message(output, &response(&id, Value::Null).to_string())?;
            }
            "exit" => {
                return Ok(());
            }
            "ping" => {
                write_message(output, &response(&id, json!("pong")).to_string())?;
            }
            other => {
                // Requests (with id) get a MethodNotFound error;
                // notifications are ignored per the spec.
                if !id.is_null() {
                    let err = error_response(&id, -32601, &format!("method not found: {other}"));
                    write_message(output, &err.to_string())?;
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
