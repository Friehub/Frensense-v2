// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Rust provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/rust_lang.rs` (Phase 6.3c; lang's copy deleted
//! in 6.3d - this static data is the sole source).

use super::call_last_segment;
use super::LanguageVocab;
use crate::role_map::{PropagatorRule, SanitizerKind};

fn rust_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        // Numeric parse: `"42".parse::<u64>()` - kills injection
        "parse" => Some(SanitizerKind::Full),
        // HTML
        "clean" | "ammonia" | "escape_html" => Some(SanitizerKind::HtmlEscape),
        // URL
        "encode" | "percent_encode" | "utf8_percent_encode" => Some(SanitizerKind::UrlEncode),
        // Path
        "canonicalize" | "normalize" => Some(SanitizerKind::PathNormalize),
        _ => None,
    }
}

pub(super) static RUST_SINK_SIGNATURES: &[(&str, &[usize], bool)] = &[
    // ── rusqlite / tokio-postgres / mysql_async: execute(sql, params) ──
    ("execute", &[0], true),
    // ── sqlx: query/query_as(sql) + fetch_*, builder takes SQL in slot 0 ──
    ("query", &[0], true),
    ("query_as", &[0], true),
    ("fetch", &[0], true),
    ("fetch_one", &[0], true),
    ("fetch_all", &[0], true),
    // ── diesel / generic prepare ──
    ("prepare", &[0], true),
];

pub(super) static RUST_PROPAGATORS: &[PropagatorRule] = &[
    // format! - any arg taints the return
    PropagatorRule {
        call: "format",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "format_args",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "write",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "writeln",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "println",
        tainted_arg: None,
        tainted_receiver: false,
    },
    // String conversions - receiver taints return
    PropagatorRule {
        call: "to_string",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "to_owned",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "clone",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "into",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "as_str",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "as_bytes",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "as_ref",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "from_utf8",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "from",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // String methods
    PropagatorRule {
        call: "replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "to_lowercase",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "to_uppercase",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trim",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trim_start",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trim_end",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "split",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "concat",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "push_str",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "push",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    // Iterator adaptors
    PropagatorRule {
        call: "map",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "filter",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "collect",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "flat_map",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // unwrap / expect: propagates taint from Result<T,_> / Option<T>
    PropagatorRule {
        call: "unwrap",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "expect",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "unwrap_or",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "ok",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "ok_or",
        tainted_arg: None,
        tainted_receiver: true,
    },
];

pub(super) static RUST_REQUEST_PARAM_NAMES: &[&str] =
    // Axum/Actix: parameter names matter less than types; type-based
    // detection via classify_param_taint is the primary mechanism.
    &["req", "request"];

pub(super) static RUST_SINK_NAMES: &[(&str, crate::role_map::SinkLabel)] = &[
    // SQL Injection
    ("execute", crate::role_map::SinkLabel::SqlInjection),
    ("fetch", crate::role_map::SinkLabel::SqlInjection),
    ("fetch_one", crate::role_map::SinkLabel::SqlInjection),
    ("fetch_all", crate::role_map::SinkLabel::SqlInjection),
    ("query", crate::role_map::SinkLabel::SqlInjection),
    ("query_as", crate::role_map::SinkLabel::SqlInjection),
    ("raw_sql", crate::role_map::SinkLabel::SqlInjection),
    ("executeRaw", crate::role_map::SinkLabel::SqlInjection),
    ("queryRaw", crate::role_map::SinkLabel::SqlInjection),
    ("prepare", crate::role_map::SinkLabel::SqlInjection),
    // Command Injection
    ("Command", crate::role_map::SinkLabel::CommandInjection),
    ("arg", crate::role_map::SinkLabel::CommandInjection),
    ("args", crate::role_map::SinkLabel::CommandInjection),
    ("status", crate::role_map::SinkLabel::CommandInjection),
    ("output", crate::role_map::SinkLabel::CommandInjection),
    ("spawn", crate::role_map::SinkLabel::CommandInjection),
    ("spawnSync", crate::role_map::SinkLabel::CommandInjection),
    ("exec", crate::role_map::SinkLabel::CommandInjection),
    // Path Traversal
    ("read", crate::role_map::SinkLabel::PathTraversal),
    ("read_to_string", crate::role_map::SinkLabel::PathTraversal),
    ("open", crate::role_map::SinkLabel::PathTraversal),
    ("create", crate::role_map::SinkLabel::PathTraversal),
    ("write", crate::role_map::SinkLabel::PathTraversal),
    ("readFile", crate::role_map::SinkLabel::PathTraversal),
    ("writeFile", crate::role_map::SinkLabel::PathTraversal),
    ("readFileSync", crate::role_map::SinkLabel::PathTraversal),
    ("join", crate::role_map::SinkLabel::PathTraversal),
    ("unlink", crate::role_map::SinkLabel::PathTraversal),
    ("stat", crate::role_map::SinkLabel::PathTraversal),
    ("access", crate::role_map::SinkLabel::PathTraversal),
    // SSRF
    ("reqwest::get", crate::role_map::SinkLabel::Ssrf),
    ("Client::get", crate::role_map::SinkLabel::Ssrf),
    ("ureq::get", crate::role_map::SinkLabel::Ssrf),
    ("http.get", crate::role_map::SinkLabel::Ssrf),
    ("https.get", crate::role_map::SinkLabel::Ssrf),
    ("got", crate::role_map::SinkLabel::Ssrf),
    ("get", crate::role_map::SinkLabel::Ssrf),
    ("post", crate::role_map::SinkLabel::Ssrf),
    ("send", crate::role_map::SinkLabel::Ssrf),
    ("request", crate::role_map::SinkLabel::Ssrf),
    // Open Redirect
    ("redirect", crate::role_map::SinkLabel::OpenRedirect),
    // XSS
    ("innerHTML", crate::role_map::SinkLabel::XssDom),
    ("outerHTML", crate::role_map::SinkLabel::XssDom),
    (
        "dangerouslySetInnerHTML",
        crate::role_map::SinkLabel::XssDom,
    ),
    // SSTI
    ("render", crate::role_map::SinkLabel::TemplateSsti),
    ("render_template", crate::role_map::SinkLabel::TemplateSsti),
    (
        "render_template_string",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    // Unsafe Memory
    ("transmute", crate::role_map::SinkLabel::UnsafeMemory),
    ("transmute_copy", crate::role_map::SinkLabel::UnsafeMemory),
    (
        "from_utf8_unchecked",
        crate::role_map::SinkLabel::UnsafeMemory,
    ),
    ("from_raw_parts", crate::role_map::SinkLabel::UnsafeMemory),
    // Unsafe Deserialization
    (
        "bincode::deserialize",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_json::from_str",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_json::from_value",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_pickle::from_slice",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    // MongoDB / ORM
    ("update", crate::role_map::SinkLabel::NoSqlInjection),
    ("updateOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("updateMany", crate::role_map::SinkLabel::NoSqlInjection),
    ("insert", crate::role_map::SinkLabel::NoSqlInjection),
    ("insertOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("insertMany", crate::role_map::SinkLabel::NoSqlInjection),
    ("delete", crate::role_map::SinkLabel::NoSqlInjection),
    ("deleteOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("deleteMany", crate::role_map::SinkLabel::NoSqlInjection),
    ("find_one", crate::role_map::SinkLabel::NoSqlInjection),
    ("find_many", crate::role_map::SinkLabel::NoSqlInjection),
    (
        "Collection::find",
        crate::role_map::SinkLabel::NoSqlInjection,
    ),
    ("findOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("findAll", crate::role_map::SinkLabel::NoSqlInjection),
    // Storage Write
    ("put", crate::role_map::SinkLabel::StorageWrite),
    // Log Leak
    ("log", crate::role_map::SinkLabel::LogLeak),
    ("error", crate::role_map::SinkLabel::LogLeak),
    ("info", crate::role_map::SinkLabel::LogLeak),
    ("debug", crate::role_map::SinkLabel::LogLeak),
    // JWT
    ("jwt.sign", crate::role_map::SinkLabel::Jwt),
];

pub(super) static RUST_SOURCE_PATTERNS: &[&str] = &[
    // Axum
    "Json",
    "Path",
    "Query",
    "Form",
    "Bytes",
    "Multipart",
    // Actix
    "web::Json",
    "web::Path",
    "web::Query",
    "web::Form",
    // Environment
    "std::env::var",
    "env::var",
];

pub(super) static RUST_SANITIZER_NAMES: &[&str] = &[
    "escape_html",
    "urlencoding::encode",
    "shell_words::quote",
    "atoi",
];

pub(super) const RUST_VOCAB: LanguageVocab = LanguageVocab {
    language: "rust",
    sink_names: RUST_SINK_NAMES,
    sink_signatures: RUST_SINK_SIGNATURES,
    idor_sinks: &[],
    source_patterns: RUST_SOURCE_PATTERNS,
    request_param_names: RUST_REQUEST_PARAM_NAMES,
    sanitizer_names: RUST_SANITIZER_NAMES,
    classify_sanitizer: rust_classify_sanitizer,
    propagators: RUST_PROPAGATORS,
    session_roots: &[],
    route_patterns: &[],
};

pub(crate) fn vocab() -> &'static LanguageVocab {
    &RUST_VOCAB
}
