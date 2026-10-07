// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Rust provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/rust_lang.rs` (Phase 6.3c; lang sheds it in 6.3d). The
//! parity test in `super` proves the translation is faithful.

use super::call_last_segment;
use super::LanguageVocab;
use frensense_lang::spec::{PropagatorRule, SanitizerKind};

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

pub(super) static RUST_SINK_NAMES: &[(&str, frensense_lang::spec::SinkLabel)] = &[
    // SQL Injection
    ("execute", frensense_lang::spec::SinkLabel::SqlInjection),
    ("fetch", frensense_lang::spec::SinkLabel::SqlInjection),
    ("fetch_one", frensense_lang::spec::SinkLabel::SqlInjection),
    ("fetch_all", frensense_lang::spec::SinkLabel::SqlInjection),
    ("query", frensense_lang::spec::SinkLabel::SqlInjection),
    ("query_as", frensense_lang::spec::SinkLabel::SqlInjection),
    ("raw_sql", frensense_lang::spec::SinkLabel::SqlInjection),
    ("executeRaw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("queryRaw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("prepare", frensense_lang::spec::SinkLabel::SqlInjection),
    // Command Injection
    ("Command", frensense_lang::spec::SinkLabel::CommandInjection),
    ("arg", frensense_lang::spec::SinkLabel::CommandInjection),
    ("args", frensense_lang::spec::SinkLabel::CommandInjection),
    ("status", frensense_lang::spec::SinkLabel::CommandInjection),
    ("output", frensense_lang::spec::SinkLabel::CommandInjection),
    ("spawn", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "spawnSync",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    ("exec", frensense_lang::spec::SinkLabel::CommandInjection),
    // Path Traversal
    ("read", frensense_lang::spec::SinkLabel::PathTraversal),
    (
        "read_to_string",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    ("open", frensense_lang::spec::SinkLabel::PathTraversal),
    ("create", frensense_lang::spec::SinkLabel::PathTraversal),
    ("write", frensense_lang::spec::SinkLabel::PathTraversal),
    ("readFile", frensense_lang::spec::SinkLabel::PathTraversal),
    ("writeFile", frensense_lang::spec::SinkLabel::PathTraversal),
    (
        "readFileSync",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    ("join", frensense_lang::spec::SinkLabel::PathTraversal),
    ("unlink", frensense_lang::spec::SinkLabel::PathTraversal),
    ("stat", frensense_lang::spec::SinkLabel::PathTraversal),
    ("access", frensense_lang::spec::SinkLabel::PathTraversal),
    // SSRF
    ("reqwest::get", frensense_lang::spec::SinkLabel::Ssrf),
    ("Client::get", frensense_lang::spec::SinkLabel::Ssrf),
    ("ureq::get", frensense_lang::spec::SinkLabel::Ssrf),
    ("http.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("https.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("got", frensense_lang::spec::SinkLabel::Ssrf),
    ("get", frensense_lang::spec::SinkLabel::Ssrf),
    ("post", frensense_lang::spec::SinkLabel::Ssrf),
    ("send", frensense_lang::spec::SinkLabel::Ssrf),
    ("request", frensense_lang::spec::SinkLabel::Ssrf),
    // Open Redirect
    ("redirect", frensense_lang::spec::SinkLabel::OpenRedirect),
    // XSS
    ("innerHTML", frensense_lang::spec::SinkLabel::XssDom),
    ("outerHTML", frensense_lang::spec::SinkLabel::XssDom),
    (
        "dangerouslySetInnerHTML",
        frensense_lang::spec::SinkLabel::XssDom,
    ),
    // SSTI
    ("render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "render_template",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "render_template_string",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    // Unsafe Memory
    ("transmute", frensense_lang::spec::SinkLabel::UnsafeMemory),
    (
        "transmute_copy",
        frensense_lang::spec::SinkLabel::UnsafeMemory,
    ),
    (
        "from_utf8_unchecked",
        frensense_lang::spec::SinkLabel::UnsafeMemory,
    ),
    (
        "from_raw_parts",
        frensense_lang::spec::SinkLabel::UnsafeMemory,
    ),
    // Unsafe Deserialization
    (
        "bincode::deserialize",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_json::from_str",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_json::from_value",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_pickle::from_slice",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    // MongoDB / ORM
    ("update", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("updateOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "updateMany",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("insert", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("insertOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "insertMany",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("delete", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("deleteOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "deleteMany",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("find_one", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("find_many", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "Collection::find",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("findOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("findAll", frensense_lang::spec::SinkLabel::NoSqlInjection),
    // Storage Write
    ("put", frensense_lang::spec::SinkLabel::StorageWrite),
    // Log Leak
    ("log", frensense_lang::spec::SinkLabel::LogLeak),
    ("error", frensense_lang::spec::SinkLabel::LogLeak),
    ("info", frensense_lang::spec::SinkLabel::LogLeak),
    ("debug", frensense_lang::spec::SinkLabel::LogLeak),
    // JWT
    ("jwt.sign", frensense_lang::spec::SinkLabel::Jwt),
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
