// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! C provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/c_lang.rs` (Phase 6.3c; lang's copy deleted in
//! 6.3d - this static data is the sole source).

use super::call_last_segment;
use super::LanguageVocab;
use crate::role_map::{PropagatorRule, SanitizerKind};

pub(super) static C_SINK_NAMES: &[(&str, crate::role_map::SinkLabel)] = &[
    // Code Execution
    ("eval", crate::role_map::SinkLabel::CodeExecution),
    ("system", crate::role_map::SinkLabel::CommandInjection),
    ("popen", crate::role_map::SinkLabel::CommandInjection),
    ("exec", crate::role_map::SinkLabel::CommandInjection),
    ("execve", crate::role_map::SinkLabel::CommandInjection),
    ("execl", crate::role_map::SinkLabel::CommandInjection),
    ("execlp", crate::role_map::SinkLabel::CommandInjection),
    ("execvp", crate::role_map::SinkLabel::CommandInjection),
    ("execvpe", crate::role_map::SinkLabel::CommandInjection),
    ("spawn", crate::role_map::SinkLabel::CommandInjection),
    ("spawnSync", crate::role_map::SinkLabel::CommandInjection),
    // SQL Injection
    ("mysql_query", crate::role_map::SinkLabel::SqlInjection),
    ("sqlite3_exec", crate::role_map::SinkLabel::SqlInjection),
    ("execute", crate::role_map::SinkLabel::SqlInjection),
    ("query", crate::role_map::SinkLabel::SqlInjection),
    ("prepare", crate::role_map::SinkLabel::SqlInjection),
    // Path Traversal
    ("fopen", crate::role_map::SinkLabel::PathTraversal),
    ("open", crate::role_map::SinkLabel::PathTraversal),
    ("read", crate::role_map::SinkLabel::PathTraversal),
    ("write", crate::role_map::SinkLabel::PathTraversal),
    ("readFile", crate::role_map::SinkLabel::PathTraversal),
    ("writeFile", crate::role_map::SinkLabel::PathTraversal),
    ("readFileSync", crate::role_map::SinkLabel::PathTraversal),
    ("join", crate::role_map::SinkLabel::PathTraversal),
    ("unlink", crate::role_map::SinkLabel::PathTraversal),
    ("stat", crate::role_map::SinkLabel::PathTraversal),
    ("access", crate::role_map::SinkLabel::PathTraversal),
    // Buffer Overflow / Memory Safety
    //
    // Unsized copies only: a tainted source into gets/strcpy/strcat is an
    // unbounded write. Sized copies (memcpy, memmove, memset, strncpy,
    // strncat) are deliberately NOT taint sinks - they carry an explicit
    // length, so boundedness is a spatial question for the capacity-based
    // checker, and every idiomatic `memcpy(buf, getenv_derived, n)` pattern
    // (config parsing, path building) alerted on normal input handling.
    ("gets", crate::role_map::SinkLabel::BufferOverflow),
    ("strcpy", crate::role_map::SinkLabel::BufferOverflow),
    ("strcat", crate::role_map::SinkLabel::BufferOverflow),
    ("sprintf", crate::role_map::SinkLabel::FormatString),
    ("vsprintf", crate::role_map::SinkLabel::FormatString),
    ("printf", crate::role_map::SinkLabel::FormatString),
    ("snprintf", crate::role_map::SinkLabel::FormatString),
    ("sscanf", crate::role_map::SinkLabel::FormatString),
    ("mktemp", crate::role_map::SinkLabel::PathTraversal),
    ("tmpnam", crate::role_map::SinkLabel::PathTraversal),
    // SSRF
    ("fetch", crate::role_map::SinkLabel::Ssrf),
    ("get", crate::role_map::SinkLabel::Ssrf),
    ("post", crate::role_map::SinkLabel::Ssrf),
    ("request", crate::role_map::SinkLabel::Ssrf),
    ("got", crate::role_map::SinkLabel::Ssrf),
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
    ("ejs.render", crate::role_map::SinkLabel::TemplateSsti),
    ("pug.compile", crate::role_map::SinkLabel::TemplateSsti),
    (
        "handlebars.compile",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    ("nunjucks.render", crate::role_map::SinkLabel::TemplateSsti),
    // Unsafe Deserialization
    (
        "pickle.loads",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    ("yaml.load", crate::role_map::SinkLabel::UnsafeDeserialize),
    (
        "bincode::deserialize",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_json::from_str",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    // Prototype Pollution
    (
        "Object.assign",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    ("_.merge", crate::role_map::SinkLabel::PrototypePollution),
    (
        "_.defaultsDeep",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    ("_.set", crate::role_map::SinkLabel::PrototypePollution),
    ("$.extend", crate::role_map::SinkLabel::PrototypePollution),
    (
        "setPrototypeOf",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    // XXE
    ("DOMParser", crate::role_map::SinkLabel::Xxe),
    // JWT
    ("jwt.sign", crate::role_map::SinkLabel::Jwt),
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
    ("find", crate::role_map::SinkLabel::NoSqlInjection),
    ("findOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("findAll", crate::role_map::SinkLabel::NoSqlInjection),
    // Storage Write
    ("put", crate::role_map::SinkLabel::StorageWrite),
    ("setItem", crate::role_map::SinkLabel::StorageWrite),
    // Log Leak
    ("log", crate::role_map::SinkLabel::LogLeak),
    ("error", crate::role_map::SinkLabel::LogLeak),
    ("info", crate::role_map::SinkLabel::LogLeak),
    ("debug", crate::role_map::SinkLabel::LogLeak),
];

pub(super) static C_SINK_SIGNATURES: &[(&str, &[usize], bool)] = &[
    // (call, dangerous slots, binding slots safe)
    // sprintf/vsprintf(dst, fmt, ...), printf(fmt, ...),
    // snprintf(dst, n, fmt, ...), sscanf(input, fmt, ...).
    ("sprintf", &[1], false),
    ("vsprintf", &[1], false),
    ("printf", &[0], false),
    ("snprintf", &[2], false),
    ("sscanf", &[1], false),
];

pub(super) static C_SOURCE_PATTERNS: &[&str] = &["argv", "getenv", "fgets", "scanf", "stdin"];

pub(super) static C_PROPAGATORS: &[PropagatorRule] = &[
    PropagatorRule {
        call: "sprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "snprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strcat",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strcpy",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strdup",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
];

pub(super) static C_SANITIZER_NAMES: &[&str] = &["atoi", "atol", "atof", "strtol", "strtoul"];

pub(super) static C_ROUTE_PATTERNS: &[&str] = &[];

fn c_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        "atoi" | "atol" | "atof" | "strtol" | "strtoul" => Some(SanitizerKind::Full),
        _ => None,
    }
}

pub(super) const C_VOCAB: LanguageVocab = LanguageVocab {
    language: "c",
    sink_names: C_SINK_NAMES,
    sink_signatures: C_SINK_SIGNATURES,
    idor_sinks: &[],
    source_patterns: C_SOURCE_PATTERNS,
    request_param_names: &[],
    sanitizer_names: C_SANITIZER_NAMES,
    classify_sanitizer: c_classify_sanitizer,
    propagators: C_PROPAGATORS,
    session_roots: &[],
    route_patterns: C_ROUTE_PATTERNS,
};

pub(crate) fn vocab() -> &'static LanguageVocab {
    &C_VOCAB
}
