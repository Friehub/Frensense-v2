// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! C provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/c_lang.rs` (Phase 6.3c; lang sheds it in 6.3d). The
//! parity test in `super` proves the translation is faithful.

use super::call_last_segment;
use super::LanguageVocab;
use frensense_lang::spec::{PropagatorRule, SanitizerKind};

pub(super) static C_SINK_NAMES: &[(&str, frensense_lang::spec::SinkLabel)] = &[
    // Code Execution
    ("eval", frensense_lang::spec::SinkLabel::CodeExecution),
    ("system", frensense_lang::spec::SinkLabel::CommandInjection),
    ("popen", frensense_lang::spec::SinkLabel::CommandInjection),
    ("exec", frensense_lang::spec::SinkLabel::CommandInjection),
    ("execve", frensense_lang::spec::SinkLabel::CommandInjection),
    ("execl", frensense_lang::spec::SinkLabel::CommandInjection),
    ("execlp", frensense_lang::spec::SinkLabel::CommandInjection),
    ("execvp", frensense_lang::spec::SinkLabel::CommandInjection),
    ("execvpe", frensense_lang::spec::SinkLabel::CommandInjection),
    ("spawn", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "spawnSync",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    // SQL Injection
    ("mysql_query", frensense_lang::spec::SinkLabel::SqlInjection),
    (
        "sqlite3_exec",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    ("execute", frensense_lang::spec::SinkLabel::SqlInjection),
    ("query", frensense_lang::spec::SinkLabel::SqlInjection),
    ("prepare", frensense_lang::spec::SinkLabel::SqlInjection),
    // Path Traversal
    ("fopen", frensense_lang::spec::SinkLabel::PathTraversal),
    ("open", frensense_lang::spec::SinkLabel::PathTraversal),
    ("read", frensense_lang::spec::SinkLabel::PathTraversal),
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
    // Buffer Overflow / Memory Safety
    //
    // Unsized copies only: a tainted source into gets/strcpy/strcat is an
    // unbounded write. Sized copies (memcpy, memmove, memset, strncpy,
    // strncat) are deliberately NOT taint sinks - they carry an explicit
    // length, so boundedness is a spatial question for the capacity-based
    // checker, and every idiomatic `memcpy(buf, getenv_derived, n)` pattern
    // (config parsing, path building) alerted on normal input handling.
    ("gets", frensense_lang::spec::SinkLabel::BufferOverflow),
    ("strcpy", frensense_lang::spec::SinkLabel::BufferOverflow),
    ("strcat", frensense_lang::spec::SinkLabel::BufferOverflow),
    ("sprintf", frensense_lang::spec::SinkLabel::FormatString),
    ("vsprintf", frensense_lang::spec::SinkLabel::FormatString),
    ("printf", frensense_lang::spec::SinkLabel::FormatString),
    ("snprintf", frensense_lang::spec::SinkLabel::FormatString),
    ("sscanf", frensense_lang::spec::SinkLabel::FormatString),
    ("mktemp", frensense_lang::spec::SinkLabel::PathTraversal),
    ("tmpnam", frensense_lang::spec::SinkLabel::PathTraversal),
    // SSRF
    ("fetch", frensense_lang::spec::SinkLabel::Ssrf),
    ("get", frensense_lang::spec::SinkLabel::Ssrf),
    ("post", frensense_lang::spec::SinkLabel::Ssrf),
    ("request", frensense_lang::spec::SinkLabel::Ssrf),
    ("got", frensense_lang::spec::SinkLabel::Ssrf),
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
    ("ejs.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    ("pug.compile", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "handlebars.compile",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "nunjucks.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    // Unsafe Deserialization
    (
        "pickle.loads",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "yaml.load",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "bincode::deserialize",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_json::from_str",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    // Prototype Pollution
    (
        "Object.assign",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "_.merge",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "_.defaultsDeep",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    ("_.set", frensense_lang::spec::SinkLabel::PrototypePollution),
    (
        "$.extend",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "setPrototypeOf",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    // XXE
    ("DOMParser", frensense_lang::spec::SinkLabel::Xxe),
    // JWT
    ("jwt.sign", frensense_lang::spec::SinkLabel::Jwt),
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
    ("find", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("findOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("findAll", frensense_lang::spec::SinkLabel::NoSqlInjection),
    // Storage Write
    ("put", frensense_lang::spec::SinkLabel::StorageWrite),
    ("setItem", frensense_lang::spec::SinkLabel::StorageWrite),
    // Log Leak
    ("log", frensense_lang::spec::SinkLabel::LogLeak),
    ("error", frensense_lang::spec::SinkLabel::LogLeak),
    ("info", frensense_lang::spec::SinkLabel::LogLeak),
    ("debug", frensense_lang::spec::SinkLabel::LogLeak),
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
