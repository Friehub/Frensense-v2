// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Go provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/go.rs` (Phase 6.3c; lang's copy deleted in
//! 6.3d - this static data is the sole source).

use super::call_last_segment;
use super::LanguageVocab;
use crate::role_map::{PropagatorRule, SanitizerKind};

fn go_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        // Numeric coercion - kills injection risk
        "Atoi" | "ParseInt" | "ParseUint" | "ParseFloat" | "ParseBool" => Some(SanitizerKind::Full),
        // HTML escaping
        "EscapeString" | "HTMLEscapeString" | "HTMLEscape" => Some(SanitizerKind::HtmlEscape),
        // URL encoding
        "QueryEscape" | "PathEscape" | "PathUnescape" => Some(SanitizerKind::UrlEncode),
        // Path cleaning - partial mitigation for path traversal
        "Clean" | "Abs" | "EvalSymlinks" => Some(SanitizerKind::PathNormalize),
        _ => None,
    }
}

pub(super) static GO_SINK_SIGNATURES: &[(&str, &[usize], bool)] = &[
    // ── database/sql: Query/Exec(sql, args...) ──
    ("Query", &[0], true),
    ("QueryRow", &[0], true),
    ("QueryContext", &[0], true),
    ("Exec", &[0], true),
    ("ExecContext", &[0], true),
    ("Prepare", &[0], true),
    ("PrepareContext", &[0], true),
    // ── sqlx (dotted names match by last segment): get/select cost slot 0 ──
    // (sqlx Get(dest, query, args), dest slot 0 is an out-param, but a
    // tainted dest is an injection only via the query; keep slot 1 only.)
    // ── D1 (Cloudflare Workers Go-style bindings) ──
    ("prepare", &[0], true),
];

pub(super) static GO_PROPAGATORS: &[PropagatorRule] = &[
    // fmt - format string propagates taint from args
    PropagatorRule {
        call: "Sprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Fprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Errorf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Stringer",
        tainted_arg: None,
        tainted_receiver: false,
    },
    // strings - receiver taints return
    PropagatorRule {
        call: "Join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "Replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "ReplaceAll",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "TrimSpace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "Trim",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "ToLower",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "ToUpper",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Split",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "SplitN",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "Contains",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "HasPrefix",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "HasSuffix",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // strconv - propagates taint (type conversion, not sanitization)
    PropagatorRule {
        call: "Itoa",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "FormatInt",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "AppendInt",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // path/filepath - path building propagates traversal risk
    PropagatorRule {
        call: "Base",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // bytes.Buffer / strings.Builder
    PropagatorRule {
        call: "WriteString",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "Write",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "String",
        tainted_arg: None,
        tainted_receiver: true,
    },
];

pub(super) static GO_REQUEST_PARAM_NAMES: &[&str] =
    // Convention: r=*http.Request, w=http.ResponseWriter, c=*gin.Context
    &["r", "req", "c", "ctx", "w"];

pub(super) static GO_SINK_NAMES: &[(&str, crate::role_map::SinkLabel)] = &[
    // Code Execution
    ("exec", crate::role_map::SinkLabel::CommandInjection),
    ("Exec", crate::role_map::SinkLabel::CommandInjection),
    ("Command", crate::role_map::SinkLabel::CommandInjection),
    ("Run", crate::role_map::SinkLabel::CommandInjection),
    ("Output", crate::role_map::SinkLabel::CommandInjection),
    (
        "CombinedOutput",
        crate::role_map::SinkLabel::CommandInjection,
    ),
    // SQL Injection
    ("Query", crate::role_map::SinkLabel::SqlInjection),
    ("QueryRow", crate::role_map::SinkLabel::SqlInjection),
    ("QueryContext", crate::role_map::SinkLabel::SqlInjection),
    ("ExecContext", crate::role_map::SinkLabel::SqlInjection),
    ("Prepare", crate::role_map::SinkLabel::SqlInjection),
    ("PrepareContext", crate::role_map::SinkLabel::SqlInjection),
    ("prepare", crate::role_map::SinkLabel::SqlInjection),
    // Path Traversal
    ("ReadFile", crate::role_map::SinkLabel::PathTraversal),
    ("Open", crate::role_map::SinkLabel::PathTraversal),
    ("Create", crate::role_map::SinkLabel::PathTraversal),
    ("WriteFile", crate::role_map::SinkLabel::PathTraversal),
    // SSRF
    ("http.Get", crate::role_map::SinkLabel::Ssrf),
    ("http.Post", crate::role_map::SinkLabel::Ssrf),
    ("http.Head", crate::role_map::SinkLabel::Ssrf),
    ("http.Do", crate::role_map::SinkLabel::Ssrf),
    ("Get", crate::role_map::SinkLabel::Ssrf),
    ("Post", crate::role_map::SinkLabel::Ssrf),
    ("Do", crate::role_map::SinkLabel::Ssrf),
    ("NewRequest", crate::role_map::SinkLabel::Ssrf),
    // Open Redirect
    ("Redirect", crate::role_map::SinkLabel::OpenRedirect),
    // SSTI
    ("ExecuteTemplate", crate::role_map::SinkLabel::TemplateSsti),
    // Insecure Deserialization
    (
        "msgpack.decode",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    // Log Leak
    ("log", crate::role_map::SinkLabel::LogLeak),
    ("error", crate::role_map::SinkLabel::LogLeak),
    ("info", crate::role_map::SinkLabel::LogLeak),
    ("debug", crate::role_map::SinkLabel::LogLeak),
];

pub(super) static GO_SOURCE_PATTERNS: &[&str] = &[
    // net/http standard library
    "r.URL.Query",
    "r.URL.Path",
    "r.URL.RawQuery",
    "r.FormValue",
    "r.PostFormValue",
    "r.Body",
    "r.Header.Get",
    "r.PathValue",
    // Gin
    "c.Param",
    "c.Query",
    "c.DefaultQuery",
    "c.PostForm",
    "c.DefaultPostForm",
    "c.GetHeader",
    "c.GetRawData",
    "c.ShouldBindJSON",
    "c.ShouldBind",
    // Echo
    "c.Param",
    "c.QueryParam",
    "c.FormValue",
    "c.Request().Body",
    // Fiber
    "c.Params",
    "c.Query",
    "c.Body",
    "c.FormValue",
    "c.Get",
];

pub(super) static GO_SANITIZER_NAMES: &[&str] = &[
    "EscapeString",
    "EscapeHTML",
    "QueryEscape",
    "PathEscape",
    "template.HTMLEscapeString",
    "url.QueryEscape",
    "strconv.Atoi",
    "Sanitize",
    "EscapeText",
];

pub(super) const GO_VOCAB: LanguageVocab = LanguageVocab {
    language: "go",
    ambiguous_verbs: crate::data::BOOTSTRAP_AMBIGUOUS_VERBS,
    sink_names: GO_SINK_NAMES,
    sink_signatures: GO_SINK_SIGNATURES,
    idor_sinks: &[],
    source_patterns: GO_SOURCE_PATTERNS,
    request_param_names: GO_REQUEST_PARAM_NAMES,
    sanitizer_names: GO_SANITIZER_NAMES,
    classify_sanitizer: go_classify_sanitizer,
    propagators: GO_PROPAGATORS,
    session_roots: &[],
    route_patterns: &[],
};

pub(crate) fn vocab() -> &'static LanguageVocab {
    &GO_VOCAB
}
