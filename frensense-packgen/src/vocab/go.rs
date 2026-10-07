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
        call: "Join",
        tainted_arg: None,
        tainted_receiver: false,
    },
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
    ("eval", crate::role_map::SinkLabel::CodeExecution),
    ("exec", crate::role_map::SinkLabel::CommandInjection),
    ("Exec", crate::role_map::SinkLabel::CommandInjection),
    ("Command", crate::role_map::SinkLabel::CommandInjection),
    ("Run", crate::role_map::SinkLabel::CommandInjection),
    ("Output", crate::role_map::SinkLabel::CommandInjection),
    (
        "CombinedOutput",
        crate::role_map::SinkLabel::CommandInjection,
    ),
    ("spawn", crate::role_map::SinkLabel::CommandInjection),
    ("spawnSync", crate::role_map::SinkLabel::CommandInjection),
    // SQL Injection
    ("Query", crate::role_map::SinkLabel::SqlInjection),
    ("QueryRow", crate::role_map::SinkLabel::SqlInjection),
    ("QueryContext", crate::role_map::SinkLabel::SqlInjection),
    ("ExecContext", crate::role_map::SinkLabel::SqlInjection),
    ("Prepare", crate::role_map::SinkLabel::SqlInjection),
    ("PrepareContext", crate::role_map::SinkLabel::SqlInjection),
    ("executeRaw", crate::role_map::SinkLabel::SqlInjection),
    ("queryRaw", crate::role_map::SinkLabel::SqlInjection),
    ("prepare", crate::role_map::SinkLabel::SqlInjection),
    // Path Traversal
    ("ReadFile", crate::role_map::SinkLabel::PathTraversal),
    ("Open", crate::role_map::SinkLabel::PathTraversal),
    ("Create", crate::role_map::SinkLabel::PathTraversal),
    ("WriteFile", crate::role_map::SinkLabel::PathTraversal),
    ("read", crate::role_map::SinkLabel::PathTraversal),
    ("read_to_string", crate::role_map::SinkLabel::PathTraversal),
    ("write", crate::role_map::SinkLabel::PathTraversal),
    ("readFile", crate::role_map::SinkLabel::PathTraversal),
    ("writeFile", crate::role_map::SinkLabel::PathTraversal),
    ("readFileSync", crate::role_map::SinkLabel::PathTraversal),
    ("join", crate::role_map::SinkLabel::PathTraversal),
    ("unlink", crate::role_map::SinkLabel::PathTraversal),
    ("stat", crate::role_map::SinkLabel::PathTraversal),
    ("access", crate::role_map::SinkLabel::PathTraversal),
    // SSRF
    ("http.Get", crate::role_map::SinkLabel::Ssrf),
    ("http.Post", crate::role_map::SinkLabel::Ssrf),
    ("http.Head", crate::role_map::SinkLabel::Ssrf),
    ("http.Do", crate::role_map::SinkLabel::Ssrf),
    ("Get", crate::role_map::SinkLabel::Ssrf),
    ("Post", crate::role_map::SinkLabel::Ssrf),
    ("Do", crate::role_map::SinkLabel::Ssrf),
    ("NewRequest", crate::role_map::SinkLabel::Ssrf),
    ("fetch", crate::role_map::SinkLabel::Ssrf),
    ("request", crate::role_map::SinkLabel::Ssrf),
    ("got", crate::role_map::SinkLabel::Ssrf),
    // Open Redirect
    ("redirect", crate::role_map::SinkLabel::OpenRedirect),
    ("Redirect", crate::role_map::SinkLabel::OpenRedirect),
    ("c.redirect", crate::role_map::SinkLabel::OpenRedirect),
    ("location.href", crate::role_map::SinkLabel::OpenRedirect),
    ("window.location", crate::role_map::SinkLabel::OpenRedirect),
    // XSS
    ("innerHTML", crate::role_map::SinkLabel::XssDom),
    ("outerHTML", crate::role_map::SinkLabel::XssDom),
    ("document.writeln", crate::role_map::SinkLabel::XssDom),
    (
        "dangerouslySetInnerHTML",
        crate::role_map::SinkLabel::XssDom,
    ),
    // SSTI - Template engine renders
    ("ExecuteTemplate", crate::role_map::SinkLabel::TemplateSsti),
    ("render_template", crate::role_map::SinkLabel::TemplateSsti),
    (
        "render_template_string",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    ("ejs.render", crate::role_map::SinkLabel::TemplateSsti),
    ("nunjucks.render", crate::role_map::SinkLabel::TemplateSsti),
    ("marko.render", crate::role_map::SinkLabel::TemplateSsti),
    ("eta.render", crate::role_map::SinkLabel::TemplateSsti),
    ("swig.render", crate::role_map::SinkLabel::TemplateSsti),
    ("liquid.render", crate::role_map::SinkLabel::TemplateSsti),
    ("mustache.render", crate::role_map::SinkLabel::TemplateSsti),
    // Insecure Deserialization
    (
        "bincode::deserialize",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_json::from_str",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    ("yaml.load", crate::role_map::SinkLabel::UnsafeDeserialize),
    (
        "js-yaml.load",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "pickle.loads",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "msgpack.decode",
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
    // Cloudflare Workers / Prisma
    ("c.redirect", crate::role_map::SinkLabel::OpenRedirect),
    ("env.KV.put", crate::role_map::SinkLabel::StorageWrite),
    ("KVNamespace.put", crate::role_map::SinkLabel::StorageWrite),
    ("env.DB.prepare", crate::role_map::SinkLabel::SqlInjection),
    ("res.send", crate::role_map::SinkLabel::ResponseLeak),
    ("res.json", crate::role_map::SinkLabel::ResponseLeak),
    ("res.redirect", crate::role_map::SinkLabel::OpenRedirect),
    ("res.render", crate::role_map::SinkLabel::TemplateSsti),
    ("revalidatePath", crate::role_map::SinkLabel::StorageWrite),
    (
        "prisma.queryRawUnsafe",
        crate::role_map::SinkLabel::SqlInjection,
    ),
    (
        "prisma.executeRawUnsafe",
        crate::role_map::SinkLabel::SqlInjection,
    ),
    ("R2Bucket.put", crate::role_map::SinkLabel::StorageWrite),
    (
        "D1Database.prepare",
        crate::role_map::SinkLabel::SqlInjection,
    ),
    ("DurableObjectStub.fetch", crate::role_map::SinkLabel::Ssrf),
    ("Queue.send", crate::role_map::SinkLabel::Ssrf),
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
