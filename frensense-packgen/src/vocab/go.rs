// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Go provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/go.rs` (Phase 6.3c; lang sheds it in 6.3d). The
//! parity test in `super` proves the translation is faithful.

use super::call_last_segment;
use super::LanguageVocab;
use frensense_lang::spec::{PropagatorRule, SanitizerKind};

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

pub(super) static GO_SINK_NAMES: &[(&str, frensense_lang::spec::SinkLabel)] = &[
    // Code Execution
    ("eval", frensense_lang::spec::SinkLabel::CodeExecution),
    ("exec", frensense_lang::spec::SinkLabel::CommandInjection),
    ("Exec", frensense_lang::spec::SinkLabel::CommandInjection),
    ("Command", frensense_lang::spec::SinkLabel::CommandInjection),
    ("Run", frensense_lang::spec::SinkLabel::CommandInjection),
    ("Output", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "CombinedOutput",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    ("spawn", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "spawnSync",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    // SQL Injection
    ("Query", frensense_lang::spec::SinkLabel::SqlInjection),
    ("QueryRow", frensense_lang::spec::SinkLabel::SqlInjection),
    (
        "QueryContext",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    ("ExecContext", frensense_lang::spec::SinkLabel::SqlInjection),
    ("Prepare", frensense_lang::spec::SinkLabel::SqlInjection),
    (
        "PrepareContext",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    ("executeRaw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("queryRaw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("prepare", frensense_lang::spec::SinkLabel::SqlInjection),
    // Path Traversal
    ("ReadFile", frensense_lang::spec::SinkLabel::PathTraversal),
    ("Open", frensense_lang::spec::SinkLabel::PathTraversal),
    ("Create", frensense_lang::spec::SinkLabel::PathTraversal),
    ("WriteFile", frensense_lang::spec::SinkLabel::PathTraversal),
    ("read", frensense_lang::spec::SinkLabel::PathTraversal),
    (
        "read_to_string",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
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
    ("http.Get", frensense_lang::spec::SinkLabel::Ssrf),
    ("http.Post", frensense_lang::spec::SinkLabel::Ssrf),
    ("http.Head", frensense_lang::spec::SinkLabel::Ssrf),
    ("http.Do", frensense_lang::spec::SinkLabel::Ssrf),
    ("Get", frensense_lang::spec::SinkLabel::Ssrf),
    ("Post", frensense_lang::spec::SinkLabel::Ssrf),
    ("Do", frensense_lang::spec::SinkLabel::Ssrf),
    ("NewRequest", frensense_lang::spec::SinkLabel::Ssrf),
    ("fetch", frensense_lang::spec::SinkLabel::Ssrf),
    ("request", frensense_lang::spec::SinkLabel::Ssrf),
    ("got", frensense_lang::spec::SinkLabel::Ssrf),
    // Open Redirect
    ("redirect", frensense_lang::spec::SinkLabel::OpenRedirect),
    ("Redirect", frensense_lang::spec::SinkLabel::OpenRedirect),
    ("c.redirect", frensense_lang::spec::SinkLabel::OpenRedirect),
    (
        "location.href",
        frensense_lang::spec::SinkLabel::OpenRedirect,
    ),
    (
        "window.location",
        frensense_lang::spec::SinkLabel::OpenRedirect,
    ),
    // XSS
    ("innerHTML", frensense_lang::spec::SinkLabel::XssDom),
    ("outerHTML", frensense_lang::spec::SinkLabel::XssDom),
    ("document.writeln", frensense_lang::spec::SinkLabel::XssDom),
    (
        "dangerouslySetInnerHTML",
        frensense_lang::spec::SinkLabel::XssDom,
    ),
    // SSTI - Template engine renders
    (
        "ExecuteTemplate",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "render_template",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "render_template_string",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    ("ejs.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "nunjucks.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "marko.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    ("eta.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    ("swig.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "liquid.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "mustache.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    // Insecure Deserialization
    (
        "bincode::deserialize",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "serde_json::from_str",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "yaml.load",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "js-yaml.load",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "pickle.loads",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "msgpack.decode",
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
    // Cloudflare Workers / Prisma
    ("c.redirect", frensense_lang::spec::SinkLabel::OpenRedirect),
    ("env.KV.put", frensense_lang::spec::SinkLabel::StorageWrite),
    (
        "KVNamespace.put",
        frensense_lang::spec::SinkLabel::StorageWrite,
    ),
    (
        "env.DB.prepare",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    ("res.send", frensense_lang::spec::SinkLabel::ResponseLeak),
    ("res.json", frensense_lang::spec::SinkLabel::ResponseLeak),
    (
        "res.redirect",
        frensense_lang::spec::SinkLabel::OpenRedirect,
    ),
    ("res.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "revalidatePath",
        frensense_lang::spec::SinkLabel::StorageWrite,
    ),
    (
        "prisma.queryRawUnsafe",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    (
        "prisma.executeRawUnsafe",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    (
        "R2Bucket.put",
        frensense_lang::spec::SinkLabel::StorageWrite,
    ),
    (
        "D1Database.prepare",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    (
        "DurableObjectStub.fetch",
        frensense_lang::spec::SinkLabel::Ssrf,
    ),
    ("Queue.send", frensense_lang::spec::SinkLabel::Ssrf),
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
