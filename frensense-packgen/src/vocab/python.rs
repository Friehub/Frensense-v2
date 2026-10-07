// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Python provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/python.rs` (Phase 6.3c; lang sheds it in 6.3d). The
//! parity test in `super` proves the translation is faithful.

use super::call_last_segment;
use super::LanguageVocab;
use frensense_lang::spec::{PropagatorRule, SanitizerKind};

fn python_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        // Numeric coercion
        "int" | "float" | "bool" | "abs" | "round" => Some(SanitizerKind::Full),
        // HTML escaping (stdlib)
        "escape" | "html_escape" | "cgi_escape" => Some(SanitizerKind::HtmlEscape),
        // Bleach, MarkupSafe
        "clean" | "linkify" | "Markup" => Some(SanitizerKind::HtmlEscape),
        // Project-local escaping wrappers: `escape_*` is the near-universal
        // naming convention for output-encoding helpers (OWASP Benchmark's
        // helpers.escape_for_html, Django's escape, in-house wrappers).
        name if name.starts_with("escape_") => Some(SanitizerKind::HtmlEscape),
        // URL encoding
        "quote" | "quote_plus" | "urlencode" => Some(SanitizerKind::UrlEncode),
        // Path normalization
        "realpath" | "abspath" | "normpath" | "normcase" => Some(SanitizerKind::PathNormalize),
        // SQL parameterization (SQLAlchemy `text()` with bound params)
        "text" | "literal" | "bindparam" => Some(SanitizerKind::SqlParameterize),
        _ => None,
    }
}

pub(super) static PY_SINK_SIGNATURES: &[(&str, &[usize], bool)] = &[
    // ── DB-API / sqlite3 / psycopg / mysql-connector: execute(sql, params) ──
    ("execute", &[0], true),
    ("executemany", &[0], true), // executemany(sql, seq_of_params)
    // ── Django raw SQL: raw(sql, params) / extra(select, params) ──
    ("raw", &[0], true),
    // Django extra(): kwargs are interpolated into SQL, only the first
    // positional (select) is the query; params still bind. Conservative:
    // restrict to slot 0 (extra's where/tables kwargs flow by keyword, not
    // position, so positional slots 1+ are the params tuple).
    ("extra", &[0], true),
    // ── SQLAlchemy: query / prepare / raw_sql ──
    ("query", &[0], true),
    ("prepare", &[0], true),
    // ── Jinja2: render is the sink; render_template(sql_string, ctx), slot
    // 0 is the template, ctx is a binding namespace ──
    ("render_template", &[0], true),
];

pub(super) static PYTHON_PROPAGATORS: &[PropagatorRule] = &[
    // str methods - receiver taints return
    PropagatorRule {
        call: "format",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "format_map",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "split",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "strip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "lstrip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "rstrip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "lower",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "upper",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "title",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "encode",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "decode",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // Type coercions that propagate (not sanitize) taint
    PropagatorRule {
        call: "str",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "bytes",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "list",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "tuple",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "dict",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // json
    PropagatorRule {
        call: "loads",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "dumps",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // re / regex
    PropagatorRule {
        call: "sub",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "subn",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "group",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "groups",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // path building
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: false,
    },
    // f-string interpolation: `f"SELECT {user}"` is handled by the
    // flow_fingerprint's is_interpolation_node check, not propagator rules.
    // Listed here for documentation completeness.

    // % formatting: `"SELECT %s" % user` - treated as format propagation
    // This is a BinaryOp in the AST, not a call. The flow fingerprinter
    // checks for `binary_operator` with operator `%` and a tainted RHS.
];

pub(super) static PY_REQUEST_PARAM_NAMES: &[&str] =
    // Flask: `request` is a global import, not a parameter.
    // Django: view functions receive a `request` parameter.
    // FastAPI: `request: Request` is an explicit parameter.
    &["request", "req", "r"];

pub(super) static PY_SINK_NAMES: &[(&str, frensense_lang::spec::SinkLabel)] = &[
    // Code Execution
    ("eval", frensense_lang::spec::SinkLabel::CodeExecution),
    ("exec", frensense_lang::spec::SinkLabel::CodeExecution),
    ("compile", frensense_lang::spec::SinkLabel::CodeExecution),
    // Command Injection
    ("system", frensense_lang::spec::SinkLabel::CommandInjection),
    ("popen", frensense_lang::spec::SinkLabel::CommandInjection),
    ("call", frensense_lang::spec::SinkLabel::CommandInjection),
    ("run", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "check_output",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    ("Popen", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "execfile",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    ("spawn", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "spawnSync",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    // SQL Injection
    ("execute", frensense_lang::spec::SinkLabel::SqlInjection),
    ("executemany", frensense_lang::spec::SinkLabel::SqlInjection),
    ("raw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("raw_sql", frensense_lang::spec::SinkLabel::SqlInjection),
    ("query", frensense_lang::spec::SinkLabel::SqlInjection),
    ("executeRaw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("queryRaw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("filter", frensense_lang::spec::SinkLabel::SqlInjection), // Django ORM raw filter
    ("extra", frensense_lang::spec::SinkLabel::SqlInjection),  // Django ORM .extra()
    ("prepare", frensense_lang::spec::SinkLabel::SqlInjection),
    // Path Traversal
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
    // SSRF
    ("get", frensense_lang::spec::SinkLabel::Ssrf),
    ("post", frensense_lang::spec::SinkLabel::Ssrf),
    ("request", frensense_lang::spec::SinkLabel::Ssrf),
    ("send", frensense_lang::spec::SinkLabel::Ssrf),
    ("fetch", frensense_lang::spec::SinkLabel::Ssrf),
    ("http.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("https.get", frensense_lang::spec::SinkLabel::Ssrf),
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
    // SSTI - Template engine renders
    (
        "render_template",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "render_template_string",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    ("from_string", frensense_lang::spec::SinkLabel::TemplateSsti),
    ("render", frensense_lang::spec::SinkLabel::TemplateSsti),
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
    // Response
    (
        "make_response",
        frensense_lang::spec::SinkLabel::XssReflected,
    ),
    ("res.send", frensense_lang::spec::SinkLabel::ResponseLeak),
    ("res.json", frensense_lang::spec::SinkLabel::ResponseLeak),
    // Unsafe Deserialization
    // (yaml.safe_load is deliberately NOT a sink: it resolves only
    // basic YAML types, which is what makes it the *safe* API.)
    (
        "pickle.loads",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "pickle.load",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "yaml.load",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "marshal.loads",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "shelve.open",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    ("loads", frensense_lang::spec::SinkLabel::UnsafeDeserialize),
    ("load", frensense_lang::spec::SinkLabel::UnsafeDeserialize),
    (
        "bincode::deserialize",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    // Log Leak
    ("log", frensense_lang::spec::SinkLabel::LogLeak),
    ("error", frensense_lang::spec::SinkLabel::LogLeak),
    ("info", frensense_lang::spec::SinkLabel::LogLeak),
    ("debug", frensense_lang::spec::SinkLabel::LogLeak),
    // Prototype Pollution
    // NOTE: JS-only prototype-pollution sinks (_.set, $.extend,
    // setPrototypeOf, Object.assign) are deliberately NOT in the
    // Python table. The engine matches sinks by last segment, so a
    // bare "_.set" entry would make every `.set(` call (e.g.
    // Flask's response.set_cookie lowering, ConfigParser.set) a
    // prototype-pollution sink. Python has no prototype chains.
    // XXE
    ("DOMParser", frensense_lang::spec::SinkLabel::Xxe),
    // JWT
    ("jwt.sign", frensense_lang::spec::SinkLabel::Jwt),
    // MongoDB / ORM operators
    ("$where", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$regex", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$gt", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$lt", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$ne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$in", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$nin", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$exists", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$expr", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("$function", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "$accumulator",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
];

pub(super) static PY_SOURCE_PATTERNS: &[&str] = &[
    // Flask
    "request.args",
    "request.args.get",
    "request.args.getlist",
    "request.form",
    "request.form.get",
    "request.json",
    "request.data",
    "request.values",
    "request.files",
    "request.cookies",
    "request.headers",
    "request.get_json()",
    "request.get_data()",
    // Django
    "request.GET",
    "request.POST",
    "request.body",
    "request.META",
    "request.FILES",
    "request.COOKIES",
    // FastAPI - these are parameter names, recognised via classify_param_taint
    // but listed here for motif matching
    "Query",
    "Path",
    "Body",
    "Form",
    "Header",
    "Cookie",
    // aiohttp
    "request.match_info",
    "request.rel_url.query",
    "await request.json()",
    "await request.text()",
    "await request.read()",
    "await request.post()",
];

pub(super) static PY_SANITIZER_NAMES: &[&str] = &[
    "escape",
    "html_escape",
    "escape_html",
    "escape_for_html",
    "escape_url",
    "escape_js",
    "escape_xml",
    "quote",
    "quote_plus",
    "sanitize",
    "validate_email",
    "bleach",
    "clean",
    "quoteattr",
    "markupsafe.escape",
    "bleach.clean",
    "int",
    "float",
    "bool",
    "shlex.quote",
    "urllib.parse.quote",
    "html.escape",
    "paramstyle",
];

pub(super) const PY_VOCAB: LanguageVocab = LanguageVocab {
    language: "python",
    sink_names: PY_SINK_NAMES,
    sink_signatures: PY_SINK_SIGNATURES,
    idor_sinks: &[],
    source_patterns: PY_SOURCE_PATTERNS,
    request_param_names: PY_REQUEST_PARAM_NAMES,
    sanitizer_names: PY_SANITIZER_NAMES,
    classify_sanitizer: python_classify_sanitizer,
    propagators: PYTHON_PROPAGATORS,
    session_roots: &[],
    route_patterns: &[],
};

pub(crate) fn vocab() -> &'static LanguageVocab {
    &PY_VOCAB
}
