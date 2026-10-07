// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Python provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/python.rs` (Phase 6.3c; lang's copy deleted
//! in 6.3d - this static data is the sole source).

use super::call_last_segment;
use super::LanguageVocab;
use crate::role_map::{PropagatorRule, SanitizerKind};

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

pub(super) static PY_SINK_NAMES: &[(&str, crate::role_map::SinkLabel)] = &[
    // Code Execution
    ("eval", crate::role_map::SinkLabel::CodeExecution),
    ("exec", crate::role_map::SinkLabel::CodeExecution),
    ("compile", crate::role_map::SinkLabel::CodeExecution),
    // Command Injection
    ("system", crate::role_map::SinkLabel::CommandInjection),
    ("popen", crate::role_map::SinkLabel::CommandInjection),
    ("call", crate::role_map::SinkLabel::CommandInjection),
    ("run", crate::role_map::SinkLabel::CommandInjection),
    ("check_output", crate::role_map::SinkLabel::CommandInjection),
    ("Popen", crate::role_map::SinkLabel::CommandInjection),
    ("execfile", crate::role_map::SinkLabel::CommandInjection),
    ("spawn", crate::role_map::SinkLabel::CommandInjection),
    ("spawnSync", crate::role_map::SinkLabel::CommandInjection),
    // SQL Injection
    ("execute", crate::role_map::SinkLabel::SqlInjection),
    ("executemany", crate::role_map::SinkLabel::SqlInjection),
    ("raw", crate::role_map::SinkLabel::SqlInjection),
    ("raw_sql", crate::role_map::SinkLabel::SqlInjection),
    ("query", crate::role_map::SinkLabel::SqlInjection),
    ("executeRaw", crate::role_map::SinkLabel::SqlInjection),
    ("queryRaw", crate::role_map::SinkLabel::SqlInjection),
    ("filter", crate::role_map::SinkLabel::SqlInjection), // Django ORM raw filter
    ("extra", crate::role_map::SinkLabel::SqlInjection),  // Django ORM .extra()
    ("prepare", crate::role_map::SinkLabel::SqlInjection),
    // Path Traversal
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
    // SSRF
    ("get", crate::role_map::SinkLabel::Ssrf),
    ("post", crate::role_map::SinkLabel::Ssrf),
    ("request", crate::role_map::SinkLabel::Ssrf),
    ("send", crate::role_map::SinkLabel::Ssrf),
    ("fetch", crate::role_map::SinkLabel::Ssrf),
    ("http.get", crate::role_map::SinkLabel::Ssrf),
    ("https.get", crate::role_map::SinkLabel::Ssrf),
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
    // SSTI - Template engine renders
    ("render_template", crate::role_map::SinkLabel::TemplateSsti),
    (
        "render_template_string",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    ("from_string", crate::role_map::SinkLabel::TemplateSsti),
    ("render", crate::role_map::SinkLabel::TemplateSsti),
    ("ejs.render", crate::role_map::SinkLabel::TemplateSsti),
    ("nunjucks.render", crate::role_map::SinkLabel::TemplateSsti),
    ("marko.render", crate::role_map::SinkLabel::TemplateSsti),
    ("eta.render", crate::role_map::SinkLabel::TemplateSsti),
    ("swig.render", crate::role_map::SinkLabel::TemplateSsti),
    ("liquid.render", crate::role_map::SinkLabel::TemplateSsti),
    ("mustache.render", crate::role_map::SinkLabel::TemplateSsti),
    // Response
    ("make_response", crate::role_map::SinkLabel::XssReflected),
    ("res.send", crate::role_map::SinkLabel::ResponseLeak),
    ("res.json", crate::role_map::SinkLabel::ResponseLeak),
    // Unsafe Deserialization
    // (yaml.safe_load is deliberately NOT a sink: it resolves only
    // basic YAML types, which is what makes it the *safe* API.)
    (
        "pickle.loads",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    ("pickle.load", crate::role_map::SinkLabel::UnsafeDeserialize),
    ("yaml.load", crate::role_map::SinkLabel::UnsafeDeserialize),
    (
        "marshal.loads",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    ("shelve.open", crate::role_map::SinkLabel::UnsafeDeserialize),
    ("loads", crate::role_map::SinkLabel::UnsafeDeserialize),
    ("load", crate::role_map::SinkLabel::UnsafeDeserialize),
    (
        "bincode::deserialize",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    // Log Leak
    ("log", crate::role_map::SinkLabel::LogLeak),
    ("error", crate::role_map::SinkLabel::LogLeak),
    ("info", crate::role_map::SinkLabel::LogLeak),
    ("debug", crate::role_map::SinkLabel::LogLeak),
    // Prototype Pollution
    // NOTE: JS-only prototype-pollution sinks (_.set, $.extend,
    // setPrototypeOf, Object.assign) are deliberately NOT in the
    // Python table. The engine matches sinks by last segment, so a
    // bare "_.set" entry would make every `.set(` call (e.g.
    // Flask's response.set_cookie lowering, ConfigParser.set) a
    // prototype-pollution sink. Python has no prototype chains.
    // XXE
    ("DOMParser", crate::role_map::SinkLabel::Xxe),
    // JWT
    ("jwt.sign", crate::role_map::SinkLabel::Jwt),
    // MongoDB / ORM operators
    ("$where", crate::role_map::SinkLabel::NoSqlInjection),
    ("$regex", crate::role_map::SinkLabel::NoSqlInjection),
    ("$gt", crate::role_map::SinkLabel::NoSqlInjection),
    ("$lt", crate::role_map::SinkLabel::NoSqlInjection),
    ("$ne", crate::role_map::SinkLabel::NoSqlInjection),
    ("$in", crate::role_map::SinkLabel::NoSqlInjection),
    ("$nin", crate::role_map::SinkLabel::NoSqlInjection),
    ("$exists", crate::role_map::SinkLabel::NoSqlInjection),
    ("$expr", crate::role_map::SinkLabel::NoSqlInjection),
    ("$function", crate::role_map::SinkLabel::NoSqlInjection),
    ("$accumulator", crate::role_map::SinkLabel::NoSqlInjection),
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
    ambiguous_verbs: crate::data::BOOTSTRAP_AMBIGUOUS_VERBS,
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
