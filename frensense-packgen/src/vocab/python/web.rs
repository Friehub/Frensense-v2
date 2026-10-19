// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Python web-framework knowledge: request-parameter conventions and
//! source patterns for Flask, FastAPI, Django, aiohttp, plus the HTTP
//! transport / response sinks. Kept together because they share the same
//! web-framework vocabulary.

/// Request-parameter names for the web frameworks.
pub(crate) static PY_REQUEST_PARAM_NAMES: &[&str] = &["request", "req", "r"];

/// Request-source patterns: which member paths carry untrusted input.
/// Split by framework because `request.args` (Flask), `request.GET` (Django)
/// and `request.query_params` (FastAPI) hit different receivers/objects.
pub(crate) static PY_SOURCE_PATTERNS: &[&str] = &[
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
    // FastAPI - parameter names recognised via classify_param_taint, listed
    // here for motif matching
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

/// Sink names related to the HTTP transport, response writing and
/// template rendering: SSRF, XSS (reflected), open redirect, template SSTI.
pub(crate) static PY_WEB_SINKS: &[(&str, crate::role_map::SinkLabel)] = &[
    // SSRF
    ("get", crate::role_map::SinkLabel::Ssrf),
    ("post", crate::role_map::SinkLabel::Ssrf),
    ("request", crate::role_map::SinkLabel::Ssrf),
    ("send", crate::role_map::SinkLabel::Ssrf),
    // HTTP clients: the URL argument is attacker-controlled when it comes
    // from the request. Declared under the client root (`requests.get`, not
    // the bare verb) so only a qualified call arms - a bare `get`/`post`
    // on an unrelated receiver stays whatever that receiver's own API says.
    ("requests.get", crate::role_map::SinkLabel::Ssrf),
    ("requests.post", crate::role_map::SinkLabel::Ssrf),
    ("requests.put", crate::role_map::SinkLabel::Ssrf),
    ("requests.patch", crate::role_map::SinkLabel::Ssrf),
    ("requests.delete", crate::role_map::SinkLabel::Ssrf),
    ("requests.head", crate::role_map::SinkLabel::Ssrf),
    ("requests.request", crate::role_map::SinkLabel::Ssrf),
    ("httpx.get", crate::role_map::SinkLabel::Ssrf),
    ("httpx.post", crate::role_map::SinkLabel::Ssrf),
    ("urllib.request.urlopen", crate::role_map::SinkLabel::Ssrf),
    // Open Redirect
    ("redirect", crate::role_map::SinkLabel::OpenRedirect),
    // XSS (reflected)
    ("make_response", crate::role_map::SinkLabel::XssReflected),
    // Template SSTI
    ("render_template", crate::role_map::SinkLabel::TemplateSsti),
    (
        "render_template_string",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    ("from_string", crate::role_map::SinkLabel::TemplateSsti),
    ("render", crate::role_map::SinkLabel::TemplateSsti),
    // XPath injection (CWE-643): lxml `XPath(expr)` / `element.xpath(expr)`.
    ("XPath", crate::role_map::SinkLabel::XpathInjection),
    ("xpath", crate::role_map::SinkLabel::XpathInjection),
];
