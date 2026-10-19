// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Python sanitizer vocabulary: the classification function and the list
//! of names recognised as sanitizers. Split by family so HTML-escaping
//! helpers, URL encoders and SQL parameterization rules stay together.

use crate::role_map::SanitizerKind;

/// Classify a Python call as a sanitizer; returns `None` for unknown names.
/// Mirrors the per-language `classify_sanitizer` used at pack install.
pub(crate) fn python_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    if call == "shlex.quote" {
        return Some(SanitizerKind::Full);
    }
    match call.rsplit('.').next().unwrap_or(call) {
        // Numeric coercion
        "int" | "float" | "bool" | "abs" | "round" => Some(SanitizerKind::Full),
        // Digit-only validity predicates. `uid.isdigit()` proves the value
        // holds no SQL/HTML/path/shell metacharacter, so it is a full
        // validator. The pack generator's `is*` guard-style heuristic
        // (`is_predicate_guard`) then lets the guard map treat
        // `if not uid.isdigit(): return` as a check on `uid`.
        "isdigit" | "isnumeric" | "isdecimal" => Some(SanitizerKind::Full),
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

/// All Python sanitizer names.
pub(crate) static PY_SANITIZER_NAMES: &[&str] = &[
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
    "isdigit",
    "isnumeric",
    "isdecimal",
    "shlex.quote",
    "urllib.parse.quote",
    "html.escape",
    "paramstyle",
];
