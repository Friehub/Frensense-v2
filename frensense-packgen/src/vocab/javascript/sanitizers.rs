// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Sanitizer name classification shared by the JS and TS specs.

use crate::role_map::SanitizerKind;
use crate::vocab::call_last_segment;

pub(super) fn js_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        // HTML escape
        "escape" | "escapeHtml" | "escapeHTML" | "encodeHTML" | "sanitizeHtml" | "sanitize"
        | "clean" | "purify" | "stripTags" | "stripHtml" | "bleach" | "xssFilter" | "filterXSS"
        | "inHTMLData" | "inDoubleQuotedAttr" | "he.encode" => Some(SanitizerKind::HtmlEscape),

        // URL encode
        "encodeURIComponent" | "encodeURI" | "encode" => Some(SanitizerKind::UrlEncode),

        // Numeric coercion - input is definitely a number after this
        "parseInt" | "parseFloat" | "Number" | "BigInt" | "toFixed" | "toPrecision" => {
            Some(SanitizerKind::Full)
        }

        // Type narrowing, regex guards, and shell escapes
        "test" | "shellescape" | "shellQuote" | "escapeShellArg" | "quoteForShell" | "isUUID"
        | "isEmail" | "isAlphanumeric" | "isNumeric" | "isInt" | "isFloat" | "isISO8601"
        | "isValid" => Some(SanitizerKind::Full),

        // SQL parameterization (knex, sequelize, pg style)
        "sqlEscape" | "escapeId" | "format" | "literal" | "raw" => {
            Some(SanitizerKind::SqlParameterize)
        }

        // NoSQL parameterization
        "sanitizeFilter" | "mongoSanitize" | "sanitizeValue" => {
            Some(SanitizerKind::NoSqlParameterize)
        }

        // Path canonicalization
        "basename" | "realpath" => Some(SanitizerKind::PathNormalize),

        _ => None,
    }
}

pub(super) static JS_SANITIZER_NAMES: &[&str] = &[
    "escape",
    "escapeHtml",
    "escapeHTML",
    "encodeHTML",
    "sanitizeHtml",
    "sanitize",
    "clean",
    "purify",
    "stripTags",
    "stripHtml",
    "bleach",
    "xssFilter",
    "filterXSS",
    "inHTMLData",
    "inDoubleQuotedAttr",
    "encodeURIComponent",
    "encodeURI",
    "encode",
    "parseInt",
    "parseFloat",
    "Number",
    "BigInt",
    "toFixed",
    "toPrecision",
    "shellescape",
    "shellQuote",
    "escapeShellArg",
    "quoteForShell",
    "isUUID",
    "isEmail",
    "isAlphanumeric",
    "isNumeric",
    "isInt",
    "isFloat",
    "isISO8601",
    "isValid",
    "test",
    "sqlEscape",
    "escapeId",
    "format",
    "literal",
    "raw",
    "sanitizeFilter",
    "mongoSanitize",
    "sanitizeValue",
    "basename",
];
