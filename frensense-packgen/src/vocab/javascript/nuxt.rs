// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Nuxt 3, Nitro, h3, and ofetch provider vocabulary.
//!
//! Covers:
//! - `h3`: server event handlers, redirects, header injections, request extractors
//! - `ofetch`: HTTP client `$fetch` SSRF sink
//! - `nuxt`: data fetching hooks (`useFetch`, `useAsyncData`) and navigation (`navigateTo`)

use crate::role_map::SinkLabel;

/// Package-scoped sinks for Nuxt, Nitro, h3, and ofetch (`call`, `package`, `label`).
pub(super) static NUXT_PACKAGE_SCOPED_SINKS: &[(&str, &str, SinkLabel)] = &[
    // h3 server sinks
    ("sendRedirect", "h3", SinkLabel::OpenRedirect),
    ("setResponseHeader", "h3", SinkLabel::HeaderInjection),
    ("appendResponseHeader", "h3", SinkLabel::HeaderInjection),
    // ofetch client sink
    ("$fetch", "ofetch", SinkLabel::Ssrf),
    // Nuxt 3 composables
    ("$fetch", "nuxt", SinkLabel::Ssrf),
    ("useFetch", "nuxt", SinkLabel::Ssrf),
    ("useAsyncData", "nuxt", SinkLabel::Ssrf),
    ("navigateTo", "nuxt", SinkLabel::OpenRedirect),
];

/// Source patterns for h3 / Nitro request extractors and Nuxt event context.
pub(super) static NUXT_SOURCE_PATTERNS: &[&str] = &[
    "getQuery",
    "getValidatedQuery",
    "readBody",
    "readValidatedBody",
    "readRawBody",
    "readFormData",
    "readMultipartFormData",
    "getCookie",
    "parseCookies",
    "getRouterParam",
    "getRouterParams",
    "getHeader",
    "getHeaders",
    "getRequestURL",
    "event.node.req",
    "event.context",
];
