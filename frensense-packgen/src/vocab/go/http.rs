// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Go HTTP-transport knowledge: request-source patterns, route-registration
//! call forms (phase 6.4), and HTTP/URL transport sink names. Framework
//! knowledge (net/http, Gin, Echo, Fiber) kept together.

/// Conventional request-parameter source patterns for Go frameworks.
/// `r` = *http.Request (net/http), `c` = *gin.Context (Gin), `c` = echo.Context (Echo).
/// `r`, `c`, `ctx` and `w` are generic Go names (receivers, contexts, the
/// response writer): the request-carrying members are dotted source
/// patterns (`r.URL.Query`, `r.FormValue`, `c.Param`, ...).
pub(crate) static GO_REQUEST_PARAM_NAMES: &[&str] = &["req"];

/// Request-source patterns: which member paths carry untrusted input.
/// Split by framework because `c.Param` (Gin) and `c.Params` (Fiber)
/// hit different receivers, and `r.Body` is a net/http thing.
pub(crate) static GO_SOURCE_PATTERNS: &[&str] = &[
    // net/http standard library
    "r.URL.Query",
    "r.URL.Path",
    "r.URL.RawQuery",
    "r.FormValue",
    "r.PostFormValue",
    "r.Body",
    "r.Header.Get",
    "r.PathValue",
    // Gin routing/context
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

/// Route-registration call forms per the framework-scope spec sec 4.2. The
/// harness reads these from `FactTable::route_patterns` (trimmed of the
/// trailing `(`). Only registration call shapes; handler arguments are
/// resolved through `is_route_registration`.
pub(crate) static GO_ROUTE_PATTERNS: &[&str] = &[
    // net/http: value- and pointer-receiver registrations
    "http.HandleFunc(",
    "http.Handle(",
    // gorilla/chi/mux framework router registration
    "mux.Handle(",
    "mux.HandleFunc(",
];
