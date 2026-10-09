// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! JS/TS provider vocabulary, verbatim from `frensense-lang`'s
//! `providers/javascript` (Phase 6.3b copy; lang's copy deleted in 6.3d -
//! this static data is the sole source).
//!
//! JavaScript and TypeScript share one vocabulary set - in lang, both
//! specs returned the same statics (the JS spec even delegated its
//! request-param and route-pattern tables to the TS spec) - so one
//! vocabulary definition backs two pack language keys.

mod propagators;
mod sanitizers;
mod tables;

use super::LanguageVocab;

/// The conventional request-parameter source names, formerly
/// `spec_ts.rs::request_param_names` (both specs emitted them).
static REQUEST_PARAM_NAMES: &[&str] = &[
    "req", "request", "ctx", "context", "event", "c", "e", "r", "input", "args", "parent", "info",
];

/// The route-registration call shapes, formerly
/// `spec_ts.rs::route_registration_patterns` (both specs emitted them).
/// The harness reads these from `FactTable::route_patterns` (Phase 6.4).
static ROUTE_PATTERNS: &[&str] = &[
    "app.get(",
    "app.post(",
    "app.put(",
    "app.delete(",
    "app.patch(",
    "router.get(",
    "router.post(",
    "fastify.get(",
    "hono.get(",
];

const TYPESCRIPT_VOCAB: LanguageVocab = LanguageVocab {
    language: "typescript",
    ambiguous_verbs: crate::data::BOOTSTRAP_AMBIGUOUS_VERBS,
    sink_names: tables::JS_SINK_NAMES,
    sink_signatures: tables::JS_SINK_SIGNATURES,
    idor_sinks: tables::JS_IDOR_SINKS,
    source_patterns: tables::JS_SOURCE_PATTERNS,
    request_param_names: REQUEST_PARAM_NAMES,
    sanitizer_names: sanitizers::JS_SANITIZER_NAMES,
    classify_sanitizer: sanitizers::js_classify_sanitizer,
    propagators: propagators::JS_PROPAGATORS,
    session_roots: tables::JS_SESSION_ROOTS,
    route_patterns: ROUTE_PATTERNS,
};

const JAVASCRIPT_VOCAB: LanguageVocab = LanguageVocab {
    language: "javascript",
    ..TYPESCRIPT_VOCAB
};

pub(crate) fn typescript_vocab() -> &'static LanguageVocab {
    &TYPESCRIPT_VOCAB
}

pub(crate) fn javascript_vocab() -> &'static LanguageVocab {
    &JAVASCRIPT_VOCAB
}
