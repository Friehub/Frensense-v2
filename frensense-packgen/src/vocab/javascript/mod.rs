// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! JS/TS provider vocabulary, assembled per framework family.
//!
//! Framework-specific knowledge lives in dedicated modules:
//! - `core.rs`: Generic DOM, Node.js, and core JavaScript/TypeScript APIs.
//! - `nextjs.rs`: Next.js App Router and Pages Router (`next/server`, `next/navigation`, `next/headers`, `next/cache`).
//! - `vue.rs`: Vue 3, Vue Router (`vue-router`), and Pinia reactivity/routing.
//! - `nestjs.rs`: NestJS controller route decorators and database ORM sinks (`@nestjs/typeorm`, `@nestjs/mongoose`).
//! - `nuxt.rs`: Nuxt 3, Nitro, h3, and ofetch (`h3`, `ofetch`, `nuxt`).
//! - `propagators.rs`: Dataflow propagator rules across collections and promises.
//! - `sanitizers.rs`: Sanitizer recognition and classification.
//!
//! JavaScript and TypeScript share this vocabulary set.

mod core;
mod nestjs;
mod nextjs;
mod nuxt;
mod propagators;
mod sanitizers;
mod vue;

use std::sync::LazyLock;

use super::LanguageVocab;

/// The conventional request-parameter source names, formerly
/// `spec_ts.rs::request_param_names` (both specs emitted them).
///
/// Only names that denote an HTTP request object stay. `ctx`, `c`, `event`,
/// `context`, `r`, `e`, `input`, `args`, `parent` and `info` are generic
/// parameter names (rpc contexts, minified single letters, callback
/// payloads); marking them tainted fired on every library that uses them.
/// Their request-carrying members are covered by the dotted source
/// patterns (`ctx.request.body`, `c.req.query`, `event.body`, ...).
static REQUEST_PARAM_NAMES: &[&str] = &["req", "request"];

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

type PackageScopedSinkRow = (&'static str, &'static str, crate::role_map::SinkLabel);
type SinkSignatureRow = (&'static str, &'static [usize], bool);

struct SharedJsVocabTables {
    package_scoped_sinks: &'static [PackageScopedSinkRow],
    sink_signatures: &'static [SinkSignatureRow],
    source_patterns: &'static [&'static str],
    propagators: &'static [crate::role_map::PropagatorRule],
    route_patterns: &'static [&'static str],
}

static SHARED_TABLES: LazyLock<SharedJsVocabTables> = LazyLock::new(|| {
    let mut package_scoped_sinks = Vec::new();
    package_scoped_sinks.extend_from_slice(core::JS_PACKAGE_SCOPED_SINKS);
    package_scoped_sinks.extend_from_slice(nextjs::NEXTJS_PACKAGE_SCOPED_SINKS);
    package_scoped_sinks.extend_from_slice(vue::VUE_PACKAGE_SCOPED_SINKS);
    package_scoped_sinks.extend_from_slice(nestjs::NESTJS_PACKAGE_SCOPED_SINKS);
    package_scoped_sinks.extend_from_slice(nuxt::NUXT_PACKAGE_SCOPED_SINKS);
    let package_scoped_sinks = Box::leak(package_scoped_sinks.into_boxed_slice());

    let mut sink_signatures = Vec::new();
    sink_signatures.extend_from_slice(core::JS_SINK_SIGNATURES);
    let sink_signatures = Box::leak(sink_signatures.into_boxed_slice());

    let mut source_patterns = Vec::new();
    source_patterns.extend_from_slice(core::JS_SOURCE_PATTERNS);
    source_patterns.extend_from_slice(nextjs::NEXTJS_SOURCE_PATTERNS);
    source_patterns.extend_from_slice(vue::VUE_SOURCE_PATTERNS);
    source_patterns.extend_from_slice(nuxt::NUXT_SOURCE_PATTERNS);
    let source_patterns = Box::leak(source_patterns.into_boxed_slice());

    let mut propagators = Vec::new();
    propagators.extend_from_slice(propagators::JS_PROPAGATORS);
    propagators.extend_from_slice(vue::VUE_PROPAGATORS);
    let propagators = Box::leak(propagators.into_boxed_slice());

    let mut route_patterns = Vec::new();
    route_patterns.extend_from_slice(ROUTE_PATTERNS);
    route_patterns.extend_from_slice(nestjs::NESTJS_ROUTE_PATTERNS);
    let route_patterns = Box::leak(route_patterns.into_boxed_slice());

    SharedJsVocabTables {
        package_scoped_sinks,
        sink_signatures,
        source_patterns,
        propagators,
        route_patterns,
    }
});

fn make_vocab(language: &'static str, s: &SharedJsVocabTables) -> LanguageVocab {
    LanguageVocab {
        language,
        ambiguous_verbs: crate::data::BOOTSTRAP_AMBIGUOUS_VERBS,
        // `eval` is a global builtin in both dialects: `engine.eval(x)` on an
        // unqualified receiver is not the language's eval (WI-12).
        global_only_sinks: &["eval"],
        sink_names: core::JS_SINK_NAMES,
        package_scoped_sinks: s.package_scoped_sinks,
        sink_signatures: s.sink_signatures,
        idor_sinks: core::JS_IDOR_SINKS,
        source_patterns: s.source_patterns,
        request_param_names: REQUEST_PARAM_NAMES,
        sanitizer_names: sanitizers::JS_SANITIZER_NAMES,
        classify_sanitizer: sanitizers::js_classify_sanitizer,
        propagators: s.propagators,
        session_roots: core::JS_SESSION_ROOTS,
        route_patterns: s.route_patterns,
        policies: &[],
    }
}

static TYPESCRIPT_VOCAB: LazyLock<LanguageVocab> =
    LazyLock::new(|| make_vocab("typescript", &SHARED_TABLES));

static JAVASCRIPT_VOCAB: LazyLock<LanguageVocab> =
    LazyLock::new(|| make_vocab("javascript", &SHARED_TABLES));

pub(crate) fn typescript_vocab() -> &'static LanguageVocab {
    &TYPESCRIPT_VOCAB
}

pub(crate) fn javascript_vocab() -> &'static LanguageVocab {
    &JAVASCRIPT_VOCAB
}
