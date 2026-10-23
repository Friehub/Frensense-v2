// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Python provider vocabulary, split per framework family (Phase 6.4).
//!
//! HTTP/Web frameworks (Flask, FastAPI, Django, aiohttp) knowledge lives in
//! `python/web.rs`, database/ORM knowledge in `python/db.rs`, and the
//! remaining sink/sanitizer/propagator lists in the matching files. This
//! module owns no static table of its own; it reassembles the single
//! `LanguageVocab` the pack emits, keeping framework knowledge together.

mod core;
mod db;
mod propagators;
mod sanitizers;
mod web;

use std::sync::LazyLock;

use super::LanguageVocab;

/// Assemble the full Python `LanguageVocab` from the per-framework
/// family files.
pub(crate) fn vocab() -> &'static LanguageVocab {
    static V: LazyLock<LanguageVocab> = LazyLock::new(|| {
        // Concat the web-framework and framework-agnostic sink names into
        // a single flat list for `LanguageVocab`. The `Vec` is leaked into
        // the static so the returned `&'static` slice stays valid for the
        // process lifetime.
        let mut sink_names = Vec::<(&str, crate::role_map::SinkLabel)>::new();
        sink_names.extend_from_slice(web::PY_WEB_SINKS);
        sink_names.extend_from_slice(core::PY_CORE_SINKS);
        let sink_names = Box::leak(Box::new(sink_names));

        LanguageVocab {
            language: "python",
            ambiguous_verbs: crate::data::BOOTSTRAP_AMBIGUOUS_VERBS,
            // Python builtins: the bare name IS the API, and a
            // receiver-qualified call on an unrelated receiver is not the
            // builtin (WI-12). `eval`/`exec`/`compile`/`open` are the
            // language's own functions; `x.eval(t)`, `x.open(t)` are
            // ordinary methods on somebody else's object.
            global_only_sinks: &["eval", "compile", "open"],
            package_scoped_sinks: &[],
            sink_names: sink_names.as_slice(),
            sink_signatures: db::PY_SINK_SIGNATURES,
            idor_sinks: &[],
            source_patterns: web::PY_SOURCE_PATTERNS,
            request_param_names: web::PY_REQUEST_PARAM_NAMES,
            sanitizer_names: sanitizers::PY_SANITIZER_NAMES,
            classify_sanitizer: sanitizers::python_classify_sanitizer,
            propagators: propagators::PYTHON_PROPAGATORS,
            session_roots: &[],
            route_patterns: &[],
            policies: web::PY_POLICIES,
        }
    });
    &V
}
