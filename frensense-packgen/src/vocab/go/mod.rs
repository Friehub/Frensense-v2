// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Go provider vocabulary, split per framework family (Phase 6.4).
//!
//! Http transport (web frameworks + clients) lives in `go/http.rs`, database
//! /ORM knowledge in `go/db.rs`, and the remaining lists in the matching
//! files. This module owns no static table of its own; it reassembles the
//! single `LanguageVocab` the pack emits, so each framework's knowledge stays
//! together in one `.rs` file under the language folder.

mod db;
mod http;

use super::LanguageVocab;

/// Assemble the full Go `LanguageVocab` from the per-framework family files.
pub(crate) fn vocab() -> &'static LanguageVocab {
    static V: LazyVocab = LazyVocab {
        data: {
            LanguageVocab {
                language: "go",
                ambiguous_verbs: crate::data::BOOTSTRAP_AMBIGUOUS_VERBS,
                global_only_sinks: &[],
                package_scoped_sinks: db::GO_PACKAGE_SCOPED_SINKS,
                sink_names: db::GO_SINK_NAMES,
                sink_signatures: db::GO_SINK_SIGNATURES,
                idor_sinks: &[],
                source_patterns: http::GO_SOURCE_PATTERNS,
                request_param_names: http::GO_REQUEST_PARAM_NAMES,
                sanitizer_names: db::GO_SANITIZER_NAMES,
                classify_sanitizer: db::go_classify_sanitizer,
                propagators: db::GO_PROPAGATORS,
                session_roots: &[],
                route_patterns: http::GO_ROUTE_PATTERNS,
                policies: &[],
            }
        },
    };
    &V.data
}

struct LazyVocab {
    data: LanguageVocab,
}
