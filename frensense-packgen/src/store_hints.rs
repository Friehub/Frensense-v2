// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Store-sink base-kind hints shipped in the default pack.
//!
//! A store sink is matched by field name alone unless its signature carries
//! base kinds, which is how a bare `x.innerHTML = t` matched a receiver that
//! had nothing to do with the DOM. The hint lives in the bundle payload's
//! `sink_base_kinds` table (v10+), keyed by `(call, package)`.

use frensense_bundler::format::SinkBaseKindScope;

/// The DOM store sinks whose field name alone is not evidence: a receiver
/// must come from one of these calls, or carry the name as its declared type.
/// `dangerouslySetInnerHTML` is deliberately absent - its base is a JSX props
/// temp with no factory origin yet, so a hint would silence the real case.
const JS_DOM_BASE_KINDS: &[&str] = &[
    "querySelector",
    "querySelectorAll",
    "getElementById",
    "getElementsByClassName",
    "getElementsByTagName",
    "createElement",
];

/// The payload table for the hints above. Keyed by call, not language: the
/// hint is the same for every front end that lowers the field write.
pub(crate) fn scopes() -> Vec<SinkBaseKindScope> {
    ["innerHTML", "outerHTML"]
        .into_iter()
        .map(|call| {
            SinkBaseKindScope::new(
                call,
                None,
                JS_DOM_BASE_KINDS.iter().map(|k| (*k).to_string()).collect(),
            )
        })
        .collect()
}
