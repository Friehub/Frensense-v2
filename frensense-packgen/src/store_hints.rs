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
use frensense_engine::ir::JSX_PROPS_BASE_KIND;

/// The DOM store sinks whose field name alone is not evidence: a receiver
/// must come from one of these calls, or carry the name as its declared type.
const JS_DOM_BASE_KINDS: &[&str] = &[
    "querySelector",
    "querySelectorAll",
    "getElementById",
    "getElementsByClassName",
    "getElementsByTagName",
    "createElement",
];

/// The JSX attribute: JSX lowering types its props temp as
/// [`JSX_PROPS_BASE_KIND`], so only a real JSX props object arms the sink.
const JSX_ONLY: &[&str] = &[JSX_PROPS_BASE_KIND];

/// The payload table. Keyed by call, not language: the hint is the same for
/// every front end that lowers the field write.
pub(crate) fn scopes() -> Vec<SinkBaseKindScope> {
    [
        ("innerHTML", JS_DOM_BASE_KINDS),
        ("outerHTML", JS_DOM_BASE_KINDS),
        ("dangerouslySetInnerHTML", JSX_ONLY),
    ]
    .into_iter()
    .map(|(call, kinds)| {
        SinkBaseKindScope::new(call, None, kinds.iter().map(|k| (*k).to_string()).collect())
    })
    .collect()
}
