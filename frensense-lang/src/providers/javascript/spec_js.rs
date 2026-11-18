// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! JavaScript [`LanguageSpec`](crate::spec::LanguageSpec) implementation.
//!
//! Everything JavaScript shares with TypeScript and Vue — classification, the
//! node-kind predicates, imports/exports, package and parameter knowledge —
//! is implemented once behind [`JsFamily`](super::JsFamily). This file states
//! only what makes JavaScript *JavaScript*.

use super::family::{JsDialect, JsFamily};

/// Plain JavaScript (`js`/`jsx`/`mjs`/`cjs`).
///
/// Parsed with the tree-sitter-javascript grammar, and every shared behaviour
/// comes from the JavaScript family's blanket `LanguageSpec` implementation.
#[derive(Debug)]
pub struct JavaScriptSpec;

impl JsFamily for JavaScriptSpec {
    const DIALECT: JsDialect = JsDialect::JavaScript;
}
