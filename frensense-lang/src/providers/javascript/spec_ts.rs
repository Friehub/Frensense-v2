// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! TypeScript [`LanguageSpec`](crate::spec::LanguageSpec) implementation.
//!
//! TypeScript is the reference member of the family: the shared behaviour
//! lives behind [`JsFamily`](super::JsFamily), and this file carries only the
//! dialect-specific spellings (TSX grammar, `ts`-family extensions,
//! `type_identifier` symbol query, NestJS route decorators).

use super::family::{JsDialect, JsFamily};

/// TypeScript (`ts`/`tsx`/`mts`/`cts`), plus the script blocks of a `.vue`
/// SFC, which parse with the same TSX grammar.
#[derive(Debug)]
pub struct TypeScriptSpec;

impl JsFamily for TypeScriptSpec {
    const DIALECT: JsDialect = JsDialect::TypeScript;
}
