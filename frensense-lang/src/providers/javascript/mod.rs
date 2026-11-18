// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//! JavaScript and TypeScript [`LanguageSpec`](crate::spec::LanguageSpec)
//! implementations.
//!
//! JavaScript, TypeScript and a Vue SFC's script blocks are one language
//! family: same AST grammar (TypeScript is a superset of JavaScript in
//! tree-sitter-typescript), same classification, same imports and exports.
//! The family's [`LanguageSpec`](crate::spec::LanguageSpec) behaviour is
//! therefore written **once** behind [`JsFamily`], and each member states only
//! its [`JsDialect`] — the extensions, grammar, symbol query and wrapper that
//! actually differ.
//!
//! Layout:
//! - `family` - the one `LanguageSpec` implementation plus [`JsDialect`]
//! - `ast` - shared AST classification (node → [`NodeRole`](crate::spec::NodeRole))
//! - `imports` - ESM/CommonJS import extraction
//! - `packages` - npm package → [`PackageCategory`](crate::spec::PackageCategory) knowledge
//! - `params` - parameter → [`TaintOrigin`](crate::spec::TaintOrigin) classification
//! - `spec_ts` / `spec_js` - the two family members ([`TypeScriptSpec`],
//!   [`JavaScriptSpec`])
//! - `spec_vue` - the Vue SFC member ([`VueSpec`]: template blanked in place by
//!   its `preprocess`, script blocks parsed by the TSX grammar)
//!
//! Security vocabulary (sinks, sources, sanitizers, propagators, session
//! roots, route patterns) lives in `frensense-packgen` since Phase 6.3;
//! the specs here are mechanism-only.

mod ast;
mod family;
mod imports;
mod packages;
mod params;
mod spec_js;
mod spec_ts;
mod spec_vue;

pub use family::{JsDialect, JsFamily};
pub use spec_js::JavaScriptSpec;
pub use spec_ts::TypeScriptSpec;
pub use spec_vue::VueSpec;
