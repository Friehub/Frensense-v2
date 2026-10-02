// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//! JavaScript and TypeScript [`LanguageSpec`](crate::spec::LanguageSpec)
//! implementations.
//!
//! Both share the same AST grammar (TypeScript is a superset of JavaScript in
//! tree-sitter-typescript). They differ only in the `tree_sitter_language()`
//! call and file extensions.
//!
//! Layout:
//! - [`ast`] - shared AST classification (node → [`NodeRole`])
//! - [`imports`] - ESM/CommonJS import extraction
//! - [`packages`] - npm package → [`PackageCategory`] knowledge
//! - [`sanitizers`] / [`propagators`] - taint-transfer rules
//! - [`params`] - parameter → [`TaintOrigin`](crate::spec::TaintOrigin) classification
//! - [`tables`] - static sink/source tables
//! - [`spec_ts`] / [`spec_js`] - the two `LanguageSpec` impls

mod ast;
mod imports;
mod packages;
mod params;
mod propagators;
mod sanitizers;
mod spec_js;
mod spec_ts;
mod tables;

pub use spec_js::JavaScriptSpec;
pub use spec_ts::TypeScriptSpec;
