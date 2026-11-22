// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Built-in [`LanguageSpec`](crate::spec::LanguageSpec) providers.
//!
//! One module per grammar family: [`c_lang`], [`go`], [`javascript`],
//! [`python`] and [`rust_lang`]. Each implements the trait for its own node
//! vocabulary and leaves the cross-language defaults in place where the
//! grammar agrees with them; the JavaScript module additionally covers the
//! TypeScript/TSX dialects and single-file containers through
//! [`javascript::JsFamily`].
//!
//! [`crate::registry`] owns the extension -> spec lookup, so nothing here
//! decides which provider handles which file.
pub mod c_lang;
pub mod go;
pub mod javascript;
pub mod python;
pub mod rust_lang;

#[cfg(test)]
#[path = "module_surface_tests.rs"]
mod module_surface_tests;

#[cfg(test)]
#[path = "node_vocabulary_tests.rs"]
mod node_vocabulary_tests;
