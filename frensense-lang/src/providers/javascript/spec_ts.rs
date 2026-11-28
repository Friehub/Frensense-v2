// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! TypeScript [`LanguageSpec`](crate::spec::LanguageSpec) implementation.
//!
//! TypeScript is the reference member of the family: the shared behaviour
//! lives behind [`JsFamily`](super::JsFamily), and this file carries only the
//! dialect-specific spellings (TSX grammar, `ts`-family extensions,
//! `type_identifier` symbol query, NestJS route decorators), plus Angular's
//! inline component templates.
//!
//! # Angular inline templates
//!
//! `@Component({ template: \`…\` })` puts markup inside a TypeScript string.
//! Angular sanitizes that markup's bindings just like an external template,
//! so only a `bypassSecurityTrust…` call inside an expression can make one
//! unsafe. [`super::angular`] finds those bindings and blanks the decorator
//! before parsing: the class and its imports still lower normally, and the
//! engine overlays each reported expression where the decorator used to be,
//! so the bypass call is matched as a sink at its original offset. A file
//! without an inline template is returned untouched.

use std::borrow::Cow;

use crate::spec::TemplateBinding;

use super::angular::{
    blank_component_decorators, component_field_initializers, inline_bypass_spans,
};
use super::family::{JsDialect, JsFamily};

/// TypeScript (`ts`/`tsx`/`mts`/`cts`).
#[derive(Debug)]
pub struct TypeScriptSpec;

impl JsFamily for TypeScriptSpec {
    const DIALECT: JsDialect = JsDialect::TypeScript;

    fn preprocess_source<'a>(&self, source: &'a str) -> Cow<'a, str> {
        blank_component_decorators(source)
    }

    fn template_expressions_source(&self, source: &str) -> Vec<(usize, usize)> {
        // A sanitized binding is not a write; lowering it lets a
        // `bypassSecurityTrust…` call inside it reach its sink.
        inline_bypass_spans(source)
    }

    fn template_bindings_source(&self, source: &str) -> Vec<TemplateBinding> {
        // A template reads the component instance, not module bindings, so
        // expose the class's field initializers under their template names.
        component_field_initializers(source, &Self::DIALECT.language())
    }
}
