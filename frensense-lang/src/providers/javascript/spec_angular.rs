// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Angular component templates ([`LanguageSpec`](crate::spec::LanguageSpec)).
//!
//! Angular keeps its template in `.component.html` (or any external `.html`
//! referenced by `templateUrl`), separate from the component class. This spec
//! covers the `*.component.html` file: the whole file is markup, so
//! `preprocess_source` blanks all of it (newlines kept) and the engine lowers
//! the expressions this spec reports.
//!
//! # Why a binding is not a sink
//!
//! Angular sanitizes markup bindings by default: `[innerHTML]`,
//! `[outerHTML]` and `[srcdoc]` are all the HTML security context, and
//! interpolation is escaped. A tainted value in one of them is therefore
//! **not** XSS, and reporting it would be a false positive. The unsafe case is
//! `DomSanitizer.bypassSecurityTrustHtml(…)`, which marks a value as trusted;
//! that call is a sink in `frensense-packgen`, so this spec reports a binding
//! only when its expression contains such a call (see [`super::angular`]).
//!
//! Inline templates in `@Component({ template: … })` are covered by the
//! TypeScript spec, which blanks the decorator and reports the same bypass
//! bindings; see [`super::angular`] for both paths.
//!
//! Only files ending in `.component.html` are claimed. A plain `index.html`
//! is not an Angular template and stays outside the scan.
//!
//! Security vocabulary (sinks, sources, sanitizers) lives in
//! `frensense-packgen`; this file is mechanism only.

use std::borrow::Cow;

use super::angular::bypass_bindings;
use super::family::{JsDialect, JsFamily};
use super::sfc::{blank_outside, comment_ranges, complement, script_body_ranges};

/// An Angular template file: markup only, parsed with the TSX grammar because
/// the engine lowers the reported expressions as TypeScript.
#[derive(Debug)]
#[non_exhaustive]
pub struct AngularSpec;

impl JsFamily for AngularSpec {
    const DIALECT: JsDialect = JsDialect::Angular;

    fn preprocess_source<'a>(&self, source: &'a str) -> Cow<'a, str> {
        // The template has no code of its own: blank all of it, preserving
        // length and newlines so reported spans stay original-file offsets.
        Cow::Owned(blank_outside(source.as_bytes(), &[]))
    }

    fn template_expressions_source(&self, source: &str) -> Vec<(usize, usize)> {
        let bytes = source.as_bytes();
        let scripts = script_body_ranges(bytes);
        let markup = complement(bytes.len(), &scripts);
        let comments = comment_ranges(bytes, &markup);
        bypass_bindings(bytes, &markup, &scripts, &comments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::LanguageSpec;

    const TEMPLATE: &str = "<div>{{ title }}</div>\n<div [innerHTML]=\"userInput\"></div>\n<div [outerHTML]='userInput'></div>\n<iframe [srcdoc]=\"html\"></iframe>\n";

    #[test]
    fn the_whole_template_blanks_without_moving_offsets() {
        let out = AngularSpec.preprocess(TEMPLATE);
        assert_eq!(out.len(), TEMPLATE.len());
        assert!(out.bytes().all(|b| b == b' ' || b == b'\n'));
        assert_eq!(out.matches('\n').count(), TEMPLATE.matches('\n').count());
    }

    /// Angular sanitizes these bindings; flagging them was the false
    /// positive this spec now avoids.
    #[test]
    fn sanitized_bindings_are_not_writes() {
        assert!(AngularSpec.template_writes(TEMPLATE).is_empty());
        assert!(AngularSpec.template_expressions(TEMPLATE).is_empty());
    }

    #[test]
    fn a_binding_that_bypasses_the_sanitizer_is_reported() {
        let src = "<div [innerHTML]=\"san.bypassSecurityTrustHtml(userInput)\"></div>\n";
        assert!(AngularSpec.template_writes(src).is_empty());
        let writes = AngularSpec.template_expressions(src);
        assert_eq!(writes.len(), 1, "{writes:?}");
        assert_eq!(
            &src[writes[0].0..writes[0].1],
            "san.bypassSecurityTrustHtml(userInput)"
        );
    }

    #[test]
    fn property_and_interpolation_lookalikes_are_not_writes() {
        let src = "<div [title]=\"x\" [innerHTMLY]=\"y\"></div>\n<p>{{ userInput }}</p>\n";
        assert!(AngularSpec.template_writes(src).is_empty());
    }

    #[test]
    fn commented_bindings_are_inert() {
        let src = "<!-- <div [innerHTML]=\"san.bypassSecurityTrustHtml(x)\"></div> -->\n<div [innerHTML]=\"san.bypassSecurityTrustHtml(live)\"></div>\n";
        let writes = AngularSpec.template_expressions(src);
        assert_eq!(writes.len(), 1, "one live binding: {writes:?}");
        assert_eq!(
            &src[writes[0].0..writes[0].1],
            "san.bypassSecurityTrustHtml(live)"
        );
    }

    #[test]
    fn fact_language_delegates_to_typescript() {
        assert_eq!(AngularSpec.fact_language(), "typescript");
    }
}
