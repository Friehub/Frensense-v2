// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Angular component templates ([`LanguageSpec`](crate::spec::LanguageSpec)).
//!
//! Angular keeps its template in `.component.html` (or any external `.html`
//! referenced by `templateUrl`), separate from the component class. This spec
//! covers that template file: the whole file is markup, so `preprocess_source`
//! blanks all of it (newlines kept) and the engine lowers the reported
//! property-binding expressions into the module IR.
//!
//! # Component prop sinks
//!
//! Angular escapes interpolation (`{{ value }}`) and sanitizes most property
//! bindings, but the bindings that write markup are reported here:
//!
//! - `[innerHTML]="expr"` - the HTML security context;
//! - `[outerHTML]="expr"` - replaces the element, including its markup;
//! - `[srcdoc]="expr"` - the `iframe` document.
//!
//! A flow reaching one of them is only exploitable when the value bypasses
//! Angular's sanitizer (`DomSanitizer.bypassSecurityTrustHtml`); the sanitizer
//! vocabulary lives in `frensense-packgen`, so a finding means "this value is
//! bound as raw HTML", not automatically "this is exploitable".
//!
//! Only quoted bindings are read. A value written through an interpolated
//! attribute is a string, not an expression. Constructs inside
//! `<!-- … -->` comments and inside `<script>` bodies are inert.
//!
//! Inline templates (`@Component({ template: \`…\` })` in a `.ts` file) are
//! not covered: their markup lives inside a string literal of an otherwise
//! TypeScript file, which needs its own lowering.
//!
//! Security vocabulary (sinks, sources, sanitizers) lives in
//! `frensense-packgen`; this file is mechanism only.

use std::borrow::Cow;

use super::family::{JsDialect, JsFamily};
use super::sfc::{blank_outside, comment_ranges, in_ranges, script_body_ranges};

/// Property bindings whose value is written to the DOM as markup.
const MARKUP_BINDINGS: &[&[u8]] = &[b"[innerHTML]", b"[outerHTML]", b"[srcdoc]"];

/// An Angular template file: markup only, parsed with the TSX grammar because
/// the engine lowers the bound expressions as TypeScript.
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

    fn template_writes_source(&self, source: &str) -> Vec<(usize, usize)> {
        let bytes = source.as_bytes();
        let scripts = script_body_ranges(bytes);
        let markup = super::sfc::complement(bytes.len(), &scripts);
        let comments = comment_ranges(bytes, &markup);
        binding_writes(bytes, &scripts, &comments)
    }
}

/// Expression spans of every quoted markup binding outside scripts and
/// `comments`.
fn binding_writes(
    bytes: &[u8],
    scripts: &[(usize, usize)],
    comments: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut writes = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let Some(binding) = MARKUP_BINDINGS
            .iter()
            .find(|b| bytes.get(i..).is_some_and(|rest| rest.starts_with(*b)))
        else {
            i += 1;
            continue;
        };
        let marker_end = i + binding.len();
        if in_ranges(scripts, i) || in_ranges(comments, i) {
            i = marker_end;
            continue;
        }
        let Some(equals) = skip_spaces(bytes, marker_end) else {
            break;
        };
        if bytes.get(equals) != Some(&b'=') {
            i = marker_end;
            continue;
        }
        let Some(quote_at) = skip_spaces(bytes, equals + 1) else {
            break;
        };
        let Some(&quote) = bytes.get(quote_at) else {
            break;
        };
        if quote != b'"' && quote != b'\'' {
            i = marker_end;
            continue;
        }
        let start = quote_at + 1;
        let Some(rel_end) = bytes
            .get(start..)
            .and_then(|rest| rest.iter().position(|&b| b == quote))
        else {
            break;
        };
        let raw_end = start + rel_end;
        if let Some((start, end)) = trimmed_span(bytes, start, raw_end) {
            writes.push((start, end));
        }
        i = raw_end + 1;
    }
    writes
}

/// First non-space index at or after `from`.
fn skip_spaces(bytes: &[u8], from: usize) -> Option<usize> {
    let rest = bytes.get(from..)?;
    let offset = rest.iter().position(|b| !b.is_ascii_whitespace())?;
    Some(from + offset)
}

/// The non-whitespace span between `start` and `end`, if any.
fn trimmed_span(bytes: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let raw = bytes.get(start..end).unwrap_or_default();
    let first = raw.iter().position(|b| !b.is_ascii_whitespace())?;
    let last = raw.iter().rposition(|b| !b.is_ascii_whitespace())? + 1;
    (first < last).then_some((start + first, start + last))
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

    #[test]
    fn markup_bindings_report_their_expressions() {
        let writes = AngularSpec.template_writes(TEMPLATE);
        assert_eq!(writes.len(), 3, "three bindings: {writes:?}");
        assert_eq!(&TEMPLATE[writes[0].0..writes[0].1], "userInput");
        assert_eq!(&TEMPLATE[writes[1].0..writes[1].1], "userInput");
        assert_eq!(&TEMPLATE[writes[2].0..writes[2].1], "html");
    }

    #[test]
    fn property_and_interpolation_lookalikes_are_not_writes() {
        let src = "<div [title]=\"x\" [innerHTMLY]=\"y\"></div>\n<p>{{ userInput }}</p>\n";
        assert!(AngularSpec.template_writes(src).is_empty());
    }

    #[test]
    fn commented_bindings_are_inert() {
        let src =
            "<!-- <div [innerHTML]=\"userInput\"></div> -->\n<div [innerHTML]=\"live\"></div>\n";
        let writes = AngularSpec.template_writes(src);
        assert_eq!(writes.len(), 1, "one live binding: {writes:?}");
        assert_eq!(&src[writes[0].0..writes[0].1], "live");
    }

    #[test]
    fn bindings_inside_a_script_are_inert() {
        let src =
            "<script>const t = '[innerHTML]=\"x\"'</script>\n<div [innerHTML]=\"live\"></div>\n";
        let writes = AngularSpec.template_writes(src);
        assert_eq!(writes.len(), 1, "one live binding: {writes:?}");
        assert_eq!(&src[writes[0].0..writes[0].1], "live");
    }

    #[test]
    fn fact_language_delegates_to_typescript() {
        assert_eq!(AngularSpec.fact_language(), "typescript");
    }
}
