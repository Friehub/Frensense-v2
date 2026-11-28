// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Svelte single-file component ([`LanguageSpec`](crate::spec::LanguageSpec)).
//!
//! A `.svelte` file is markup plus one or two `<script>` blocks, with the same
//! shape as a Vue SFC but different markup syntax: Svelte has no `<template>`
//! element (markup is implicit), so this spec always blanks outside the script
//! blocks ([`super::sfc::blank_scripts`]) instead of looking for a tag.
//!
//! Markup reaches the DOM unescaped through exactly two constructs:
//!
//! - `{@html expression}` - the raw-HTML tag;
//! - `innerHTML={expression}` on a plain HTML element - Svelte assigns the
//!   DOM property, which parses the string as markup. A component
//!   (`<Widget innerHTML={…}>`, capitalised tag) receives a *prop* instead;
//!   that is not a sink unless the component renders it, and if it does the
//!   sink is its own `{@html}` which this spec already reports.
//!
//! Everything else is escaped or inert: `{value}` interpolations, `{@render
//! snippet()}`, `{@const …}` and `{@debug …}` produce text or run code, not
//! markup. `{@render}` is the snippet render tag: its output is escaped like
//! any other value, so it must not be reported as a write.
//!
//! Reported spans are expressions, not rewritten code
//! ([`LanguageSpec::template_writes`](crate::spec::LanguageSpec::template_writes)):
//! the engine synthesizes the sink call in its IR after the script body, so
//! the write reads the values the script defined. Constructs inside
//! `<!-- … -->` comments are inert and are skipped.
//!
//! Svelte's reactive labels (`$: doubled = count * 2`), store references
//! (`$count`) and Svelte 5 runes (`$state(…)`) are ordinary JavaScript
//! identifiers, labelled statements and calls to the TSX grammar, so they
//! need no rewrite. A block with `lang="ts"` is TypeScript; anything else is
//! still parsed by the TSX grammar, which accepts JavaScript.
//!
//! Security vocabulary (sinks, sources, sanitizers) lives in
//! `frensense-packgen`; this file is mechanism only.

use std::borrow::Cow;

use super::family::{JsDialect, JsFamily};
use super::sfc::{
    blank_scripts, braced_end, comment_ranges, complement, in_ranges, script_body_ranges,
    starts_with_ci,
};

/// Marker that opens a Svelte raw-HTML tag, including its `{`.
const RAW_HTML: &[u8] = b"{@html";

/// The DOM property Svelte assigns when written as an element attribute.
const INNER_HTML: &[u8] = b"innerHTML";

/// A `.svelte` component whose script blocks are parsed with the TypeScript/TSX
/// grammar after its `preprocess` blanks the markup in place.
///
/// Registered by [`LanguageRegistry::with_default_specs`]; consumers normally
/// reach it through the registry rather than constructing it.
#[derive(Debug)]
#[non_exhaustive]
pub struct SvelteSpec;

impl JsFamily for SvelteSpec {
    const DIALECT: JsDialect = JsDialect::Svelte;

    fn preprocess_source<'a>(&self, source: &'a str) -> Cow<'a, str> {
        blank_scripts(source)
    }

    fn template_writes_source(&self, source: &str) -> Vec<(usize, usize)> {
        let bytes = source.as_bytes();
        let scripts = script_body_ranges(bytes);
        let comments = comment_ranges(bytes, &complement(bytes.len(), &scripts));
        let mut writes = raw_html_writes(bytes, &scripts, &comments);
        writes.extend(prop_writes(bytes, &scripts, &comments));
        writes.sort_unstable();
        writes
    }
}

/// Expression spans of every `{@html …}` tag, skipping scripts and comments.
///
/// The returned span is the expression only - the `{@html` marker, surrounding
/// whitespace and the closing `}` are excluded - because the engine overlays
/// exactly those bytes onto the blanked source and lowers them as one
/// expression.
fn raw_html_writes(
    bytes: &[u8],
    scripts: &[(usize, usize)],
    comments: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut writes = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !starts_with_ci(bytes.get(i..).unwrap_or_default(), "{@html") {
            i += 1;
            continue;
        }
        let marker_end = i + RAW_HTML.len();
        if in_ranges(scripts, i) || in_ranges(comments, i) {
            i = marker_end;
            continue;
        }
        // Whitespace is required between the tag and its expression, which
        // also rejects lookalikes such as `{@htmls}`.
        if !bytes.get(marker_end).is_some_and(u8::is_ascii_whitespace) {
            i = marker_end;
            continue;
        }
        let Some(close) = braced_end(bytes, i) else {
            break;
        };
        if let Some((start, end)) = trimmed_span(bytes, marker_end, close) {
            writes.push((start, end));
        }
        i = close + 1;
    }
    writes
}

/// Expression spans of `innerHTML={…}` on plain HTML elements.
///
/// Only an element write is a sink. A capitalised tag is a component: its
/// `innerHTML` attribute is a prop, and the raw-HTML decision belongs to that
/// component (`{@html}` inside it), not to the call site.
fn prop_writes(
    bytes: &[u8],
    scripts: &[(usize, usize)],
    comments: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut writes = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !starts_with_ci(bytes.get(i..).unwrap_or_default(), "innerHTML") {
            i += 1;
            continue;
        }
        let marker_end = i + INNER_HTML.len();
        if !is_word_start(bytes, i)
            || bytes.get(marker_end).copied().is_some_and(is_word_byte)
            || in_ranges(scripts, i)
            || in_ranges(comments, i)
        {
            i = marker_end;
            continue;
        }
        let Some(tag) = element_tag_before(bytes, i) else {
            i = marker_end;
            continue;
        };
        if !is_html_element(tag) {
            i = marker_end;
            continue;
        }
        // `innerHTML` must be followed by an `=` and a braced expression:
        // a static string value is not tainted, and a bare attribute is a
        // boolean property write with no markup.
        let Some(equals) = skip_spaces(bytes, marker_end) else {
            break;
        };
        if bytes.get(equals) != Some(&b'=') {
            i = marker_end;
            continue;
        }
        let Some(open) = skip_spaces(bytes, equals + 1) else {
            break;
        };
        if bytes.get(open) != Some(&b'{') {
            i = marker_end;
            continue;
        }
        let Some(close) = braced_end(bytes, open) else {
            break;
        };
        if let Some((start, end)) = trimmed_span(bytes, open + 1, close) {
            writes.push((start, end));
        }
        i = close + 1;
    }
    writes
}

/// The non-whitespace span between `start` and `end`, if any.
///
/// Trimming matters because the engine overlays exactly the reported bytes
/// and parses them as one expression: leading/trailing whitespace is fine,
/// but an empty span is not a write.
fn trimmed_span(bytes: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let raw = bytes.get(start..end).unwrap_or_default();
    let first = raw.iter().position(|b| !b.is_ascii_whitespace())?;
    let last = raw.iter().rposition(|b| !b.is_ascii_whitespace())? + 1;
    (first < last).then_some((start + first, start + last))
}

/// First non-space index at or after `from`.
fn skip_spaces(bytes: &[u8], from: usize) -> Option<usize> {
    let rest = bytes.get(from..)?;
    let offset = rest.iter().position(|b| !b.is_ascii_whitespace())?;
    Some(from + offset)
}

/// Whether `byte` can continue an identifier/property name.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')
}

/// Whether the token at `pos` starts at a word boundary.
fn is_word_start(bytes: &[u8], pos: usize) -> bool {
    pos == 0 || !bytes.get(pos - 1).copied().is_some_and(is_word_byte)
}

/// The tag name of the element whose opening `<` precedes `pos`, if any.
fn element_tag_before(bytes: &[u8], pos: usize) -> Option<&[u8]> {
    let mut i = pos;
    while i > 0 {
        i -= 1;
        match bytes.get(i) {
            Some(b'>') => return None,
            Some(b'<') => {
                let rest = bytes.get(i + 1..pos)?;
                let rest = rest.strip_prefix(b"/").unwrap_or(rest);
                let rest = rest.strip_prefix(b"!").unwrap_or(rest);
                let skip = rest.iter().position(|b| !b.is_ascii_whitespace())?;
                let rest = rest.get(skip..)?;
                let end = rest
                    .iter()
                    .position(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b':' | b'.')))
                    .unwrap_or(rest.len());
                return rest.get(..end);
            }
            _ => {}
        }
    }
    None
}

/// Whether `tag` is a plain HTML element rather than a component.
///
/// Svelte components are capitalised (or namespaced, e.g. `svelte:element`);
/// HTML elements are lowercase.
fn is_html_element(tag: &[u8]) -> bool {
    tag.first().is_some_and(u8::is_ascii_lowercase) && !tag.starts_with(b"svelte:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::LanguageSpec;

    const SVELTE: &str = "<script lang=\"ts\">\n  let name = 'world'\n</script>\n\n<h1>Hello {name}</h1>\n\n<style>\n  h1 { color: red; }\n</style>\n";

    #[test]
    fn blanking_preserves_length_offsets_and_names() {
        let out = SvelteSpec.preprocess(SVELTE);
        assert_eq!(out.len(), SVELTE.len());
        let code = SVELTE.find("let name").unwrap();
        assert_eq!(
            &out[code..code + "let name = 'world'".len()],
            "let name = 'world'"
        );
        assert!(!out.contains("<h1>"));
        assert!(!out.contains("color"));
        assert_eq!(out.matches('\n').count(), SVELTE.matches('\n').count());
    }

    #[test]
    fn markup_only_component_is_blanked() {
        let src = "{#if ok}\n  <p>{value}</p>\n{/if}\n";
        let out = SvelteSpec.preprocess(src);
        assert_eq!(out.len(), src.len());
        assert!(out.bytes().all(|b| b == b' ' || b == b'\n'));
    }

    #[test]
    fn raw_html_reports_only_its_expression() {
        let src = "<script>let html = x</script>\n{@html html}\n";
        let writes = SvelteSpec.template_writes(src);
        assert_eq!(writes.len(), 1, "one write: {writes:?}");
        assert_eq!(&src[writes[0].0..writes[0].1], "html");
    }

    #[test]
    fn escaped_interpolation_is_not_a_write() {
        let src = "<p>{name}</p>\n{#if ok}{value}{/if}\n";
        assert!(SvelteSpec.template_writes(src).is_empty());
    }

    /// `{@render}` renders a snippet through Svelte's escaping path; the
    /// snippet's own `{@html}`, if any, is where a write is reported.
    #[test]
    fn render_tag_is_not_a_write() {
        let src = "<script>import { children } from 'svelte'</script>\n{@render children()}\n{@render fallback?.()}\n";
        assert!(SvelteSpec.template_writes(src).is_empty());
    }

    #[test]
    fn inner_html_on_an_element_is_a_write() {
        let src = "<div innerHTML={markup}></div>\n";
        let writes = SvelteSpec.template_writes(src);
        assert_eq!(writes.len(), 1, "one write: {writes:?}");
        assert_eq!(&src[writes[0].0..writes[0].1], "markup");
    }

    #[test]
    fn inner_html_on_a_component_is_not_a_write() {
        let src = "<Widget innerHTML={markup} />\n<svelte:element this=\"div\" innerHTML={x} />\n";
        assert!(SvelteSpec.template_writes(src).is_empty());
    }

    #[test]
    fn lookalike_property_names_are_not_writes() {
        let src = "<div data-innerHTML={x} innerHTMLY={y}></div>\n";
        assert!(SvelteSpec.template_writes(src).is_empty());
    }

    #[test]
    fn raw_html_inside_a_script_is_not_a_write() {
        let src = "<script>\nconst tpl = '{@html x}'\n</script>\n";
        assert!(SvelteSpec.template_writes(src).is_empty());
    }

    #[test]
    fn raw_html_inside_a_comment_is_not_a_write() {
        let src = "<!-- {@html userInput} -->\n<div>{@html real}</div>\n";
        let writes = SvelteSpec.template_writes(src);
        assert_eq!(writes.len(), 1, "only the live write: {writes:?}");
        assert_eq!(&src[writes[0].0..writes[0].1], "real");
    }

    #[test]
    fn object_and_template_literal_expressions_are_whole() {
        let src = "{@html { a: 1 }.a}{@html `${a} ${b}`}";
        let writes = SvelteSpec.template_writes(src);
        assert_eq!(writes.len(), 2, "two writes: {writes:?}");
        assert_eq!(&src[writes[0].0..writes[0].1], "{ a: 1 }.a");
        assert_eq!(&src[writes[1].0..writes[1].1], "`${a} ${b}`");
    }

    #[test]
    fn brace_inside_a_string_does_not_close_the_tag() {
        let src = "{@html '}' + tail}";
        let writes = SvelteSpec.template_writes(src);
        assert_eq!(writes.len(), 1);
        assert_eq!(&src[writes[0].0..writes[0].1], "'}' + tail");
    }

    #[test]
    fn multibyte_markup_keeps_offsets() {
        let src = "<h1>héllo ✨</h1>\n{@html x}\n";
        let writes = SvelteSpec.template_writes(src);
        assert_eq!(writes.len(), 1);
        let out = SvelteSpec.preprocess(src);
        assert_eq!(out.len(), src.len());
        assert!(!out.contains("héllo"));
    }

    /// Reactive labels and store refs are why a Svelte script needs no
    /// rewrite: they must parse as plain TypeScript.
    #[test]
    fn reactive_script_parses_without_errors() {
        let src = "<script lang=\"ts\">\n  export let count: number\n  $: doubled = count * 2\n  const label = $count\n</script>\n<p>{doubled}</p>\n";
        let blanked = SvelteSpec.preprocess(src);
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&SvelteSpec.tree_sitter_language())
            .expect("TSX grammar available");
        let tree = parser.parse(&*blanked, None).expect("parse");
        assert!(
            !tree.root_node().has_error(),
            "blanked Svelte script must parse: {}",
            tree.root_node().to_sexp()
        );
    }

    #[test]
    fn fact_language_delegates_to_typescript() {
        assert_eq!(SvelteSpec.fact_language(), "typescript");
    }
}
