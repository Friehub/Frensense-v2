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
//! The only way Svelte renders unescaped HTML is the `{@html expression}`
//! tag. Interpolations (`{value}`) are escaped by the compiler, so they are not
//! writes and are deliberately not reported. `{@html …}` spans are handed to
//! the engine as expression spans
//! ([`LanguageSpec::template_writes`](crate::spec::LanguageSpec::template_writes));
//! the engine synthesizes the sink call in its IR after the script body, so
//! the write reads the values the script defined.
//!
//! Svelte's reactive labels (`$: doubled = count * 2`) and store references
//! (`$count`) are ordinary JavaScript identifiers and labelled statements to
//! the TSX grammar, so they need no rewrite. Svelte 5 runes (`$state(…)`) are
//! plain calls for the same reason. A block with `lang="ts"` is TypeScript;
//! anything else is still parsed by the TSX grammar, which accepts JavaScript.
//!
//! Security vocabulary (sinks, sources, sanitizers) lives in
//! `frensense-packgen`; this file is mechanism only.

use std::borrow::Cow;

use super::family::{JsDialect, JsFamily};
use super::sfc::{blank_scripts, script_body_ranges, starts_with_ci};

/// Marker that opens a Svelte raw-HTML tag, including its `{`.
const RAW_HTML: &[u8] = b"{@html";

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
        raw_html_writes(bytes, &script_body_ranges(bytes))
    }
}

/// Expression spans of every `{@html …}` tag, skipping script bodies.
///
/// `scripts` are body ranges of `<script>` blocks: a `{@html` inside them is
/// a string or code, not markup. The returned span is the expression only -
/// the `{@html` marker, surrounding whitespace and the closing `}` are
/// excluded - because the engine overlays exactly those bytes onto the
/// blanked source and lowers them as one expression.
fn raw_html_writes(bytes: &[u8], scripts: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut writes = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !starts_with_ci(bytes.get(i..).unwrap_or_default(), "{@html") {
            i += 1;
            continue;
        }
        let marker_end = i + RAW_HTML.len();
        if scripts
            .iter()
            .any(|&(start, end)| i < end && marker_end > start)
        {
            i = marker_end;
            continue;
        }
        // Whitespace is required between the tag and its expression, which
        // also rejects lookalikes such as `{@htmls}`.
        if !bytes.get(marker_end).is_some_and(u8::is_ascii_whitespace) {
            i = marker_end;
            continue;
        }
        let expr_start = bytes[marker_end..]
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .map_or(marker_end, |p| marker_end + p);
        let Some(close) = expression_end(bytes, i) else {
            break;
        };
        let expr_end = bytes
            .get(expr_start..close)
            .unwrap_or_default()
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
            .map_or(expr_start, |p| expr_start + p + 1);
        if expr_end > expr_start {
            writes.push((expr_start, expr_end));
        }
        i = close + 1;
    }
    writes
}

/// Index of the `}` closing the `{` at `open`, honouring nesting and strings.
///
/// Svelte expressions may contain object literals, arrow bodies and template
/// literals, so a plain `find('}')` would cut `{@html { a: 1 }}` or
/// `{@html `${a}`}` short. Quotes are tracked so a brace inside a string does
/// not change the depth; a template literal's `${…}` nests like any other
/// braces.
fn expression_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = 0u8;
    let mut i = open;
    while let Some(&byte) = bytes.get(i) {
        if quote != 0 {
            if byte == b'\\' {
                i += 2;
                continue;
            }
            if byte == quote {
                quote = 0;
            }
        } else {
            match byte {
                b'\'' | b'"' | b'`' => quote = byte,
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
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

    #[test]
    fn raw_html_inside_a_script_is_not_a_write() {
        let src = "<script>\nconst tpl = '{@html x}'\n</script>\n";
        assert!(SvelteSpec.template_writes(src).is_empty());
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
