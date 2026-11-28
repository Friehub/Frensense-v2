// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Astro component ([`LanguageSpec`](crate::spec::LanguageSpec)).
//!
//! An `.astro` file is optional TypeScript frontmatter plus an HTML template:
//!
//! ```text
//! ---
//! const html = Astro.url.searchParams.get('q')
//! ---
//! <div set:html={html}></div>
//! ```
//!
//! The frontmatter is the code the engine analyses; everything after the
//! closing `---` fence is markup. `preprocess_source` keeps the frontmatter
//! body verbatim and blanks the fences and markup in place, so the TSX grammar
//! sees a plain TS module while every offset still points at the original
//! file. A frontmatter-only file is ordinary code; a template-only file (no
//! frontmatter) blanks to an empty module.
//!
//! # Component prop sinks
//!
//! Astro renders expressions escaped, so `{value}` is not a write. The
//! unescaped escape hatches are the `set:html` directives:
//!
//! - `<div set:html={html} />` on an element, and
//! - `<Fragment set:html={html} />` / `<Widget set:html={html} />` on a
//!   component, where the directive is a *prop* that forwards raw markup.
//!
//! Both are reported; `set:text` is escaped and is not. `is:raw` disables
//! expression evaluation for its children rather than injecting a value into
//! the DOM, so it is inert here.
//!
//! Constructs inside `<!-- … -->` are skipped: comments are not rendered.
//!
//! Security vocabulary (sinks, sources, sanitizers) lives in
//! `frensense-packgen`; this file is mechanism only.

use std::borrow::Cow;

use super::family::{JsDialect, JsFamily};
use super::sfc::{
    blank_outside, braced_end, comment_ranges, complement, frontmatter_span, in_ranges,
};

/// The directive that renders its expression as raw HTML.
const SET_HTML: &[u8] = b"set:html";

/// An `.astro` component whose frontmatter is parsed with the TypeScript/TSX
/// grammar after its `preprocess` blanks the template in place.
#[derive(Debug)]
#[non_exhaustive]
pub struct AstroSpec;

impl JsFamily for AstroSpec {
    const DIALECT: JsDialect = JsDialect::Astro;

    fn preprocess_source<'a>(&self, source: &'a str) -> Cow<'a, str> {
        let bytes = source.as_bytes();
        // A file with no frontmatter is all template: blank everything.
        let keep: Vec<_> = frontmatter_span(bytes).into_iter().collect();
        Cow::Owned(blank_outside(bytes, &keep))
    }

    fn template_writes_source(&self, source: &str) -> Vec<(usize, usize)> {
        let bytes = source.as_bytes();
        let keep: Vec<_> = frontmatter_span(bytes).into_iter().collect();
        let markup = complement(bytes.len(), &keep);
        let comments = comment_ranges(bytes, &markup);
        set_html_writes(bytes, &markup, &comments)
    }
}

/// Expression spans of every `set:html={…}` directive in `markup`.
///
/// `markup` excludes frontmatter; `comments` are the inert comment ranges
/// inside it. The reported span is the expression only, so the engine can
/// overlay it and lower it as one expression.
fn set_html_writes(
    bytes: &[u8],
    markup: &[(usize, usize)],
    comments: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut writes = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !in_ranges(markup, i)
            || !bytes
                .get(i..)
                .is_some_and(|rest| rest.starts_with(SET_HTML))
        {
            i += 1;
            continue;
        }
        let marker_end = i + SET_HTML.len();
        if in_ranges(comments, i)
            || pos_is_word(bytes, i)
            || bytes.get(marker_end).copied().is_some_and(is_word_byte)
        {
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

/// Whether the token at `pos` continues a preceding word.
fn pos_is_word(bytes: &[u8], pos: usize) -> bool {
    pos > 0 && bytes.get(pos - 1).copied().is_some_and(is_word_byte)
}

/// Whether `byte` can continue a directive/property name.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.')
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

    const ASTRO: &str = "---\nconst html = process.argv[2]\nconst safe = '<b>x</b>'\n---\n\n<div set:html={html}></div>\n<div set:html={safe}></div>\n<div set:text={html}></div>\n<p>{html}</p>\n";

    #[test]
    fn frontmatter_is_kept_and_markup_is_blanked() {
        let out = AstroSpec.preprocess(ASTRO);
        assert_eq!(out.len(), ASTRO.len());
        assert!(out.contains("const html = process.argv[2]"));
        assert!(!out.contains("set:html"));
        assert!(!out.contains("<div"));
        assert_eq!(out.matches('\n').count(), ASTRO.matches('\n').count());
    }

    #[test]
    fn set_html_on_elements_and_components_is_a_write() {
        let src = "<div set:html={a}></div>\n<Fragment set:html={b} />\n";
        let writes = AstroSpec.template_writes(src);
        assert_eq!(writes.len(), 2, "two writes: {writes:?}");
        assert_eq!(&src[writes[0].0..writes[0].1], "a");
        assert_eq!(&src[writes[1].0..writes[1].1], "b");
    }

    #[test]
    fn escaped_and_static_forms_are_not_writes() {
        let src = "<p>{value}</p>\n<div set:text={value}></div>\n<div set:html=\"<b>static</b>\"></div>\n";
        assert!(AstroSpec.template_writes(src).is_empty());
    }

    #[test]
    fn set_html_in_frontmatter_or_comments_is_inert() {
        let src = "---\nconst s = 'set:html={x}'\n---\n<!-- <div set:html={x}></div> -->\n<div set:html={live}></div>\n";
        let writes = AstroSpec.template_writes(src);
        assert_eq!(writes.len(), 1, "one live write: {writes:?}");
        assert_eq!(&src[writes[0].0..writes[0].1], "live");
    }

    #[test]
    fn object_expressions_are_whole() {
        let src = "<div set:html={{ a: 1 }.a}></div>";
        let writes = AstroSpec.template_writes(src);
        assert_eq!(writes.len(), 1);
        assert_eq!(&src[writes[0].0..writes[0].1], "{ a: 1 }.a");
    }

    #[test]
    fn template_only_file_blanks_to_an_empty_module() {
        let src = "<h1>{title}</h1>\n";
        let out = AstroSpec.preprocess(src);
        assert_eq!(out.len(), src.len());
        assert!(out.bytes().all(|b| b == b' ' || b == b'\n'));
    }

    #[test]
    fn fact_language_delegates_to_typescript() {
        assert_eq!(AstroSpec.fact_language(), "typescript");
    }
}
