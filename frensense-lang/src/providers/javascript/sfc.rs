// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Shared plumbing for single-file components (`.vue`, `.svelte`).
//!
//! A component file is markup wrapped around zero or more `<script>` bodies,
//! but the engine parses *one* grammar per file. The common fix is a
//! **position-preserving blanking**: every byte outside a script body becomes
//! a space (newlines are kept), so the parser sees a plain TS module while
//! every offset, line and column still points at the original file.
//!
//! Blanking, not extracting, is the contract. Callers may therefore combine
//! the blanked text with byte spans of the original (see
//! [`template_writes`](crate::spec::LanguageSpec::template_writes)) without
//! translating positions.
//!
//! This module owns only the mechanics shared by every component format.
//! Which markup construct is a write (`v-html`, `{@html}`, …) stays in the
//! format's own spec, because that is the part that differs.
//!
//! # Template writes
//!
//! A spec's
//! [`template_writes`](crate::spec::LanguageSpec::template_writes) reports the
//! expression span of each construct that renders **unescaped** HTML. The
//! contract, and why it is spans rather than rewritten code:
//!
//! - A span covers exactly one expression: no surrounding quotes, `{}` or
//!   directive name, so it parses on its own.
//! - Positions are the original file's, because blanking preserves byte
//!   length and newlines.
//! - The engine copies those original bytes back over the blanked source and
//!   lowers the expression in the module IR **after** the script statements,
//!   so its value is defined before the write.
//! - Each span becomes one `CallStatic` under
//!   `frensense_engine::ir::TEMPLATE_SINK_CALL`; the rule that name means (the
//!   XSS sink) is declared by `frensense-packgen`, never here.
//!
//! Escaped or inert constructs must not be reported: `{value}` in Svelte and
//! `{{ interpolation }}` in Vue are escaped by their compilers, and a span for
//! them would invent a sink the runtime does not have. Reporting spans instead
//! of rewriting markup also means a write is never limited by the spare bytes
//! next to a directive - the bug the byte-rewriting approach had.

use std::borrow::Cow;

/// True when `bytes` starts with `tag` (ASCII case-insensitive).
pub(super) fn starts_with_ci(bytes: &[u8], tag: &str) -> bool {
    bytes.len() >= tag.len() && bytes[..tag.len()].eq_ignore_ascii_case(tag.as_bytes())
}

/// Index of the next case-insensitive occurrence of `tag` in `bytes`.
#[must_use]
pub(super) fn find_ci(bytes: &[u8], tag: &str) -> Option<usize> {
    if bytes.len() < tag.len() {
        return None;
    }
    (0..=bytes.len() - tag.len()).find(|&i| starts_with_ci(&bytes[i..], tag))
}

/// Body byte ranges of every `<script …> … </script>` block, in source order.
///
/// The opener and closer tags are excluded. A `<script src="…">` block yields
/// an empty range, which is correct: it has no inline code. An unterminated
/// block keeps the rest of the file, mirroring what the parser would see.
///
/// Recognition is deliberately narrow: `"<script"` must be followed by `>`,
/// `/` or whitespace, so `<scriptx>` and `<pluginscript>` are not openers.
#[must_use]
pub(super) fn script_body_ranges(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !starts_with_ci(&bytes[i..], "<script") {
            i += 1;
            continue;
        }
        let after = bytes.get(i + 7).copied();
        if !after.is_some_and(|c| c == b'>' || c == b'/' || c.is_ascii_whitespace()) {
            i += 1;
            continue;
        }
        // Skip the opener `<script … >`.
        let Some(gt_rel) = bytes[i..].iter().position(|&c| c == b'>') else {
            break; // malformed opener: nothing more to keep
        };
        let body_start = i + gt_rel + 1;
        match find_ci(&bytes[body_start..], "</script") {
            Some(rel_end) => {
                let body_end = body_start + rel_end;
                ranges.push((body_start, body_end));
                // Resume after the closer's `>`.
                i = bytes[body_end..]
                    .iter()
                    .position(|&c| c == b'>')
                    .map_or(bytes.len(), |p| body_end + p + 1);
            }
            None => {
                // Unterminated block: the remainder is code.
                ranges.push((body_start, bytes.len()));
                break;
            }
        }
    }
    ranges
}

/// Blank every byte outside `ranges` into a space, keeping newlines.
///
/// Non-ASCII blanked characters become one space per original byte, so the
/// byte length - and every offset after it - is unchanged and the result stays
/// valid UTF-8.
#[must_use]
pub(super) fn blank_outside(bytes: &[u8], ranges: &[(usize, usize)]) -> String {
    let mut keep = vec![false; bytes.len()];
    for &(start, end) in ranges {
        if let Some(slice) = keep.get_mut(start..end) {
            slice.fill(true);
        }
    }
    let blanked = bytes
        .iter()
        .zip(keep)
        .map(|(&byte, kept)| if kept || byte == b'\n' { byte } else { b' ' })
        .collect();
    // Blanking only replaces bytes with ASCII spaces, so the input's UTF-8
    // validity is preserved.
    String::from_utf8(blanked).expect("blanking preserves valid UTF-8")
}

/// Rewrite an SFC that may not contain any tag: keep script bodies, blank the
/// rest.
///
/// A file with neither `<script` nor `<template` is returned untouched, so a
/// plain TS source that happens to carry a `.vue` extension still parses. The
/// check is a fast path, not part of the position contract: components always
/// contain one of the two tags, and a markup-only component (template, no
/// script) is still blanked.
#[must_use]
pub(super) fn extract_script_blocks(source: &str) -> Cow<'_, str> {
    let bytes = source.as_bytes();
    if find_ci(bytes, "<script").is_none() && find_ci(bytes, "<template").is_none() {
        return Cow::Borrowed(source);
    }
    Cow::Owned(blank_outside(bytes, &script_body_ranges(bytes)))
}

/// Blank everything outside `<script>` bodies, unconditionally.
///
/// Unlike [`extract_script_blocks`] there is no plain-source fast path: a
/// `.svelte` file is always a component, so markup-only files with no
/// `<template>` tag (Svelte has no such element) must still be blanked.
#[must_use]
pub(super) fn blank_scripts(source: &str) -> Cow<'_, str> {
    Cow::Owned(blank_outside(
        source.as_bytes(),
        &script_body_ranges(source.as_bytes()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_ranges_exclude_the_tags() {
        let src = "<template><t/></template>\n<script setup lang=\"ts\">\nconst a = 1\n</script>\n";
        let ranges = script_body_ranges(src.as_bytes());
        assert_eq!(ranges.len(), 1);
        assert_eq!(&src[ranges[0].0..ranges[0].1], "\nconst a = 1\n");
    }

    #[test]
    fn blank_scripts_blanks_markup_only_files() {
        let src = "{#if ok}<p>{value}</p>{/if}\n";
        let out = blank_scripts(src);
        assert_eq!(out.len(), src.len());
        assert!(out.bytes().all(|b| b == b' ' || b == b'\n'));
    }

    #[test]
    fn blank_scripts_keeps_script_bytes_at_their_offsets() {
        let src = "<script>\nconst a = 1\n</script>\n<div>{a}</div>\n";
        let out = blank_scripts(src);
        let code = src.find("const a").expect("fixture");
        assert_eq!(&out[code..code + "const a = 1".len()], "const a = 1");
        assert!(!out.contains("<div>"));
    }

    #[test]
    fn lookalike_tags_are_not_openers() {
        let src = "<scriptx>no</scriptx>\n<script>\nkeep\n</script>";
        let ranges = script_body_ranges(src.as_bytes());
        assert_eq!(ranges.len(), 1);
        assert_eq!(&src[ranges[0].0..ranges[0].1], "\nkeep\n");
    }
}
