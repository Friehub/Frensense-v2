// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Vue single-file component ([`LanguageSpec`](crate::spec::LanguageSpec)).
//!
//! A `.vue` SFC is not one language: it is a `<template>`, zero or more
//! `<script>`/`<script setup>` blocks, and `<style>` sections. The engine
//! parses *one* grammar per file, so this spec's `preprocess` rewrites the
//! SFC before parsing: everything outside a `<script>` body is blanked into
//! same-length runs of spaces (newlines kept), and only the script code —
//! already typed TypeScript in this repo's usage — reaches the parser.
//!
//! Blanking rather than extracting keeps the **position contract** every
//! other spec relies on: byte offsets, line numbers and columns of the
//! parse tree are the original file's, so findings land on the exact
//! source line. All the heavy lifting (node classification, imports,
//! packages, params) is delegated to the shared JavaScript/TS provider:
//! the tree the parser sees is plain TS, because the Vue markup is
//! whitespace by then.
//!
//! Security vocabulary (sinks, sources, sanitizers) lives in
//! `frensense-packgen`; this file is mechanism only.

use std::borrow::Cow;

use super::family::{JsDialect, JsFamily};

/// A `.vue` SFC whose script blocks are parsed with the TypeScript/TSX
/// grammar after its `preprocess` blanks the template and style sections in
/// place.
///
/// The script blocks are TypeScript, so every behavioural method comes from
/// the JavaScript family's blanket [`LanguageSpec`](crate::spec::LanguageSpec)
/// implementation; this type adds only the SFC rewrite.
#[derive(Debug)]
pub struct VueSpec;

impl JsFamily for VueSpec {
    const DIALECT: JsDialect = JsDialect::Vue;

    /// Blank everything outside a `<script>` body into same-length runs of
    /// spaces (newlines kept), so the TSX grammar sees a plain TS module and
    /// every offset still points at the original file.
    fn preprocess_source<'a>(&self, source: &'a str) -> Cow<'a, str> {
        extract_script_blocks(source)
    }
}

/// True when `bytes` starts with `tag` (ASCII case-insensitive).
fn starts_with_ci(bytes: &[u8], tag: &str) -> bool {
    bytes.len() >= tag.len() && bytes[..tag.len()].eq_ignore_ascii_case(tag.as_bytes())
}

/// Index of the next case-insensitive occurrence of `tag` in `bytes`.
#[must_use]
fn find_ci(bytes: &[u8], tag: &str) -> Option<usize> {
    if bytes.len() < tag.len() {
        return None;
    }
    (0..=bytes.len() - tag.len()).find(|&i| starts_with_ci(&bytes[i..], tag))
}

/// Rewrite an SFC: keep only bytes inside `<script>` blocks, blank the rest.
///
/// Blanked bytes become spaces (newlines are kept), so the output is a valid
/// TS module with exactly the same length and newline layout as the input.
/// Every offset — and therefore every reported line/column — stays anchored
/// to the original file.
///
/// Note: a `<script src="…">` block has an empty body, so its attribute
/// string (and the empty body) stay verbatim between the (blanked) tags.
/// That is deliberate: `src="…"` is a valid TS expression sequence of
/// nothing once we blank it, and keeping the body region lets a stray
/// `<script>` inside markup degrade to a parse error rather than vanish.
#[must_use]
pub(super) fn extract_script_blocks(source: &str) -> Cow<'_, str> {
    let bytes = source.as_bytes();
    // Fast path: the source is not an SFC at all (no `<script` and no
    // `<template`), so it is ordinary TS already: return it untouched. A
    // template-only component (no `<script`) is still an SFC and must be
    // blanked so the parser sees an empty module, not HTML.
    if find_ci(bytes, "<script").is_none() && find_ci(bytes, "<template").is_none() {
        return Cow::Borrowed(source);
    }

    // Byte mask: true = keep verbatim, false = blank to space (newline kept).
    let mut keep = vec![false; bytes.len()];

    let mut i = 0;
    while i < bytes.len() {
        if !starts_with_ci(&bytes[i..], "<script") {
            i += 1;
            continue;
        }
        // `"<script"` must be followed by `>`, `/` or whitespace: rejects
        // `<scriptx`-shaped markup around real code.
        let after = bytes.get(i + 7).copied();
        if !after.is_some_and(|c| c == b'>' || c == b'/' || c.is_ascii_whitespace()) {
            i += 1;
            continue;
        }
        // Blank the opener `<script … >`.
        let Some(gt_rel) = bytes[i..].iter().position(|&c| c == b'>') else {
            break; // malformed opener: nothing more to keep
        };
        let body_start = i + gt_rel + 1;
        match find_ci(&bytes[body_start..], "</script") {
            Some(rel_end) => {
                let body_end = body_start + rel_end;
                keep[body_start..body_end].fill(true);
                // Blank the closer `</script … >`; resume scanning after it.
                i = bytes[body_end..]
                    .iter()
                    .position(|&c| c == b'>')
                    .map_or(bytes.len(), |p| body_end + p + 1);
            }
            None => {
                // Unterminated block: keep the remainder as code; whatever
                // the file had reached EOF is what the parser sees.
                keep[body_start..].fill(true);
                break;
            }
        }
    }

    let blanked: Vec<u8> = blank(bytes, &keep);
    Cow::Owned(String::from_utf8(blanked).expect("blanking preserves valid UTF-8"))
}

/// Blank `bytes` per `keep`: kept bytes verbatim, others space (newline kept).
///
/// A non-ASCII blanked character becomes one space per original byte, so the
/// byte length — and every offset after it — is unchanged, and the result
/// stays valid UTF-8.
fn blank(bytes: &[u8], keep: &[bool]) -> Vec<u8> {
    bytes
        .iter()
        .zip(keep)
        .map(|(&byte, &kept)| if kept || byte == b'\n' { byte } else { b' ' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::LanguageSpec;

    const SFC: &str = "<template>\n  <div>{{ msg }}</div>\n</template>\n\n<script setup lang=\"ts\">\nconst msg = 'hello'\nfunction handler() {\n  return msg\n}\n</script>\n\n<style scoped>\n.x { color: red; }\n</style>\n";

    /// Byte range of the script body in `SFC`.
    fn script_body(sfc: &str) -> (usize, usize) {
        let open_end = sfc.find("lang=\"ts\">").unwrap() + "lang=\"ts\">".len();
        let close = sfc.find("</script>").unwrap();
        (open_end, close)
    }

    #[test]
    fn length_and_newlines_are_preserved() {
        let out = extract_script_blocks(SFC);
        assert_eq!(out.len(), SFC.len(), "byte length must not change");
        assert_eq!(
            out.bytes().filter(|&b| b == b'\n').count(),
            SFC.bytes().filter(|&b| b == b'\n').count()
        );
    }

    #[test]
    fn script_code_is_kept_verbatim() {
        let out = extract_script_blocks(SFC);
        let (start, end) = script_body(SFC);
        assert_eq!(&out[start..end], &SFC[start..end]);
        assert!(out.contains("const msg = 'hello'"));
        assert!(out.contains("function handler() {"));
    }

    #[test]
    fn template_and_style_are_blanked() {
        let out = extract_script_blocks(SFC);
        assert!(!out.contains("div"), "template markup must not survive");
        assert!(!out.contains("color"), "style content must not survive");
        assert!(!out.contains("<script"), "tags must not survive");
    }

    #[test]
    fn offsets_still_point_at_the_same_line() {
        let out = extract_script_blocks(SFC);
        let needle = "const msg";
        let before = SFC.find(needle).unwrap();
        let after = out.find(needle).unwrap();
        assert_eq!(before, after, "code offsets must be identical");
        assert_eq!(
            SFC[..before].matches('\n').count(),
            out[..after].matches('\n').count()
        );
    }

    #[test]
    fn multiple_script_blocks_are_all_kept() {
        let sfc = "<template><div/></template>\n<script>\nconst a = 1\n</script>\n<script setup>\nconst b = 2\n</script>\n";
        let out = extract_script_blocks(sfc);
        assert_eq!(out.len(), sfc.len());
        assert!(out.contains("const a = 1"));
        assert!(out.contains("const b = 2"));
    }

    #[test]
    fn template_only_component_blanks_to_an_empty_module() {
        let sfc = "<template>\n  <button>go</button>\n</template>\n";
        let out = extract_script_blocks(sfc);
        assert_eq!(out.len(), sfc.len());
        assert!(!out.contains("button"));
        assert!(out.bytes().all(|b| b == b' ' || b == b'\n'));
    }

    #[test]
    fn unterminated_script_keeps_code_to_eof() {
        let sfc = "<template><t/></template>\n<script setup>\nconst a = 1\n";
        let out = extract_script_blocks(sfc);
        assert_eq!(out.len(), sfc.len());
        assert!(out.contains("const a = 1"));
    }

    #[test]
    fn src_attribute_script_is_blanked_to_nothing() {
        let sfc = "<script src=\"./x.ts\"></script>\n<template><t/></template>\n";
        let out = extract_script_blocks(sfc);
        assert_eq!(out.len(), sfc.len());
        assert!(out.bytes().all(|b| b == b' ' || b == b'\n'));
    }

    #[test]
    fn similar_non_script_tags_are_ignored() {
        let sfc = "<scriptx>not-a-script</scriptx>\n<pluginscript>t</pluginscript>\n<script>keep</script>";
        let out = extract_script_blocks(sfc);
        assert_eq!(out.len(), sfc.len());
        assert!(out.contains("keep"));
        assert!(!out.contains("<script "), "real opener must be blanked");
    }

    #[test]
    fn non_ascii_markup_blanks_to_equal_length() {
        let sfc = "<template>\n  <span>héllo ✨</span>\n</template>\n<script>\nconst a = '✅'\n</script>\n";
        let out = extract_script_blocks(sfc);
        assert_eq!(out.len(), sfc.len());
        assert!(out.contains("const a = '✅'"));
        assert!(!out.contains("héllo"));
    }

    #[test]
    fn identity_when_no_script_tag() {
        let src = "const a = 1\nfunction f() { return a }\n";
        match extract_script_blocks(src) {
            Cow::Borrowed(s) => assert_eq!(s, src),
            Cow::Owned(_) => panic!("plain TS must be returned borrowed"),
        }
    }

    #[test]
    fn fact_language_delegates_to_typescript() {
        // The pack sections and bundle facts are keyed by this; `.vue`
        // must land in the `typescript` vocabulary, not a `vue` section
        // nothing fills.
        assert_eq!(VueSpec.fact_language(), "typescript");
    }
}
