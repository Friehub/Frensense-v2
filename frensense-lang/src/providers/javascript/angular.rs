// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Angular template scanning shared by external templates and inline
//! `@Component({ template: … })` decorators.
//!
//! # Angular sanitizes markup bindings
//!
//! Angular runs every markup property binding through `DomSanitizer`:
//! `innerHTML`, `outerHTML` and `iframe.srcdoc` are all the HTML security
//! context (see Angular's `dom_security_schema.ts`), and interpolation is
//! escaped. A tainted value bound there is **not** XSS by itself, so it must
//! not be reported as a template write - that was the false positive this
//! module removes.
//!
//! The only way a template binding becomes unsafe is
//! `DomSanitizer.bypassSecurityTrust*`, which marks a value as trusted and
//! makes the binding set it verbatim. Those calls are declared as XSS sinks
//! in `frensense-packgen`, so the analysis reports the *bypass*, not the
//! binding. Bindings are therefore reported only when their own expression
//! contains a `bypassSecurityTrust…` call; the engine then lowers that
//! expression and the sink fires where the bypass happens.
//!
//! # Inline templates
//!
//! `@Component({ template: \`…\` })` keeps the markup inside a TypeScript
//! string. TypeScript's spec blanks such a decorator before parsing (the
//! class itself is untouched) and reports the bypass bindings inside its
//! template, so the same rule works for inline and external templates. The
//! template string is replaced by blanks, so its expressions need the
//! engine's overlay to become code.
//!
//! Security vocabulary (sinks, sources, sanitizers) lives in
//! `frensense-packgen`; this file is mechanism only.

use std::borrow::Cow;

use super::sfc::{blank_outside, comment_ranges, complement, find_bytes, in_ranges};

/// Property bindings that Angular would write to the DOM as markup.
const MARKUP_BINDINGS: &[&[u8]] = &[b"[innerHTML]", b"[outerHTML]", b"[srcdoc]"];

/// Prefix of the DomSanitizer calls that disable Angular's sanitizer.
const BYPASS: &[u8] = b"bypassSecurityTrust";

/// Quoted markup bindings in `regions`, skipping `scripts` and `comments`.
///
/// A binding is `[innerHTML]="expression"` (single or double quotes). Its
/// span is the trimmed expression, so the engine can overlay and lower it.
#[must_use]
pub(super) fn binding_spans(
    bytes: &[u8],
    regions: &[(usize, usize)],
    scripts: &[(usize, usize)],
    comments: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for &(start, end) in regions {
        let mut i = start;
        while i < end {
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
            let Some(equals) = skip_spaces(bytes, marker_end, end) else {
                break;
            };
            if bytes.get(equals) != Some(&b'=') {
                i = marker_end;
                continue;
            }
            let Some(quote_at) = skip_spaces(bytes, equals + 1, end) else {
                break;
            };
            let Some(&quote) = bytes.get(quote_at) else {
                break;
            };
            if quote != b'"' && quote != b'\'' {
                i = marker_end;
                continue;
            }
            let expr_start = quote_at + 1;
            let Some(rel_end) = bytes
                .get(expr_start..end)
                .and_then(|rest| rest.iter().position(|&b| b == quote))
            else {
                break;
            };
            let raw_end = expr_start + rel_end;
            if let Some((start, end)) = trimmed_span(bytes, expr_start, raw_end) {
                spans.push((start, end));
            }
            i = raw_end + 1;
        }
    }
    spans
}

/// The bindings whose expression itself disables Angular's sanitizer.
///
/// The returned spans are the expressions the engine lowers; the
/// `bypassSecurityTrust…` call inside them is the XSS sink, so this is the
/// only case where a template binding reaches one.
#[must_use]
pub(super) fn bypass_bindings(
    bytes: &[u8],
    regions: &[(usize, usize)],
    scripts: &[(usize, usize)],
    comments: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    binding_spans(bytes, regions, scripts, comments)
        .into_iter()
        .filter(|&(start, end)| {
            bytes
                .get(start..end)
                .is_some_and(|expr| find_bytes(expr, BYPASS).is_some())
        })
        .collect()
}

/// One `@Component({ template: \`…\` })` decorator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InlineTemplate {
    /// The whole decorator call, `@` through its closing `)`.
    pub decorator: (usize, usize),
    /// The template literal's body, delimiters excluded.
    pub body: (usize, usize),
}

/// Every inline-template decorator in a TypeScript file, in source order.
///
/// Only backtick-delimited templates are recognised: they are the only form
/// that can hold a multi-line template without escaping its own attribute
/// quotes, and escaped-quote templates would make the binding scanner misread
/// the template's boundaries.
#[must_use]
pub(super) fn inline_templates(bytes: &[u8]) -> Vec<InlineTemplate> {
    component_decorators(bytes)
        .into_iter()
        .filter_map(|decorator| {
            template_body(bytes, decorator).map(|body| InlineTemplate { decorator, body })
        })
        .collect()
}

/// The span of every `@Component(…)` decorator, inline template or not.
///
/// External templates (`templateUrl`) need their component's fields too, so
/// this is broader than [`inline_templates`].
#[must_use]
fn component_decorators(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut decorators = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes
            .get(i..)
            .is_some_and(|rest| rest.starts_with(b"@Component"))
        {
            i += 1;
            continue;
        }
        let after = i + "@Component".len();
        if bytes.get(after).copied().is_some_and(is_word_byte) {
            i = after;
            continue;
        }
        let Some(open) = skip_spaces(bytes, after, bytes.len()) else {
            break;
        };
        if bytes.get(open) != Some(&b'(') {
            i = after;
            continue;
        }
        let Some(close) = paren_end(bytes, open) else {
            break;
        };
        decorators.push((i, close + 1));
        i = close + 1;
    }
    decorators
}

/// The `(start, end)` of each binding that must be lowered in an inline
/// template, in source order.
#[must_use]
pub(super) fn inline_bypass_spans(source: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut spans = Vec::new();
    for template in inline_templates(bytes) {
        let regions = [template.body];
        let comments = comment_ranges(bytes, &regions);
        spans.extend(bypass_bindings(bytes, &regions, &[], &comments));
    }
    spans
}

/// The initializer of every field declared by a class that owns an inline
/// template: `(field name, initializer span)`.
///
/// A template reads the component instance, not module scope, so a binding
/// like `[innerHTML]="san.bypassSecurityTrustHtml(raw)"` cannot link `raw` to
/// the class's `raw = …` without this. The engine binds each name before
/// lowering the template expressions, which keeps the template scope faithful
/// to what Angular evaluates.
#[must_use]
pub(super) fn component_field_initializers(
    source: &str,
    language: &tree_sitter::Language,
) -> Vec<crate::spec::TemplateBinding> {
    let decorators = component_decorators(source.as_bytes());
    if decorators.is_empty() {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(language).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut classes = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "class_declaration" | "class") {
            classes.push(node);
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    classes.sort_by_key(|node| node.start_byte());
    let mut fields = Vec::new();
    for decorator in decorators {
        let class = classes
            .iter()
            .find(|class| class.start_byte() <= decorator.0 && class.end_byte() >= decorator.1)
            .or_else(|| {
                classes
                    .iter()
                    .find(|class| class.start_byte() >= decorator.1)
            });
        let Some(body) = class.and_then(|class| class.child_by_field_name("body")) else {
            continue;
        };
        let mut cursor = body.walk();
        for member in body.named_children(&mut cursor) {
            if !matches!(
                member.kind(),
                "public_field_definition" | "property_declaration"
            ) {
                continue;
            }
            let (Some(name), Some(value)) = (
                member.child_by_field_name("name"),
                member.child_by_field_name("value"),
            ) else {
                continue;
            };
            let field = source.get(name.start_byte()..name.end_byte());
            if let Some(field) = field.filter(|field| !field.is_empty()) {
                fields.push((field.to_string(), (value.start_byte(), value.end_byte())));
            }
        }
    }
    fields
}

/// Blank every inline-template decorator in `source`.
///
/// The decorator call is executable only for its side effects on the class
/// metadata; the class body, imports and every other decorator stay verbatim.
/// Each binding that [`inline_bypass_spans`] reports gets a `;` at its end
/// (inside the blanked decorator), so the overlaid expression becomes a
/// standalone statement - `expr;` - instead of running into the next one.
#[must_use]
pub(super) fn blank_component_decorators(source: &str) -> Cow<'_, str> {
    let bytes = source.as_bytes();
    let templates = inline_templates(bytes);
    if templates.is_empty() {
        return Cow::Borrowed(source);
    }
    let decorators: Vec<_> = templates.iter().map(|t| t.decorator).collect();
    let mut blanked = blank_outside(bytes, &complement(bytes.len(), &decorators)).into_bytes();
    for (_, end) in inline_bypass_spans(source) {
        if let Some(byte) = blanked.get_mut(end) {
            *byte = b';';
        }
    }
    // Blanking only writes ASCII spaces and semicolons, so the lossy path
    // never has anything to replace; it avoids an infallible `expect`.
    Cow::Owned(String::from_utf8_lossy(&blanked).into_owned())
}

/// The template literal body of a component decorator, if it has one.
fn template_body(bytes: &[u8], decorator: (usize, usize)) -> Option<(usize, usize)> {
    let mut i = decorator.0;
    while i < decorator.1 {
        let rel = find_bytes(bytes.get(i..decorator.1)?, b"template")?;
        let token = i + rel;
        let after = token + "template".len();
        i = after;
        // `templateUrl` is not an inline template.
        if bytes.get(after).copied().is_some_and(is_word_byte) {
            continue;
        }
        let Some(colon) = skip_spaces(bytes, after, decorator.1) else {
            return None;
        };
        if bytes.get(colon) != Some(&b':') {
            continue;
        }
        let Some(open) = skip_spaces(bytes, colon + 1, decorator.1) else {
            return None;
        };
        if bytes.get(open) != Some(&b'`') {
            return None;
        }
        let close = quoted_end(bytes, open, b'`')?;
        return Some((open + 1, close));
    }
    None
}

/// Index of the `)` closing the `(` at `open`, honouring strings and nesting.
fn paren_end(bytes: &[u8], open: usize) -> Option<usize> {
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
                b'(' => depth += 1,
                b')' => {
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

/// Index of the delimiter closing the one at `open`.
fn quoted_end(bytes: &[u8], open: usize, delimiter: u8) -> Option<usize> {
    let mut i = open + 1;
    while let Some(&byte) = bytes.get(i) {
        if byte == b'\\' {
            i += 2;
            continue;
        }
        if byte == delimiter {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// First non-space index between `from` and `end`.
fn skip_spaces(bytes: &[u8], from: usize, end: usize) -> Option<usize> {
    let rest = bytes.get(from..end)?;
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

/// Whether `byte` can continue an identifier.
///
/// Punctuation is deliberately excluded: it separates `template` from its
/// `:`, so a boundary check on this predicate does not read `template:` as
/// `template` followed by a name character.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    const INLINE: &str = "import { Component } from '@angular/core'\nconst san: any = {}\n@Component({\n  selector: 'app-hero',\n  template: `<div [innerHTML]=\"san.bypassSecurityTrustHtml(process.argv[2])\"></div>`,\n})\nexport class HeroComponent {}\n";

    #[test]
    fn inline_template_is_found_with_its_body() {
        let templates = inline_templates(INLINE.as_bytes());
        assert_eq!(templates.len(), 1, "{templates:?}");
        let body = &INLINE[templates[0].body.0..templates[0].body.1];
        assert!(body.contains("[innerHTML]"));
        assert!(!body.contains("selector"));
    }

    #[test]
    fn only_bypass_bindings_are_reported() {
        let sanitized = "<div [innerHTML]=\"userInput\"></div>";
        let src = format!("@Component({{ template: `{sanitized}` }})\nexport class A {{}}\n",);
        assert!(inline_bypass_spans(&src).is_empty());
    }

    #[test]
    fn bypass_binding_is_reported_at_its_expression() {
        let spans = inline_bypass_spans(INLINE);
        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(
            &INLINE[spans[0].0..spans[0].1],
            "san.bypassSecurityTrustHtml(process.argv[2])"
        );
    }

    #[test]
    fn blanking_keeps_offsets_and_removes_the_decorator() {
        let out = blank_component_decorators(INLINE);
        assert_eq!(out.len(), INLINE.len());
        assert!(!out.contains("@Component"));
        assert!(!out.contains("[innerHTML]"));
        assert!(out.contains("export class HeroComponent {}"));
        let spans = inline_bypass_spans(INLINE);
        assert_eq!(out.as_bytes()[spans[0].1], b';');
    }

    #[test]
    fn component_fields_bind_to_their_class_initializers() {
        let src = concat!(
            "import { Component } from '@angular/core'\n",
            "@Component({ template: `<div [innerHTML]=\"san.bypassSecurityTrustHtml(raw)\"></div>` })\n",
            "export class HeroComponent {\n",
            "  raw = process.argv[2]\n",
            "  title = 'hero'\n",
            "}\n",
            "@Component({ template: `<p></p>` })\n",
            "export class OtherComponent {\n",
            "  other = source\n",
            "}\n",
        );
        let fields =
            component_field_initializers(src, &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into());
        let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["raw", "title", "other"], "{fields:?}");
        assert_eq!(&src[fields[0].1 .0..fields[0].1 .1], "process.argv[2]");
    }

    #[test]
    fn templateUrl_is_not_an_inline_template() {
        let src =
            "@Component({ selector: 'x', templateUrl: './x.component.html' })\nexport class A {}\n";
        assert!(inline_templates(src.as_bytes()).is_empty());
        assert!(matches!(blank_component_decorators(src), Cow::Borrowed(_)));
    }

    #[test]
    fn templateUrl_component_fields_are_still_exposed() {
        let src = concat!(
            "@Component({ templateUrl: './hero.component.html' })\n",
            "export class HeroComponent {\n",
            "  raw = process.argv[2]\n",
            "}\n",
        );
        let fields =
            component_field_initializers(src, &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into());
        assert_eq!(fields.len(), 1, "{fields:?}");
        assert_eq!(fields[0].0, "raw");
        assert_eq!(&src[fields[0].1 .0..fields[0].1 .1], "process.argv[2]");
    }

    #[test]
    fn escaped_backtick_does_not_end_the_template() {
        let src = "@Component({ template: `<p>\\`x\\`</p><div [innerHTML]=\"san.bypassSecurityTrustHtml(v)\"></div>` })\nclass A {}\n";
        let templates = inline_templates(src.as_bytes());
        assert_eq!(templates.len(), 1);
        let body = &src[templates[0].body.0..templates[0].body.1];
        assert!(body.contains("bypassSecurityTrustHtml"));
    }
}
