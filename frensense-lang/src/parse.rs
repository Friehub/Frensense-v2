// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing
//!
//! Source text to syntax tree, with the spec's grammar and preprocessing.
//!
//! A [`LanguageSpec`] knows which grammar a file uses and whether the source
//! has to be rewritten first (a Vue SFC's markup is blanked so the TypeScript
//! parser sees only its script blocks). Both steps must happen before any
//! role, import or query answer is meaningful, and the rewrite must preserve
//! byte offsets. Doing that by hand means every consumer repeats:
//!
//! ```text
//! let rewritten = spec.preprocess(&text);
//! let mut parser = tree_sitter::Parser::new();
//! parser.set_language(&spec.tree_sitter_language())?;
//! let tree = parser.parse(rewritten.as_ref(), None)?;
//! ```
//!
//! [`parse`] is that sequence once. It does not hide tree-sitter: the tree is
//! a [`Tree`], its nodes are [`Node`](tree_sitter::Node)s, and a caller still
//! walks them. It removes the setup that has language knowledge in it - which
//! grammar, and whether to preprocess - so the answer always comes from the
//! spec.
//!
//! ```
//! use frensense_lang::{parse, spec_for_ext};
//!
//! let spec = spec_for_ext("ts").expect("TypeScript is registered");
//! let parsed = parse(spec, "const id = req.query.id;\n").expect("parses");
//! assert!(!parsed.has_errors());
//! assert_eq!(parsed.text(), "const id = req.query.id;\n");
//! ```
//!
//! `parsed.text()` is the text the tree indexes into. Because the position
//! contract in [`LanguageSpec::preprocess`] preserves offsets, those byte
//! ranges also address the caller's original string.

use std::borrow::Cow;

use tree_sitter::Tree;

use crate::spec::LanguageSpec;

/// A parsed file: the tree and the exact text its byte ranges index into.
///
/// The text is the spec's preprocessed source. For most languages that is the
/// input unchanged; for a single-file container it is the input with non-code
/// regions blanked to spaces, at the same offsets.
#[derive(Debug)]
pub struct ParsedSource<'a> {
    tree: Tree,
    source: Cow<'a, str>,
}

impl ParsedSource<'_> {
    /// The parsed text, as the tree sees it.
    #[must_use]
    pub fn text(&self) -> &str {
        self.source.as_ref()
    }

    /// The tree's root node.
    #[must_use]
    pub fn root_node(&self) -> tree_sitter::Node<'_> {
        self.tree.root_node()
    }

    /// Did the grammar report an incomplete parse?
    ///
    /// tree-sitter does not fail on a syntax error: it returns a tree
    /// containing `ERROR` or missing nodes. A caller that renders findings
    /// should say the file was only partially analyzed rather than clean.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.tree.root_node().has_error()
    }
}

/// Why [`parse`] could not produce a tree.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// The grammar rejected the spec's `Language` object.
    Grammar(tree_sitter::LanguageError),
    /// tree-sitter returned no tree for the input, which means the parse was
    /// cancelled.
    Cancelled,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Grammar(err) => write!(f, "cannot use the spec's grammar: {err}"),
            Self::Cancelled => f.write_str("the parse was cancelled"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Grammar(err) => Some(err),
            Self::Cancelled => None,
        }
    }
}

impl From<tree_sitter::LanguageError> for ParseError {
    fn from(err: tree_sitter::LanguageError) -> Self {
        Self::Grammar(err)
    }
}

/// Parse `source` with `spec`'s grammar, after the spec's preprocessing.
///
/// # Errors
///
/// [`ParseError::Grammar`] when the grammar rejects the spec's `Language`
/// object, [`ParseError::Cancelled`] when tree-sitter returns no tree.
pub fn parse<'a>(spec: &dyn LanguageSpec, source: &'a str) -> Result<ParsedSource<'a>, ParseError> {
    let rewritten = spec.preprocess(source);
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&spec.tree_sitter_language())?;
    let tree = parser
        .parse(rewritten.as_ref(), None)
        .ok_or(ParseError::Cancelled)?;
    Ok(ParsedSource {
        tree,
        source: rewritten,
    })
}

#[cfg(all(test, feature = "typescript"))]
mod tests {
    use super::*;
    use crate::registry::spec_for_ext;

    #[test]
    fn parses_with_the_specs_grammar() {
        let spec = spec_for_ext("ts").expect("TypeScript is registered");
        let parsed = parse(spec, "const id = req.query.id;\n").expect("parses");
        assert!(!parsed.has_errors());
        assert_eq!(parsed.text(), "const id = req.query.id;\n");
        assert!(parsed.root_node().child_count() > 0);
    }

    #[test]
    fn a_container_spec_parses_its_blanked_source() {
        // Vue has no grammar of its own: the spec blanks markup so the
        // TypeScript parser sees only the script block, at the same offsets.
        let spec = spec_for_ext("vue").expect("Vue is registered");
        let source = "<template><p>{{ x }}</p></template>\n<script>\nconst y = 1;\n</script>\n";
        let parsed = parse(spec, source).expect("parses");
        assert_eq!(parsed.text().len(), source.len());
        assert!(!parsed.text().contains("<template>"));
        assert!(parsed.text().contains("const y = 1;"));
        assert!(!parsed.has_errors());
    }

    #[test]
    fn a_broken_file_reports_errors_instead_of_failing() {
        let spec = spec_for_ext("ts").expect("TypeScript is registered");
        let parsed = parse(spec, "function ( {\n").expect("tree-sitter still returns a tree");
        assert!(parsed.has_errors());
    }
}
