// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Language support queries, backed by `frensense-lang` specs.

use std::path::Path;

/// True if the file's extension is handled by a registered language spec.
#[must_use]
pub fn is_supported(path: &Path) -> bool {
    frensense_lang::spec_for_path(path).is_some()
}

/// True when `path`'s file name ends with `.<ext>`.
///
/// `ext` may be compound (`component.html`), which a plain `Path::extension`
/// cannot express; the caller compares it against a language's registered
/// extensions.
#[must_use]
pub fn path_has_extension(path: &Path, ext: &str) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    name.len() > ext.len()
        && name.ends_with(ext)
        && name.as_bytes().get(name.len() - ext.len() - 1) == Some(&b'.')
}

/// Extensions registered for a language name (e.g. "typescript" → ts, tsx...).
#[must_use]
pub fn extensions_for(name: &str) -> Option<&'static [&'static str]> {
    frensense_lang::all_specs()
        .find(|s| s.name().eq_ignore_ascii_case(name))
        .map(|s| s.extensions())
}

/// Registered language names, sorted for stable help output (WI-56: the
/// CLI help, MCP tool descriptions and docs must agree on one generated
/// list instead of hand-maintained copies).
#[must_use]
pub fn language_names_help() -> String {
    let mut names: Vec<&'static str> = frensense_lang::all_specs().map(|s| s.name()).collect();
    names.sort_unstable();
    names.join(", ")
}

#[cfg(test)]
mod tests {
    use super::path_has_extension;
    use std::path::Path;

    #[test]
    fn compound_extensions_match_the_whole_suffix() {
        assert!(path_has_extension(
            Path::new("src/app/hero.component.html"),
            "component.html"
        ));
        assert!(!path_has_extension(
            Path::new("public/index.html"),
            "component.html"
        ));
        assert!(path_has_extension(Path::new("src/main.TS"), "ts"));
        assert!(!path_has_extension(Path::new("src/ts"), "ts"));
    }
}
