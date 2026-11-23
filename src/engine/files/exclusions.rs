// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Paths the default rules skip, and the options that change them.

/// A path the walk deliberately did not scan, and why.
///
/// Exclusions exist because scanning `node_modules` or a minified bundle is
/// noise, but a report that does not say so lets a project whose real code
/// lives in `build/` or `cache/` read as scanned when most of it never was.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct ExcludedPath {
    /// Path as the scanner knows it.
    pub path: String,
    /// Why it was skipped: `dir:<name>`, `hidden-dir`, `size>500k` or
    /// `minified`.
    pub reason: String,
    /// Supported source files that were not scanned because of this
    /// exclusion. `None` for dependency and tool directories (`node_modules`,
    /// `target`, hidden directories): they are listed, but their contents are
    /// neither counted nor treated as a coverage gap.
    pub source_files: Option<usize>,
}

/// Overrides for the default exclusion rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CollectOptions {
    /// Directory names that must be scanned even though a default rule would
    /// skip them (`--include-dir cache`).
    pub include_dirs: Vec<String>,
    /// Scan everything the extension filter allows: no directory, size or
    /// minified-file exclusions (`--no-default-excludes`).
    pub no_default_excludes: bool,
}
