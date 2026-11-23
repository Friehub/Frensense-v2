// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! What one directory walk produced.

use super::{CollectedFiles, ExcludedPath};

/// What one directory walk produced: the files it can scan, plus the paths
/// the default exclusion rules skipped.
///
/// The exclusions sit beside [`CollectedFiles`] rather than inside it, so a
/// walk can carry more detail without changing that struct's public shape.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CollectedTree {
    /// Supported files, and files in a language with no engine spec.
    pub files: CollectedFiles,
    /// Paths skipped by the default exclusion rules, with the reason and the
    /// source files each hid.
    pub excluded: Vec<ExcludedPath>,
}
