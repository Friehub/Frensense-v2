// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! What the default exclusion rules skipped, in the detail a report shows.

use crate::engine::files::ExcludedPath;

use super::COVERAGE_SAMPLE;

/// What the default exclusion rules skipped, in the detail a report shows.
///
/// Kept beside [`crate::policy::Coverage`] rather than inside it: the counts a report needs
/// are derivable from `Coverage`, and putting the reasons and the sample in
/// their own type means adding detail later never changes `Coverage`'s
/// public shape. New fields here are additive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Exclusions {
    /// Excluded paths by reason (`dir:vendor`, `size>500k`, `minified`,
    /// `hidden-dir`). A directory counts once, so dependency directories
    /// appear here without inflating `files_excluded`.
    pub by_reason: std::collections::BTreeMap<String, usize>,
    /// Supported source files the exclusions hid. This is the number
    /// [`crate::policy::Coverage`] adds to its denominator.
    pub files_excluded: usize,
    /// First [`COVERAGE_SAMPLE`] excluded paths, those holding source files
    /// first.
    pub sample: Vec<ExcludedPath>,
}

impl Exclusions {
    /// Summarize one walk's excluded paths for the report.
    #[must_use]
    pub fn from_paths(excluded: &[ExcludedPath]) -> Self {
        let mut by_reason: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        let mut files_excluded = 0usize;
        for e in excluded {
            *by_reason.entry(e.reason.clone()).or_insert(0) += 1;
            files_excluded += e.source_files.unwrap_or(0);
        }
        let mut sample: Vec<ExcludedPath> = excluded.to_vec();
        // Paths holding source first, then by path: the sample leads with the
        // exclusions that matter.
        sample.sort_by(|a, b| {
            (a.source_files.unwrap_or(0) == 0, &a.path)
                .cmp(&(b.source_files.unwrap_or(0) == 0, &b.path))
        });
        sample.truncate(COVERAGE_SAMPLE);
        Self {
            by_reason,
            files_excluded,
            sample,
        }
    }
}
