// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! File collection: walk the target, keep supported source files.

use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

/// Collects all files reachable from `root` that match supported extensions
/// and the optional language filter.
#[must_use]
pub fn collect_files(root: &Path, language_filter: Option<&Vec<&'static str>>) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            if e.file_type().is_dir() && e.path() != root {
                return name != "target"
                    && name != "node_modules"
                    && name != "dist"
                    && name != "build"
                    && name != "vendor"
                    && name != "out"
                    && name != ".next"
                    && name != ".nuxt"
                    && name != ".cache"
                    && name != "coverage"
                    && name != "cypress"
                    && name != "playwright"
                    && name != "storybook-static"
                    && !name.starts_with('.');
            }
            if e.file_type().is_file() {
                if let Ok(meta) = e.metadata()
                    && meta.len() > 500_000
                {
                    return false;
                }
                if name.ends_with(".min.js")
                    || name.ends_with(".bundle.js")
                    || name.ends_with(".chunk.js")
                    || name.ends_with(".debug.js")
                {
                    return false;
                }
            }
            true
        })
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .filter(|p| crate::parser::is_supported(p))
        // Test classification is relative to the scan root: a project that
        // happens to live under a `tests/` path component (an absolute
        // path such as /ci/tests/app, or a root the user pointed at
        // directly) is production code for this scan. Absolute and
        // relative invocations must see the same files.
        .filter(|p| !is_test_file(p.strip_prefix(root).unwrap_or(p)))
        .filter(|p| {
            if let Some(allowed) = language_filter {
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
                allowed.contains(&ext)
            } else {
                true
            }
        })
        .collect()
}

#[must_use]
fn is_test_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let stem = path.file_stem().and_then(|n| n.to_str()).unwrap_or("");

    if name.ends_with(".test.ts")
        || name.ends_with(".test.tsx")
        || name.ends_with(".test.js")
        || name.ends_with(".test.jsx")
        || name.ends_with(".spec.ts")
        || name.ends_with(".spec.tsx")
        || name.ends_with(".spec.js")
        || name.ends_with(".spec.jsx")
        || name.ends_with("_test.rs")
        || name.ends_with(".test.rs")
    {
        return true;
    }

    // Component matching, not substring matching: `tests/app.go` (relative)
    // and `/x/tests/app.go` (absolute) must classify identically, and the
    // separator is platform-dependent.
    if path.components().any(|c| {
        matches!(c, Component::Normal(name)
            if name == "tests"
                || name == "test"
                || name == "__tests__"
                || name == "mocks"
                || name == "__mocks__")
    }) {
        return true;
    }

    stem.starts_with("mock") || stem.to_lowercase().ends_with(".mock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Scratch tree removed on drop; unique per test by tag.
    struct Tree(PathBuf);

    impl Tree {
        fn new(tag: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("frensense-files-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).expect("create scratch tree");
            Self(base)
        }

        fn file(&self, rel: &str) -> PathBuf {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().expect("parent")).expect("create dirs");
            fs::write(&p, "fn main() {}\n").expect("write fixture");
            p
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rel_names(root: &Path) -> Vec<String> {
        let mut names: Vec<String> = collect_files(root, None)
            .iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        names.sort();
        names
    }

    /// Regression: an absolute root whose own path contains a `tests`
    /// component (e.g. /ci/tests/app) used to classify every file as a test
    /// file and report a clean scan. The root is the user's subject, not a
    /// test directory relative to something else.
    #[test]
    fn root_under_a_tests_component_is_scanned() {
        let tree = Tree::new("root-tests");
        tree.file("tests/app/src/main.rs");
        let root = tree.0.join("tests/app");
        assert_eq!(rel_names(&root), vec!["src/main.rs"]);
    }

    /// Test directories *inside* the root keep being skipped, whatever the
    /// root is called.
    #[test]
    fn nested_test_dirs_are_still_skipped() {
        let tree = Tree::new("nested-tests");
        tree.file("proj/src/lib.rs");
        tree.file("proj/tests/e2e.rs");
        tree.file("proj/src/__tests__/unit.rs");
        let root = tree.0.join("proj");
        assert_eq!(rel_names(&root), vec!["src/lib.rs"]);
    }

    /// Absolute and relative spellings of the same root must select the
    /// same files; the classification is root-relative, so the prefix
    /// cannot change the outcome.
    #[test]
    fn classification_is_root_relative() {
        let tree = Tree::new("root-relative");
        tree.file("tests/app/src/main.rs");
        let root = tree.0.join("tests/app");
        let nested = root.join("src/main.rs");
        assert!(!is_test_file(
            nested.strip_prefix(&root).expect("strip root")
        ));
        assert!(is_test_file(
            tree.0
                .join("proj/tests/e2e.rs")
                .strip_prefix(tree.0.join("proj"))
                .expect("strip root")
        ));
    }

    /// Named markers match path components, so a path that merely contains
    /// "mock" or "test" as a substring is not a test file.
    #[test]
    fn test_dir_markers_match_components_not_substrings() {
        assert!(is_test_file(Path::new("a/mocks/x.rs")));
        assert!(is_test_file(Path::new("test/x.rs")));
        assert!(!is_test_file(Path::new("src/hammock.rs")));
        assert!(!is_test_file(Path::new("src/attestation.rs")));
    }
}
