// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! File collection: walk the target, keep supported source files.

use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

/// Hidden directories that are still source trees. Vite/VitePress keeps
/// a site's real application code — the theme (Vue SFCs), config and
/// types — under `.vitepress`, so scanning a docs project root must not
/// blind itself to it. Every other hidden directory stays excluded
/// (caches, VCS internals, tool state).
const HIDDEN_SOURCE_DIRS: &[&str] = &[".vitepress"];

/// Source-language extensions the engine does not implement, mapped to the
/// language a user recognizes. A directory scan drops these files (there is
/// no spec to lower them with), so they are collected separately and reported:
/// silently scanning 3 of 40 files in a polyglot repository reads as "clean"
/// when it only means "we never looked at 37 of them".
///
/// Deliberately source languages only. Data and asset extensions (`.json`,
/// `.yaml`, `.md`, images, lockfiles) are not source files and stay ignored.
const UNSUPPORTED_LANGUAGES: &[(&str, &str)] = &[
    ("rb", "Ruby"),
    ("rake", "Ruby"),
    ("gemspec", "Ruby"),
    ("php", "PHP"),
    ("phtml", "PHP"),
    ("java", "Java"),
    ("kt", "Kotlin"),
    ("kts", "Kotlin"),
    ("scala", "Scala"),
    ("sc", "Scala"),
    ("swift", "Swift"),
    ("cs", "C#"),
    ("fs", "F#"),
    ("fsi", "F#"),
    ("fsx", "F#"),
    ("vb", "Visual Basic"),
    ("bas", "Visual Basic"),
    ("pl", "Perl"),
    ("pm", "Perl"),
    ("lua", "Lua"),
    ("r", "R"),
    ("jl", "Julia"),
    ("dart", "Dart"),
    ("ex", "Elixir"),
    ("exs", "Elixir"),
    ("erl", "Erlang"),
    ("hrl", "Erlang"),
    ("hs", "Haskell"),
    ("lhs", "Haskell"),
    ("ml", "OCaml"),
    ("mli", "OCaml"),
    ("clj", "Clojure"),
    ("cljs", "Clojure"),
    ("cljc", "Clojure"),
    ("groovy", "Groovy"),
    ("nim", "Nim"),
    ("zig", "Zig"),
    ("sol", "Solidity"),
    ("svelte", "Svelte"),
    ("astro", "Astro"),
    ("sh", "Shell"),
    ("bash", "Shell"),
    ("zsh", "Shell"),
    ("ksh", "Shell"),
    ("ps1", "PowerShell"),
    ("psm1", "PowerShell"),
    ("bat", "Batch"),
    ("cmd", "Batch"),
    ("sql", "SQL"),
    ("asm", "Assembly"),
    ("s", "Assembly"),
    ("f", "Fortran"),
    ("f90", "Fortran"),
    ("f95", "Fortran"),
    ("for", "Fortran"),
    ("pas", "Pascal"),
    ("pp", "Pascal"),
    ("tcl", "Tcl"),
    ("v", "SystemVerilog"),
    ("sv", "SystemVerilog"),
    ("vhd", "VHDL"),
    ("vhdl", "VHDL"),
    ("ada", "Ada"),
    ("adb", "Ada"),
    ("ads", "Ada"),
    ("cob", "COBOL"),
    ("cbl", "COBOL"),
    ("hx", "Haxe"),
    ("cr", "Crystal"),
    ("d", "D"),
    ("elm", "Elm"),
    ("purs", "PureScript"),
    ("re", "ReasonML"),
    ("rei", "ReasonML"),
];

/// One collected source file whose language has no engine spec.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnsupportedSourceFile {
    /// Path as the scanner knows it (relative to how the root was passed).
    pub path: String,
    /// Language name shown to the user, e.g. `Ruby`.
    pub language: &'static str,
}

/// Result of one directory walk: what can be scanned and what was skipped
/// because its language is not supported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectedFiles {
    /// Files the engine has a spec for (and that pass the scan's filters).
    pub supported: Vec<PathBuf>,
    /// Source files skipped solely because the engine has no spec for the
    /// language. Empty when a language filter scoped the scan.
    pub unsupported: Vec<UnsupportedSourceFile>,
}

/// Collects all files reachable from `root` that match supported extensions
/// and the optional language filter.
#[must_use]
pub fn collect_files(root: &Path, language_filter: Option<&Vec<&'static str>>) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    collect_files_detailed(root, language_filter).supported
}

/// Like [`collect_files`], but also reports source files skipped because the
/// engine has no language spec for them.
///
/// A single-file root is supported only when its extension is; an unsupported
/// file contributes one entry to `unsupported` (when its language is known)
/// and nothing to `supported`, which is how the caller distinguishes "the
/// explicit input could not be read" from "the tree had nothing to scan".
#[must_use]
pub fn collect_files_detailed(
    root: &Path,
    language_filter: Option<&Vec<&'static str>>,
) -> CollectedFiles {
    if root.is_file() {
        if crate::parser::is_supported(root) {
            return CollectedFiles {
                supported: vec![root.to_path_buf()],
                unsupported: Vec::new(),
            };
        }
        return CollectedFiles {
            supported: Vec::new(),
            unsupported: unsupported_source_file(root).into_iter().collect(),
        };
    }

    let mut collected = CollectedFiles::default();
    for path in walk_source_candidates(root) {
        if crate::parser::is_supported(&path) {
            let matches_filter = language_filter.is_none_or(|allowed| {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                allowed.contains(&ext)
            });
            // Test classification is relative to the scan root: a project
            // that happens to live under a `tests/` path component (an
            // absolute path such as /ci/tests/app, or a root the user pointed
            // at directly) is production code for this scan. Absolute and
            // relative invocations must see the same files.
            if matches_filter
                && !looks_minified(&path)
                && !is_test_file(path.strip_prefix(root).unwrap_or(&path))
            {
                collected.supported.push(path);
            }
        } else if language_filter.is_none()
            && let Some(file) = unsupported_source_file(&path)
        {
            collected.unsupported.push(file);
        }
    }
    collected
}

/// The source candidates under `root`: directories that are not build/VCS
/// output, files that are not oversized or machine-compacted.
fn walk_source_candidates(root: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    WalkDir::new(root)
        .into_iter()
        .filter_entry(move |e| {
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
                    && name != "cache"
                    && name != "coverage"
                    && name != "cypress"
                    && name != "playwright"
                    && name != "storybook-static"
                    && (!name.starts_with('.') || HIDDEN_SOURCE_DIRS.contains(&name.as_ref()));
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
}

/// Build the skipped-language entry for `path`, or `None` when the extension
/// is not a source language (data, assets, config).
fn unsupported_source_file(path: &Path) -> Option<UnsupportedSourceFile> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)?;
    let language = UNSUPPORTED_LANGUAGES
        .iter()
        .find_map(|(known, language)| (*known == ext).then_some(*language))?;
    Some(UnsupportedSourceFile {
        path: path.to_string_lossy().into_owned(),
        language,
    })
}

/// True for JavaScript that was machine-compacted: a file that is not named
/// `.min.js` can still be a vendored bundle. Its single-letter identifiers
/// (`c`, `e`) and thousands-of-characters lines match nothing a reviewer can
/// act on, and every finding in one is noise. Real source averages well under
/// 100 bytes per line; compacted output is far above 300.
fn looks_minified(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if !matches!(ext, "js" | "mjs" | "cjs") {
        return false;
    }
    let Ok(text) = std::fs::read(path) else {
        return false;
    };
    if text.len() < 2_000 {
        return false;
    }
    let lines = text.iter().filter(|&&b| b == b'\n').count() + 1;
    text.len() / lines > 300
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

    /// `.vitepress` holds a docs site's real theme code (Vue SFCs, TS);
    /// scanning a docs project root must include it, every other hidden
    /// directory stays excluded, and the build-output subtrees Vite keeps
    /// INSIDE `.vitepress` (plain-named `cache`/`deps` of dependency
    /// pre-bundles) must not sweep vendored artifacts into the scan.
    #[test]
    fn hidden_source_dirs_are_scanned_but_other_hidden_dirs_stay_excluded() {
        let tree = Tree::new("hidden-source-dirs");
        tree.file("docs-site/.vitepress/theme/Comp.vue");
        tree.file("docs-site/.vitepress/theme/index.ts");
        tree.file("docs-site/scripts/tool.py");
        tree.file("docs-site/.cache/artifact.js");
        tree.file("docs-site/.vitepress/cache/deps/vendored.js");
        let root = tree.0.join("docs-site");
        assert_eq!(
            rel_names(&root),
            vec![
                ".vitepress/theme/Comp.vue".to_string(),
                ".vitepress/theme/index.ts".to_string(),
                "scripts/tool.py".to_string(),
            ],
            "the .vitepress source dir must be in, .cache and its caches must stay out"
        );
    }

    fn skipped(tree: &Tree) -> Vec<(String, &'static str)> {
        let mut files: Vec<(String, &'static str)> = collect_files_detailed(&tree.0, None)
            .unsupported
            .into_iter()
            .map(|f| {
                let rel = Path::new(&f.path)
                    .strip_prefix(&tree.0)
                    .unwrap_or(Path::new(&f.path))
                    .to_string_lossy()
                    .replace('\\', "/");
                (rel, f.language)
            })
            .collect();
        files.sort();
        files
    }

    /// A polyglot tree must say which source files it could not read. The
    /// engine has no Ruby/PHP/Java/Shell spec, and dropping those files
    /// silently made a 1-of-5-file scan look complete.
    #[test]
    fn unsupported_source_languages_are_collected() {
        let tree = Tree::new("unsupported-langs");
        tree.file("src/lib.rs");
        tree.file("src/app.rb");
        tree.file("api/index.php");
        tree.file("web/App.java");
        tree.file("scripts/deploy.sh");
        tree.file("README.md");
        tree.file("data.json");
        assert_eq!(rel_names(&tree.0), vec!["src/lib.rs"]);
        assert_eq!(
            skipped(&tree),
            vec![
                ("api/index.php".to_string(), "PHP"),
                ("scripts/deploy.sh".to_string(), "Shell"),
                ("src/app.rb".to_string(), "Ruby"),
                ("web/App.java".to_string(), "Java"),
            ],
            "source languages are reported; README.md and data.json are not source"
        );
    }

    /// An explicit unsupported input stays a legacy `collect_files` result
    /// (the runner decides whether that is an error), while the detailed
    /// walk names the language it could not scan.
    #[test]
    fn explicit_unsupported_file_reports_its_language() {
        let tree = Tree::new("explicit-unsupported");
        let ruby = tree.file("app.rb");
        assert_eq!(collect_files(&ruby, None), vec![ruby.clone()]);
        let detailed = collect_files_detailed(&ruby, None);
        assert!(detailed.supported.is_empty());
        assert_eq!(detailed.unsupported.len(), 1);
        assert_eq!(detailed.unsupported[0].language, "Ruby");
    }

    /// A language filter scopes the scan, so files outside it are not
    /// "unsupported"; the user asked for one language on purpose.
    #[test]
    fn language_filter_suppresses_unsupported_reporting() {
        let tree = Tree::new("filtered-unsupported");
        tree.file("src/lib.rs");
        tree.file("src/app.rb");
        let filter = vec!["rs"];
        let detailed = collect_files_detailed(&tree.0, Some(&filter));
        assert_eq!(detailed.supported.len(), 1);
        assert!(detailed.unsupported.is_empty());
    }

    /// Data/asset extensions are not language gaps and must stay quiet.
    #[test]
    fn non_source_extensions_are_not_reported() {
        for path in ["README.md", "package.json", "logo.png", "Cargo.lock"] {
            assert!(
                unsupported_source_file(Path::new(path)).is_none(),
                "{path} is not a source language"
            );
        }
        assert_eq!(
            unsupported_source_file(Path::new("x.rb")).map(|f| f.language),
            Some("Ruby")
        );
    }
}
