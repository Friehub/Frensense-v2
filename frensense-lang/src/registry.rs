// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing
//!
//! A thread-safe registry that maps file extensions and language names to
//! [`LanguageSpec`] implementations.
//!
//! ## Usage
//!
//! ```rust
//! use frensense_lang::registry::LanguageRegistry;
//!
//! let reg = LanguageRegistry::global();
//! let spec = reg.for_extension("ts").expect("TypeScript not registered");
//! // spec is &dyn LanguageSpec - call any trait method
//! ```
//!
//! ## Building your own registry
//!
//! [`LanguageRegistry::global`] is a convenience for the common case: every
//! language enabled through Cargo features. A consumer that needs a different
//! set - its own grammar, a subset of the built-ins, or both - owns a
//! registry instead:
//!
//! ```text
//! use std::sync::Arc;
//! use frensense_lang::registry::LanguageRegistry;
//! use frensense_lang::spec::LanguageSpec;
//!
//! // Every built-in language the crate's features enable.
//! let mut reg = LanguageRegistry::with_default_specs();
//! // ... or start from nothing and register only what you handle.
//! let mut only_mine = LanguageRegistry::new();
//!
//! reg.register(Arc::new(MySpec));
//! only_mine.register(Arc::new(MySpec));
//! let spec: &dyn LanguageSpec = only_mine.for_extension("myext").unwrap();
//! ```
//!
//! A registry you own is independent of the global one: registering into it
//! never changes what [`LanguageRegistry::global`] answers.
//!
//! ## Adding a new language
//!
//! 1. Create a new file in `src/providers/` implementing `LanguageSpec`.
//!    A JavaScript-family member (a component container such as Vue or
//!    Svelte) implements [`JsFamily`](crate::providers::javascript::JsFamily)
//!    instead and names its dialect; see
//!    [`providers::javascript`](crate::providers::javascript) for the full
//!    checklist.
//! 2. Call `registry.register(Arc::new(YourProvider))` inside
//!    [`LanguageRegistry::with_default_specs`]. Registration also makes the
//!    language appear in the CLI's `--language` help, which is generated from
//!    this registry.
//! 3. Add its path shapes to [`crate::framework::FRAMEWORKS`] when files of
//!    the language have framework-specific meaning (routes, server-only
//!    modules, single-file components), so the engine and corpus resolve the
//!    same file kind from one table.
//! 4. Done.  Every engine subsystem picks it up automatically.

use std::sync::{Arc, OnceLock};

use rustc_hash::FxHashMap;

use crate::spec::LanguageSpec;

// ── Registry ──────────────────────────────────────────────────────────────────

/// Thread-safe registry of all known [`LanguageSpec`] implementations.
pub struct LanguageRegistry {
    by_ext: FxHashMap<&'static str, Arc<dyn LanguageSpec>>,
    by_name: FxHashMap<&'static str, Arc<dyn LanguageSpec>>,
}

impl std::fmt::Debug for LanguageRegistry {
    /// Lists the registered language names and extensions, sorted so the
    /// output is deterministic (the specs themselves are trait objects).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut languages: Vec<&str> = self.by_name.keys().copied().collect();
        languages.sort_unstable();
        let mut extensions: Vec<&str> = self.by_ext.keys().copied().collect();
        extensions.sort_unstable();
        f.debug_struct("LanguageRegistry")
            .field("languages", &languages)
            .field("extensions", &extensions)
            .finish()
    }
}

impl LanguageRegistry {
    // ── Global singleton ──────────────────────────────────────────────────

    /// Returns the process-wide default registry, constructed once on first call.
    ///
    /// The default registry includes every language enabled via Cargo features.
    /// It is immutable: to register languages of your own, build a registry
    /// with [`with_default_specs`](Self::with_default_specs) or
    /// [`new`](Self::new) and keep it.
    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<LanguageRegistry> = OnceLock::new();
        INSTANCE.get_or_init(Self::with_default_specs)
    }

    // ── Construction ─────────────────────────────────────────────────────

    /// An empty registry.
    ///
    /// Use it when you handle your own languages only: register exactly the
    /// specs you want and every other extension answers `None`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_ext: FxHashMap::default(),
            by_name: FxHashMap::default(),
        }
    }

    /// The built-in languages this crate's features enable.
    ///
    /// Same contents as [`global`](Self::global), but owned, so you can
    /// [`register`](Self::register) a provider of your own on top.
    #[must_use]
    pub fn with_default_specs() -> Self {
        // The list is empty when every grammar feature is off.
        let specs: Vec<Arc<dyn LanguageSpec>> = vec![
            #[cfg(feature = "typescript")]
            Arc::new(crate::providers::javascript::TypeScriptSpec),
            #[cfg(feature = "typescript")]
            Arc::new(crate::providers::javascript::VueSpec),
            #[cfg(feature = "typescript")]
            Arc::new(crate::providers::javascript::SvelteSpec),
            #[cfg(feature = "typescript")]
            Arc::new(crate::providers::javascript::AstroSpec),
            #[cfg(feature = "typescript")]
            Arc::new(crate::providers::javascript::AngularSpec),
            #[cfg(feature = "javascript")]
            Arc::new(crate::providers::javascript::JavaScriptSpec),
            #[cfg(feature = "go")]
            Arc::new(crate::providers::go::GoSpec),
            #[cfg(feature = "python")]
            Arc::new(crate::providers::python::PythonSpec),
            #[cfg(feature = "rust-grammar")]
            Arc::new(crate::providers::rust_lang::RustSpec),
            #[cfg(feature = "c-grammar")]
            Arc::new(crate::providers::c_lang::CSpec),
        ];

        let mut reg = Self::new();
        for spec in specs {
            reg.register(spec);
        }
        reg
    }

    /// Register a [`LanguageSpec`] for every extension and name it declares.
    ///
    /// Works on any registry you own - one from [`new`](Self::new) or
    /// [`with_default_specs`](Self::with_default_specs). When two specs claim
    /// the same extension the later registration wins, which is how a
    /// consumer overrides a built-in for one file type.
    pub fn register(&mut self, spec: Arc<dyn LanguageSpec>) {
        for &ext in spec.extensions() {
            self.by_ext.insert(ext, Arc::clone(&spec));
        }
        self.by_name.insert(spec.name(), spec);
    }

    // ── Lookups ───────────────────────────────────────────────────────────

    /// Look up the spec for a file extension (lowercase, no leading dot).
    ///
    /// Returns `None` when the extension is unknown - the engine should skip
    /// or fall back gracefully.
    #[must_use]
    pub fn for_extension(&self, ext: &str) -> Option<&dyn LanguageSpec> {
        self.by_ext.get(ext).map(Arc::as_ref)
    }

    /// Look up the spec by the canonical language name.
    #[must_use]
    pub fn for_name(&self, name: &str) -> Option<&dyn LanguageSpec> {
        self.by_name.get(name).map(Arc::as_ref)
    }

    /// Look up the spec for a file path, extracting the extension automatically.
    #[must_use]
    pub fn for_path(&self, path: &std::path::Path) -> Option<&dyn LanguageSpec> {
        let ext = path.extension()?.to_str()?.to_lowercase();
        self.for_extension(ext.as_str())
    }

    /// All registered language names.
    pub fn language_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.by_name.keys().copied()
    }

    /// All registered language specs (deduplicated by language name).
    pub fn all_specs(&self) -> impl Iterator<Item = &dyn LanguageSpec> + '_ {
        self.by_name.values().map(|arc| arc.as_ref())
    }
}

// ── Convenience free functions ─────────────────────────────────────────────────

/// Convenience: `spec_for_ext("ts")` → `Some(&dyn LanguageSpec)`.
#[inline]
pub fn spec_for_ext(ext: &str) -> Option<&'static dyn LanguageSpec> {
    LanguageRegistry::global().for_extension(ext)
}

/// Convenience: `spec_for_path(Path::new("src/main.rs"))`.
#[inline]
pub fn spec_for_path(path: &std::path::Path) -> Option<&'static dyn LanguageSpec> {
    LanguageRegistry::global().for_path(path)
}

/// Convenience: iterate all registered language specs.
#[inline]
pub fn all_specs() -> impl Iterator<Item = &'static dyn LanguageSpec> {
    LanguageRegistry::global().all_specs()
}

// ── Tests ────────────────────────────────────────────────────────────────────

// The toy spec answers with the TypeScript grammar so the tests need no
// grammar crate of their own; that is why they are feature-gated on it.
#[cfg(all(test, feature = "typescript"))]
mod tests {
    use std::sync::Arc;

    use tree_sitter::Node;

    use super::LanguageRegistry;
    use crate::spec::{Import, LanguageSpec, NodeRole, PackageCategory, TaintOrigin};

    /// A downstream provider: a language this crate has never heard of.
    struct ToySpec;

    impl LanguageSpec for ToySpec {
        fn name(&self) -> &'static str {
            "toy"
        }

        fn extensions(&self) -> &'static [&'static str] {
            &["toy"]
        }

        fn tree_sitter_language(&self) -> tree_sitter::Language {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        }

        fn classify(&self, _kind: &str) -> NodeRole {
            NodeRole::Other
        }

        fn wrap_region(&self, code: &str) -> String {
            code.to_owned()
        }

        fn import_node_kinds(&self) -> &'static [&'static str] {
            &[]
        }

        fn extract_imports(&self, _root: Node<'_>, _source: &str) -> Vec<Import> {
            Vec::new()
        }

        fn package_category(&self, _package: &str) -> Option<PackageCategory> {
            None
        }

        fn classify_param_taint(
            &self,
            _name: Option<&str>,
            _type_annotation: Option<&str>,
        ) -> Option<TaintOrigin> {
            None
        }
    }

    #[test]
    fn a_new_registry_is_empty() {
        let reg = LanguageRegistry::new();
        assert!(reg.for_extension("ts").is_none());
        assert!(reg.for_name("typescript").is_none());
        assert_eq!(reg.all_specs().count(), 0);
    }

    #[test]
    fn an_owned_registry_takes_a_downstream_spec() {
        let mut reg = LanguageRegistry::new();
        reg.register(Arc::new(ToySpec));

        assert_eq!(
            reg.for_extension("toy").map(|spec| spec.name()),
            Some("toy")
        );
        assert_eq!(reg.for_name("toy").map(|spec| spec.name()), Some("toy"));
        assert!(
            reg.for_extension("ts").is_none(),
            "only what was registered"
        );
        assert_eq!(reg.all_specs().count(), 1);
    }

    #[test]
    fn the_built_in_set_can_be_extended() {
        let mut reg = LanguageRegistry::with_default_specs();
        let built_in = reg.for_extension("ts").is_some();
        assert!(built_in, "the default specs are present");

        reg.register(Arc::new(ToySpec));
        assert!(reg.for_extension("toy").is_some());
        assert!(reg.for_extension("ts").is_some(), "built-ins survive");
    }

    #[test]
    fn a_local_registry_does_not_change_the_global_one() {
        let mut reg = LanguageRegistry::with_default_specs();
        reg.register(Arc::new(ToySpec));

        assert!(reg.for_extension("toy").is_some());
        assert!(
            LanguageRegistry::global().for_extension("toy").is_none(),
            "the global registry is immutable and unaffected"
        );
    }

    #[test]
    fn the_global_registry_is_the_feature_gated_default_set() {
        let global = LanguageRegistry::global();
        let owned = LanguageRegistry::with_default_specs();
        assert_eq!(
            global.all_specs().count(),
            owned.all_specs().count(),
            "global() is with_default_specs() built once"
        );
    }

    #[test]
    fn for_path_reads_a_file_extension() {
        let reg = LanguageRegistry::with_default_specs();
        let spec = reg
            .for_path(std::path::Path::new("src/main.ts"))
            .expect("ts is registered");
        assert_eq!(spec.name(), "typescript");
        assert!(reg.for_path(std::path::Path::new("Makefile")).is_none());
    }
}
