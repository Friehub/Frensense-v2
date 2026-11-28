// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Declarative framework models: which file is what, and which packages make
//! a file that framework's.
//!
//! A language spec answers "how do I read this syntax"; a framework model
//! answers "what am I looking at". They are separate because the same
//! TypeScript file means different things in different trees: `route.ts`
//! under `app/` is a Next.js route module, `.server.ts` is a server-only
//! module in SvelteKit/SolidStart, and `.vue`/`.svelte`/`.astro`/`.html` are
//! component templates whose markup is not TypeScript at all.
//!
//! Everything here is data plus a deterministic resolver, so the engine and
//! the corpus read the same answer without a second implementation:
//! [`resolve_file`] is the one entry point, and [`ROUTE_KINDS`] the one list
//! of kinds that declare HTTP entry points.
//!
//! # Adding a framework model
//!
//! Adding support is data, not engine code:
//!
//! 1. Add a [`Framework`] entry to [`FRAMEWORKS`]: its `name` (used in
//!    provenance), the `language` its facts are keyed under, the `packages`
//!    that mark an import as this framework's, and its ordered `rules`.
//! 2. Order matters twice: models are tried in [`FRAMEWORKS`] order and a
//!    model's rules are tried in their own order, first match wins. Put the
//!    most specific model/rule first (`.server.ts` before a generic segment).
//! 3. If the model claims single-file components, add the extension's
//!    [`LanguageSpec`](crate::spec::LanguageSpec) (for the JS family, a
//!    `JsDialect` plus a spec in `providers::javascript`); a file kind without
//!    a parseable spec is skipped by the engine.
//! 4. Add resolver tests at the bottom of this module for each new path shape,
//!    including a Windows-separator and a false-positive case.
//!
//! Nothing else changes: routing reads [`FileKind::is_route`], and the corpus
//! reads [`resolve_file`], so both see the new model immediately.

/// What a file is, as far as routing and sink semantics care.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FileKind {
    /// Ordinary module: no framework-specific meaning.
    Library,
    /// A component whose markup is a template, not code (`.vue`, `.svelte`,
    /// `.astro`, and Angular's `.html` templates).
    Sfc,
    /// A module that must not reach the client bundle (`*.server.ts`).
    ServerOnly,
    /// A file-based HTTP entry point (`app/**/route.ts`, `+server.ts`).
    RouteModule,
    /// A legacy file-based API endpoint (`pages/api/**`).
    ApiRoute,
}

/// File kinds that register HTTP entry points.
///
/// Route detection reads this list instead of assuming every language's
/// `.get`/`.post` calls are registrations.
pub const ROUTE_KINDS: &[FileKind] = &[FileKind::RouteModule, FileKind::ApiRoute];

impl FileKind {
    /// Whether this kind is an HTTP entry point.
    #[must_use]
    pub fn is_route(self) -> bool {
        ROUTE_KINDS.contains(&self)
    }
}

/// How a model recognises one of its files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileMatch {
    /// The path ends with this text (`route.ts`, `.server.ts`).
    Suffix(&'static str),
    /// The path contains this directory fragment (`/app/`, `pages/api/`).
    Segment(&'static str),
}

impl FileMatch {
    fn matches(self, path: &str) -> bool {
        match self {
            Self::Suffix(suffix) => path.ends_with(suffix),
            Self::Segment(fragment) => path.contains(fragment),
        }
    }
}

/// One `(match, kind)` rule of a framework model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileRule {
    /// Path shape the rule recognises.
    pub matcher: FileMatch,
    /// Kind such a path has.
    pub kind: FileKind,
}

/// A framework model: name, language, packages, and its file rules.
#[derive(Debug)]
#[non_exhaustive]
pub struct Framework {
    /// Model name, used in provenance and reports.
    pub name: &'static str,
    /// Fact language the model's facts are keyed under.
    pub language: &'static str,
    /// Packages whose import marks a file as this framework's.
    pub packages: &'static [&'static str],
    /// File rules, evaluated in order; the first match wins.
    pub rules: &'static [FileRule],
}

const fn rule(matcher: FileMatch, kind: FileKind) -> FileRule {
    FileRule { matcher, kind }
}

/// Every framework model the resolver knows, in resolution order.
///
/// A model is only listed here when its file shapes are a fact rather than a
/// guess: an unknown tree resolves to [`FileKind::Library`] and keeps the
/// language's plain semantics. See the module docs for the steps to add one.
pub static FRAMEWORKS: &[Framework] = &[
    Framework {
        name: "vue",
        language: "typescript",
        packages: &["vue", "nuxt", "@vue"],
        rules: &[rule(FileMatch::Suffix(".vue"), FileKind::Sfc)],
    },
    Framework {
        name: "svelte",
        language: "typescript",
        packages: &["svelte", "@sveltejs", "sveltekit"],
        rules: &[
            rule(FileMatch::Suffix(".svelte"), FileKind::Sfc),
            rule(FileMatch::Suffix("+server.ts"), FileKind::RouteModule),
            rule(FileMatch::Suffix("+server.js"), FileKind::RouteModule),
            rule(FileMatch::Suffix(".server.ts"), FileKind::ServerOnly),
            rule(FileMatch::Suffix(".server.js"), FileKind::ServerOnly),
        ],
    },
    Framework {
        name: "angular",
        language: "typescript",
        packages: &["@angular/core", "@angular/common"],
        // Before `next`: an Angular template can live under `src/app/`,
        // which Next's `/app/` segment rule would otherwise claim first.
        rules: &[rule(FileMatch::Suffix(".component.html"), FileKind::Sfc)],
    },
    Framework {
        name: "next",
        language: "typescript",
        packages: &["next", "react", "react-dom"],
        rules: &[
            rule(FileMatch::Segment("/app/"), FileKind::RouteModule),
            rule(FileMatch::Segment("pages/api/"), FileKind::ApiRoute),
        ],
    },
    Framework {
        name: "astro",
        language: "typescript",
        packages: &["astro"],
        rules: &[rule(FileMatch::Suffix(".astro"), FileKind::Sfc)],
    },
];

/// A resolved file: the framework that claims it, if any, and its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedFile {
    /// Framework model name (`None` = no model claims the path).
    pub framework: Option<&'static str>,
    /// Resolved kind.
    pub kind: FileKind,
}

/// Resolve a path against the models of one fact language.
///
/// First matching model in [`FRAMEWORKS`] order wins, and within a model the
/// first matching rule wins, so the answer is deterministic and independent
/// of directory iteration order. `language` is the fact language
/// (`typescript`), not the extension: `.vue` script blocks are TypeScript.
#[must_use]
pub fn resolve_file(path: &str, language: &str) -> ResolvedFile {
    let normalized = path.replace('\\', "/");
    for model in FRAMEWORKS.iter().filter(|m| m.language == language) {
        if let Some(rule) = model.rules.iter().find(|r| r.matcher.matches(&normalized)) {
            return ResolvedFile {
                framework: Some(model.name),
                kind: rule.kind,
            };
        }
    }
    ResolvedFile {
        framework: None,
        kind: FileKind::Library,
    }
}

/// Whether `path` is an HTTP entry point for `language`.
#[must_use]
pub fn is_route_file(path: &str, language: &str) -> bool {
    resolve_file(path, language).kind.is_route()
}

/// Packages that make an import this framework's, from every model.
#[must_use]
pub fn framework_packages(framework: &str) -> &'static [&'static str] {
    FRAMEWORKS
        .iter()
        .find(|m| m.name == framework)
        .map_or(&[], |m| m.packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vue_component_resolves_to_an_sfc() {
        let f = resolve_file("src/components/Button.vue", "typescript");
        assert_eq!(f.framework, Some("vue"));
        assert_eq!(f.kind, FileKind::Sfc);
        assert!(!f.kind.is_route());
    }

    #[test]
    fn next_app_route_is_a_route_module() {
        assert!(is_route_file("src/app/api/users/route.ts", "typescript"));
    }

    #[test]
    fn next_pages_api_is_a_legacy_api_route() {
        let f = resolve_file("pages/api/hello.ts", "typescript");
        assert_eq!(f.framework, Some("next"));
        assert_eq!(f.kind, FileKind::ApiRoute);
    }

    #[test]
    fn angular_template_is_an_sfc_before_next_claims_app_paths() {
        let f = resolve_file("src/app/heroes/hero.component.html", "typescript");
        assert_eq!(f.framework, Some("angular"));
        assert_eq!(f.kind, FileKind::Sfc);
        assert!(!f.kind.is_route(), "a template never registers routes");
    }

    #[test]
    fn plain_html_is_not_an_angular_template() {
        let f = resolve_file("public/index.html", "typescript");
        assert_eq!(f.framework, None);
        assert_eq!(f.kind, FileKind::Library);
    }

    #[test]
    fn svelte_server_module_is_server_only_not_a_route() {
        let f = resolve_file("src/routes/+page.server.ts", "typescript");
        assert_eq!(f.framework, Some("svelte"));
        assert_eq!(f.kind, FileKind::ServerOnly);
        assert!(!f.kind.is_route());
    }

    #[test]
    fn svelte_endpoint_is_a_route_module() {
        assert!(is_route_file("src/routes/api/+server.ts", "typescript"));
    }

    #[test]
    fn windows_separators_resolve_like_unix_ones() {
        assert!(is_route_file(
            "src\\app\\api\\users\\route.ts",
            "typescript"
        ));
    }

    #[test]
    fn unknown_paths_stay_plain_library_modules() {
        let f = resolve_file("src/lib/format.ts", "typescript");
        assert_eq!(
            f,
            ResolvedFile {
                framework: None,
                kind: FileKind::Library
            }
        );
    }

    #[test]
    fn another_language_does_not_claim_js_paths() {
        let f = resolve_file("src/components/Button.vue", "python");
        assert_eq!(f.kind, FileKind::Library);
        assert_eq!(f.framework, None);
    }

    #[test]
    fn framework_packages_come_from_the_model() {
        assert!(framework_packages("next").contains(&"next"));
        assert!(framework_packages("nonexistent").is_empty());
    }
}
