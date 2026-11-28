// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing
//! JavaScript, TypeScript and component ([`LanguageSpec`](crate::spec::LanguageSpec))
//! implementations.
//!
//! JavaScript, TypeScript and the script blocks of a Vue or Svelte component
//! are one language family: same AST grammar (TypeScript is a superset of
//! JavaScript in tree-sitter-typescript), same classification, same imports and
//! exports. The family's [`LanguageSpec`](crate::spec::LanguageSpec) behaviour
//! is therefore written **once** behind [`JsFamily`], and each member states
//! only its [`JsDialect`] — the extensions, grammar, symbol-query and wrapper
//! that actually differ.
//!
//! Layout:
//! - `family` - the one `LanguageSpec` implementation plus [`JsDialect`]
//! - `ast` - shared AST classification (node → [`NodeRole`](crate::spec::NodeRole))
//! - `imports` - ESM/CommonJS import extraction
//! - `packages` - npm package → [`PackageCategory`](crate::spec::PackageCategory) knowledge
//! - `params` - parameter → [`TaintOrigin`](crate::spec::TaintOrigin) classification
//! - `spec_ts` / `spec_js` - the two plain family members ([`TypeScriptSpec`],
//!   [`JavaScriptSpec`])
//! - `angular` - Angular binding scanning shared by external templates and
//!   inline `@Component({ template: … })` decorators (sanitizer-aware)
//! - `sfc` - shared single-file-component blanking (markup → spaces, offsets kept)
//! - `spec_vue` / `spec_svelte` - component members with script blocks
//!   ([`VueSpec`], [`SvelteSpec`]: markup blanked in place, script blocks
//!   parsed by the TSX grammar, raw-HTML writes reported as expression spans)
//! - `spec_astro` - an Astro component ([`AstroSpec`]: `---` frontmatter kept,
//!   template blanked, `set:html` writes)
//! - `spec_angular` - an Angular `*.component.html` template ([`AngularSpec`]:
//!   the whole file is markup and blanked; only bindings that bypass Angular's
//!   sanitizer are reported)
//!
//! # Adding a component format
//!
//! A component file is markup plus `<script>` bodies. It needs three things
//! and no engine change:
//!
//! 1. **A dialect.** Add a [`JsDialect`] variant in `family.rs` with the
//!    extensions, the grammar (TSX for every script dialect here), the fact
//!    language (the script's real language, usually `"typescript"`), the
//!    symbol query and the region wrapper. Every exhaustive `match` in
//!    `JsDialect` must gain an arm; the compiler lists them.
//! 2. **A spec.** Add `spec_<name>.rs` with a unit struct implementing
//!    [`JsFamily`], naming the dialect. Override `preprocess_source` to blank
//!    markup via [`sfc`] (use `extract_script_blocks` when the format has an
//!    explicit template tag, `blank_scripts` when markup is implicit,
//!    `frontmatter_span` for a fenced code block, and no kept region when the
//!    file is pure markup) and `template_writes_source` to report the
//!    expression spans of constructs that render unescaped HTML. Re-export it
//!    from this module and register it in
//!    [`LanguageRegistry::with_default_specs`](crate::registry::LanguageRegistry::with_default_specs).
//! 3. **A framework model.** Add or extend the entry in
//!    [`crate::framework::FRAMEWORKS`] so `resolve_file` knows the extension
//!    is a [`FileKind::Sfc`](crate::framework::FileKind::Sfc), plus resolver
//!    tests for its path shapes.
//!
//! Do **not** rewrite markup into code: the engine lowers template writes from
//! the reported spans, which keeps every byte offset anchored to the original
//! file and removes any byte budget next to a directive.
//!
//! Security vocabulary (sinks, sources, sanitizers, propagators, session
//! roots, route patterns) lives in `frensense-packgen` since Phase 6.3; the
//! specs here are mechanism-only.

mod angular;
mod ast;
mod family;
mod imports;
mod packages;
mod params;
mod sfc;
mod spec_angular;
mod spec_astro;
mod spec_js;
mod spec_svelte;
mod spec_ts;
mod spec_vue;

pub use family::{JsDialect, JsFamily};
pub use spec_angular::AngularSpec;
pub use spec_astro::AstroSpec;
pub use spec_js::JavaScriptSpec;
pub use spec_svelte::SvelteSpec;
pub use spec_ts::TypeScriptSpec;
pub use spec_vue::VueSpec;
