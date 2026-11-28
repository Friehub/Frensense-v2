// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Companion component sources for external Angular templates.
//!
//! An external `*.component.html` reads its component instance's fields, and
//! those live in the sibling `*.component.ts`. Lowering the template alone
//! leaves every field reference unbound, so a sanitizer bypass that reads a
//! field cannot link to the value the class assigned. This module finds the
//! sibling, asks the TypeScript spec for the component's field initializers,
//! and hands both to the template's lowering.

use std::path::Path;

use frensense_engine::analysis::taint::facts::FactTable;
use frensense_engine::scan::{FileReport, ProgramBuilder};
use frensense_lang::spec::TemplateBinding;
use frensense_lang::spec_for_path;

/// Lower `path` with its Angular component fields in scope when it is an
/// external template, and without them otherwise.
pub(super) fn add_file<'a>(
    builder: &mut ProgramBuilder<'a>,
    path: &str,
    source: &'a str,
    ext: &str,
    facts: &FactTable,
) -> FileReport {
    let scope = companion_scope(path);
    let companion = scope
        .as_ref()
        .map(|(text, bindings)| (text.as_str(), bindings.as_slice()));
    builder.add_file_with_companion(path, source, ext, Some(facts), companion)
}

/// The sibling component's source and field initializers, when `path` is an
/// external Angular template with a readable companion.
///
/// The suffix (not the collected extension) identifies the template: the
/// walker records `component.html` as an `html` file, while the spec is
/// resolved from the path.
fn companion_scope(path: &str) -> Option<(String, Vec<TemplateBinding>)> {
    let companion_path = path.strip_suffix("component.html")?;
    let companion_path = format!("{companion_path}component.ts");
    let source = std::fs::read_to_string(&companion_path).ok()?;
    let spec = spec_for_path(Path::new(&companion_path))?;
    let bindings = spec.template_bindings(&source);
    (!bindings.is_empty()).then_some((source, bindings))
}
