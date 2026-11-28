// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The shape of a prepared program: everything lowering resolves once, so a
//! program can be re-scanned under many fact tables without lowering again.
//!
//! Split out of `scan.rs` so the type's fields - and what each table means -
//! stay in one place while the scanning logic grows around them.

use rustc_hash::FxHashMap;

use crate::graph::module::NamespaceBindings;
use crate::ir::function::FunctionIR;
use crate::telemetry::{CapHit, FileTiming};
use frensense_lang::spec::{Export, Import, ModuleItem};

/// A program lowered once, ready for repeated scans under different fact
/// tables. The replay gate lowers each family exactly once and re-scans it
/// per candidate fact, lowering dominates scan cost, so this turns the
/// gate's O(candidates × families) lowerings into O(families).
pub struct PreparedProgram {
    pub(super) irs: FxHashMap<String, FunctionIR>,
    pub(super) fn_file: FxHashMap<String, String>,
    pub(super) file_source: FxHashMap<String, String>,
    /// Per file, the local names that an import binds to a program function.
    pub file_aliases: crate::graph::module::FileAliases,
    /// Per file, the local names that an import binds to an external package.
    pub(crate) file_package_imports: crate::graph::module::PackageImportTable,
    /// Per file, the local names that bind a whole module, and where each
    /// one points.
    pub(crate) file_namespace_aliases: NamespaceBindings,
    /// Import declarations per file (see `ModuleResolution`).
    ///
    /// `ModuleResolution`: crate::graph::module::ModuleResolution
    pub file_imports: FxHashMap<String, Vec<Import>>,
    /// Export/re-export declarations per file, with visibility and kind.
    pub file_exports: FxHashMap<String, Vec<Export>>,
    /// Every top-level declaration per file, exported or not.
    pub file_module_items: FxHashMap<String, Vec<ModuleItem>>,
    /// Files that could not be lowered, with the reason. The scan continues
    /// without them and says so; it never drops one silently.
    pub lower_errors: Vec<String>,
    /// Files whose parse tree contained errors, so they were analyzed from
    /// whatever tree-sitter recovered rather than from an intact tree.
    pub parse_partial: Vec<String>,
    /// Number of source inputs attempted by this prepared program.
    pub submitted: usize,
    /// Safety cap events that happened during per-file lowering.
    pub(crate) lower_caps: Vec<CapHit>,
    /// Paths that failed lowering, independent of error message formatting.
    pub lower_failed_files: Vec<String>,
    /// Lowering cost per file, feeding the slowest-file report.
    pub(crate) file_timings: Vec<FileTiming>,
}

impl std::fmt::Debug for PreparedProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedProgram")
            .field("files", &self.file_timings.len())
            .field("functions", &self.irs.len())
            .field("lower_errors", &self.lower_errors.len())
            .finish()
    }
}
