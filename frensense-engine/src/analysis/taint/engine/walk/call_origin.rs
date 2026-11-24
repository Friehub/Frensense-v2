// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Where a call site's callee comes from: the file's import table, and the
//! symbol the call graph resolved the instruction to.
//!
//! Both answers exist before the matcher runs. Reading them here is what keeps
//! a sink match from being re-derived out of the call's written text.

use super::*;

use crate::ir::function::BlockId;

impl<'a> BackwardTaintEngine<'a> {
    /// The package (and imported symbol) a local name is bound to by an import
    /// in this function's file, owned so the caller can keep mutating `self`.
    ///
    /// Falls back to the only import table when the file map has a single
    /// entry: synthetic modules do not always carry a resolvable path key.
    pub(super) fn import_of(&self, fi: usize, symbol: &str) -> Option<(String, Option<String>)> {
        self.fn_file
            .get(&self.prog.functions[fi].name)
            .and_then(|file| self.file_package_imports.get(file))
            .and_then(|imports| imports.get(symbol))
            .or_else(|| {
                if self.file_package_imports.len() == 1 {
                    self.file_package_imports
                        .values()
                        .next()
                        .and_then(|m| m.get(symbol))
                } else {
                    None
                }
            })
            .map(|pkg| (pkg.package.clone(), pkg.symbol.clone()))
    }

    /// The external symbol the call graph resolved this instruction to, if it
    /// recorded one.
    ///
    /// Owned so the caller can keep mutating `self` while a `&str` from the
    /// graph is alive. `None` covers a program-local site and a site the graph
    /// never reached, and both fall back to the call's written name.
    pub(super) fn external_callee_name(
        &self,
        fi: usize,
        block: BlockId,
        idx: usize,
    ) -> Option<String> {
        let callee = self.prog.functions.get(fi)?;
        let name = self
            .prog
            .callgraph()
            .external_name(&callee.name, block.0, idx)?;
        // Placeholders the builder records for a callee it could not name (an
        // indirect call through an unknown pointer) are not spellings a fact
        // could key on.
        (!name.starts_with('<')).then(|| name.to_string())
    }
}
