// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Read-only queries over the resolved call graph.
//!
//! Split out of `graph::callgraph` so the graph, its builder and the
//! answers consumers ask after the build each stay reviewable. Consumers:
//! interprocedural binding discovery and the taint sink matcher.

use super::*;

impl CallGraph {
    /// Where one call instruction dispatches, for consumers that only need
    /// the internal/external split.
    ///
    /// `Some(true)` means at least one target is program code, `Some(false)`
    /// means the site is external (the resolved name is in
    /// [`CallGraph::unresolved`]), and `None` means the graph recorded no
    /// entry for the site - so the caller must fall back to its own guards
    /// rather than assume either answer.
    pub(crate) fn dispatch_is_program(
        &self,
        fn_name: &str,
        block: usize,
        instr_idx: usize,
    ) -> Option<bool> {
        let key = (fn_name.to_string(), (block, instr_idx));
        if let Some(targets) = self.sites.get(&key) {
            return Some(!targets.is_empty());
        }
        self.unresolved.get(&key).map(|_| false)
    }

    /// Targets for one call instruction inside `fn`.
    pub(crate) fn targets_at(
        &self,
        fn_name: &str,
        block: usize,
        instr_idx: usize,
    ) -> &[CallTarget] {
        self.sites
            .get(&(fn_name.to_string(), (block, instr_idx)))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}
