// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Entry gates for a candidate sink call.
//!
//! Split out of `walk::sink` so the dispatch question and the spelling
//! heuristics sit together, ahead of the matcher they guard.

use super::*;

use crate::ir::function::BlockId;

impl<'a> BackwardTaintEngine<'a> {
    /// Whether dispatch resolved this call instruction to program code.
    ///
    /// The call graph follows import aliases, SSA alias chains, receiver
    /// classes and callbacks, so this is the same answer the interprocedural
    /// layer used to link the edge. A site that runs program code is not a
    /// library sink: the callee's own instructions are matched where they are
    /// written, which also stops a local helper that merely shares a sink's
    /// name from arming it (`from helper import run as exec`).
    pub(super) fn dispatch_runs_program_code(&self, fi: usize, block: BlockId, idx: usize) -> bool {
        let Some(callee) = self.prog.functions.get(fi) else {
            return false;
        };
        self.prog
            .callgraph()
            .dispatch_is_program(&callee.name, block.0, idx)
            == Some(true)
    }

    /// Whether a bare static call can match no configured sink: a local
    /// callable, a function defined in this program, or a verb that requires a
    /// receiver object.
    pub(super) fn skip_unanchored_static(
        &mut self,
        ir: &FunctionIR,
        name: &str,
        is_static: bool,
        has_package_import: bool,
    ) -> bool {
        if !is_static || has_package_import {
            return false;
        }
        // A static call to a local variable/closure defined in this function is
        // not an external sink.
        if ir
            .var_metadata
            .values()
            .any(|m| m.source_name.as_deref() == Some(name))
        {
            self.funnel.skipped_local_callable += 1;
            return true;
        }
        // Verb sinks that strictly require a receiver object (get, post,
        // render, etc.); a bare static call without package import is not a
        // client method invocation.
        if is_receiver_only_verb(name) {
            self.funnel.skipped_receiver_only_verb += 1;
            return true;
        }
        false
    }
}
