// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

impl<'a> BackwardTaintEngine<'a> {
    /// Build the reverse cross-edge index once.
    /// The `(caller_fn, call_site)` through which the function under walk was
    /// entered, or `None` for the empty (k=0) context.
    pub(super) fn ctx_last(&self, ctx: u32) -> Option<(usize, NodeKey)> {
        if ctx == 0 {
            return None;
        }
        let link = self.ctx_chains.get(ctx as usize)?;
        Some((link.caller_fn, link.site))
    }

    /// Push a call-site entry when the walk enters a callee. Returns 0
    /// (k=0 collapse) past the depth/count caps - sound, just unfiltered.
    pub(super) fn ctx_enter(&mut self, parent: u32, caller_fn: usize, site: NodeKey) -> u32 {
        let key = (parent, caller_fn, site);
        if let Some(&id) = self.ctx_interner.get(&key) {
            return id;
        }
        let mut depth = 0usize;
        let mut p = parent;
        while p != 0 && depth < MAX_CTX_DEPTH {
            p = self.ctx_chains[p as usize].parent;
            depth += 1;
        }
        if p != 0 || self.ctx_chains.len() >= MAX_CTX_CHAINS {
            return 0;
        }
        let id = self.ctx_chains.len() as u32;
        self.ctx_chains.push(CtxLink {
            parent,
            caller_fn,
            site,
        });
        self.ctx_interner.insert(key, id);
        id
    }

    /// Pop the innermost call-site entry (unwinding out of a callee).
    pub(super) fn ctx_exit(&self, ctx: u32) -> u32 {
        if ctx == 0 {
            0
        } else {
            self.ctx_chains[ctx as usize].parent
        }
    }
}
