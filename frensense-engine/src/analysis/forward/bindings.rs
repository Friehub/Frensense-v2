// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

// ---------------------------------------------------------------------------
// Call-site bindings
// ---------------------------------------------------------------------------

/// One resolved call site inside a function.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct CallBinding {
    /// Sentinel key identifying the call instruction (var = `VarId(usize::MAX)`).
    pub call_site: NodeKey,
    /// Indices of resolved callees in [`ProgramSvfg::functions`], sorted and
    /// deduped. Empty when every target is external/unresolved, dynamic
    /// dispatch and callbacks may resolve to several callees at once; the
    /// cross-edge installer links all of them (sound: any may run).
    /// Resolution comes from [`callgraph`] (aliases, receiver classes,
    /// higher-order callbacks); bare-name matching is the fallback.
    pub callees: Vec<usize>,
    /// Best-known callee name for diagnostics and external fact lookup
    /// (source/sink classification); `<indirect>` when unresolved.
    pub callee_name: String,
    /// The caller's receiver node, if this is a virtual call on a receiver.
    pub receiver: Option<NodeKey>,
    /// `(arg use-node key, arg index)`. Positional arguments indexed from 0.
    pub args: Vec<(NodeKey, usize)>,
    /// The caller's `ActualRet` def node, if the call has a destination.
    pub ret_node: Option<NodeKey>,
}

impl<'a> ProgramSvfg<'a> {
    // -----------------------------------------------------------------------
    // Step 1: discover call-site bindings
    // -----------------------------------------------------------------------

    pub(super) fn discover_bindings(&mut self, callgraph: &CallGraph) {
        for fi in 0..self.functions.len() {
            let ir = self.functions[fi].ir;
            let fname = self.functions[fi].name.clone();
            let mut bindings: Vec<CallBinding> = Vec::new();
            let mut arg_slots: FxHashMap<NodeKey, (usize, usize)> = FxHashMap::default();

            let mut block_ids: Vec<BlockId> = ir.blocks.keys().copied().collect();
            block_ids.sort_by_key(|b| b.0);

            for &block in &block_ids {
                let bdata = &ir.blocks[&block];
                for (idx, instr) in bdata.instructions.iter().enumerate() {
                    // Call-shape extraction. `CallPointer` sites participate
                    // when the callgraph resolved them (aliases, callbacks);
                    // unresolved ones keep the sound local pass-through
                    // fallback instead of a binding.
                    let (callee_name, receiver, args, dest): (
                        String,
                        Option<&Operand>,
                        &Vec<Operand>,
                        Option<VarId>,
                    ) = match instr {
                        Instruction::CallStatic {
                            func, args, dest, ..
                        } => (func.clone(), None, args, *dest),
                        Instruction::CallVirtual {
                            method,
                            receiver,
                            args,
                            dest,
                            ..
                        } => (method.clone(), Some(receiver), args, *dest),
                        Instruction::CallPointer { args, dest, .. } => {
                            let targets = callgraph.targets_at(&fname, block.0, idx);
                            if targets.is_empty() {
                                continue; // unresolved indirect → sound fallback
                            }
                            let name = targets
                                .iter()
                                .find_map(|t| t.internal_key())
                                .unwrap_or_else(|| "<indirect>".to_string());
                            (name, None, args, *dest)
                        }
                        _ => continue,
                    };

                    let call_site = NodeKey::instr(block, idx, VarId(usize::MAX));
                    let mut bargs: Vec<(NodeKey, usize)> = Vec::new();
                    let recv_node = if let Some(Operand::Var(r)) = receiver {
                        Some(NodeKey::instr(block, idx, *r))
                    } else {
                        None
                    };
                    for (slot, a) in args.iter().enumerate() {
                        if let Operand::Var(v) = a {
                            bargs.push((NodeKey::instr(block, idx, *v), slot));
                        }
                    }
                    let ret_node = dest.map(|d| NodeKey::instr(block, idx, d));

                    // Resolve targets: callgraph first (aliases, class-
                    // qualified methods, callbacks), bare-name fallback.
                    let mut callees: Vec<usize> = callgraph
                        .targets_at(&fname, block.0, idx)
                        .iter()
                        .filter_map(|t| t.internal_key())
                        .filter_map(|k| self.func_index.get(&k).copied())
                        .collect();
                    if callees.is_empty()
                        && let Some(gi) = self.func_index.get(&callee_name).copied()
                    {
                        callees.push(gi);
                    }
                    callees.sort_unstable();
                    callees.dedup();

                    bindings.push(CallBinding {
                        call_site,
                        callees,
                        callee_name,
                        receiver: recv_node,
                        args: bargs,
                        ret_node,
                    });
                    let bi = bindings.len() - 1;
                    if let Some(r) = bindings[bi].receiver {
                        arg_slots.insert(r, (bi, usize::MAX));
                    }
                    for (k, s) in &bindings[bi].args {
                        arg_slots.insert(*k, (bi, *s));
                    }
                }
            }

            self.functions[fi].bindings = bindings;
            self.functions[fi].arg_slots = arg_slots;
        }
    }
}
