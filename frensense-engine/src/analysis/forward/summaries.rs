// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

// ---------------------------------------------------------------------------
// Relational taint summary
// ---------------------------------------------------------------------------

/// CFTaint-style relational summary: *not* "is this function tainted?" but
/// "if argument slot `s` is tainted, which outputs become tainted?".
///
/// Applied differently at each call site, this gives context sensitivity for
/// free at the summary-application step.
#[derive(Debug, Clone, Default)]
pub struct TaintSummary {
    pub function_name: String,
    /// Indexed by formal parameter slot. `true` if taint introduced at that
    /// parameter can reach any of the function's return values.
    pub param_taints_return: Vec<bool>,
    /// Indexed by formal parameter slot. `true` if taint introduced at that
    /// parameter can reach a configured sink inside this function.
    pub param_reaches_sink: Vec<bool>,
}

impl TaintSummary {
    /// True if taint at parameter slot `slot` flows to the return value.
    pub fn taints_return(&self, slot: usize) -> bool {
        self.param_taints_return.get(slot).copied().unwrap_or(false)
    }
}

impl<'a> ProgramSvfg<'a> {
    // -----------------------------------------------------------------------
    // Step 2: bottom-up topological order (leaves first)
    // -----------------------------------------------------------------------

    pub(super) fn compute_topological_order(&mut self) {
        let n = self.functions.len();
        let mut state = vec![0u8; n]; // 0 = unvisited, 1 = in progress, 2 = done
        let mut order = Vec::with_capacity(n);

        for fi in 0..n {
            self.dfs_topo(fi, &mut state, &mut order);
        }
        self.topological_order = order;
    }

    pub(super) fn dfs_topo(&self, fi: usize, state: &mut [u8], order: &mut Vec<usize>) {
        if state[fi] != 0 {
            return; // done, or back-edge into an in-progress function (cycle)
        }
        state[fi] = 1;
        // Visit callees in deterministic order.
        let mut callees: Vec<usize> = self.functions[fi]
            .bindings
            .iter()
            .flat_map(|b| b.callees.iter().copied())
            .collect();
        callees.sort_unstable();
        callees.dedup();
        for gi in callees {
            self.dfs_topo(gi, state, order);
        }
        state[fi] = 2;
        order.push(fi);
    }

    // -----------------------------------------------------------------------
    // Step 3: bottom-up summaries (one analysis per function)
    // -----------------------------------------------------------------------

    pub(super) fn compute_summaries(&mut self, config: &TaintConfig, facts: &FactTable) {
        for &fi in &self.topological_order {
            // Suppress local pass-through edges for callees that already have
            // summaries (their relational summary replaces the local edge).
            let mut suppressible: Vec<(NodeKey, NodeKey)> = self.functions[fi]
                .bindings
                .iter()
                .filter(|b| {
                    b.callees
                        .iter()
                        .any(|&gi| self.functions[gi].summary.is_some())
                })
                .filter_map(|b| b.ret_node.map(|r| (b, r)))
                .flat_map(|(b, r)| {
                    b.args
                        .iter()
                        .map(move |(a, _)| (*a, r))
                        .chain(b.receiver.map(|recv| (recv, r)))
                })
                .collect();

            // External calls with registered propagator rules: suppress pass-through
            // edges for argument slots that do NOT propagate taint.
            for b in &self.functions[fi].bindings {
                if b.callees.is_empty()
                    && let Some(r) = b.ret_node
                    && let Some(propagating_slots) = facts.propagator_input_args(&b.callee_name)
                {
                    for (a, slot) in &b.args {
                        if !propagating_slots.contains(slot) {
                            suppressible.push((*a, r));
                        }
                    }
                }
            }

            for (from, to) in suppressible {
                self.suppressed.insert((fi, from, to));
            }

            let summary = self.compute_one_summary(fi, config, facts);
            self.functions[fi].summary = Some(summary);
        }
    }

    /// Compositional summary for one function: BFS restricted to the
    /// function's *own* graph; at call sites with summarised callees, apply
    /// the callee summary instead of crossing into it.
    pub(super) fn compute_one_summary(
        &self,
        fi: usize,
        config: &TaintConfig,
        facts: &FactTable,
    ) -> TaintSummary {
        let fe = &self.functions[fi];
        let nparams = fe.ir.parameters.len();
        let mut param_taints_return = vec![false; nparams];
        let mut param_reaches_sink = vec![false; nparams];

        for p in 0..nparams {
            let Some(&seed) = fe.def_site.get(&fe.ir.parameters[p]) else {
                continue;
            };
            let mut visited: FxHashSet<NodeKey> = FxHashSet::default();
            visited.insert(seed);
            let mut queue: VecDeque<NodeKey> = VecDeque::new();
            queue.push_back(seed);

            while let Some(cur) = queue.pop_front() {
                let node = match fe.svfg.node(&cur) {
                    Some(n) => n,
                    None => continue,
                };

                if node.kind == NodeKind::FormalRet {
                    param_taints_return[p] = true;
                }
                if sink_alert_with_facts(fe.ir, config, facts, &cur).is_some() {
                    param_reaches_sink[p] = true;
                }

                // Apply a summarised callee at an ActualArg node instead of
                // crossing into the callee graph (compositional step).
                if let Some(&(bi, slot)) = fe.arg_slots.get(&cur) {
                    let binding = &fe.bindings[bi];
                    for &gi in &binding.callees {
                        let callee_has_recv =
                            self.functions[gi].ir.parameters.first().is_some_and(|&p| {
                                self.functions[gi]
                                    .ir
                                    .var_metadata
                                    .get(&p)
                                    .and_then(|m| m.source_name.as_deref())
                                    .is_some_and(|name| name == "self" || name == "this")
                            });
                        let callee_slot = if slot == usize::MAX {
                            if callee_has_recv { Some(0) } else { None }
                        } else {
                            Some(slot + if callee_has_recv { 1 } else { 0 })
                        };
                        if let Some(cs) = callee_slot
                            && let Some(sum) = &self.functions[gi].summary
                            && sum.taints_return(cs)
                            && let Some(ret) = binding.ret_node
                            && visited.insert(ret)
                        {
                            queue.push_back(ret);
                            break; // ret already queued
                        }
                    }
                }

                for succ in node.successors() {
                    if self.suppressed.contains(&(fi, cur, succ)) {
                        continue;
                    }
                    if is_sanitizer_use_with_facts(fe.ir, config, facts, &succ) {
                        continue;
                    }
                    if visited.insert(succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }

        TaintSummary {
            function_name: fe.name.clone(),
            param_taints_return,
            param_reaches_sink,
        }
    }
}
