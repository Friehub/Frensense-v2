// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
//! The backward walk itself: node-by-node exploration from a sink
//! argument to a source, with its cut sites and stop reasons.
//!
//! Split out of `walk.rs`. One step of the walk is one call: `walk_stops`
//! decides whether the node ends the branch, `gather_predecessors` collects
//! its edges and `enqueue_predecessors` pushes them with their context.

use super::*;

/// One step of the backward walk: the node being explored plus the state the
/// k=1 context stack and the field-demand mode carry for it.
#[derive(Clone, Copy)]
struct WalkStep<'a> {
    /// Function the node lives in.
    cf: usize,
    /// IR of that function, borrowed for the whole walk.
    ir: &'a FunctionIR,
    /// The node being explored.
    key: NodeKey,
    /// Block whose guard map decides whether the value is used under a guard.
    use_block: BlockId,
    /// Whether the walk seeks one field/element of a container.
    field_demand: bool,
    /// k=1 call-site context encoded by the engine's context stack.
    ctx: u32,
    /// Call site the walk enters when this node is a call destination.
    enter_call: Option<(usize, NodeKey)>,
    /// Whether this node is a formal parameter (context filters its preds).
    is_formal_param: bool,
}

/// A queued walk node: function, node, use block, field demand, context.
pub(super) type WalkNode = (usize, NodeKey, BlockId, bool, u32);

/// Local and cross-function predecessors of one walk step.
type Preds = (Vec<NodeKey>, Vec<(usize, NodeKey)>);

impl<'a> BackwardTaintEngine<'a> {
    /// Does the root argument's own definition read one specific
    /// field/element? Such walks carry *field demand*: the value they seek
    /// can only come from field-matching stores, never from the
    /// whole-container fill edges of an allocation.
    pub(super) fn root_reads_field(&self, fi: usize, root: &NodeKey) -> bool {
        let ir = self.prog.functions[fi].ir;
        for b in ir.blocks.values() {
            for phi in &b.phis {
                if phi.dest == root.var {
                    return false;
                }
            }
            for ins in &b.instructions {
                if ins.dest() == Some(root.var) {
                    return matches!(
                        ins,
                        Instruction::LoadField { .. } | Instruction::LoadElement { .. }
                    );
                }
            }
        }
        false
    }

    /// Is `cur` the defining node of an `Allocate` instruction?
    pub(super) fn def_is_allocation(&self, fi: usize, cur: &NodeKey) -> bool {
        let NodeKey {
            block,
            instr_idx: Some(i),
            var,
            ..
        } = *cur
        else {
            return false;
        };
        self.prog.functions[fi]
            .ir
            .blocks
            .get(&block)
            .and_then(|b| b.instructions.get(i))
            .is_some_and(|ins| matches!(ins, Instruction::Allocate { dest, .. } if *dest == var))
    }

    pub(super) fn explore_from(&mut self, fi: usize, root: NodeKey, state: &mut ExploreState) {
        // Field demand at the root: the sink argument's own definition reads
        // one specific field/element, so whole-container fill edges stay off
        // limits for this whole walk (see the allocation stop below).
        let root_field = self.root_reads_field(fi, &root);
        let root_ctx: u32 = 0;
        state
            .visited
            .insert((fi, root, root.block, root_field, root_ctx));
        let mut queue: VecDeque<WalkNode> = VecDeque::new();
        queue.push_back((fi, root, root.block, root_field, root_ctx));

        let dbg = DebugFlags::get();
        while let Some((cf, cur, use_block, field_demand, ctx)) = queue.pop_front() {
            let (is_formal_param, enter_call) = self.classify_node(cf, &cur);
            dbg_trace!(
                dbg.walk,
                "[walk] cf={cf} key={cur:?} kind={:?}",
                self.prog.functions[cf].svfg.node(&cur).map(|n| &n.kind)
            );
            let step = WalkStep {
                cf,
                ir: self.prog.functions[cf].ir,
                key: cur,
                use_block,
                field_demand,
                ctx,
                enter_call,
                is_formal_param,
            };

            if self.walk_stops(fi, &step, root.block, state) {
                continue;
            }

            let (local_preds, cross_preds) = self.gather_predecessors(&step);

            if local_preds.is_empty() && cross_preds.is_empty() {
                dbg_trace!(
                    dbg.deadend,
                    "[deadend] cf={cf} key={cur:?} kind={:?}",
                    self.prog.functions[cf].svfg.node(&cur).map(|n| &n.kind)
                );
                // Dead end. Classify: unresolvable roots (formal params never
                // fed by an analysed call site, or environment-defined values
                // like LoadGlobal / Dereference / CallPointer) are "unknown",
                // we can't prove them clean. Everything else (literals,
                // allocations) is a genuinely clean root.
                if self.node_is_unresolvable(cf, &cur) {
                    state.saw_unknown = true;
                    record_cut(&mut state.cuts, "unresolvable");
                    if let Some(site) = self.cut_site(cf, &cur) {
                        record_cut_site(&mut state.cut_sites, site);
                    }
                }
                // Otherwise: clean root, stop.
                continue;
            }

            // An external call whose result the walk follows into its
            // arguments: sound only as an assumption (the library might
            // sanitise or might not propagate), so name it.
            if enter_call.is_some()
                && cross_preds.is_empty()
                && !local_preds.is_empty()
                && let Some(mut site) = self.cut_site(cf, &cur)
                && site.kind == "external-call"
                && !is_std_forwarder(&site.detail)
            {
                site.kind = PASSED_THROUGH;
                record_cut_site(&mut state.cut_sites, site);
            }

            self.enqueue_predecessors(&step, &cross_preds, local_preds, state, &mut queue);
        }
    }

    /// Classify the node the walk stands on, once per step: a formal parameter
    /// filters its cross predecessors by the entry call site, and a call
    /// destination (`ActualRet`) pushes that site when the walk steps into the
    /// callee.
    fn classify_node(&self, cf: usize, cur: &NodeKey) -> (bool, Option<(usize, NodeKey)>) {
        match self.prog.functions[cf].svfg.node(cur).map(|n| &n.kind) {
            Some(NodeKind::FormalParam) => (true, None),
            Some(NodeKind::ActualRet { call_site }) => (false, Some((cf, *call_site))),
            _ => (false, None),
        }
    }

    /// Every stop the walk evaluates before following predecessors. Returns
    /// `true` when the node ends this walk, after recording why in `state`.
    fn walk_stops(
        &mut self,
        fi: usize,
        step: &WalkStep<'_>,
        root_block: BlockId,
        state: &mut ExploreState,
    ) -> bool {
        let WalkStep {
            cf,
            ir,
            key,
            use_block,
            ..
        } = *step;

        // Stop: guard check. If this node's variable is checked by a
        // guard-style call (`.test(x)` / `includes(x)`) whose branch dominates
        // the block where the value is (re)used, the value was validated on
        // every path reaching here, sanitized (task 8.3 guard map). Pure
        // value-flow cannot see this: the guard is a sibling use, not a link
        // in the chain.
        let guard_hit = self.guard_maps.get(&cf).and_then(|gm| {
            let class = state.sink_class.as_deref();
            gm.guard_hit(key.var, use_block, class).or_else(|| {
                (cf == fi)
                    .then(|| gm.guard_hit(key.var, root_block, class))
                    .flatten()
            })
        });
        if let Some(hit) = guard_hit {
            // Name the fact behind the guard so `--show-suppressed` audits a
            // guard-style cut the way it audits a call-style one.
            if let Some(GuardFact { call, classes }) = hit {
                let suppression = SanitizerSuppression { call, classes };
                if !state.suppressions.contains(&suppression) {
                    state.suppressions.push(suppression);
                }
            }
            state.saw_sanitized_root_only = true;
            record_cut(&mut state.cuts, "guard");
            return true;
        }

        // Stop: source reached, vulnerable path confirmed.
        if is_source(ir, self.config, &self.facts, &key) {
            state.saw_source = true;
            if state.source_node.is_none() {
                state.source_node = Some((cf, key));
                state.source_desc = source_description(ir, self.config, &self.facts, &key);
            }
            return true;
        }

        // Stop: provably attacker-independent value (constant, string literal,
        // boolean, or bounded integer range from the per-function value
        // lattice). Every non-`Top` lattice value derives from literals,
        // literal arithmetic, or branch sharpening - no source payload can be
        // hiding behind this node - so the branch is cut as clean
        // (unrealizable-path elimination) instead of exploring its
        // predecessors, which may include over-approximated edges. Gated on
        // fixpoint convergence: a truncated fixpoint may hold
        // narrower-than-true values, and pruning on those could drop a real
        // flow.
        let provably_independent = self
            .value_info_for(cf)
            .is_some_and(|info| info.converged && info.values.contains_key(&key.var));
        if provably_independent {
            record_cut(&mut state.cuts, "value-const");
            return true;
        }

        // Stop: sanitizer use, this branch is clean. Fact-table aware: includes
        // learned methods like .replace()/.test() guards, qualified by sink
        // role. Package-scoped sanitizer facts additionally require the call's
        // own import origin to name their package; unknown origin leaves them
        // inert.
        let san_origin = self.sanitizer_origin_package(cf, &key);
        if is_sanitizer_effective_for_role(
            ir,
            self.config,
            &self.facts,
            &key,
            state.sink_role,
            state.sink_label.as_deref(),
            Some(state.sink_name.as_str()),
            san_origin.as_deref(),
        ) {
            state.saw_sanitized_root_only = true;
            if let Some(fact) = crate::analysis::forward::sanitizer_fact_defeating(
                ir,
                &self.facts,
                &key,
                state.sink_role,
                state.sink_label.as_deref(),
                Some(state.sink_name.as_str()),
                san_origin.as_deref(),
            ) {
                let suppression = SanitizerSuppression {
                    call: fact.call.clone(),
                    classes: self
                        .facts
                        .sanitizer_classes(&fact.call, san_origin.as_deref()),
                };
                if !state.suppressions.contains(&suppression) {
                    state.suppressions.push(suppression);
                }
            }
            record_cut(&mut state.cuts, "sanitizer");
            return true;
        }

        // Stop: a field-demand walk that reached a container's allocation. The
        // requested field's value can only arrive through field-matching store
        // edges, entered directly at the load's destination (same-function
        // Pass 3, cross-function heap edges). Following the whole-container
        // fill edges here would union every stored property - `sink(p.other)`
        // must not see the store of `p.data` in the caller just because both
        // share the container.
        step.field_demand && self.def_is_allocation(cf, &key)
    }

    /// The predecessors of the step's node: local value-flow edges (phi arms
    /// pruned by branch feasibility) and cross-function edges (a formal
    /// parameter's actual arguments, a call destination's callee returns),
    /// restricted to the entry call site when the k=1 context names one.
    fn gather_predecessors(&self, step: &WalkStep<'_>) -> Preds {
        let WalkStep {
            cf,
            ir,
            key,
            ctx,
            is_formal_param,
            ..
        } = *step;

        // Local predecessors (optionally honouring suppression).
        let mut local_preds: Vec<NodeKey> = if self.honour_suppression {
            self.prog.local_predecessors(cf, &key)
        } else {
            match self.prog.functions[cf].svfg.node(&key) {
                Some(n) => n.predecessors(),
                None => Vec::new(),
            }
        };

        // Branch feasibility at phis: a Phi merges values from sibling arms;
        // when the branch condition is a constant comparison, the infeasible
        // arm never executes and its definition must not feed the merge
        // (`bar = const if 7*18+106 > 200 else param` - the tainted else arm is
        // dead). Filter phi predecessors here rather than in the SVFG:
        // feasibility is a walk-time question and the graph stays a pure
        // value-flow structure.
        let is_phi = self.prog.functions[cf]
            .svfg
            .node(&key)
            .is_some_and(|n| n.kind == NodeKind::Phi);
        if is_phi {
            let infeasible = phi_infeasible_incoming(ir, key.block, key.var);
            if !infeasible.is_empty() {
                local_preds.retain(|pk| {
                    // Post-SSA each incoming var is defined in its arm block;
                    // the def node key carries that block.
                    !infeasible
                        .iter()
                        .any(|(blk, var)| *blk == pk.block && *var == pk.var)
                });
            }
        }

        // Cross predecessors (reverse index): who feeds this node from another
        // function? For a FormalParam that means actual-args at caller call
        // sites; for an ActualRet that means the callee's FormalRet nodes.
        let mut cross_preds: Vec<(usize, NodeKey)> = self
            .reverse_cross
            .get(&(cf, key))
            .cloned()
            .unwrap_or_default();

        // k=1 call-site context (phase 5): a formal parameter's value arrived
        // through ONE invocation - the call site the walk entered this function
        // by. Only that site's actual arguments explain it; sibling callers'
        // args are a different invocation entirely. Empty context (root
        // function, heap-edge entry, cap collapse): no filter - the sound k=0
        // over-approximation.
        if is_formal_param && let Some((f_expect, site_expect)) = self.ctx_last(ctx) {
            cross_preds.retain(|(pf, pk)| {
                *pf == f_expect
                    && matches!(
                        self.prog.functions[*pf].svfg.node(pk).map(|n| &n.kind),
                        Some(NodeKind::ActualArg { call_site, .. })
                            if *call_site == site_expect
                    )
            });
        }

        (local_preds, cross_preds)
    }

    /// Push every predecessor the walk has not seen, carrying the context each
    /// edge implies.
    fn enqueue_predecessors(
        &mut self,
        step: &WalkStep<'_>,
        cross_preds: &[(usize, NodeKey)],
        local_preds: Vec<NodeKey>,
        state: &mut ExploreState,
        queue: &mut VecDeque<WalkNode>,
    ) {
        let WalkStep {
            cf,
            key,
            ctx,
            enter_call,
            field_demand,
            ..
        } = *step;
        for &(pf, pk) in cross_preds {
            // Context transition for the k=1 stack:
            //  - landing on an ActualArg unwinds out of a callee → pop;
            //  - leaving an ActualRet steps into a callee → push its site;
            //  - any other cross jump (heap edges) has no call/return
            //    shape → reset to the empty context (k=0 where it lands,
            //    sound: never wrong-strict).
            let pred_is_actual_arg = self.prog.functions[pf]
                .svfg
                .node(&pk)
                .is_some_and(|n| matches!(n.kind, NodeKind::ActualArg { .. }));
            let new_ctx = if pred_is_actual_arg {
                self.ctx_exit(ctx)
            } else if let Some((caller_fn, site)) = enter_call {
                self.ctx_enter(ctx, caller_fn, site)
            } else {
                0
            };
            if state
                .visited
                .insert((pf, pk, pk.block, field_demand, new_ctx))
            {
                state.seen_nodes.insert((pf, pk));
                if self.capture_paths {
                    self.record_parent((pf, pk), (cf, key));
                }
                queue.push_back((pf, pk, pk.block, field_demand, new_ctx));
            }
        }
        for pk in local_preds {
            if state.visited.insert((cf, pk, key.block, field_demand, ctx)) {
                state.seen_nodes.insert((cf, pk));
                if self.capture_paths {
                    self.record_parent((cf, pk), (cf, key));
                }
                queue.push_back((cf, pk, key.block, field_demand, ctx));
            }
        }
    }
}

impl<'a> BackwardTaintEngine<'a> {
    /// Describe an unresolvable dead-end node (see [`Self::node_is_unresolvable`])
    /// as a [`CutSite`]: what the engine could not see, and where.
    pub(super) fn cut_site(&self, fi: usize, key: &NodeKey) -> Option<CutSite> {
        let ir = self.prog.functions[fi].ir;
        let span = ir.var_metadata.get(&key.var).and_then(|m| m.byte_range);
        let named = |kind: &'static str, detail: String| CutSite {
            kind,
            function: ir.name.clone(),
            detail,
            span,
        };
        let node = self.prog.functions[fi].svfg.node(key)?;
        if node.kind == crate::graph::svfg::NodeKind::FormalParam {
            let name = ir
                .var_metadata
                .get(&key.var)
                .and_then(|m| m.source_name.clone())
                .unwrap_or_default();
            return Some(named("param-no-caller", name));
        }
        let idx = key.instr_idx?;
        let ins = ir.blocks.get(&key.block)?.instructions.get(idx)?;
        Some(match ins {
            Instruction::CallStatic { func, .. } => named("external-call", func.clone()),
            Instruction::CallVirtual { method, .. } => named("external-call", method.clone()),
            Instruction::CallPointer { .. } => named("indirect-call", String::new()),
            Instruction::LoadGlobal { name, .. } => named("global", name.clone()),
            Instruction::Dereference { .. } => named("pointer-deref", String::new()),
            _ => return None,
        })
    }

    /// A node is unresolvable if we cannot prove its value clean within the
    /// analysed program:
    ///   * a `FormalParam` with no cross-edge feeders (external entry point,
    ///     or called only with literal args), or
    ///   * a def produced by an environment-read instruction (`LoadGlobal`,
    ///     `Dereference`, `CallPointer`), its value comes from outside the
    ///     local value-flow graph.
    pub(super) fn node_is_unresolvable(&self, fi: usize, key: &NodeKey) -> bool {
        let fe = &self.prog.functions[fi];
        let Some(node) = fe.svfg.node(key) else {
            return false;
        };
        if node.kind == crate::graph::svfg::NodeKind::FormalParam {
            // Unresolvable iff there are no cross edges feeding it.
            return !self.reverse_cross.contains_key(&(fi, *key));
        }
        // A call result with no cross-edge feeding it is a call to an
        // unknown/external callee (library API): its semantics are unknown,
        // so "clean" would be unsound, classify as unknown. Resolved
        // internal callees have ActualRet→FormalRet reverse edges and never
        // reach this dead-end classification.
        if matches!(node.kind, crate::graph::svfg::NodeKind::ActualRet { .. }) {
            dbg_trace!(
                DebugFlags::get().unres,
                "[unresolvable] ActualRet key={key:?} has_cross={} block={:?} idx={:?}",
                self.reverse_cross.contains_key(&(fi, *key)),
                key.block,
                key.instr_idx
            );
            let NodeKey {
                block,
                instr_idx: Some(idx),
                var,
            } = *key
            else {
                return false;
            };
            if let Some(b) = fe.ir.blocks.get(&block)
                && idx < b.instructions.len()
                && matches!(
                    &b.instructions[idx],
                    Instruction::CallStatic { dest: Some(d), .. }
                        | Instruction::CallVirtual { dest: Some(d), .. }
                        | Instruction::CallPointer { dest: Some(d), .. }
                    if *d == var
                )
            {
                return true;
            }
            return false;
        }
        if node.kind == crate::graph::svfg::NodeKind::InstrDef {
            let Some(instr) = key.instruction(fe.ir) else {
                return false;
            };
            if matches!(
                instr,
                Instruction::LoadGlobal { .. }
                    | Instruction::Dereference { .. }
                    | Instruction::CallPointer { .. }
            ) {
                return true;
            }
            // A call result with no cross-edge feeding it is a call to an
            // unknown/external callee (library API): its semantics are
            // unknown, so "clean" would be unsound, classify as unknown.
            // Resolved internal callees have ActualRet→FormalRet reverse
            // edges and never reach this dead-end classification.
            if matches!(node.kind, crate::graph::svfg::NodeKind::ActualRet { .. })
                && matches!(
                    instr,
                    Instruction::CallStatic { dest: Some(d), .. }
                        | Instruction::CallVirtual { dest: Some(d), .. }
                    if *d == key.var
                )
            {
                return true;
            }
        }
        false
    }
}
