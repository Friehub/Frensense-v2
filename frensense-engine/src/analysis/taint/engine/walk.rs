// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

use std::collections::VecDeque;

use crate::analysis::forward::{is_sanitizer_use_with_facts, is_source, sink_alert_with_facts};
use crate::dbg_trace;
use crate::debug_flags::DebugFlags;
use crate::graph::svfg::NodeKind;

// ---------------------------------------------------------------------------
// Constant evaluation + branch feasibility
// ---------------------------------------------------------------------------

/// Constant-fold a variable's definition chain to an integer value.
///
/// Handles the literal-arithmetic shapes that decide ternary/if branches:
/// `Assign` from an `IntLiteral`, and `BinaryOp` arithmetic over literal
/// operands (`7 * 18 + num > 200` folds bottom-up). Bounded hops keep
/// pathological chains cheap. `None` = not a constant.
fn const_eval(ir: &FunctionIR, var: VarId) -> Option<i64> {
    fn operand_const(ir: &FunctionIR, op: &Operand, hops: u8) -> Option<i64> {
        match op {
            Operand::IntLiteral(i) => Some(*i),
            Operand::Var(v) => const_eval_hops(ir, *v, hops),
            _ => None,
        }
    }
    fn const_eval_hops(ir: &FunctionIR, var: VarId, hops: u8) -> Option<i64> {
        if hops == 0 {
            return None;
        }
        let def = defs_of_var(ir, var)?;
        match def {
            Instruction::Assign {
                src: Operand::IntLiteral(i),
                ..
            } => Some(*i),
            Instruction::BinaryOp { op, lhs, rhs, .. } => {
                let l = operand_const(ir, lhs, hops - 1)?;
                let r = operand_const(ir, rhs, hops - 1)?;
                // The lowering maps `+` to op "concat" (the generic
                // additive fold); arithmetic on IntLiterals is still
                // integer addition there.
                Some(match op.as_str() {
                    "concat" | "+" => l.wrapping_add(r),
                    "-" => l.wrapping_sub(r),
                    "*" => l.wrapping_mul(r),
                    "/" => {
                        if r == 0 {
                            return None;
                        }
                        l.wrapping_div(r)
                    }
                    "%" => {
                        if r == 0 {
                            return None;
                        }
                        l.wrapping_rem(r)
                    }
                    _ => return None,
                })
            }
            _ => None,
        }
    }
    const_eval_hops(ir, var, 8)
}

/// Find the single instruction defining `var` (bounded scan).
fn defs_of_var(ir: &FunctionIR, var: VarId) -> Option<&Instruction> {
    for b in ir.blocks.values() {
        for i in &b.instructions {
            let dests: Vec<VarId> = match i {
                Instruction::Assign { dest, .. }
                | Instruction::BinaryOp { dest, .. }
                | Instruction::UnaryOp { dest, .. }
                | Instruction::LoadField { dest, .. }
                | Instruction::LoadElement { dest, .. }
                | Instruction::LoadGlobal { dest, .. }
                | Instruction::Cast { dest, .. } => vec![*dest],
                Instruction::CallStatic { dest: Some(d), .. }
                | Instruction::CallVirtual { dest: Some(d), .. } => vec![*d],
                _ => Vec::new(),
            };
            if dests.contains(&var) {
                return Some(i);
            }
        }
    }
    None
}

/// Evaluate a comparison over two constant operands.
fn compare_consts(op: &str, l: i64, r: i64) -> Option<bool> {
    Some(match op {
        ">" => l > r,
        "<" => l < r,
        ">=" => l >= r,
        "<=" => l <= r,
        "==" => l == r,
        "!=" => l != r,
        _ => return None,
    })
}

/// For the Phi `dest_var` in `merge_block`, return the incoming edges whose
/// arm block is unreachable because the branch condition is a constant
/// comparison with a decided outcome. Empty = nothing prunable.
fn phi_infeasible_incoming(
    ir: &FunctionIR,
    merge_block: BlockId,
    dest_var: VarId,
) -> Vec<(BlockId, VarId)> {
    let block = match ir.blocks.get(&merge_block) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let Some(phi) = block.phis.iter().find(|p| p.dest == dest_var) else {
        return Vec::new();
    };
    // An incoming (pred_block, var) is infeasible when pred_block is
    // reached by a Branch whose condition is a decided constant and the
    // edge taken is the OTHER side.
    let mut out = Vec::new();
    for &(pred_block, inc_var) in &phi.incoming {
        // Find the branch that targets pred_block.
        for b in ir.blocks.values() {
            let (cond, true_block, false_block) = match &b.terminator {
                Terminator::Branch {
                    cond: Operand::Var(c),
                    true_block,
                    false_block,
                } => (*c, *true_block, *false_block),
                _ => continue,
            };
            if true_block != pred_block && false_block != pred_block {
                continue;
            }
            let taken = match defs_of_var(ir, cond) {
                Some(Instruction::BinaryOp { op, lhs, rhs, .. }) => {
                    let l = match lhs {
                        Operand::IntLiteral(i) => Some(*i),
                        Operand::Var(v) => const_eval(ir, *v),
                        _ => None,
                    };
                    let r = match rhs {
                        Operand::IntLiteral(i) => Some(*i),
                        Operand::Var(v) => const_eval(ir, *v),
                        _ => None,
                    };
                    match (l, r) {
                        (Some(l), Some(r)) => compare_consts(op, l, r),
                        _ => None,
                    }
                }
                Some(Instruction::Assign {
                    src: Operand::IntLiteral(i),
                    ..
                }) => Some(*i != 0),
                _ => None,
            };
            let Some(taken) = taken else {
                continue;
            };
            let feasible_block = if taken { true_block } else { false_block };
            if feasible_block != pred_block {
                out.push((pred_block, inc_var));
            }
            break;
        }
    }
    out
}

impl<'a> BackwardTaintEngine<'a> {
    /// Explore one call site if it is a configured sink.
    pub(super) fn explore_call_site(
        &mut self,
        fi: usize,
        block: BlockId,
        idx: usize,
        instr: &Instruction,
    ) {
        let (name, receiver, args, call_dest): (
            &str,
            Option<&Operand>,
            &Vec<Operand>,
            Option<VarId>,
        ) = match instr {
            Instruction::CallStatic {
                func, args, dest, ..
            } => (func, None, args, dest.as_ref().copied()),
            Instruction::CallVirtual {
                method,
                receiver,
                args,
                dest,
                ..
            } => (method, Some(receiver), args, dest.as_ref().copied()),
            _ => return,
        };
        let ir = self.prog.functions[fi].ir;
        // Receiver-aware sink match: verb-named sinks (get/post/...) from
        // dotted client entries only fire when the receiver root is a known
        // client, `map.get(t)` is a Map accessor, `got.get(t)` is SSRF.
        let receiver_root = match receiver {
            Some(Operand::Var(r)) => FactTable::receiver_root(ir, *r),
            _ => None,
        };
        if !self.facts.is_sink_call(name, receiver_root.as_deref()) {
            return;
        }
        // Receiver-aware role: `kv.put(t)` resolves Storage (dotted
        // KVNamespace.put) while `axios.put(t)` stays Ssrf, the
        // receiver root is the disambiguator, mirroring verb-sink
        // matching above.
        let role = self
            .facts
            .role_for_call(name, receiver_root.as_deref())
            .unwrap_or(crate::analysis::taint::role::SinkRole::Other);
        // Engine purity: every fact-declared sink is explored and reported
        // when tainted data reaches it, regardless of role. Severity policy
        // (Response/Validation rank at `info`) is lang-declared ranking
        // applied when findings become advisories - it must never gate the
        // analysis itself, or no bundle knowledge can ever unblock a sink
        // the built-in tables happen to rank low.

        // Collect (slot, var, arg-node) triplets. For virtual calls the
        // receiver is slot usize::MAX (matching the forward engine's arg_slots convention).
        let mut triplets: Vec<(usize, VarId, NodeKey)> = Vec::new();
        if let Some(Operand::Var(r)) = receiver {
            triplets.push((usize::MAX, *r, NodeKey::instr(block, idx, *r)));
        }
        for (slot, a) in args.iter().enumerate() {
            if let Operand::Var(v) = a {
                triplets.push((slot, *v, NodeKey::instr(block, idx, *v)));
            }
        }
        if triplets.is_empty() {
            return;
        }

        self.stats.sink_args_explored += triplets.len();

        for (arg_slot, var, arg_node) in triplets {
            let Some(alert_info) = sink_alert_with_facts(ir, self.config, &self.facts, &arg_node)
            else {
                continue;
            };
            let finding_class = alert_info.class;
            let mut state = ExploreState::default();
            state.seen_nodes.insert((fi, arg_node));
            self.current_parents.clear();
            self.explore_from(fi, arg_node, &mut state);

            let verdict = if state.saw_source {
                BackwardVerdict::Vulnerable
            } else if state.saw_unknown {
                BackwardVerdict::Unknown
            } else if state.saw_sanitized_root_only {
                BackwardVerdict::Sanitized
            } else {
                BackwardVerdict::Clean
            };

            // Bookkeeping for stats.
            self.stats.nodes_visited += state.seen_nodes.len();
            let mut fns: FxHashSet<usize> = FxHashSet::default();
            for (f, _) in state.seen_nodes.iter() {
                fns.insert(*f);
            }
            self.stats.functions_visited += fns.len();

            match verdict {
                BackwardVerdict::Vulnerable => self.stats.vulnerable += 1,
                BackwardVerdict::Sanitized => self.stats.sanitized += 1,
                BackwardVerdict::Unknown => self.stats.unknown += 1,
                BackwardVerdict::Clean => self.stats.clean += 1,
            }

            let alert = if verdict == BackwardVerdict::Vulnerable {
                Some(alert_info)
            } else {
                None
            };

            // Reconstruct the source→sink chain for vulnerable findings.
            let path = if verdict == BackwardVerdict::Vulnerable && self.capture_paths {
                self.reconstruct_path(state.source_node, state.source_desc.clone())
            } else {
                TaintPath::default()
            };

            self.findings.push(SinkFinding {
                function: ir.name.clone(),
                sink: name.to_string(),
                arg_slot,
                alert,
                verdict,
                finding_class,
                role,
                source_desc: state.source_desc.clone(),
                path,
                // Span of the SINK CALL itself, not the tainted operand's
                // definition: reports must point at the line the user fixes.
                // (Reporting the operand's def site put `search.ts` SQLi at
                // line 18 instead of the vulnerable `query(...)` on line 21.)
                sink_span: call_dest
                    .and_then(|d| ir.var_metadata.get(&d))
                    .and_then(|m| m.byte_range)
                    .or_else(|| ir.var_metadata.get(&var).and_then(|m| m.byte_range)),
            });
            let _ = var;
        }
    }

    /// Does the root argument's own definition read one specific
    /// field/element? Such walks carry *field demand*: the value they seek
    /// can only come from field-matching stores, never from the
    /// whole-container fill edges of an allocation.
    fn root_reads_field(&self, fi: usize, root: &NodeKey) -> bool {
        let ir = self.prog.functions[fi].ir;
        for b in ir.blocks.values() {
            for phi in &b.phis {
                if phi.dest == root.var {
                    return false;
                }
            }
            for ins in &b.instructions {
                if Self::instr_defines(ins, root.var) {
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
    fn def_is_allocation(&self, fi: usize, cur: &NodeKey) -> bool {
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

    /// Does this instruction define `var` (value destinations only)?
    fn instr_defines(instr: &Instruction, var: VarId) -> bool {
        let dest = match instr {
            Instruction::Assign { dest, .. }
            | Instruction::LoadField { dest, .. }
            | Instruction::LoadElement { dest, .. }
            | Instruction::LoadGlobal { dest, .. }
            | Instruction::AddressOf { dest, .. }
            | Instruction::Dereference { dest, .. }
            | Instruction::Cast { dest, .. }
            | Instruction::ExtractValue { dest, .. }
            | Instruction::BinaryOp { dest, .. }
            | Instruction::UnaryOp { dest, .. }
            | Instruction::Allocate { dest, .. }
            | Instruction::Await { dest, .. } => Some(*dest),
            Instruction::CallStatic { dest, .. }
            | Instruction::CallVirtual { dest, .. }
            | Instruction::CallPointer { dest, .. }
            | Instruction::Yield { dest, .. } => *dest,
            _ => None,
        };
        dest == Some(var)
    }

    /// Backward BFS from `root` within one root's exploration state.
    fn explore_from(&mut self, fi: usize, root: NodeKey, state: &mut ExploreState) {
        // Field demand at the root: the sink argument's own definition reads
        // one specific field/element, so whole-container fill edges stay off
        // limits for this whole walk (see the allocation stop below).
        let root_field = self.root_reads_field(fi, &root);
        let root_ctx: u32 = 0;
        state
            .visited
            .insert((fi, root, root.block, root_field, root_ctx));
        let mut queue: VecDeque<(usize, NodeKey, BlockId, bool, u32)> = VecDeque::new();
        queue.push_back((fi, root, root.block, root_field, root_ctx));

        let dbg = DebugFlags::get();
        while let Some((cf, cur, use_block, field_demand, ctx)) = queue.pop_front() {
            // Classify `cur` once for the k=1 transitions below: formal
            // params filter their cross preds by the entry call site; a call
            // destination (ActualRet) pushes its site when the walk steps
            // into the callee.
            let (is_formal_param, enter_call) =
                match self.prog.functions[cf].svfg.node(&cur).map(|n| &n.kind) {
                    Some(NodeKind::FormalParam) => (true, None),
                    Some(NodeKind::ActualRet { call_site }) => (false, Some((cf, *call_site))),
                    _ => (false, None),
                };
            dbg_trace!(
                dbg.walk,
                "[walk] cf={cf} key={cur:?} kind={:?}",
                self.prog.functions[cf]
                    .svfg
                    .node(&cur)
                    .map(|n| format!("{:?}", n.kind))
                    .unwrap_or_else(|| "NONE".into())
            );
            let ir = self.prog.functions[cf].ir;

            // Stop: guard check. If this node's variable is checked by a
            // guard-style call (`.test(x)` / `includes(x)`) whose branch
            // dominates the block where the value is (re)used, the value was
            // validated on every path reaching here, sanitized (task 8.3
            // guard map). Pure value-flow cannot see this: the guard is a
            // sibling use, not a link in the chain.
            if let Some(gm) = self.guard_maps.get(&cf)
                && (gm.is_guarded(cur.var, use_block)
                    || (cf == fi && gm.is_guarded(cur.var, root.block)))
            {
                state.saw_sanitized_root_only = true;
                continue;
            }

            // Stop: source reached, vulnerable path confirmed.
            if is_source(ir, self.config, &cur) {
                state.saw_source = true;
                if state.source_node.is_none() {
                    state.source_node = Some((cf, cur));
                    state.source_desc = source_description(ir, self.config, &cur);
                }
                continue;
            }

            // Stop: provably attacker-independent value (constant, string
            // literal, boolean, or bounded integer range from the
            // per-function value lattice). Every non-`Top` lattice value
            // derives from literals, literal arithmetic, or branch
            // sharpening - no source payload can be hiding behind this
            // node - so the branch is cut as clean (unrealizable-path
            // elimination) instead of exploring its predecessors, which may
            // include over-approximated edges. Gated on fixpoint
            // convergence: a truncated fixpoint may hold
            // narrower-than-true values, and pruning on those could drop a
            // real flow.
            let provably_independent = self
                .value_info_for(cf)
                .is_some_and(|info| info.converged && info.values.contains_key(&cur.var));
            if provably_independent {
                continue;
            }

            // Stop: sanitizer use, this branch is clean. Fact-table aware:
            // includes learned methods like .replace()/.test() guards.
            if is_sanitizer_use_with_facts(ir, self.config, &self.facts, &cur) {
                state.saw_sanitized_root_only = true;
                continue;
            }

            // Stop: a field-demand walk that reached a container's allocation.
            // The requested field's value can only arrive through
            // field-matching store edges, entered directly at the load's
            // destination (same-function Pass 3, cross-function heap edges).
            // Following the whole-container fill edges here would union every
            // stored property - `sink(p.other)` must not see the store of
            // `p.data` in the caller just because both share the container.
            if field_demand && self.def_is_allocation(cf, &cur) {
                continue;
            }

            // Local predecessors (optionally honouring suppression).
            let mut local_preds: Vec<NodeKey> = if self.honour_suppression {
                self.prog.local_predecessors(cf, &cur)
            } else {
                match self.prog.functions[cf].svfg.node(&cur) {
                    Some(n) => n.predecessors(),
                    None => Vec::new(),
                }
            };

            // Branch feasibility at phis: a Phi merges values from sibling
            // arms; when the branch condition is a constant comparison, the
            // infeasible arm never executes and its definition must not feed
            // the merge (`bar = const if 7*18+106 > 200 else param` - the
            // tainted else arm is dead). Filter phi predecessors here rather
            // than in the SVFG: feasibility is a walk-time question and the
            // graph stays a pure value-flow structure.
            let is_phi = self.prog.functions[cf]
                .svfg
                .node(&cur)
                .is_some_and(|n| n.kind == NodeKind::Phi);
            if is_phi {
                let infeasible = phi_infeasible_incoming(ir, cur.block, cur.var);
                if !infeasible.is_empty() {
                    local_preds.retain(|pk| {
                        // Post-SSA each incoming var is defined in its arm
                        // block; the def node key carries that block.
                        !infeasible
                            .iter()
                            .any(|(blk, var)| *blk == pk.block && *var == pk.var)
                    });
                }
            }

            // Cross predecessors (reverse index): who feeds this node from
            // another function? For a FormalParam that means actual-args at
            // caller call sites; for an ActualRet that means the callee's
            // FormalRet nodes.
            let mut cross_preds: Vec<(usize, NodeKey)> = self
                .reverse_cross
                .get(&(cf, cur))
                .cloned()
                .unwrap_or_default();

            // k=1 call-site context (phase 5): a formal parameter's value
            // arrived through ONE invocation - the call site the walk entered
            // this function by. Only that site's actual arguments explain it;
            // sibling callers' args are a different invocation entirely.
            // Empty context (root function, heap-edge entry, cap collapse):
            // no filter - the sound k=0 over-approximation.
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

            if local_preds.is_empty() && cross_preds.is_empty() {
                dbg_trace!(
                    dbg.deadend,
                    "[deadend] cf={cf} key={cur:?} kind={:?}",
                    self.prog.functions[cf]
                        .svfg
                        .node(&cur)
                        .map(|n| format!("{:?}", n.kind))
                        .unwrap_or_else(|| "NONE".into())
                );
                // Dead end. Classify: unresolvable roots (formal params never
                // fed by an analysed call site, or environment-defined values
                // like LoadGlobal / Dereference / CallPointer) are "unknown",
                // we can't prove them clean. Everything else (literals,
                // allocations) is a genuinely clean root.
                if self.node_is_unresolvable(cf, &cur) {
                    state.saw_unknown = true;
                }
                // Otherwise: clean root, stop.
                continue;
            }

            for (pf, pk) in cross_preds {
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
                        self.current_parents.insert((pf, pk), (cf, cur));
                    }
                    queue.push_back((pf, pk, pk.block, field_demand, new_ctx));
                }
            }
            for pk in local_preds {
                if state.visited.insert((cf, pk, cur.block, field_demand, ctx)) {
                    state.seen_nodes.insert((cf, pk));
                    if self.capture_paths {
                        self.current_parents.insert((cf, pk), (cf, cur));
                    }
                    queue.push_back((cf, pk, cur.block, field_demand, ctx));
                }
            }
        }
    }

    /// A node is unresolvable if we cannot prove its value clean within the
    /// analysed program:
    ///   * a `FormalParam` with no cross-edge feeders (external entry point,
    ///     or called only with literal args), or
    ///   * a def produced by an environment-read instruction (`LoadGlobal`,
    ///     `Dereference`, `CallPointer`), its value comes from outside the
    ///     local value-flow graph.
    fn node_is_unresolvable(&self, fi: usize, key: &NodeKey) -> bool {
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
            let NodeKey {
                block,
                instr_idx: Some(idx),
                ..
            } = *key
            else {
                return false;
            };
            let Some(b) = fe.ir.blocks.get(&block) else {
                return false;
            };
            if idx >= b.instructions.len() {
                return false;
            }
            if matches!(
                &b.instructions[idx],
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
                    &b.instructions[idx],
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
