// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::forward::ProgramSvfg;
use crate::checks::memory_summary::MemorySummaryRegistry;
use crate::graph::svfg::{NodeKey, NodeKind, Svfg};
use crate::ir::function::{BlockId, FunctionIR, Instruction, Operand, VarId};

use super::discovery::{free_of, instr_at};
use super::types::{CrossCtx, Pair, PairCheck, Violation};

/// Backward-walk budget per start site: bounds provenance + discovery work
/// on deep or cyclic value-flow chains (exhaustion = unprovable = silent).
pub const MAX_WALK_NODES: usize = 512;

/// Forward-scan budget inside a callee when looking for parameter frees.
pub const MAX_SCAN_NODES: usize = 256;

pub struct Walker<'a> {
    pub start_fi: usize,
    pub start_ir: &'a FunctionIR,
    pub start_svfg: &'a Svfg,
    pub prog: Option<&'a ProgramSvfg<'a>>,
    pub rev: &'a FxHashMap<(usize, NodeKey), Vec<(usize, NodeKey)>>,
    pub summaries: &'a MemorySummaryRegistry,
    pub violation: Violation,
    /// 1 = in progress (cycle), 2 = done.
    pub state: FxHashMap<(usize, NodeKey), u8>,
    pub prov_memo: FxHashMap<(usize, NodeKey), bool>,
    pub pairs: Vec<Pair>,
    /// `(call, callee) → blocks in that callee containing a free` (for the
    /// all-returns exit check).
    pub cross_frees: FxHashMap<((BlockId, usize), usize), FxHashSet<BlockId>>,
    pub nodes: usize,
}

impl<'a> Walker<'a> {
    pub fn ir_of(&self, fi: usize) -> &'a FunctionIR {
        if fi == self.start_fi {
            self.start_ir
        } else {
            self.prog
                .expect("cross-fn walk requires a program graph")
                .functions[fi]
                .ir
        }
    }

    pub fn svfg_of(&self, fi: usize) -> &'a Svfg {
        if fi == self.start_fi {
            self.start_svfg
        } else {
            &self
                .prog
                .expect("cross-fn walk requires a program graph")
                .functions[fi]
                .svfg
        }
    }

    pub fn is_out_param_fresh(&self, ir: &FunctionIR, var: VarId) -> bool {
        for blk in ir.blocks.values() {
            for instr in &blk.instructions {
                if let Instruction::CallStatic { func, args, .. } = instr {
                    let out_slots = self.summaries.out_params_fresh(func);
                    for &slot in &out_slots {
                        if let Some(Operand::Var(arg_v)) = args.get(slot) {
                            for other_blk in ir.blocks.values() {
                                for check_instr in &other_blk.instructions {
                                    if let Instruction::AddressOf { dest, src } = check_instr
                                        && *dest == *arg_v
                                        && *src == var
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Visit one node: memoised provenance ("every reachable root is a
    /// provable allocation") with candidate collection on first visit.
    pub fn visit_walker(&mut self, fi: usize, key: NodeKey, depth: u8, ctx: CrossCtx) -> bool {
        self.nodes += 1;
        if self.nodes > MAX_WALK_NODES {
            return false;
        }
        match self.state.get(&(fi, key)) {
            Some(&2) => return self.prov_memo.get(&(fi, key)).copied().unwrap_or(false),
            // Cycle through a loop-carried value: optimistic for the AND
            // fixpoint (other roots still veto if unprovable).
            Some(&1) => return true,
            _ => {}
        }
        self.state.insert((fi, key), 1);
        let prov = self.visit_inner(fi, key, depth, ctx);
        self.state.insert((fi, key), 2);
        self.prov_memo.insert((fi, key), prov);
        prov
    }

    fn visit_inner(&mut self, fi: usize, key: NodeKey, depth: u8, ctx: CrossCtx) -> bool {
        let ir = self.ir_of(fi);
        let svfg = self.svfg_of(fi);
        let Some(node) = svfg.node(&key) else {
            return false;
        };
        let collect = depth <= 1;

        // --- Candidate collection at definition nodes -------------------
        let is_def = matches!(
            node.kind,
            NodeKind::InstrDef | NodeKind::Phi | NodeKind::FormalParam | NodeKind::ActualRet { .. }
        );
        if is_def && collect {
            for s in node.successors() {
                if let Some(instr) = instr_at(ir, s.block, s.instr_idx)
                    && free_of(instr, s.var, self.summaries)
                {
                    self.record_free(s.block, s.instr_idx.unwrap_or(0), ctx);
                }
            }
            // Callee-internal frees of a passed argument (only from the
            // start function: cross-function discovery entry point).
            if depth == 0 && fi == self.start_fi {
                for s in node.successors() {
                    let Some(sn) = svfg.node(&s) else { continue };
                    let NodeKind::ActualArg { arg_index, .. } = sn.kind else {
                        continue;
                    };
                    if arg_index == usize::MAX {
                        continue;
                    }
                    let Some(callee_fi) = self.single_callee(fi, &s) else {
                        continue;
                    };
                    let Some(blocks) = self.scan_callee_frees(callee_fi, arg_index) else {
                        continue;
                    };
                    if blocks.is_empty() {
                        continue;
                    }
                    let call = (s.block, s.instr_idx.unwrap_or(0));
                    let group = self.cross_frees.entry((call, callee_fi)).or_default();
                    let mut first = None;
                    for b in &blocks {
                        if group.insert(*b) && first.is_none() {
                            first = Some(*b);
                        }
                    }
                    if let Some(fb) = first {
                        self.pairs.push(Pair {
                            violation: self.violation,
                            check: PairCheck::Callee { call, callee_fi },
                            free_block: fb,
                            free_idx: 0,
                        });
                    }
                }
            }
        }

        // --- Provenance --------------------------------------------------
        match &node.kind {
            NodeKind::FormalParam => {
                let Some(callers) = self.rev.get(&(fi, key)) else {
                    return false;
                };
                if callers.is_empty() {
                    return false;
                }
                if depth == 0 && callers.len() > 1 {
                    return false;
                }
                let mut ok = true;
                for &(cfi, ck) in callers {
                    let call = (ck.block, ck.instr_idx.unwrap_or(0));
                    ok &= self.visit_walker(
                        cfi,
                        ck,
                        depth + 1,
                        CrossCtx::InCaller {
                            call,
                            caller_fi: cfi,
                        },
                    );
                }
                ok
            }
            NodeKind::ActualRet { .. } => {
                if let Some(instr) = instr_at(ir, key.block, key.instr_idx) {
                    match instr {
                        Instruction::CallStatic {
                            func,
                            dest: Some(d),
                            ..
                        } if *d == key.var => {
                            if self.summaries.returns_fresh(func) {
                                return true;
                            }
                        }
                        Instruction::CallVirtual { dest: Some(d), .. }
                        | Instruction::CallPointer { dest: Some(d), .. }
                            if *d == key.var => {}
                        _ => {
                            return self.and_preds(fi, svfg, key, depth, ctx);
                        }
                    }
                }
                let Some(targets) = self.rev.get(&(fi, key)) else {
                    return false;
                };
                if targets.is_empty() {
                    return false;
                }
                let call = (key.block, key.instr_idx.unwrap_or(0));
                let mut ok = true;
                for &(tfi, tk) in targets {
                    ok &= self.visit_walker(
                        tfi,
                        tk,
                        depth + 1,
                        CrossCtx::InCallee {
                            call,
                            callee_fi: tfi,
                        },
                    );
                }
                ok
            }
            NodeKind::InstrDef => {
                if let Some(instr) = instr_at(ir, key.block, key.instr_idx)
                    && matches!(instr, Instruction::Allocate { .. })
                {
                    return true;
                }

                if self.is_out_param_fresh(ir, key.var) {
                    return true;
                }
                self.and_preds(fi, svfg, key, depth, ctx)
            }
            _ => {
                if self.is_out_param_fresh(ir, key.var) {
                    return true;
                }
                self.and_preds(fi, svfg, key, depth, ctx)
            }
        }
    }

    /// Provenance = AND over backward edges (every feeding value must be
    /// provably allocated); a dead end (no preds, unresolvable root) is
    /// unprovable.
    pub fn and_preds(
        &mut self,
        fi: usize,
        svfg: &Svfg,
        key: NodeKey,
        depth: u8,
        ctx: CrossCtx,
    ) -> bool {
        let Some(node) = svfg.node(&key) else {
            return false;
        };
        let preds = node.predecessors();
        if preds.is_empty() {
            return false;
        }
        let mut ok = true;
        for p in preds {
            ok &= self.visit_walker(fi, p, depth, ctx);
        }
        ok
    }

    pub fn single_callee(&self, fi: usize, arg_node: &NodeKey) -> Option<usize> {
        let fe = &self.prog?.functions[fi];
        let (bi, _) = fe.arg_slots.get(arg_node)?;
        let callees = &fe.bindings[*bi].callees;
        if callees.len() == 1 {
            Some(callees[0])
        } else {
            None
        }
    }

    /// Forward scan from a callee's formal parameter: blocks in that callee
    /// that release the parameter. External / unresolved callees yield
    /// `None` (covered at the call site by the summary registry's
    /// deallocator vocabulary when known).
    pub fn scan_callee_frees(
        &self,
        callee_fi: usize,
        param_idx: usize,
    ) -> Option<FxHashSet<BlockId>> {
        let prog = self.prog?;
        let fe = &prog.functions[callee_fi];
        let ir = fe.ir;
        let param_var = *ir.parameters.get(param_idx)?;
        let start = NodeKey::instr(ir.entry_block, usize::MAX - 2 - param_idx, param_var);
        let svfg = &fe.svfg;
        svfg.node(&start)?;
        let mut seen: FxHashSet<NodeKey> = FxHashSet::default();
        let mut queue: std::collections::VecDeque<NodeKey> = std::collections::VecDeque::new();
        let mut blocks: FxHashSet<BlockId> = FxHashSet::default();
        seen.insert(start);
        queue.push_back(start);
        let mut budget = MAX_SCAN_NODES;
        while let Some(n) = queue.pop_front() {
            budget = budget.saturating_sub(1);
            if budget == 0 {
                break;
            }
            if let Some(instr) = instr_at(ir, n.block, n.instr_idx)
                && free_of(instr, n.var, self.summaries)
            {
                blocks.insert(n.block);
            }
            let Some(node) = svfg.node(&n) else {
                continue;
            };
            for s in node.successors() {
                if seen.insert(s) {
                    queue.push_back(s);
                }
            }
        }
        Some(blocks)
    }

    pub fn record_free(&mut self, block: BlockId, idx: usize, ctx: CrossCtx) {
        let violation = self.violation;
        match ctx {
            CrossCtx::None => self.pairs.push(Pair {
                violation,
                check: PairCheck::Local,
                free_block: block,
                free_idx: idx,
            }),
            CrossCtx::InCallee { call, callee_fi } => {
                self.cross_frees
                    .entry((call, callee_fi))
                    .or_default()
                    .insert(block);
                self.pairs.push(Pair {
                    violation,
                    check: PairCheck::Callee { call, callee_fi },
                    free_block: block,
                    free_idx: idx,
                });
            }
            CrossCtx::InCaller { call, caller_fi } => self.pairs.push(Pair {
                violation,
                check: PairCheck::Caller { call, caller_fi },
                free_block: block,
                free_idx: idx,
            }),
        }
    }
}
