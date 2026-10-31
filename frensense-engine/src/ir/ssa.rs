// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Phase 2: Static Single Assignment (SSA) Construction
//!
//! This module converts our "unstructured" FunctionIR into strict SSA form.
//! It seamlessly versions standard variables AND Memory States to produce
//! a perfectly flow-sensitive graph.

use crate::ir::function::*;
use rustc_hash::{FxHashMap, FxHashSet};

/// Default per-function work budget for SSA construction, in abstract work
/// units (dominance-fixer block visits, frontier-walk steps, phi worklist
/// pops). One unit is a constant amount of work, so the budget bounds the
/// whole phase for a single function.
///
/// Nothing legitimate reaches it: a 50 000-instruction function spends
/// ~50 000 units. It exists because the analysis used to be UNBOUNDED - a
/// generated parser with hundreds of sequential `if` branches (quadratic
/// block count) spent 12 s in here at 400 branches and never finished at
/// 3000, with no message. On expiry the IR is kept in its raw,
/// flow-insensitive form (a sound over-approximation) and flagged
/// `analysis_incomplete`, which the scanner reports instead of hanging or
/// silently weakening the result.
pub const DEFAULT_SSA_BUDGET: u64 = 5_000_000;

pub struct SSABuilder {
    ir: FunctionIR,
    /// Phi rename bookkeeping: `new_dest → original variable`. Filled while
    /// renaming a block's phis; consulted when predecessors fill
    /// `incoming` so the stack lookup uses the ORIGINAL variable even after
    /// the phi's dest has been renamed (the successor-fill for a later
    /// predecessor must find the same stack the rename pushed onto).
    phi_origins: FxHashMap<VarId, VarId>,
    /// Work budget for this build (see [`DEFAULT_SSA_BUDGET`]).
    budget: u64,
    /// Units spent so far.
    used: u64,
    /// Budget exhausted: stop before starting another phase and hand back
    /// the unversioned IR, flagged as incomplete.
    degraded: bool,
}

impl SSABuilder {
    pub fn new(ir: FunctionIR) -> Self {
        Self {
            ir,
            phi_origins: FxHashMap::default(),
            budget: DEFAULT_SSA_BUDGET,
            used: 0,
            degraded: false,
        }
    }

    /// Override the work budget. Tests use a tiny budget to exercise the
    /// degraded path deterministically.
    #[must_use]
    pub fn with_budget(mut self, budget: u64) -> Self {
        self.budget = budget;
        self
    }

    /// Work units consumed by the last [`Self::build`] attempt.
    #[must_use]
    pub fn work_used(&self) -> u64 {
        self.used
    }

    /// Charge `units` against this function's budget.
    fn charge(&mut self, units: u64) {
        self.used = self.used.saturating_add(units);
        if self.used >= self.budget {
            self.degraded = true;
        }
    }

    pub fn build(mut self) -> FunctionIR {
        let idoms = self.compute_immediate_dominators();
        if self.degraded {
            return self.finish_degraded();
        }
        let df = self.compute_dominance_frontiers(&idoms);
        if self.degraded {
            return self.finish_degraded();
        }
        if !self.place_phi_nodes(&df) {
            return self.finish_degraded();
        }
        self.rename_variables(&idoms);

        self.ir
    }

    /// Budget exhausted: hand back the IR WITHOUT phi placement or variable
    /// renaming (nothing of either phase survives - phi placement undoes its
    /// pushes on failure) and flag it. The raw form is flow-insensitive:
    /// every use sees every def of the same name, which can add spurious
    /// flows but never loses a real one, so degrading stays in the
    /// over-approximating direction the engine already commits to.
    fn finish_degraded(mut self) -> FunctionIR {
        self.ir.analysis_incomplete = true;
        self.ir
    }

    /// Immediate dominators, Cooper-Harvey-Kennedy ("A Simple, Fast
    /// Dominance Algorithm", 2001).
    ///
    /// The previous implementation kept a full dominator SET per block and
    /// re-intersected every set from scratch in `while changed` walking
    /// blocks in hash-map order, then searched each block's strict
    /// dominators for the immediate one (another O(B²) of set building).
    /// Both loops are cubic on the one CFG shape real generated code has: a
    /// long chain of blocks, one per sequential `if` in a generated
    /// parser/validator. Measured: 400 branches spent 12 s in SSA alone and
    /// 3000 branches never finished, with no message.
    ///
    /// This version keeps ONE idom per block, visits blocks in reverse
    /// postorder (a structured CFG converges in a single pass) and
    /// intersects by climbing the partial dominator tree guided by
    /// postorder numbers.
    ///
    /// Unreachable blocks (lowering legitimately leaves dead arms behind)
    /// never enter the postorder, so they receive no idom - exactly the old
    /// contract, and the reason an ill-defined dominator set can no longer
    /// pick a cycle that spun the frontier walk forever.
    fn compute_immediate_dominators(&mut self) -> FxHashMap<BlockId, BlockId> {
        let entry = self.ir.entry_block;
        if !self.ir.blocks.contains_key(&entry) {
            return FxHashMap::default();
        }

        // 1. Iterative DFS postorder from the entry: an explicit stack,
        //    because a chain of thousands of blocks must not recurse.
        let mut postorder: Vec<BlockId> = Vec::new();
        let mut seen: FxHashSet<BlockId> = FxHashSet::default();
        let mut stack: Vec<(BlockId, usize)> = vec![(entry, 0)];
        seen.insert(entry);
        while let Some((b, next)) = stack.pop() {
            let block = &self.ir.blocks[&b];
            if next < block.successors.len() {
                stack.push((b, next + 1));
                let s = block.successors[next];
                if self.ir.blocks.contains_key(&s) && seen.insert(s) {
                    stack.push((s, 0));
                }
            } else {
                postorder.push(b);
            }
        }
        self.charge(postorder.len() as u64);

        // 2. Postorder numbers. A dominator finishes DFS after its
        //    descendants, so it carries the HIGHER number (entry the
        //    highest of all).
        let mut post_idx: FxHashMap<BlockId, usize> = FxHashMap::default();
        for (i, &b) in postorder.iter().enumerate() {
            post_idx.insert(b, i);
        }

        // 3. Reverse-postorder fixpoint over single idoms.
        let mut idom: FxHashMap<BlockId, BlockId> = FxHashMap::default();
        idom.insert(entry, entry);
        let mut changed = true;
        while changed && !self.degraded {
            changed = false;
            for &b in postorder.iter().rev() {
                self.charge(1);
                if self.degraded || b == entry {
                    continue;
                }
                let Some(block) = self.ir.blocks.get(&b) else {
                    continue;
                };
                let mut new_idom: Option<BlockId> = None;
                for &p in &block.predecessors {
                    // Unreachable predecessors are not on any path from the
                    // entry and never received an idom; they must not
                    // constrain the intersection.
                    if !idom.contains_key(&p) {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(cur) => Self::intersect_idoms(p, cur, &idom, &post_idx),
                    });
                }
                if let Some(n) = new_idom
                    && idom.get(&b) != Some(&n)
                {
                    idom.insert(b, n);
                    changed = true;
                }
            }
        }

        // Contract preserved: the entry carries no idom of its own, and only
        // reachable blocks appear.
        idom.remove(&entry);
        idom
    }

    /// Climb both partial dominator trees until they meet. The node with the
    /// SMALLER postorder number is the deeper one, and climbing its idom
    /// strictly increases that number, so this terminates.
    fn intersect_idoms(
        mut a: BlockId,
        mut b: BlockId,
        idom: &FxHashMap<BlockId, BlockId>,
        post_idx: &FxHashMap<BlockId, usize>,
    ) -> BlockId {
        while a != b {
            let (ia, ib) = (post_idx[&a], post_idx[&b]);
            if ia < ib {
                a = idom[&a];
            } else {
                b = idom[&b];
            }
        }
        a
    }

    fn compute_dominance_frontiers(
        &mut self,
        idoms: &FxHashMap<BlockId, BlockId>,
    ) -> FxHashMap<BlockId, FxHashSet<BlockId>> {
        let mut df: FxHashMap<BlockId, FxHashSet<BlockId>> = FxHashMap::default();
        for &b_id in self.ir.blocks.keys() {
            df.insert(b_id, FxHashSet::default());
        }

        // Join blocks with their predecessor lists, copied OUT of `self`:
        // the budget is charged below through a `&mut self` method, which
        // cannot run under an active borrow of `self.ir.blocks`.
        let joins: Vec<(BlockId, Vec<BlockId>)> = self
            .ir
            .blocks
            .iter()
            .filter(|(_, blk)| blk.predecessors.len() >= 2)
            .map(|(&id, blk)| (id, blk.predecessors.clone()))
            .collect();

        let entry = self.ir.entry_block;
        for (b_id, preds) in joins {
            for pred in preds {
                let mut runner = pred;
                let mut visited = FxHashSet::default();
                while runner != *idoms.get(&b_id).unwrap_or(&entry) && visited.insert(runner) {
                    self.charge(1);
                    if self.degraded {
                        return df;
                    }
                    match df.get_mut(&runner) {
                        Some(set) => set.insert(b_id),
                        // A predecessor that is not a real block (dangling
                        // CFG edge) has no frontier to contribute to.
                        None => break,
                    };
                    if let Some(&next) = idoms.get(&runner) {
                        runner = next;
                    } else {
                        break;
                    }
                }
            }
        }
        df
    }

    /// Place phi nodes for every variable defined in more than one block.
    ///
    /// Returns `false` when the work budget expired: every phi pushed so far
    /// is popped again, so the caller falls back to the RAW IR instead of a
    /// half-SSA form. A missing phi would leave the merge block's uses
    /// reading only the dominating arm - an under-approximation that loses
    /// flows, the one direction this engine never takes.
    fn place_phi_nodes(&mut self, df: &FxHashMap<BlockId, FxHashSet<BlockId>>) -> bool {
        let mut def_blocks: FxHashMap<VarId, FxHashSet<BlockId>> = FxHashMap::default();

        for (b_id, block) in &self.ir.blocks {
            for instr in &block.instructions {
                for dest in Self::get_instruction_dests(instr) {
                    def_blocks.entry(dest).or_default().insert(*b_id);
                }
            }
        }

        let mut phi_placements: FxHashMap<BlockId, FxHashSet<VarId>> = FxHashMap::default();
        // Every phi this run pushed, in push order: undone in reverse when
        // the budget expires.
        let mut pushed: Vec<(BlockId, VarId)> = Vec::new();
        for (&var, blocks) in &def_blocks {
            let mut worklist: Vec<BlockId> = blocks.iter().copied().collect();
            let mut added_to_worklist = FxHashSet::default();

            while let Some(n) = worklist.pop() {
                self.charge(1);
                if self.degraded {
                    for (b, v) in pushed.into_iter().rev() {
                        if let Some(blk) = self.ir.blocks.get_mut(&b)
                            && blk.phis.last().is_some_and(|p| p.dest == v)
                        {
                            blk.phis.pop();
                        }
                    }
                    return false;
                }
                if let Some(frontiers) = df.get(&n) {
                    for &f in frontiers {
                        let placed = phi_placements.entry(f).or_default();
                        if !placed.contains(&var) {
                            placed.insert(var);
                            self.ir.blocks.get_mut(&f).unwrap().phis.push(Phi {
                                dest: var,
                                incoming: Vec::new(),
                            });
                            pushed.push((f, var));

                            if added_to_worklist.insert(f) {
                                worklist.push(f);
                            }
                        }
                    }
                }
            }
        }
        true
    }

    fn rename_variables(&mut self, idoms: &FxHashMap<BlockId, BlockId>) {
        let mut dom_tree: FxHashMap<BlockId, Vec<BlockId>> = FxHashMap::default();
        for (&node, &idom) in idoms {
            dom_tree.entry(idom).or_default().push(node);
        }

        let mut counts: FxHashMap<VarId, usize> = FxHashMap::default();
        let mut stacks: FxHashMap<VarId, Vec<VarId>> = FxHashMap::default();

        for &param in &self.ir.parameters {
            stacks.entry(param).or_default().push(param);
        }

        stacks
            .entry(self.ir.initial_memory_state)
            .or_default()
            .push(self.ir.initial_memory_state);

        self.rename_block(self.ir.entry_block, &dom_tree, &mut counts, &mut stacks);
    }

    fn rename_block(
        &mut self,
        block_id: BlockId,
        dom_tree: &FxHashMap<BlockId, Vec<BlockId>>,
        counts: &mut FxHashMap<VarId, usize>,
        stacks: &mut FxHashMap<VarId, Vec<VarId>>,
    ) {
        let mut pushed_vars = Vec::new();

        let mut phis = std::mem::take(&mut self.ir.blocks.get_mut(&block_id).unwrap().phis);
        for phi in &mut phis {
            let orig = phi.dest;
            let new_id = self.generate_new_name(orig, counts, stacks);
            self.phi_origins.insert(new_id, orig);
            phi.dest = new_id;
            pushed_vars.push(orig);
        }
        self.ir.blocks.get_mut(&block_id).unwrap().phis = phis;

        let mut instructions =
            std::mem::take(&mut self.ir.blocks.get_mut(&block_id).unwrap().instructions);
        for instr in &mut instructions {
            Self::replace_uses(instr, stacks);
            self.rename_instruction_defs(instr, counts, stacks, &mut pushed_vars);
        }
        self.ir.blocks.get_mut(&block_id).unwrap().instructions = instructions;

        Self::replace_uses_in_terminator(
            &mut self.ir.blocks.get_mut(&block_id).unwrap().terminator,
            stacks,
        );

        let successors = self.ir.blocks.get(&block_id).unwrap().successors.clone();
        for succ_id in successors {
            if let Some(succ) = self.ir.blocks.get_mut(&succ_id) {
                for phi in &mut succ.phis {
                    // Resolve the phi's ORIGINAL variable (pre-rename): if a
                    // dom-tree child already renamed this phi, `phi.dest` is
                    // the new id whose stack is empty. Without the origin
                    // mapping, every predecessor visited after the merge
                    // block's rename silently contributes no incoming edge.
                    let orig = *self.phi_origins.get(&phi.dest).unwrap_or(&phi.dest);
                    if let Some(stack) = stacks.get(&orig)
                        && let Some(&active_var) = stack.last()
                    {
                        phi.incoming.push((block_id, active_var));
                    }
                }
            }
        }

        if let Some(children) = dom_tree.get(&block_id) {
            for &child in children {
                self.rename_block(child, dom_tree, counts, stacks);
            }
        }

        for orig in pushed_vars {
            stacks.get_mut(&orig).unwrap().pop();
        }
    }

    fn generate_new_name(
        &mut self,
        orig: VarId,
        counts: &mut FxHashMap<VarId, usize>,
        stacks: &mut FxHashMap<VarId, Vec<VarId>>,
    ) -> VarId {
        *counts.entry(orig).or_insert(0) += 1;
        let meta = self
            .ir
            .var_metadata
            .get(&orig)
            .cloned()
            .unwrap_or(VarMetadata {
                source_name: None,
                type_name: None,
                byte_range: None,
                is_memory_state: false,
                object_keys: Vec::new(),
                declared: false,
            });
        let new_id = self.ir.new_var(meta);
        stacks.entry(orig).or_default().push(new_id);
        new_id
    }

    fn replace_uses(instr: &mut Instruction, stacks: &FxHashMap<VarId, Vec<VarId>>) {
        let replace_var = |v: &mut VarId| {
            if let Some(stack) = stacks.get(v)
                && let Some(&top) = stack.last()
            {
                *v = top;
            }
        };
        let replace_op = |op: &mut Operand| {
            if let Operand::Var(v) = op {
                replace_var(v);
            }
        };

        match instr {
            Instruction::Assign { src, .. } => replace_op(src),

            Instruction::LoadField { mem_in, base, .. } => {
                replace_var(mem_in);
                replace_var(base);
            }
            Instruction::StoreField {
                mem_in, base, src, ..
            } => {
                replace_var(mem_in);
                replace_var(base);
                replace_op(src);
            }

            Instruction::LoadElement {
                mem_in,
                base,
                index,
                ..
            } => {
                replace_var(mem_in);
                replace_var(base);
                replace_op(index);
            }
            Instruction::StoreElement {
                mem_in,
                base,
                index,
                src,
                ..
            } => {
                replace_var(mem_in);
                replace_var(base);
                replace_op(index);
                replace_op(src);
            }

            Instruction::LoadGlobal { mem_in, .. } => {
                replace_var(mem_in);
            }
            Instruction::StoreGlobal { mem_in, src, .. } => {
                replace_var(mem_in);
                replace_op(src);
            }

            Instruction::Allocate { mem_in, .. } => replace_var(mem_in),
            Instruction::AddressOf { src, .. } => replace_var(src),
            Instruction::Dereference { mem_in, ptr, .. } => {
                replace_var(mem_in);
                replace_op(ptr);
            }

            Instruction::CallStatic { mem_in, args, .. } => {
                replace_var(mem_in);
                args.iter_mut().for_each(replace_op);
            }
            Instruction::CallVirtual {
                mem_in,
                receiver,
                args,
                ..
            } => {
                replace_var(mem_in);
                replace_op(receiver);
                args.iter_mut().for_each(replace_op);
            }
            Instruction::CallPointer {
                mem_in,
                func_ptr,
                args,
                ..
            } => {
                replace_var(mem_in);
                replace_op(func_ptr);
                args.iter_mut().for_each(replace_op);
            }

            Instruction::BinaryOp { lhs, rhs, .. } => {
                replace_op(lhs);
                replace_op(rhs);
            }
            Instruction::UnaryOp { src, .. } => replace_op(src),
            Instruction::Cast { src, .. } => replace_op(src),
            Instruction::ExtractValue { tuple, .. } => replace_op(tuple),

            Instruction::Await {
                mem_in, promise, ..
            } => {
                replace_var(mem_in);
                replace_op(promise);
            }
            Instruction::Yield { mem_in, src, .. } => {
                replace_var(mem_in);
                if let Some(s) = src {
                    replace_op(s);
                }
            }
        }
    }

    fn replace_uses_in_terminator(term: &mut Terminator, stacks: &FxHashMap<VarId, Vec<VarId>>) {
        let replace_op = |op: &mut Operand| {
            if let Operand::Var(v) = op
                && let Some(stack) = stacks.get(v)
                && let Some(&top) = stack.last()
            {
                *v = top;
            }
        };

        match term {
            Terminator::Branch { cond, .. } => replace_op(cond),
            Terminator::Return { src: Some(src) } => replace_op(src),
            Terminator::Throw { src } => replace_op(src),
            Terminator::Switch { cond, cases, .. } => {
                replace_op(cond);
                for (case_op, _) in cases {
                    replace_op(case_op);
                }
            }
            _ => {}
        }
    }

    fn get_instruction_dests(instr: &Instruction) -> Vec<VarId> {
        let mut dests = Vec::new();
        match instr {
            Instruction::Assign { dest, .. }
            | Instruction::LoadField { dest, .. }
            | Instruction::LoadElement { dest, .. }
            | Instruction::LoadGlobal { dest, .. }
            | Instruction::AddressOf { dest, .. }
            | Instruction::Dereference { dest, .. }
            | Instruction::Cast { dest, .. }
            | Instruction::ExtractValue { dest, .. }
            | Instruction::BinaryOp { dest, .. }
            | Instruction::UnaryOp { dest, .. } => dests.push(*dest),

            Instruction::StoreField { mem_out, .. }
            | Instruction::StoreElement { mem_out, .. }
            | Instruction::StoreGlobal { mem_out, .. } => dests.push(*mem_out),

            Instruction::Allocate { dest, mem_out, .. }
            | Instruction::Await { dest, mem_out, .. } => {
                dests.push(*dest);
                dests.push(*mem_out);
            }

            Instruction::CallStatic { dest, mem_out, .. }
            | Instruction::CallVirtual { dest, mem_out, .. }
            | Instruction::CallPointer { dest, mem_out, .. }
            | Instruction::Yield { dest, mem_out, .. } => {
                if let Some(d) = dest {
                    dests.push(*d);
                }
                dests.push(*mem_out);
            }
        }
        dests
    }

    fn rename_instruction_defs(
        &mut self,
        instr: &mut Instruction,
        counts: &mut FxHashMap<VarId, usize>,
        stacks: &mut FxHashMap<VarId, Vec<VarId>>,
        pushed_vars: &mut Vec<VarId>,
    ) {
        let mut process = |dest: &mut VarId| {
            let orig = *dest;
            let new_id = self.generate_new_name(orig, counts, stacks);
            *dest = new_id;
            pushed_vars.push(orig);
        };

        match instr {
            Instruction::Assign { dest, .. }
            | Instruction::LoadField { dest, .. }
            | Instruction::LoadElement { dest, .. }
            | Instruction::LoadGlobal { dest, .. }
            | Instruction::AddressOf { dest, .. }
            | Instruction::Dereference { dest, .. }
            | Instruction::Cast { dest, .. }
            | Instruction::ExtractValue { dest, .. }
            | Instruction::BinaryOp { dest, .. }
            | Instruction::UnaryOp { dest, .. } => process(dest),

            Instruction::StoreField { mem_out, .. }
            | Instruction::StoreElement { mem_out, .. }
            | Instruction::StoreGlobal { mem_out, .. } => process(mem_out),

            Instruction::Allocate { dest, mem_out, .. }
            | Instruction::Await { dest, mem_out, .. } => {
                process(dest);
                process(mem_out);
            }

            Instruction::CallStatic { dest, mem_out, .. }
            | Instruction::CallVirtual { dest, mem_out, .. }
            | Instruction::CallPointer { dest, mem_out, .. }
            | Instruction::Yield { dest, mem_out, .. } => {
                if let Some(d) = dest {
                    process(d);
                }
                process(mem_out);
            }
        }
    }
}
