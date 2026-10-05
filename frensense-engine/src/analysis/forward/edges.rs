// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

impl<'a> ProgramSvfg<'a> {
    // -----------------------------------------------------------------------
    // Step 4: explicit interprocedural edges
    // -----------------------------------------------------------------------

    pub(super) fn install_cross_edges(&mut self, facts: &FactTable) {
        for fi in 0..self.functions.len() {
            let bindings = self.functions[fi].bindings.clone();
            for b in &bindings {
                for &gi in &b.callees {
                    let ge = &self.functions[gi];

                    let callee_has_recv = ge.ir.parameters.first().is_some_and(|&p| {
                        ge.ir
                            .var_metadata
                            .get(&p)
                            .and_then(|m| m.source_name.as_deref())
                            .is_some_and(|name| facts.is_receiver_param(name))
                    });

                    // Receiver passing: only if callee has a formal receiver parameter.
                    if callee_has_recv
                        && let Some(r_key) = b.receiver
                        && let Some(&param_var) = ge.ir.parameters.first()
                        && let Some(&param_key) = ge.def_site.get(&param_var)
                    {
                        self.cross_edges
                            .entry((fi, r_key))
                            .or_default()
                            .push((gi, param_key));
                    }

                    // Parameter passing: ActualArg(use node) → FormalParam(slot).
                    let slot_offset = if callee_has_recv { 1 } else { 0 };
                    for (arg_key, slot) in &b.args {
                        let target_slot = *slot + slot_offset;
                        if let Some(&param_var) = ge.ir.parameters.get(target_slot)
                            && let Some(&param_key) = ge.def_site.get(&param_var)
                        {
                            self.cross_edges
                                .entry((fi, *arg_key))
                                .or_default()
                                .push((gi, param_key));
                        }
                    }

                    // Return passing: every FormalRet node of the callee feeds the
                    // caller's ActualRet def node. Keyed by the CALLEE (the from-node
                    // lives there) so the map always stores edges in value-flow
                    // direction: FormalRet → ActualRet.
                    if let Some(ret) = b.ret_node {
                        let mut formal_rets: Vec<NodeKey> = ge
                            .svfg
                            .nodes
                            .values()
                            .filter(|n| n.kind == NodeKind::FormalRet)
                            .map(|n| n.key)
                            .collect();
                        formal_rets.sort_by_key(|k| (k.block.0, k.instr_idx, k.var.0));
                        for fr in formal_rets {
                            self.cross_edges
                                .entry((gi, fr))
                                .or_default()
                                .push((fi, ret));
                        }
                    }
                }
            }
        }

        // Deterministic edge lists (sorted + deduped).
        for edges in self.cross_edges.values_mut() {
            edges.sort_by_key(|(f, k)| (*f, k.block.0, k.instr_idx, k.var.0));
            edges.dedup();
        }
    }

    /// Closure (captured free-variable) edges. A function extracted from a
    /// nested position reads variables its own IR never defines; the value
    /// lives in the innermost enclosing extracted function that DOES define
    /// them, resolved through [`FunctionIR::enclosing_fn`]. The module-scope
    /// boundary ends the walk - no analysed IR owns those names (matching
    /// the pre-restructure behavior where inlining resolved captures only
    /// inside a function's own IR).
    ///
    /// Value-flow direction `def(E, name) ──▶ use(F, v)`, keyed by the
    /// DEFINING node (the map's convention: key = value source, as with
    /// `FormalRet → ActualRet`), so the backward taint walk crosses into the
    /// defining scope at each free use node - including multi-block free
    /// vars (per-scope `VarId`s) and terminator uses, since every node whose
    /// var has no def site is covered.
    pub(super) fn install_closure_edges(&mut self) {
        for fi in 0..self.functions.len() {
            // Free use nodes grouped by source name: a node whose var has no
            // definition (or formal parameter) in this function.
            let mut free_by_name: FxHashMap<String, Vec<NodeKey>> = FxHashMap::default();
            {
                let fe = &self.functions[fi];
                for &key in fe.svfg.nodes.keys() {
                    if fe.def_site.contains_key(&key.var) {
                        continue;
                    }
                    let Some(meta) = fe.ir.var_metadata.get(&key.var) else {
                        continue;
                    };
                    if meta.is_memory_state {
                        continue;
                    }
                    let Some(name) = meta.source_name.as_deref() else {
                        continue;
                    };
                    if name.is_empty() {
                        continue;
                    }
                    free_by_name.entry(name.to_string()).or_default().push(key);
                }
            }
            if free_by_name.is_empty() {
                continue;
            }

            for (name, mut use_nodes) in free_by_name {
                // Walk the lexical chain to the first enclosing function
                // that actually defines `name`.
                let mut target: Option<usize> = None;
                let mut cur = self.functions[fi].ir.enclosing_fn.clone();
                let mut hops = 0;
                while let Some(enc) = cur
                    && hops < 32
                {
                    hops += 1;
                    let Some(&gi) = self.func_index.get(&enc) else {
                        break;
                    };
                    if self.defines_name(gi, &name) {
                        target = Some(gi);
                        break;
                    }
                    cur = self.functions[gi].ir.enclosing_fn.clone();
                }
                let Some(gi) = target else {
                    continue; // module scope: no analysed IR owns the name
                };

                // All def nodes of `name` in the target (params, assignments,
                // phis): conservative may-reach, like any other cross edge.
                let mut def_nodes: Vec<NodeKey> = Vec::new();
                for (&var, &dkey) in &self.functions[gi].def_site {
                    if self.functions[gi]
                        .ir
                        .var_metadata
                        .get(&var)
                        .is_some_and(|m| m.source_name.as_deref() == Some(name.as_str()))
                    {
                        def_nodes.push(dkey);
                    }
                }
                if def_nodes.is_empty() {
                    continue;
                }
                def_nodes.sort_by_key(|k| (k.block.0, k.instr_idx, k.var.0));
                def_nodes.dedup();
                use_nodes.sort_by_key(|k| (k.block.0, k.instr_idx, k.var.0));
                use_nodes.dedup();

                for u in use_nodes {
                    for &d in &def_nodes {
                        // Key = value source (the def in the defining
                        // scope), so reverse lookup at the free use node
                        // finds its feeders.
                        self.cross_edges.entry((gi, d)).or_default().push((fi, u));
                    }
                }
            }
        }

        // Re-establish determinism over the whole map (closure edges join
        // the parameter/return/heap edges).
        for edges in self.cross_edges.values_mut() {
            edges.sort_by_key(|(f, k)| (*f, k.block.0, k.instr_idx, k.var.0));
            edges.dedup();
        }
    }
}

impl<'a> ProgramSvfg<'a> {
    // -----------------------------------------------------------------------
    // Step 4b: field-sensitive cross-function heap edges
    // -----------------------------------------------------------------------

    /// Install heap value-flow edges *across* call boundaries:
    ///
    /// ```text
    ///   caller: obj.data = src          callee: return p.data
    ///           call f(obj)      ⟶            (load of p.data)
    /// ```
    ///
    /// Scalar parameter/return edges (Step 4) carry direct values, but a
    /// field *written into an object* before a call and *read from it*
    /// (before or during the call) has no edge, the classic missed bug
    /// `obj.data = source(); sink(obj.data)` split across two functions.
    ///
    /// Two directions are installed per call site, per matching field:
    ///
    ///  1. **caller-store → callee-load**: a `StoreField` in the caller whose
    ///     base is the same object as an actual argument feeds every
    ///     `LoadField` in the callee whose base is that callee parameter.
    ///  2. **callee-store → caller-load**: a `StoreField` in the callee on
    ///     its parameter object feeds every `LoadField` in the caller whose
    ///     base is the corresponding actual argument (covers callee-side
    ///     mutation the caller reads afterwards).
    ///  3. **callee-store → sibling-load**: two callees that receive the
    ///     *same argument object* (same arg variable at the same call-site
    ///     root) are linked: a store in one feeds loads of the same field in
    ///     the other. This is the write-then-read pipeline,
    ///     `handler(obj, input)` calling `writer(obj, input)` then
    ///     `reader(obj)`, where neither the caller nor either callee alone
    ///     completes the flow.
    ///
    /// Object identity is anchored on SSA roots (`object_roots`): parameters
    /// and allocation sites. A field matches on exact name, or when either
    /// side is the element wildcard `"*"`. Edges enter the regular
    /// `cross_edges` map, so both the forward engine and the demand-driven
    /// backward engine (via its reverse index) traverse them unchanged.
    pub(super) fn install_heap_cross_edges(&mut self) {
        // Per-function caches, computed lazily.
        let mut roots: Vec<Option<FxHashMap<VarId, ObjectRoot>>> = vec![None; self.functions.len()];
        let mut field_ops: Vec<Option<(Vec<FieldStore>, Vec<FieldLoad>)>> =
            vec![None; self.functions.len()];

        let mut new_edges: Vec<((usize, NodeKey), (usize, NodeKey))> = Vec::new();

        for fi in 0..self.functions.len() {
            let (c_stores, c_loads) = {
                if field_ops[fi].is_none() {
                    field_ops[fi] = Some(collect_field_ops(self.functions[fi].ir));
                }
                field_ops[fi].as_ref().unwrap().clone()
            };
            // Sibling heap edges (direction 3) need only the callees' field
            // ops, so an empty caller set must not skip the whole loop:
            // directions 1-2 iterate empty vectors harmlessly.
            if self.functions[fi].bindings.is_empty() {
                continue;
            }
            let bindings = self.functions[fi].bindings.clone();
            for b in &bindings {
                for &gi in &b.callees {
                    let (g_stores, g_loads) = {
                        if field_ops[gi].is_none() {
                            field_ops[gi] = Some(collect_field_ops(self.functions[gi].ir));
                        }
                        field_ops[gi].as_ref().unwrap().clone()
                    };

                    for (arg_key, slot) in &b.args {
                        let arg_var = arg_key.var;
                        if roots[fi].is_none() {
                            roots[fi] = Some(object_roots(self.functions[fi].ir));
                        }
                        let arg_root = match roots[fi].as_ref().unwrap().get(&arg_var).copied() {
                            Some(r) => r,
                            None => continue,
                        };
                        let param_root = ObjectRoot::Param(*slot);

                        // 1. caller store → callee load.
                        for st in &c_stores {
                            if roots[fi].as_ref().unwrap().get(&st.base).copied() != Some(arg_root)
                            {
                                continue;
                            }
                            for ld in &g_loads {
                                if roots[gi].is_none() {
                                    roots[gi] = Some(object_roots(self.functions[gi].ir));
                                }
                                if roots[gi].as_ref().unwrap().get(&ld.base).copied()
                                    != Some(param_root)
                                {
                                    continue;
                                }
                                if !fields_match(st.field.as_str(), ld.field.as_str()) {
                                    continue;
                                }
                                new_edges.push(((fi, st.src_use), (gi, ld.dest)));
                            }
                        }

                        // 2. callee store → caller load.
                        for st in &g_stores {
                            if roots[gi].is_none() {
                                roots[gi] = Some(object_roots(self.functions[gi].ir));
                            }
                            if roots[gi].as_ref().unwrap().get(&st.base).copied()
                                != Some(param_root)
                            {
                                continue;
                            }
                            for ld in &c_loads {
                                if roots[fi].as_ref().unwrap().get(&ld.base).copied()
                                    != Some(arg_root)
                                {
                                    continue;
                                }
                                if !fields_match(st.field.as_str(), ld.field.as_str()) {
                                    continue;
                                }
                                new_edges.push(((gi, st.src_use), (fi, ld.dest)));
                            }
                        }

                        // 3. callee store → sibling callee load. Every OTHER
                        // binding of this call site whose arg at the SAME
                        // slot carries the same object root receives the
                        // stores this callee makes on that parameter object.
                        // Pairwise across all bindings of `fi`, so both
                        // directions emerge from the (writer, reader) loop.
                        for bj in self.functions[fi].bindings.iter() {
                            if bj.call_site == b.call_site {
                                continue; // same binding: directions 1+2 cover it
                            }
                            let Some(&(_, sj)) = bj
                                .args
                                .iter()
                                .find(|(k, s)| *s == *slot && k.var == arg_var)
                            else {
                                continue; // sibling does not bind this object here
                            };
                            for &gj in &bj.callees {
                                if gj == gi {
                                    continue;
                                }
                                if field_ops[gj].is_none() {
                                    field_ops[gj] = Some(collect_field_ops(self.functions[gj].ir));
                                }
                                if roots[gj].is_none() {
                                    roots[gj] = Some(object_roots(self.functions[gj].ir));
                                }
                                let sibling_root = ObjectRoot::Param(sj);
                                for st in &g_stores {
                                    if roots[gi].as_ref().unwrap().get(&st.base).copied()
                                        != Some(param_root)
                                    {
                                        continue;
                                    }
                                    for ld in &field_ops[gj].as_ref().unwrap().1 {
                                        if roots[gj].as_ref().unwrap().get(&ld.base).copied()
                                            != Some(sibling_root)
                                        {
                                            continue;
                                        }
                                        if !fields_match(st.field.as_str(), ld.field.as_str()) {
                                            continue;
                                        }
                                        new_edges.push(((gi, st.src_use), (gj, ld.dest)));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        for ((ff, fk), (tf, tk)) in new_edges {
            self.cross_edges.entry((ff, fk)).or_default().push((tf, tk));
        }

        // Re-establish determinism over the whole map (heap edges join the
        // parameter/return edges installed by Step 4).
        for edges in self.cross_edges.values_mut() {
            edges.sort_by_key(|(f, k)| (*f, k.block.0, k.instr_idx, k.var.0));
            edges.dedup();
        }
    }
}

// ---------------------------------------------------------------------------
// Field-sensitive cross-function heap modeling
// ---------------------------------------------------------------------------

/// SSA-anchored identity of an object: where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ObjectRoot {
    /// A formal parameter (slot order = parameter index).
    Param(usize),
    /// An `Allocate` instruction (block, idx), a locally created object.
    Alloc(BlockId, usize),
    /// The initial/global memory state (module-level objects).
    Global,
}

/// A field write: `base.field = src` (or `base[field] = src`).
#[derive(Debug, Clone)]
pub(crate) struct FieldStore {
    pub base: VarId,
    pub field: String,
    /// The SVFG *use* node of the stored value inside the store instruction,
    /// the point where value-flow leaves the writer.
    pub src_use: NodeKey,
}

/// A field read: `dest = base.field` (or `dest = base[field]`).
#[derive(Debug, Clone)]
pub(crate) struct FieldLoad {
    pub base: VarId,
    pub field: String,
    /// The SVFG *def* node of the destination, the point where value-flow
    /// enters the reader.
    pub dest: NodeKey,
}

/// Do two field names denote the same heap slot? Exact match, or either side
/// is the dynamic-element wildcard `"*"` (an unknown index can hit any slot).
pub(crate) fn fields_match(a: &str, b: &str) -> bool {
    a == b || a == "*" || b == "*"
}

/// Map every variable to the SSA root of the object it denotes (parameter,
/// allocation site, or global state). Follows `Assign`/`Cast` chains; nothing
/// else propagates object identity (a `LoadField` result is a *field value*,
/// not the object itself, treating it as such would be unsound in the other
/// direction only for receiver-chaining, which `member_access_path` already
/// handles for sources).
pub(crate) fn object_roots(ir: &FunctionIR) -> FxHashMap<VarId, ObjectRoot> {
    let mut map: FxHashMap<VarId, ObjectRoot> = FxHashMap::default();

    for (slot, &p) in ir.parameters.iter().enumerate() {
        map.insert(p, ObjectRoot::Param(slot));
    }
    map.insert(ir.initial_memory_state, ObjectRoot::Global);

    let mut block_ids: Vec<BlockId> = ir.blocks.keys().copied().collect();
    block_ids.sort_by_key(|b| b.0);
    for &b in &block_ids {
        let blk = &ir.blocks[&b];
        for (idx, instr) in blk.instructions.iter().enumerate() {
            match instr {
                Instruction::Allocate { dest, .. } => {
                    map.insert(*dest, ObjectRoot::Alloc(b, idx));
                }
                Instruction::Assign {
                    dest,
                    src: Operand::Var(s),
                }
                | Instruction::Cast {
                    dest,
                    src: Operand::Var(s),
                    ..
                } => {
                    if let Some(r) = map.get(s).copied() {
                        // First writer wins (SSA: one def per var; multiple
                        // entries can only come from the parameter seeding,
                        // which is authoritative).
                        map.entry(*dest).or_insert(r);
                    }
                }
                // An object literal `{}` / `[]` lowers to `dest = Unknown`
                // (or a literal) with no Allocate, it is still a *fresh*
                // object. Anchor it as its own allocation site so field
                // stores into it participate in heap flow.
                Instruction::Assign {
                    dest,
                    src: Operand::Unknown,
                }
                | Instruction::Assign {
                    dest,
                    src: Operand::Null,
                }
                | Instruction::Assign {
                    dest,
                    src: Operand::StringLiteral(_),
                }
                | Instruction::Assign {
                    dest,
                    src: Operand::IntLiteral(_),
                }
                | Instruction::Assign {
                    dest,
                    src: Operand::BoolLiteral(_),
                } => {
                    map.entry(*dest).or_insert(ObjectRoot::Alloc(b, idx));
                }
                _ => {}
            }
        }
    }
    map
}

/// Collect all field stores/loads of a function with their SVFG attachment
/// points (store: the src *use* node; load: the dest *def* node).
pub(crate) fn collect_field_ops(ir: &FunctionIR) -> (Vec<FieldStore>, Vec<FieldLoad>) {
    let mut stores = Vec::new();
    let mut loads = Vec::new();

    let mut block_ids: Vec<BlockId> = ir.blocks.keys().copied().collect();
    block_ids.sort_by_key(|b| b.0);
    for &b in &block_ids {
        let blk = &ir.blocks[&b];
        for (idx, instr) in blk.instructions.iter().enumerate() {
            match instr {
                Instruction::StoreField {
                    base,
                    field,
                    src: Operand::Var(sv),
                    ..
                } => {
                    stores.push(FieldStore {
                        base: *base,
                        field: field.clone(),
                        src_use: NodeKey::instr(b, idx, *sv),
                    });
                }
                Instruction::StoreElement {
                    base, index, src, ..
                } => {
                    if let (Operand::Var(sv), Some(field)) = (src, elem_field(index)) {
                        stores.push(FieldStore {
                            base: *base,
                            field,
                            src_use: NodeKey::instr(b, idx, *sv),
                        });
                    }
                }
                Instruction::LoadField {
                    dest, base, field, ..
                } => {
                    loads.push(FieldLoad {
                        base: *base,
                        field: field.clone(),
                        dest: NodeKey::instr(b, idx, *dest),
                    });
                }
                Instruction::LoadElement {
                    dest, base, index, ..
                } => {
                    if let Some(field) = elem_field(index) {
                        loads.push(FieldLoad {
                            base: *base,
                            field,
                            dest: NodeKey::instr(b, idx, *dest),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    (stores, loads)
}

/// Field name for an element index operand: string literal verbatim,
/// anything dynamic is the wildcard.
fn elem_field(index: &Operand) -> Option<String> {
    Some(match index {
        Operand::StringLiteral(s) => s.clone(),
        _ => "*".to_string(),
    })
}
