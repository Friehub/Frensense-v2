// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Interprocedural memory semantics and function summaries (Limitation M1).
//!
//! Tracks allocation and deallocation contracts across function boundaries:
//! - `@returns_fresh`: Functions returning fresh heap memory (factory functions).
//! - `@consumes(param_idx)`: Functions deallocating a pointer passed to a parameter slot.
//!
//! Maintains strict 0-FP: only functions provably returning fresh allocations
//! or executing deallocations on parameters receive contracts. Pointers passed
//! for reading/writing without deallocation are never marked consumed.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::value;
use crate::checks::last_segment;
use crate::ir::function::{FunctionIR, Instruction, Operand, Terminator, VarId};

/// Buffer capacity specification for an allocation contract.
///
/// Derives serde so it can travel inside a `.frc` bundle's bincode payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Default)]
pub enum CapacitySpec {
    /// Exact constant byte/element capacity (e.g. malloc(64)).
    Exact(i64),
    /// Capacity matches the value passed to argument at index `usize`.
    Param(usize),
    /// Capacity matches `args[p1] * args[p2]` (e.g. calloc(n, sz)).
    ParamProduct(usize, usize),
    /// Fresh allocation, but capacity is dynamic or unconstrained.
    #[default]
    Unknown,
}

/// Summary contract describing a function's memory semantics.
///
/// Derives serde so it can travel inside a `.frc` bundle's bincode payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct MemorySummary {
    /// True if the function returns a newly allocated object.
    pub returns_fresh: bool,
    /// Capacity specification for the returned object.
    pub return_capacity: CapacitySpec,
    /// Parameter indices consumed (freed/deallocated) by this function.
    pub consumes_params: Vec<usize>,
    /// Parameter indices through which freshly allocated objects are written (out-parameters).
    #[cfg_attr(feature = "serialize", serde(default))]
    pub out_params_fresh: Vec<usize>,
}

/// Registry storing interprocedural memory contracts for library primitives
/// and program functions.
#[derive(Debug, Clone, Default)]
pub struct MemorySummaryRegistry {
    pub summaries: FxHashMap<String, MemorySummary>,
}

impl MemorySummaryRegistry {
    /// Build a registry from a memory-function vocabulary (seeded into a
    /// [`crate::analysis::taint::facts::FactTable`] by the default pack):
    /// one summary per entry, mapping the vocabulary's capacity shape
    /// onto [`CapacitySpec`].
    fn from_vocabulary(vocab: &[crate::analysis::taint::facts::MemoryFuncSpec]) -> Self {
        use crate::analysis::taint::facts::AllocCapacity;
        let mut summaries = FxHashMap::default();
        for f in vocab {
            summaries.insert(
                f.name.to_string(),
                MemorySummary {
                    returns_fresh: f.returns_fresh,
                    return_capacity: match f.capacity {
                        AllocCapacity::Unknown => CapacitySpec::Unknown,
                        AllocCapacity::Param(n) => CapacitySpec::Param(n),
                        AllocCapacity::ParamProduct(a, b) => CapacitySpec::ParamProduct(a, b),
                    },
                    consumes_params: f.consumes_params.to_vec(),
                    out_params_fresh: Vec::new(),
                },
            );
        }
        Self { summaries }
    }

    /// Seed a registry from the spec's memory vocabulary in `facts`
    /// (spec-seeded via `fact_table_from_spec`), then layer
    /// bundle-learned contracts on top. Learned contracts override the
    /// vocabulary on name collision (more specific corpus knowledge wins).
    ///
    /// Call this instead of `default()` when a `.frc` bundle is loaded, then
    /// follow up with `infer_program_summaries_into` for the current project's
    /// per-file fixpoint.
    pub fn from_facts(facts: &crate::analysis::taint::facts::FactTable) -> Self {
        let mut reg = Self::from_vocabulary(&facts.memory_functions);
        for contract in &facts.memory_contracts {
            reg.summaries.insert(
                contract.name.clone(),
                MemorySummary {
                    returns_fresh: contract.returns_fresh,
                    return_capacity: contract.return_capacity.clone(),
                    consumes_params: contract.consumes_params.clone(),
                    out_params_fresh: Vec::new(),
                },
            );
        }
        for alloc in &facts.custom_allocators {
            reg.summaries
                .entry(alloc.clone())
                .or_insert_with(|| MemorySummary {
                    returns_fresh: true,
                    return_capacity: CapacitySpec::Unknown,
                    consumes_params: Vec::new(),
                    out_params_fresh: Vec::new(),
                });
        }
        for dealloc in &facts.custom_deallocators {
            reg.summaries
                .entry(dealloc.clone())
                .or_insert_with(|| MemorySummary {
                    returns_fresh: false,
                    return_capacity: CapacitySpec::Unknown,
                    consumes_params: vec![0],
                    out_params_fresh: Vec::new(),
                });
        }
        reg
    }

    /// Run the fixpoint inference in-place on `self` (which was already seeded
    /// from the bundle via `from_facts`).  This is the per-project pass: it
    /// discovers project-specific wrapper chains on top of whatever the bundle
    /// already taught.
    pub fn infer_program_summaries_into(mut self, irs: &[&FunctionIR]) -> Self {
        self.run_fixpoint(irs);
        self
    }

    /// Insert or update a summary contract for a function name.
    pub fn insert(&mut self, name: String, summary: MemorySummary) {
        self.summaries.insert(name, summary);
    }

    /// Retrieve summary for a function by exact or short segment name.
    pub fn get(&self, name: &str) -> Option<&MemorySummary> {
        self.summaries
            .get(name)
            .or_else(|| self.summaries.get(last_segment(name)))
    }

    /// Returns true if calling `name` returns a freshly allocated object.
    /// Vocabulary-driven: the registry was seeded from the default pack
    /// through `FactTable::memory_functions`.
    pub fn returns_fresh(&self, name: &str) -> bool {
        self.get(name).is_some_and(|s| s.returns_fresh)
    }

    /// Returns the capacity specification for a fresh allocation returned by `name`.
    pub fn return_capacity(&self, name: &str) -> Option<&CapacitySpec> {
        self.get(name).and_then(|s| {
            if s.returns_fresh {
                Some(&s.return_capacity)
            } else {
                None
            }
        })
    }

    /// Returns the indices of parameters consumed (deallocated) by `name`.
    pub fn consumes_params(&self, name: &str) -> Vec<usize> {
        self.get(name)
            .map(|s| s.consumes_params.clone())
            .unwrap_or_default()
    }

    /// Returns the indices of parameters through which fresh allocations are written by `name`.
    pub fn out_params_fresh(&self, name: &str) -> Vec<usize> {
        self.get(name)
            .map(|s| s.out_params_fresh.clone())
            .unwrap_or_default()
    }

    /// Internal fixpoint pass shared by `infer_program_summaries` and
    /// `infer_program_summaries_into`. Mutates `self` in place.
    fn run_fixpoint(&mut self, irs: &[&FunctionIR]) {
        // Trace a variable back to a parameter index through SSA assignments / casts.
        fn trace_to_param(ir: &FunctionIR, var: VarId) -> Option<usize> {
            if let Some(pos) = ir.parameters.iter().position(|&p| p == var) {
                return Some(pos);
            }
            let mut cur = var;
            let mut visited = FxHashSet::default();
            while visited.insert(cur) {
                let mut found_next = None;
                for blk in ir.blocks.values() {
                    for instr in &blk.instructions {
                        match instr {
                            Instruction::Assign {
                                dest,
                                src: Operand::Var(src),
                            }
                            | Instruction::Cast {
                                dest,
                                src: Operand::Var(src),
                                ..
                            } if *dest == cur => {
                                if let Some(pos) = ir.parameters.iter().position(|&p| p == *src) {
                                    return Some(pos);
                                }
                                found_next = Some(*src);
                                break;
                            }
                            _ => {}
                        }
                    }
                    if found_next.is_some() {
                        break;
                    }
                }
                match found_next {
                    Some(n) => cur = n,
                    None => break,
                }
            }
            None
        }

        // Trace a variable back to its defining instruction.
        fn find_definition(ir: &FunctionIR, var: VarId) -> Option<&Instruction> {
            for blk in ir.blocks.values() {
                for instr in &blk.instructions {
                    match instr {
                        Instruction::Assign { dest, .. }
                        | Instruction::Cast { dest, .. }
                        | Instruction::CallStatic {
                            dest: Some(dest), ..
                        }
                        | Instruction::Allocate { dest, .. }
                        | Instruction::BinaryOp { dest, .. }
                        | Instruction::UnaryOp { dest, .. }
                            if *dest == var =>
                        {
                            return Some(instr);
                        }
                        _ => {}
                    }
                }
            }
            None
        }

        // Fixed-point inference loop over program functions.
        let mut changed = true;
        let mut iterations = 0;
        while changed && iterations < 10 {
            changed = false;
            iterations += 1;

            for &ir in irs {
                let mut consumes: Vec<usize> = Vec::new();
                let mut returns_fresh = false;
                let mut return_capacity = CapacitySpec::Unknown;

                // 1. Infer consumed parameters
                for blk in ir.blocks.values() {
                    for instr in &blk.instructions {
                        if let Instruction::CallStatic { func, args, .. } = instr {
                            let consumed_slots = self.consumes_params(func.as_str());
                            for slot in consumed_slots {
                                if let Some(Operand::Var(v)) = args.get(slot)
                                    && let Some(param_idx) = trace_to_param(ir, *v)
                                    && !consumes.contains(&param_idx)
                                {
                                    consumes.push(param_idx);
                                }
                            }
                        }
                    }
                }
                consumes.sort();

                // 2. Infer returned allocation provenance
                let mut return_vars: Vec<VarId> = Vec::new();
                for blk in ir.blocks.values() {
                    if let Terminator::Return {
                        src: Some(Operand::Var(v)),
                    } = &blk.terminator
                    {
                        return_vars.push(*v);
                    }
                }

                if !return_vars.is_empty() {
                    let val_info = value::analyze(ir);

                    // Chase through Assign/Cast chains to find the root allocation
                    // instruction for a given var (handles SSA copies like `p = malloc(n);
                    // tmp = p; return tmp;`).
                    let find_alloc_root = |start: VarId| -> Option<&Instruction> {
                        let mut cur = start;
                        let mut seen = FxHashSet::default();
                        loop {
                            if !seen.insert(cur) {
                                break;
                            }
                            match find_definition(ir, cur) {
                                Some(
                                    instr @ Instruction::CallStatic { .. }
                                    | instr @ Instruction::Allocate { .. },
                                ) => return Some(instr),
                                Some(Instruction::Assign {
                                    src: Operand::Var(next),
                                    ..
                                })
                                | Some(Instruction::Cast {
                                    src: Operand::Var(next),
                                    ..
                                }) => {
                                    cur = *next;
                                }
                                _ => break,
                            }
                        }
                        None
                    };

                    for ret_var in return_vars {
                        if let Some(def) = find_alloc_root(ret_var) {
                            match def {
                                Instruction::CallStatic { func, args, .. }
                                    if self.returns_fresh(func) =>
                                {
                                    returns_fresh = true;
                                    if let Some(cap_spec) = self.return_capacity(func) {
                                        match cap_spec {
                                            CapacitySpec::Param(p_idx) => {
                                                if let Some(arg_op) = args.get(*p_idx) {
                                                    match arg_op {
                                                        Operand::IntLiteral(k) => {
                                                            return_capacity =
                                                                CapacitySpec::Exact(*k);
                                                        }
                                                        Operand::Var(v) => {
                                                            if let Some(param_idx) =
                                                                trace_to_param(ir, *v)
                                                            {
                                                                return_capacity =
                                                                    CapacitySpec::Param(param_idx);
                                                            } else if let Some(c) =
                                                                val_info.const_int(*v)
                                                            {
                                                                return_capacity =
                                                                    CapacitySpec::Exact(c);
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                            CapacitySpec::ParamProduct(p1, p2) => {
                                                let param1 =
                                                    args.get(*p1).and_then(|op| match op {
                                                        Operand::Var(v) => trace_to_param(ir, *v),
                                                        _ => None,
                                                    });
                                                let param2 =
                                                    args.get(*p2).and_then(|op| match op {
                                                        Operand::Var(v) => trace_to_param(ir, *v),
                                                        _ => None,
                                                    });
                                                if let (Some(a), Some(b)) = (param1, param2) {
                                                    return_capacity =
                                                        CapacitySpec::ParamProduct(a, b);
                                                }
                                            }
                                            CapacitySpec::Exact(k) => {
                                                return_capacity = CapacitySpec::Exact(*k);
                                            }
                                            CapacitySpec::Unknown => {}
                                        }
                                    }
                                }
                                // Object/array literals (`Allocate`) are not
                                // freshness roots: inferring factories from
                                // them marks every wrapper of a literal fresh,
                                // pulling GC-managed objects (whose lifetime
                                // needs no release) into allocation-lifetime
                                // candidates. Freshness roots at the declared
                                // allocator vocabulary - a `CallStatic`
                                // returning a call that is already fresh.
                                _ => {}
                            }
                        }
                    }
                }

                // 3. Infer out-parameter allocation provenance
                let mut out_params: Vec<usize> = Vec::new();
                for blk in ir.blocks.values() {
                    for instr in &blk.instructions {
                        match instr {
                            Instruction::StoreElement {
                                base,
                                src: Operand::Var(src),
                                ..
                            }
                            | Instruction::StoreField {
                                base,
                                src: Operand::Var(src),
                                ..
                            } => {
                                if let Some(param_idx) = trace_to_param(ir, *base) {
                                    let mut cur = *src;
                                    let mut is_fresh = false;
                                    let mut seen = FxHashSet::default();
                                    while seen.insert(cur) {
                                        match find_definition(ir, cur) {
                                            Some(Instruction::CallStatic { func, .. }) => {
                                                if self.returns_fresh(func) {
                                                    is_fresh = true;
                                                }
                                                break;
                                            }
                                            Some(Instruction::Allocate { .. }) => {
                                                is_fresh = true;
                                                break;
                                            }
                                            Some(Instruction::Assign {
                                                src: Operand::Var(next),
                                                ..
                                            })
                                            | Some(Instruction::Cast {
                                                src: Operand::Var(next),
                                                ..
                                            }) => {
                                                cur = *next;
                                            }
                                            _ => break,
                                        }
                                    }
                                    if is_fresh && !out_params.contains(&param_idx) {
                                        out_params.push(param_idx);
                                    }
                                }
                            }
                            Instruction::CallStatic { func, args, .. } => {
                                let callee_out = self.out_params_fresh(func);
                                for &slot in &callee_out {
                                    if let Some(Operand::Var(arg_var)) = args.get(slot) {
                                        let target = match find_definition(ir, *arg_var) {
                                            Some(Instruction::AddressOf { src, .. }) => *src,
                                            _ => *arg_var,
                                        };
                                        if let Some(param_idx) = trace_to_param(ir, target)
                                            && !out_params.contains(&param_idx)
                                        {
                                            out_params.push(param_idx);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                out_params.sort();

                // If any contract was discovered, register it.
                if returns_fresh || !consumes.is_empty() || !out_params.is_empty() {
                    let summary = MemorySummary {
                        returns_fresh,
                        return_capacity,
                        consumes_params: consumes,
                        out_params_fresh: out_params,
                    };
                    let prev = self.summaries.get(&ir.name);
                    if prev != Some(&summary) {
                        self.summaries.insert(ir.name.clone(), summary);
                        changed = true;
                    }
                }
            }
        }
    }
}
