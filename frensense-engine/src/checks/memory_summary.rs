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
use crate::ir::function::{FunctionIR, Instruction, Operand, Terminator, VarId};

/// Callee last segments that release heap memory directly.
const DIRECT_FREE_CALLS: &[&str] = &["free"];

/// Callee last segments that allocate heap memory directly.
const DIRECT_ALLOC_CALLS: &[&str] = &[
    "malloc",
    "calloc",
    "realloc",
    "aligned_alloc",
    "valloc",
    "alloca",
];

fn last_segment(call: &str) -> &str {
    let s = call.rsplit('.').next().unwrap_or(call);
    s.rsplit("::").next().unwrap_or(s)
}

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
}

/// Registry storing interprocedural memory contracts for library primitives
/// and program functions.
#[derive(Debug, Clone)]
pub struct MemorySummaryRegistry {
    pub summaries: FxHashMap<String, MemorySummary>,
}

impl Default for MemorySummaryRegistry {
    fn default() -> Self {
        let mut reg = Self {
            summaries: FxHashMap::default(),
        };
        reg.register_builtins();
        reg
    }
}

impl MemorySummaryRegistry {
    /// Create an empty registry with built-in library primitives.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if `name` is one of the built-in bootstrap contracts.
    ///
    /// The bundler uses this to skip re-emitting builtins into the `.frc`
    /// (they're already in the hardcoded bootstrap, no need to inflate bundle size).
    pub fn is_builtin(name: &str) -> bool {
        const BUILTIN_NAMES: &[&str] = &[
            "free",
            "malloc",
            "calloc",
            "realloc",
            "aligned_alloc",
            "valloc",
            "alloca",
            "g_free",
            "g_malloc",
            "g_malloc0",
            "g_realloc",
            "g_strdup",
            "kfree",
            "kmalloc",
            "kzalloc",
            "kcalloc",
            "sqlite3_free",
            "sqlite3_malloc",
            "sqlite3_malloc64",
            "sqlite3_realloc",
            "CRYPTO_free",
            "apr_palloc",
            "xmlFree",
            "cJSON_Delete",
            "strdup",
            "strndup",
        ];
        BUILTIN_NAMES.contains(&name)
    }

    /// Seed a registry from bundle-learned memory contracts, then add the
    /// built-in bootstrap.  Bundle-learned contracts override builtins on
    /// name collision (more specific corpus knowledge wins).
    ///
    /// Call this instead of `default()` when a `.frc` bundle is loaded, then
    /// follow up with `infer_program_summaries_into` for the current project's
    /// per-file fixpoint.
    pub fn from_facts(facts: &crate::analysis::taint::facts::FactTable) -> Self {
        // Start with the hardcoded bootstrap so the engine always works even
        // without a bundle, then merge bundle-learned contracts on top.
        let mut reg = Self::default();
        for contract in &facts.memory_contracts {
            reg.summaries.insert(
                contract.name.clone(),
                MemorySummary {
                    returns_fresh: contract.returns_fresh,
                    return_capacity: contract.return_capacity.clone(),
                    consumes_params: contract.consumes_params.clone(),
                },
            );
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

    /// Static entry point that starts from a fresh default registry and runs
    /// fixpoint inference.  Kept for call-sites that have no bundle.
    pub fn infer_program_summaries(irs: &[&FunctionIR]) -> Self {
        let mut registry = Self::default();
        registry.run_fixpoint(irs);
        registry
    }

    fn register_builtins(&mut self) {
        // Standard deallocators (consumes param 0)
        let deallocs = &[
            "free",
            "g_free",
            "kfree",
            "cJSON_Delete",
            "apr_palloc",
            "CRYPTO_free",
            "xmlFree",
            "sqlite3_free",
        ];
        for &name in deallocs {
            self.summaries.insert(
                name.to_string(),
                MemorySummary {
                    returns_fresh: false,
                    return_capacity: CapacitySpec::Unknown,
                    consumes_params: vec![0],
                },
            );
        }

        // Standard allocators (returns fresh with param 0 capacity)
        let param0_allocs = &[
            "malloc",
            "valloc",
            "alloca",
            "g_malloc",
            "g_malloc0",
            "kmalloc",
            "kzalloc",
            "sqlite3_malloc",
        ];
        for &name in param0_allocs {
            self.summaries.insert(
                name.to_string(),
                MemorySummary {
                    returns_fresh: true,
                    return_capacity: CapacitySpec::Param(0),
                    consumes_params: vec![],
                },
            );
        }

        // Calloc-style allocators (returns fresh with param0 * param1 capacity)
        let calloc_allocs = &["calloc", "sqlite3_malloc64", "kcalloc"];
        for &name in calloc_allocs {
            self.summaries.insert(
                name.to_string(),
                MemorySummary {
                    returns_fresh: true,
                    return_capacity: CapacitySpec::ParamProduct(0, 1),
                    consumes_params: vec![],
                },
            );
        }

        // Realloc-style allocators (consumes param 0, returns fresh with param 1 capacity)
        let realloc_allocs = &["realloc", "g_realloc", "sqlite3_realloc"];
        for &name in realloc_allocs {
            self.summaries.insert(
                name.to_string(),
                MemorySummary {
                    returns_fresh: true,
                    return_capacity: CapacitySpec::Param(1),
                    consumes_params: vec![0],
                },
            );
        }

        // String duplicates (returns fresh with unknown capacity)
        let str_allocs = &["strdup", "strndup", "g_strdup"];
        for &name in str_allocs {
            self.summaries.insert(
                name.to_string(),
                MemorySummary {
                    returns_fresh: true,
                    return_capacity: CapacitySpec::Unknown,
                    consumes_params: vec![],
                },
            );
        }
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
    pub fn returns_fresh(&self, name: &str) -> bool {
        let seg = last_segment(name);
        if DIRECT_ALLOC_CALLS.contains(&seg) {
            return true;
        }
        self.get(name).is_some_and(|s| s.returns_fresh)
    }

    /// Returns the capacity specification for a fresh allocation returned by `name`.
    pub fn return_capacity(&self, name: &str) -> Option<&CapacitySpec> {
        let seg = last_segment(name);
        if seg == "malloc" || seg == "valloc" || seg == "alloca" {
            return Some(&CapacitySpec::Param(0));
        }
        if seg == "calloc" {
            return Some(&CapacitySpec::ParamProduct(0, 1));
        }
        if seg == "realloc" || seg == "aligned_alloc" {
            return Some(&CapacitySpec::Param(1));
        }
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
        let seg = last_segment(name);
        if DIRECT_FREE_CALLS.contains(&seg) {
            return vec![0];
        }
        self.get(name)
            .map(|s| s.consumes_params.clone())
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
                                Instruction::Allocate { .. } => {
                                    returns_fresh = true;
                                    return_capacity = CapacitySpec::Unknown;
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // If any contract was discovered, register it.
                if returns_fresh || !consumes.is_empty() {
                    let summary = MemorySummary {
                        returns_fresh,
                        return_capacity,
                        consumes_params: consumes,
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
