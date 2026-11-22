// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Task 4.2: Bottom-Up Interprocedural Value-Flow (CFTaint-style)
//!
//! This module wires many per-function [`Svfg`]s into one program-level
//! value-flow structure with **real interprocedural edges**:
//!
//! ```text
//!   caller ActualArg  ──▶ callee FormalParam     (parameter passing)
//!   callee FormalRet  ──▶ caller ActualRet       (return value passing)
//! ```
//!
//! ## Bottom-up analysis order
//!
//! The call graph is topologically sorted **leaves first** (DFS post-order).
//! Each function is processed exactly once, in that order:
//!
//! 1. Analyse the function's own SVFG, treating callees as black boxes.
//! 2. Where a callee already has a summary, apply it (relational: "if argument
//!    slot `s` is tainted, the return value becomes tainted").
//! 3. Produce a [`TaintSummary`] and cache it.
//!
//! Because callees are summarised before callers, every function is analysed
//! exactly once, for a corpus with shared utility libraries, the summary is
//! computed once and applied at every call site (the key corpus-scale
//! optimisation from the 4.2 spec).
//!
//! ## Pass-through suppression
//!
//! The single-function SVFG contains conservative `arg-use → dest-def`
//! pass-through edges for *every* call (sound when the callee is unknown).
//! When a callee is known **and** its summary is available, those edges are
//! suppressed for that call site and replaced by the callee's summary, this
//! is strictly more precise (a sanitising callee no longer leaks taint through
//! a local pass-through edge) and matches "apply the callee's summary rather
//! than inlining its analysis".
//!
//! For callees inside reference cycles (where no summary exists yet), the
//! local pass-through edges are kept: the analysis stays sound (may
//! over-approximate) while the SVFG cross-edges still carry exact flow.
//!
//! ## Result artifacts
//!
//! * [`ProgramSvfg::cross_edges`], the explicit interprocedural edge list
//!   (deterministic, serialisable, feeds task 4.5's corpus graph store).
//! * [`ProgramSvfg`]'s per-function [`TaintSummary`]s, computed bottom-up.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::taint::config::TaintConfig;
use crate::analysis::taint::facts::FactTable;
use crate::graph::callgraph::{CallGraph, CallGraphBuilder};
use crate::graph::svfg::{NodeKey, NodeKind, Svfg, SvfgBuilder};
use crate::ir::function::*;

/// Call-site bindings: which callees a call reaches and how arguments map to formals.
pub mod bindings;
/// Interprocedural value-flow edges between call sites and callees.
pub mod edges;
/// Source, sink and sanitizer predicates over the fact table.
pub mod predicates;
/// Per-function summaries used to cut or pass taint across calls.
pub mod summaries;

pub(crate) use bindings::*;
pub use predicates::SinkAlert;
pub(crate) use predicates::*;
pub(crate) use summaries::*;

// ---------------------------------------------------------------------------
// Per-function entry
// ---------------------------------------------------------------------------

/// Everything the interprocedural layer knows about one function.
#[derive(Debug)]
pub struct FunctionEntry<'a> {
    /// Program name of the function.
    pub name: String,
    /// The function's IR.
    pub ir: &'a FunctionIR,
    /// The function's value-flow graph.
    pub svfg: Svfg,
    /// Maps each VarId to the SVFG node that defines it.
    pub def_site: FxHashMap<VarId, NodeKey>,
    /// Resolved call sites in this function (discovery order is deterministic:
    /// blocks sorted by id, instructions by index).
    pub bindings: Vec<CallBinding>,
    /// Arg use-node key → `(binding index, formal slot)`.
    pub arg_slots: FxHashMap<NodeKey, (usize, usize)>,
    /// Filled bottom-up while the program-level value-flow structure is built.
    pub summary: Option<TaintSummary>,
}

// ---------------------------------------------------------------------------
// Program-level SVFG
// ---------------------------------------------------------------------------

/// The whole-program value-flow structure: per-function SVFGs linked by
/// explicit interprocedural edges, with bottom-up summaries cached per fn.
#[derive(Debug)]
pub struct ProgramSvfg<'a> {
    /// Deterministic order: sorted by function name.
    pub functions: Vec<FunctionEntry<'a>>,
    func_index: FxHashMap<String, usize>,
    /// DFS post-order (leaves first) over the call graph.
    pub topological_order: Vec<usize>,
    /// `(caller_fn, from_node) → [(callee_fn, to_node)]`, sorted & deduped.
    /// Parameter edges: ActualArg → FormalParam. Return edges: FormalRet → ActualRet.
    pub cross_edges: FxHashMap<(usize, NodeKey), Vec<(usize, NodeKey)>>,
    /// Local pass-through edges `(fn, from, to)` suppressed because a summary
    /// replaced them. Consulted by both the summary BFS and the taint engine.
    suppressed: FxHashSet<(usize, NodeKey, NodeKey)>,
}

impl<'a> ProgramSvfg<'a> {
    /// Build the whole-program structure from a set of SSA-converted
    /// `FunctionIR`s. `config` is needed at build time because summaries must
    /// know which calls are sinks.
    pub fn new(irs: &FxHashMap<String, &'a FunctionIR>, config: &TaintConfig) -> Self {
        let facts = FactTable::from_config(config);
        Self::new_with_facts(irs, config, &facts)
    }

    /// Like [`ProgramSvfg::new`] but consults an explicit [`FactTable`] for
    /// learned sink signatures and sanitizers during summary computation.
    pub(crate) fn new_with_facts(
        irs: &FxHashMap<String, &'a FunctionIR>,
        config: &TaintConfig,
        facts: &FactTable,
    ) -> Self {
        Self::new_with_module_aliases(irs, config, facts, None, None)
    }

    /// Build a [`ProgramSvfg`] with explicit module aliases and function-to-file mappings.
    pub(crate) fn new_with_module_aliases(
        irs: &FxHashMap<String, &'a FunctionIR>,
        config: &TaintConfig,
        facts: &FactTable,
        aliases: Option<&FxHashMap<String, FxHashMap<String, String>>>,
        fn_file: Option<&FxHashMap<String, String>>,
    ) -> Self {
        // 1. Build per-function SVFGs (deterministic name order).
        let mut names: Vec<&String> = irs.keys().collect();
        names.sort();
        let functions: Vec<FunctionEntry<'a>> = names
            .iter()
            .map(|n| {
                let ir = irs[*n];
                let (svfg, def_site) =
                    SvfgBuilder::new(ir).build_with_buffer_builtins(&facts.buffer_builtins);
                FunctionEntry {
                    name: (*n).clone(),
                    ir,
                    svfg,
                    def_site,
                    bindings: Vec::new(),
                    arg_slots: FxHashMap::default(),
                    summary: None,
                }
            })
            .collect();
        let func_index: FxHashMap<String, usize> = functions
            .iter()
            .enumerate()
            .map(|(i, f)| (f.name.clone(), i))
            .collect();

        let mut prog = Self {
            functions,
            func_index,
            topological_order: Vec::new(),
            cross_edges: FxHashMap::default(),
            suppressed: FxHashSet::default(),
        };

        // Resolve the call graph once (aliases, receiver-class methods,
        // higher-order callbacks) and use it for all binding discovery.
        let mut borrowed: FxHashMap<String, &FunctionIR> = FxHashMap::default();
        for (name, ir) in irs.iter() {
            borrowed.insert(name.clone(), ir);
        }
        let callgraph = CallGraphBuilder::new(&borrowed)
            .with_aliases(aliases, fn_file)
            .build();

        if crate::debug_flags::DebugFlags::get().mem {
            eprintln!(
                "[mem]   svfg:fns={} rss_kb={}",
                prog.functions.len(),
                crate::debug_flags::rss_kb()
            );
            eprintln!(
                "[mem]   callgraph edges={} rss_kb={}",
                callgraph.edges.values().map(Vec::len).sum::<usize>(),
                crate::debug_flags::rss_kb()
            );
        }

        prog.discover_bindings(&callgraph);
        if crate::debug_flags::DebugFlags::get().mem {
            eprintln!(
                "[mem]   bindings={} rss_kb={}",
                prog.functions
                    .iter()
                    .map(|f| f.bindings.len())
                    .sum::<usize>(),
                crate::debug_flags::rss_kb()
            );
        }
        prog.compute_topological_order();
        prog.compute_summaries(config, facts);
        if crate::debug_flags::DebugFlags::get().mem {
            eprintln!(
                "[mem]   summaries={} rss_kb={}",
                prog.functions
                    .iter()
                    .filter(|f| f.summary.is_some())
                    .count(),
                crate::debug_flags::rss_kb()
            );
        }
        prog.install_cross_edges(facts);
        if crate::debug_flags::DebugFlags::get().mem {
            eprintln!(
                "[mem]   cross_edges={} rss_kb={}",
                prog.cross_edges.len(),
                crate::debug_flags::rss_kb()
            );
        }
        prog.install_heap_cross_edges();
        if crate::debug_flags::DebugFlags::get().mem {
            eprintln!(
                "[mem]   heap_cross={} rss_kb={}",
                prog.cross_edges.len(),
                crate::debug_flags::rss_kb()
            );
        }
        prog.install_closure_edges();
        if crate::debug_flags::DebugFlags::get().mem {
            eprintln!(
                "[mem]   closure_cross={} rss_kb={}",
                prog.cross_edges.len(),
                crate::debug_flags::rss_kb()
            );
        }
        prog
    }

    /// Look up a function's index by name.
    pub(crate) fn function_index(&self, name: &str) -> Option<usize> {
        self.func_index.get(name).copied()
    }

    /// True when function `fi` has a defined variable (def site or formal
    /// parameter) whose source name is `name`.
    fn defines_name(&self, fi: usize, name: &str) -> bool {
        let fe = &self.functions[fi];
        fe.def_site.keys().any(|&var| {
            fe.ir
                .var_metadata
                .get(&var)
                .is_some_and(|m| m.source_name.as_deref() == Some(name))
        })
    }

    /// Local predecessors of a node, minus suppressed pass-through edges (the
    /// demand-driven walk's edge set; suppression is what keeps a sanitizing
    /// callee from leaking taint through the local pass-through edge).
    pub(crate) fn local_predecessors(&self, fi: usize, key: &NodeKey) -> Vec<NodeKey> {
        match self.functions[fi].svfg.node(key) {
            Some(n) => n
                .predecessors()
                .into_iter()
                .filter(|p| !self.suppressed.contains(&(fi, *p, *key)))
                .collect(),
            None => Vec::new(),
        }
    }
}
