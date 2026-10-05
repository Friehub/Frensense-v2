// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

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
//! * [`InterproceduralTaintEngine`], BFS over local + cross edges; alerts are
//!   reported with the function in which the sink lives.

use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;

use crate::analysis::taint::config::TaintConfig;
use crate::analysis::taint::facts::FactTable;
use crate::graph::callgraph::{CallGraph, CallGraphBuilder};
use crate::graph::svfg::{NodeKey, NodeKind, Svfg, SvfgBuilder};
use crate::ir::function::*;

pub mod bindings;
pub mod edges;
pub mod predicates;
#[cfg(feature = "serialize")]
pub mod serialize;
pub mod summaries;

pub use bindings::*;
pub use predicates::SinkAlert;
pub(crate) use predicates::*;
#[cfg(feature = "serialize")]
pub use serialize::*;
pub use summaries::*;

// ---------------------------------------------------------------------------
// Per-function entry
// ---------------------------------------------------------------------------

/// Everything the interprocedural layer knows about one function.
pub struct FunctionEntry<'a> {
    pub name: String,
    pub ir: &'a FunctionIR,
    pub svfg: Svfg,
    /// Maps each VarId to the SVFG node that defines it.
    pub def_site: FxHashMap<VarId, NodeKey>,
    /// Resolved call sites in this function (discovery order is deterministic:
    /// blocks sorted by id, instructions by index).
    pub bindings: Vec<CallBinding>,
    /// Arg use-node key → `(binding index, formal slot)`.
    pub arg_slots: FxHashMap<NodeKey, (usize, usize)>,
    /// Filled bottom-up during [`ProgramSvfg::compute_summaries`].
    pub summary: Option<TaintSummary>,
}

// ---------------------------------------------------------------------------
// Program-level SVFG
// ---------------------------------------------------------------------------

/// The whole-program value-flow structure: per-function SVFGs linked by
/// explicit interprocedural edges, with bottom-up summaries cached per fn.
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
    pub fn new_with_facts(
        irs: &FxHashMap<String, &'a FunctionIR>,
        config: &TaintConfig,
        facts: &FactTable,
    ) -> Self {
        // 1. Build per-function SVFGs (deterministic name order).
        let mut names: Vec<&String> = irs.keys().collect();
        names.sort();
        let functions: Vec<FunctionEntry<'a>> = names
            .iter()
            .map(|n| {
                let ir = irs[*n];
                let (svfg, def_site) = SvfgBuilder::new(ir).build();
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
        let callgraph = CallGraphBuilder::new(&borrowed).build();

        prog.discover_bindings(&callgraph);
        prog.compute_topological_order();
        prog.compute_summaries(config, facts);
        prog.install_cross_edges();
        prog.install_heap_cross_edges();
        prog.install_closure_edges();
        prog
    }

    /// Look up a function's index by name.
    pub fn function_index(&self, name: &str) -> Option<usize> {
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

    /// Local successors of a node, minus suppressed pass-through edges.
    pub fn local_successors(&self, fi: usize, key: &NodeKey) -> Vec<NodeKey> {
        match self.functions[fi].svfg.node(key) {
            Some(n) => n
                .successors()
                .into_iter()
                .filter(|s| !self.suppressed.contains(&(fi, *key, *s)))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Local predecessors of a node, minus suppressed pass-through edges
    /// (mirror of [`ProgramSvfg::local_successors`] for backward traversal).
    pub fn local_predecessors(&self, fi: usize, key: &NodeKey) -> Vec<NodeKey> {
        match self.functions[fi].svfg.node(key) {
            Some(n) => n
                .predecessors()
                .into_iter()
                .filter(|p| !self.suppressed.contains(&(fi, *p, *key)))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Interprocedural successors of a node (cross edges out).
    pub fn inter_successors(&self, fi: usize, key: &NodeKey) -> Vec<(usize, NodeKey)> {
        self.cross_edges
            .get(&(fi, *key))
            .cloned()
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Interprocedural taint engine
// ---------------------------------------------------------------------------

/// BFS taint propagation over the whole-program value-flow structure.
///
/// Cost remains proportional to the taint-reachable subgraph: local successors
/// plus explicit cross edges, no fixed-point loop, no visit to functions or
/// variables off every taint path.
pub struct InterproceduralTaintEngine<'a> {
    prog: &'a ProgramSvfg<'a>,
    config: &'a TaintConfig,
    facts: FactTable,
    tainted: FxHashSet<(usize, NodeKey)>,
    pub alerts: Vec<SinkAlert>,
}

impl<'a> InterproceduralTaintEngine<'a> {
    pub fn new(prog: &'a ProgramSvfg<'a>, config: &'a TaintConfig) -> Self {
        Self {
            prog,
            config,
            facts: FactTable::from_config(config),
            tainted: FxHashSet::default(),
            alerts: Vec::new(),
        }
    }

    /// Merge additional (e.g. bundle-learned) facts over the default table.
    pub fn with_fact_table(mut self, facts: &FactTable) -> Self {
        self.facts.merge(facts);
        self
    }

    /// Run the BFS from all source nodes across all functions.
    pub fn run(&mut self) {
        let mut queue: VecDeque<(usize, NodeKey)> = VecDeque::new();

        // Seeds: source definitions in every function (deterministic order).
        for fi in 0..self.prog.functions.len() {
            let fe = &self.prog.functions[fi];
            let mut keys: Vec<NodeKey> = fe.svfg.nodes.keys().copied().collect();
            keys.sort_by_key(|k| (k.block.0, k.instr_idx, k.var.0));
            for k in keys {
                if is_source(fe.ir, self.config, &k) {
                    self.tainted.insert((fi, k));
                    queue.push_back((fi, k));
                }
            }
        }

        while let Some((fi, cur)) = queue.pop_front() {
            let fe = &self.prog.functions[fi];

            // Sink check at every visited node.
            if let Some(alert) = sink_alert_with_facts(fe.ir, self.config, &self.facts, &cur)
                && !self.alerts.contains(&alert)
            {
                self.alerts.push(alert);
            }

            if fe.svfg.node(&cur).is_none() {
                continue;
            }

            // Local edges (suppressed pass-through edges removed).
            for succ in self.prog.local_successors(fi, &cur) {
                if is_sanitizer_use_with_facts(fe.ir, self.config, &self.facts, &succ) {
                    continue;
                }
                self.visit(fi, succ, &mut queue);
            }

            // Interprocedural edges (actual-arg → formal-param,
            // formal-ret → actual-ret).
            for (gi, gk) in self.prog.inter_successors(fi, &cur) {
                let ge = &self.prog.functions[gi];
                if is_sanitizer_use_with_facts(ge.ir, self.config, &self.facts, &gk) {
                    continue;
                }
                self.visit(gi, gk, &mut queue);
            }
        }
    }

    fn visit(&mut self, fi: usize, key: NodeKey, queue: &mut VecDeque<(usize, NodeKey)>) {
        if self.tainted.insert((fi, key)) {
            queue.push_back((fi, key));
        }
    }

    /// The set of tainted `(function, node)` pairs, for debugging/tests.
    pub fn tainted_nodes(&self) -> &FxHashSet<(usize, NodeKey)> {
        &self.tainted
    }
}
