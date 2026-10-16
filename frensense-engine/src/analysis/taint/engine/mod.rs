// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Task 4.4: Demand-Driven Backward Taint Analysis
//!
//! The forward engines seed at **sources** and push taint through everything
//! reachable. For corpus analysis that is often wasteful: a repository may
//! have 10,000 functions but only 12 that touch a configured sink. This
//! module inverts the direction (Oracle Labs / Allen et al. 2021 style):
//!
//! ```text
//! 1. Start at each configured **sink** (its argument use-nodes).
//! 2. Walk BACKWARD along value-flow edges: which definitions could feed
//!    this sink argument?
//! 3. For each such definition, walk backward further: what feeds IT?
//! 4. Stop conditions:
//!      - a configured **source**   → real vulnerability path → alert
//!      - a configured **sanitizer** → this branch is clean → prune
//!      - a node with no further predecessors:
//!          - an unlinked formal param (callee never resolved) → **unknown**
//!          - anything else (literal, external, allocate) → clean root
//! ```
//!
//! `run` precomputes guard maps (guards + dominators) for every function
//! and probes every call site for configured sink arguments; the backward
//! walks then only expand nodes on some sink's reverse-reachable subgraph.
//! Cross edges are consulted lazily per node through a reverse index built
//! once on demand - no whole-program call graph is materialized.
//!
//! ## Soundness note
//!
//! Backward analysis is *unsound* by nature when pass-through edges are
//! suppressed (a sanitizing callee makes the local arg→dest edge vanish), so
//! this engine deliberately runs over the **unsuppressed** predecessor view:
//! it asks "could tainted data reach here?" rather than "does summary-tainted
//! data reach here?". Call it with [`BackwardEngine::with_suppression`] to
//! honour the summary-driven suppression instead (more precise, matches the
//! forward engine's alerts exactly).
//!
//! ## Verdicts
//!
//! Each explored sink argument gets a [`BackwardVerdict`]:
//! `Vulnerable` (source reached), `Sanitized` (only sanitizer-cut branches),
//! `Unknown` (unresolvable definitions on the path), or `Clean`.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::forward::{ProgramSvfg, SinkAlert, member_access_path, source_path_matches};
use crate::analysis::taint::config::TaintConfig;
use crate::analysis::taint::facts::FactTable;
use crate::analysis::taint::path::TaintPath;
use crate::graph::svfg::NodeKey;
use crate::ir::function::*;

mod context;
mod guard;
mod walk;

use self::guard::GuardMap;

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// Outcome of the backward exploration of one sink argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackwardVerdict {
    /// A configured source reaches this sink argument, real alert.
    Vulnerable,
    /// All backward paths are cut by sanitizers, safe.
    Sanitized,
    /// The backward walk hit definitions that cannot be resolved within the
    /// analysed program (unlinked params of external callees, globals with no
    /// local def, pointer sources). Manual review or a wider config needed.
    Unknown,
    /// No definitions at all feed this argument (pure literal / constant).
    Clean,
}

/// Shape classification of a finding, derived from the sink-call argument
/// shape (object-literal query payload vs raw value).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FindingClass {
    /// Taint reaches a raw injection channel (SQL string, exec, redirect...).
    #[default]
    Injection,
    /// Taint controls a field of an identity-payload query object
    /// (`findOne({ _id: taint })`), an access-control concern.
    Idor,
}

/// One explored sink argument with its verdict.
///
/// `#[non_exhaustive]`: this is an evolving output DTO. New diagnostic fields
/// (e.g. `cut_reasons` in 0.8.0) are added as minor releases; consumers read
/// fields, they do not construct literals.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SinkFinding {
    /// Function in which the sink call lives.
    pub function: String,
    pub sink: String,
    /// Formal slot of the tainted argument (receiver = slot 0 on virtual calls).
    pub arg_slot: usize,
    /// Structured sink alert (present exactly when the slot is dangerous);
    /// `None` when the slot is a safe channel.
    pub alert: Option<SinkAlert>,
    pub verdict: BackwardVerdict,
    /// Shape classification of the finding (`"idor"` for access-control
    /// query payloads, `"injection"` for everything else). Consumers rank
    /// idor findings below Critical.
    pub finding_class: FindingClass,
    /// What the sink does with its input, the primary severity signal.
    pub role: crate::analysis::taint::role::SinkRole,
    /// Semantic label slug for identity reporting (e.g. "prototype", "ssrf", "regex").
    pub label: Option<String>,
    /// Human description of the taint origin (the source access path,
    /// e.g. `req.body.target`), populated for `Vulnerable` verdicts.
    pub source_desc: Option<String>,
    /// Byte range of the sink call instruction in the source file,
    /// when the lowering recorded spans.
    pub sink_span: Option<(usize, usize)>,
    /// Reconstructed source→sink chain (vulnerable findings only; empty
    /// otherwise, and empty when path capture is disabled).
    pub path: TaintPath,
    /// Distinct reasons the backward walk was cut short on this argument
    /// (non-empty only for non-vulnerable verdicts). Each entry names a
    /// silent stop site: `"guard"`, `"value-const"`, `"sanitizer"`,
    /// `"unresolvable"`. Surfaces *where* a flow died under `--explain`;
    /// empty for vulnerable findings and for walks that simply exhausted
    /// their predecessors without hitting a source.
    pub cut_reasons: Vec<&'static str>,
}

impl SinkFinding {
    /// Start a [`SinkFindingBuilder`].
    ///
    /// `SinkFinding` is `#[non_exhaustive]`, so downstream crates cannot build
    /// it with a struct literal. This builder is the sanctioned constructor:
    /// each field starts at a neutral value and is set with a chained method.
    /// Adding a field later is a minor release (it gains a builder method).
    pub fn builder() -> SinkFindingBuilder {
        SinkFindingBuilder {
            function: String::new(),
            sink: String::new(),
            arg_slot: 0,
            alert: None,
            verdict: BackwardVerdict::Clean,
            finding_class: FindingClass::default(),
            role: crate::analysis::taint::role::SinkRole::Execution,
            label: None,
            source_desc: None,
            sink_span: None,
            path: TaintPath::default(),
            cut_reasons: Vec::new(),
        }
    }
}

/// Builder for [`SinkFinding`] (which is `#[non_exhaustive]`).
///
/// All fields start at neutral defaults; set only what you care about, then
/// call [`SinkFindingBuilder::build`].
#[derive(Debug, Clone)]
#[must_use]
pub struct SinkFindingBuilder {
    function: String,
    sink: String,
    arg_slot: usize,
    alert: Option<SinkAlert>,
    verdict: BackwardVerdict,
    finding_class: FindingClass,
    role: crate::analysis::taint::role::SinkRole,
    label: Option<String>,
    source_desc: Option<String>,
    sink_span: Option<(usize, usize)>,
    path: TaintPath,
    cut_reasons: Vec<&'static str>,
}

impl SinkFindingBuilder {
    /// Set the enclosing function name.
    pub fn function(mut self, v: impl Into<String>) -> Self {
        self.function = v.into();
        self
    }
    /// Set the sink call name.
    pub fn sink(mut self, v: impl Into<String>) -> Self {
        self.sink = v.into();
        self
    }
    /// Set the tainted argument slot (receiver = 0).
    pub fn arg_slot(mut self, v: usize) -> Self {
        self.arg_slot = v;
        self
    }
    /// Set the structured sink alert.
    pub fn alert(mut self, v: Option<SinkAlert>) -> Self {
        self.alert = v;
        self
    }
    /// Set the backward-walk verdict.
    pub fn verdict(mut self, v: BackwardVerdict) -> Self {
        self.verdict = v;
        self
    }
    /// Set the shape classification.
    pub fn finding_class(mut self, v: FindingClass) -> Self {
        self.finding_class = v;
        self
    }
    /// Set what the sink does with its input.
    pub fn role(mut self, v: crate::analysis::taint::role::SinkRole) -> Self {
        self.role = v;
        self
    }
    /// Set the identity-reporting label slug.
    pub fn label(mut self, v: Option<String>) -> Self {
        self.label = v;
        self
    }
    /// Set the human description of the taint origin.
    pub fn source_desc(mut self, v: Option<String>) -> Self {
        self.source_desc = v;
        self
    }
    /// Set the byte range of the sink call.
    pub fn sink_span(mut self, v: Option<(usize, usize)>) -> Self {
        self.sink_span = v;
        self
    }
    /// Set the reconstructed source-to-sink chain.
    pub fn path(mut self, v: TaintPath) -> Self {
        self.path = v;
        self
    }
    /// Set the distinct reasons the backward walk was cut short.
    pub fn cut_reasons(mut self, v: Vec<&'static str>) -> Self {
        self.cut_reasons = v;
        self
    }
    /// Finish, returning the [`SinkFinding`].
    pub fn build(self) -> SinkFinding {
        SinkFinding {
            function: self.function,
            sink: self.sink,
            arg_slot: self.arg_slot,
            alert: self.alert,
            verdict: self.verdict,
            finding_class: self.finding_class,
            role: self.role,
            label: self.label,
            source_desc: self.source_desc,
            sink_span: self.sink_span,
            path: self.path,
            cut_reasons: self.cut_reasons,
        }
    }
}

/// Traversal statistics, proof of the demand-driven cost model.
///
/// `#[non_exhaustive]`: evolving metrics DTO; new counters are minor releases.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct BackwardStats {
    /// `(function, node)` pairs visited during backward exploration.
    pub nodes_visited: usize,
    /// Distinct functions entered (should be ≪ total functions on big repos).
    pub functions_visited: usize,
    /// Number of sink arguments explored.
    pub sink_args_explored: usize,
    /// Per-verdict counts.
    pub vulnerable: usize,
    pub sanitized: usize,
    pub unknown: usize,
    pub clean: usize,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// One link in an interned k=1 call-site stack (phase 5): the call through
/// which the current function was entered, chained to the previous link.
#[derive(Clone, Copy)]
struct CtxLink {
    parent: u32,
    caller_fn: usize,
    site: NodeKey,
}

/// Safety valve: stack depth and total interned chains; beyond the cap the
/// context collapses to the empty stack (k=0 for that walk - sound, merely
/// less precise).
const MAX_CTX_DEPTH: usize = 8;
const MAX_CTX_CHAINS: usize = 4096;

/// Type alias for the route-registration predicate used in the engine's
/// per-call-site framing (schema §5.1 of the framework-scope doc): the
/// exact signature of the harness's `is_route_registration`.
pub type RouteRegistration = fn(
    callee_text: &str,
    spec: &dyn frensense_lang::spec::LanguageSpec,
    facts: Option<&FactTable>,
) -> bool;

/// Demand-driven backward taint engine over the whole-program SVFG.
pub struct BackwardTaintEngine<'a> {
    pub(crate) prog: &'a ProgramSvfg<'a>,
    config: &'a TaintConfig,
    /// Merged fact table (sink signatures + sanitizer facts), built once.
    facts: FactTable,
    /// If `true` (the default), honour summary-driven pass-through
    /// suppression, this is what makes "stop when you hit a sanitizer →
    /// safe" work across call boundaries: a sanitizing callee's summary
    /// removes the local arg→dest leak edge, so the backward walk proceeds
    /// through the callee's FormalRet (past its sanitizer) instead.
    honour_suppression: bool,
    /// Reverse cross-edge index, built lazily on first use:
    /// `(callee_fn, to_node) → [(caller_fn, from_node)]`.
    reverse_cross: FxHashMap<(usize, NodeKey), Vec<(usize, NodeKey)>>,

    pub findings: Vec<SinkFinding>,
    pub stats: BackwardStats,
    /// Per-function guard maps, built lazily on first entry into the fn.
    guard_maps: FxHashMap<usize, GuardMap>,
    /// Per-function value lattices, built lazily on first walk into the fn.
    /// Used to cut backward branches at provably constant/range values.
    value_infos: FxHashMap<usize, crate::analysis::value::ValueInfo>,
    /// Bounded k=1 call-site stacks (phase 5): interned chains of
    /// `(caller_fn, call_site)` entries. Id 0 is the empty stack (k=0).
    /// The stack top is the call site through which the *current* function
    /// was entered; `FormalParam` crossings keep only that site's actual
    /// arguments. Over-cap chains collapse to 0 (k→0, sound).
    ctx_chains: Vec<CtxLink>,
    ctx_interner: FxHashMap<(u32, usize, NodeKey), u32>,
    /// Function-name → source-file mapping for path step locations
    /// (populated via [`with_fn_file`]; empty in tests without files).
    pub(crate) fn_file: FxHashMap<String, String>,
    /// Per-file external package imports: `file_path -> local_name -> PackageImport`.
    pub(crate) file_package_imports:
        FxHashMap<String, FxHashMap<String, crate::graph::module::PackageImport>>,
    /// Route-registration predicate for per-call-site framing, wired from
    /// the harness via [`BackwardTaintEngine::with_route_registration`]
    /// (schema §5.1 of the framework-scope doc). Consulted before a
    /// framework-stemmable receiver is treated as a source; `None` keeps
    /// the pre-wiring behaviour (spec verbs only, no pack route patterns).
    pub route_registration: Option<RouteRegistration>,
    /// When `true`, reconstruct the walked source→sink chain per vulnerable
    /// finding (small extra bookkeeping; path reporting needs it).
    capture_paths: bool,
    /// BFS parent of each visited node for the *current* root exploration,
    /// consumed right after `explore_from` in `explore_call_site`.
    pub(crate) current_parents: FxHashMap<(usize, NodeKey), (usize, NodeKey)>,
}

/// Per-root exploration state (not per-node: a node can be re-explored from
/// another sink root with a different outcome, that's the point of verdicts).
#[derive(Default)]
struct ExploreState {
    sink_role: crate::analysis::taint::role::SinkRole,
    sink_label: Option<String>,
    saw_source: bool,
    /// The first source node reached (for path reconstruction).
    source_node: Option<(usize, NodeKey)>,
    /// Human description of the first source found (access path / call name).
    source_desc: Option<String>,
    saw_sanitized_root_only: bool,
    saw_unknown: bool,
    /// Nodes whose predecessors were fully expanded for this root, keyed by
    /// `(function, node, use-context block, field-demand, call-site context)`.
    /// The context is part of the key because the guard-stop decision is
    /// context-dependent: a shared node first visited with a guard-stopped
    /// context must still be expanded when reached again with an unguarded
    /// context (bounded by O(E) - a node re-enqueues at most once per
    /// distinct consumer block).
    ///
    /// The demand flag distinguishes walks that read a *specific field*
    /// (`sink(o.f)` - value arrives only through field-matching store edges)
    /// from walks that consume the container *as a whole* (`sink(o)` - every
    /// stored value counts). A field-demand walk reaching an allocation must
    /// not follow the whole-container fill edges back into sibling stores.
    ///
    /// The context is the interned k=1 call-site stack (phase 5): the same
    /// node entered through a different invocation is a distinct state.
    visited: FxHashSet<(usize, NodeKey, BlockId, bool, u32)>,
    /// Distinct `(function, node)` pairs seen, for stats only.
    seen_nodes: FxHashSet<(usize, NodeKey)>,
    /// Silent stop sites hit during this root's exploration, for
    /// `--explain` diagnostics (pure bookkeeping; no analysis effect).
    cuts: Vec<&'static str>,
}

/// Human-readable description of the taint origin at a source node:
/// the source call name (`.getQuery()`) or the member access path
/// (`req.body.args`). Returns `None` when the node is not a source.
pub(crate) fn source_description(
    ir: &FunctionIR,
    config: &TaintConfig,
    key: &NodeKey,
) -> Option<String> {
    let NodeKey {
        block,
        instr_idx: Some(idx),
        var,
    } = *key
    else {
        return None;
    };
    let b = ir.blocks.get(&block)?;
    if idx >= b.instructions.len() {
        // Parameter sentinel: the source is the parameter's own name.
        return ir
            .var_metadata
            .get(&var)
            .and_then(|m| m.source_name.clone())
            .filter(|n| config.sources.contains(n));
    }
    match &b.instructions[idx] {
        Instruction::CallStatic {
            func,
            dest: Some(d),
            ..
        } if config.sources.contains(func) && *d == var => Some(func.clone()),
        Instruction::CallVirtual {
            method,
            dest: Some(d),
            receiver,
            ..
        } if *d == var => {
            // Module-qualified calls (`random.randint(...)`) lower as
            // CallVirtual: prefer the full `receiver.method` path (dotted
            // source facts), fall back to the bare method name.
            if config.sources.contains(method) {
                return Some(method.clone());
            }
            if let Operand::Var(r) = receiver
                && let Some(root) = crate::analysis::taint::facts::FactTable::receiver_root(ir, *r)
            {
                let path = format!("{root}.{method}");
                if config.sources.contains(&path)
                    || config.sources.iter().any(|s| {
                        path.starts_with(s.as_str()) && path.as_bytes().get(s.len()) == Some(&b'.')
                    })
                {
                    return Some(path);
                }
            }
            None
        }
        Instruction::LoadField { base, field, .. } => {
            let path = member_access_path(ir, *base, field);
            let root = path.split('.').next().unwrap_or("");
            if source_path_matches(config, &path, root) {
                Some(path)
            } else {
                None
            }
        }
        _ => None,
    }
}

impl<'a> BackwardTaintEngine<'a> {
    pub fn new(prog: &'a ProgramSvfg<'a>, config: &'a TaintConfig) -> Self {
        Self {
            prog,
            config,
            facts: FactTable::from_config(config),
            route_registration: None,
            honour_suppression: true,
            reverse_cross: FxHashMap::default(),
            guard_maps: FxHashMap::default(),
            value_infos: FxHashMap::default(),
            ctx_chains: vec![CtxLink {
                parent: 0,
                caller_fn: 0,
                site: NodeKey::phi(BlockId(0), VarId(0)),
            }],
            ctx_interner: FxHashMap::default(),
            capture_paths: true,
            current_parents: FxHashMap::default(),
            fn_file: FxHashMap::default(),
            file_package_imports: FxHashMap::default(),
            findings: Vec::new(),
            stats: BackwardStats::default(),
        }
    }

    /// Merge additional (e.g. bundle-learned) facts over the built-in table.
    /// Bundle-learned source patterns must be merged into the scan's
    /// `TaintConfig` by the caller (see `FactTable::source_patterns`):
    /// this engine holds the config behind a shared reference.
    pub fn with_fact_table(mut self, facts: &FactTable) -> Self {
        self.facts.merge(facts);
        self
    }

    /// Provide the function-name → source-file mapping so captured taint
    /// paths carry real file locations per step (cross-function and
    /// cross-file flows otherwise report the function name as the file).
    pub fn with_fn_file(mut self, fn_file: &FxHashMap<String, String>) -> Self {
        self.fn_file = fn_file.clone();
        self
    }

    /// Wire the harness's `is_route_registration` predicate into the engine
    /// so the backward analysis consults it before arming a framework
    /// origin (schema §5.1 of the framework-scope doc).
    pub fn with_route_registration(mut self, predicate: RouteRegistration) -> Self {
        self.route_registration = Some(predicate);
        self
    }

    pub fn with_file_package_imports(
        mut self,
        imports: &FxHashMap<String, FxHashMap<String, crate::graph::module::PackageImport>>,
    ) -> Self {
        self.file_package_imports = imports.clone();
        self
    }

    /// Disable summary-driven pass-through suppression (over-approximating
    /// mode: any caller-side arg→dest edge leaks the walk past sanitizing
    /// callees, so verdicts may be `Vulnerable` where the precise mode says
    /// `Sanitized`). Useful as a sound upper bound.
    pub fn without_suppression(mut self) -> Self {
        self.honour_suppression = false;
        self
    }

    /// Toggle taint-path capture (on by default). Turning it off saves the
    /// per-root parent map when path reporting is not needed.
    pub fn capture_paths(mut self, yes: bool) -> Self {
        self.capture_paths = yes;
        self
    }

    /// Build the reverse cross-edge index once.
    fn ensure_reverse_index(&mut self) {
        if !self.reverse_cross.is_empty() {
            return;
        }
        for ((from_f, from_k), edges) in &self.prog.cross_edges {
            for (to_f, to_k) in edges {
                self.reverse_cross
                    .entry((*to_f, *to_k))
                    .or_default()
                    .push((*from_f, *from_k));
            }
        }
        for v in self.reverse_cross.values_mut() {
            v.sort_by_key(|(f, k)| (*f, k.block.0, k.instr_idx, k.var.0));
            v.dedup();
        }
    }

    /// The per-function value lattice for `fi`, computed once on first use.
    fn value_info_for(&mut self, fi: usize) -> Option<&crate::analysis::value::ValueInfo> {
        if !self.value_infos.contains_key(&fi) {
            let ir = self.prog.functions[fi].ir;
            self.value_infos
                .insert(fi, crate::analysis::value::analyze(ir));
        }
        self.value_infos.get(&fi)
    }

    /// Run the demand-driven analysis over every configured sink argument.
    pub fn run(&mut self) {
        self.ensure_reverse_index();

        for fi in 0..self.prog.functions.len() {
            let ir = self.prog.functions[fi].ir;
            // Guard map per function (task 8.3): guards + dominators.
            // Package-import context arms package-scoped guard-style
            // sanitizers through their import origin (single-file
            // fallback when the function's own file is untracked).
            let fn_name = self.prog.functions[fi].name.clone();
            let imports = self
                .fn_file
                .get(&fn_name)
                .and_then(|file| self.file_package_imports.get(file))
                .or_else(|| {
                    if self.file_package_imports.len() == 1 {
                        self.file_package_imports.values().next()
                    } else {
                        None
                    }
                });
            self.guard_maps
                .entry(fi)
                .or_insert_with(|| GuardMap::build(ir, &self.facts, self.config, imports));
            let mut block_ids: Vec<BlockId> = ir.blocks.keys().copied().collect();
            block_ids.sort_by_key(|b| b.0);

            for &block in &block_ids {
                let bdata = &ir.blocks[&block];
                for (idx, instr) in bdata.instructions.iter().enumerate() {
                    self.explore_call_site(fi, block, idx, instr);
                }
            }
        }
    }
}
