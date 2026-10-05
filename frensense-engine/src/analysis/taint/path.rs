// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Taint-path representation (R3c).
//!
//! A taint path is the ordered chain of SVFG nodes the
//! [`BackwardTaintEngine`](super::engine::BackwardTaintEngine) walked from a
//! sink argument back to a source. It is intentionally *data*: the engine only
//! records it; rendering (text/SARIF/LSP) lives in the consumer. Keeping
//! capture and rendering apart means new output formats never touch the
//! engine.

use std::fmt::Write as _;

use rustc_hash::FxHashMap;

use super::engine::BackwardTaintEngine;
use crate::graph::svfg::{NodeKey, NodeKind};
use crate::ir::function::{FunctionIR, Instruction};

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// One step on a taint path, in **source → sink** order (the walk runs the
/// other way; [`TaintPath::new`] reverses it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathStep {
    /// The origin: a configured source (access path or call name).
    Source { description: String },
    /// A `phi` merging several incoming values.
    Phi { function: String, variable: u32 },
    /// A load from an object field (`x = obj.f`).
    FieldLoad {
        function: String,
        base: String,
        field: String,
    },
    /// A value returned by a call (interprocedural hop into the callee).
    CallReturn {
        function: String,
        callee: String,
        /// `true` when the callee could not be resolved in-program.
        external: bool,
    },
    /// A value passed as an argument at a call site (hop into the callee).
    CallArgument {
        function: String,
        callee: String,
        slot: usize,
    },
    /// A value bound to a callee's formal parameter (callee side of the hop).
    FormalParam { function: String, param: String },
    /// A value returned from a callee back to its call site (callee→caller).
    ReturnToCaller { caller: String },
    /// Any other def→use propagation inside one function.
    Assignment { function: String, variable: u32 },
}

impl PathStep {
    /// Function this step lives in (source steps have no function).
    pub fn function(&self) -> Option<&str> {
        match self {
            PathStep::Source { .. } => None,
            PathStep::ReturnToCaller { .. } => None,
            PathStep::Phi { function, .. }
            | PathStep::FieldLoad { function, .. }
            | PathStep::CallReturn { function, .. }
            | PathStep::CallArgument { function, .. }
            | PathStep::FormalParam { function, .. }
            | PathStep::Assignment { function, .. } => Some(function),
        }
    }

    /// Deterministic one-line description (used by both text and SARIF output).
    pub fn describe(&self) -> String {
        match self {
            PathStep::Source { description } => {
                format!("source: `{description}`")
            }
            PathStep::Phi { function, variable } => {
                format!("`{function}`: merge of incoming values (v{variable})")
            }
            PathStep::FieldLoad {
                function,
                base,
                field,
            } => format!("`{function}`: reads `{base}.{field}`"),
            PathStep::CallReturn {
                function,
                callee,
                external,
            } => {
                if *external {
                    format!("`{function}`: value from unresolvable call `{callee}`")
                } else {
                    format!("`{function}`: value returned by `{callee}`")
                }
            }
            PathStep::CallArgument {
                function,
                callee,
                slot,
            } => format!("`{function}`: passes value to `{callee}` (arg {slot})"),
            PathStep::FormalParam { function, param } => {
                format!("`{function}`: enters as parameter `{param}`")
            }
            PathStep::ReturnToCaller { caller } => {
                format!("returns into `{caller}`")
            }
            PathStep::Assignment { function, variable } => {
                format!("`{function}`: flows through v{variable}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Path
// ---------------------------------------------------------------------------

/// The full source→sink chain for one vulnerable finding.
#[derive(Debug, Clone, Default)]
pub struct TaintPath {
    /// Steps in source→sink order. Empty for non-vulnerable findings.
    pub steps: Vec<PathStep>,
    /// (function, byte-range) of each step, aligned with `steps` where the
    /// lowering recorded a span. Sources have no function, so their entry is
    /// `None`.
    pub spans: Vec<Option<(String, (usize, usize))>>,
}

impl TaintPath {
    /// Build a path from a sink→source walk (parent chain), reversing it into
    /// source→sink order. `chain` yields `(function_name, function_ir, node,
    /// step)` from the sink backwards; source steps must already carry their
    /// description. `fn_file` maps function names to their source files so
    /// step spans point at real files (unmapped functions, engine-internal
    /// tests without files, keep the function name as a pseudo-file).
    pub(crate) fn new(
        chain: Vec<(String, FunctionIR, NodeKey, PathStep)>,
        source_desc: Option<String>,
        fn_file: &FxHashMap<String, String>,
    ) -> Self {
        let mut steps = Vec::with_capacity(chain.len() + 1);
        let mut spans = Vec::with_capacity(chain.len() + 1);
        // Source first (the chain starts at the sink).
        steps.push(PathStep::Source {
            description: source_desc.unwrap_or_else(|| "unknown origin".into()),
        });
        spans.push(None);
        // The chain runs sink→source; walk it backwards for source→sink.
        for (fname, ir, key, step) in chain.iter().rev() {
            let _ = (fname, key);
            let file = fn_file
                .get(&ir.name)
                .cloned()
                .unwrap_or_else(|| ir.name.clone());
            let span = span_of(ir, key).map(|r| (file, r));
            steps.push(step.clone());
            spans.push(span);
        }
        Self { steps, spans }
    }

    /// Stable identity of the path's *shape*: the sequence of step kinds with
    /// function names, but no variable numbers. Two findings whose paths
    /// differ only in SSA numbering dedup to the same shape.
    pub fn shape_id(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for s in &self.steps {
            match s {
                PathStep::Source { description: _ } => "src".hash(&mut h),
                PathStep::Phi { .. } => "phi".hash(&mut h),
                PathStep::FieldLoad {
                    function, field, ..
                } => format!("fld:{function}.{field}").hash(&mut h),
                PathStep::CallReturn {
                    function, callee, ..
                } => format!("ret:{function}>{callee}").hash(&mut h),
                PathStep::CallArgument {
                    function,
                    callee,
                    slot,
                } => format!("arg:{function}>{callee}#{slot}").hash(&mut h),
                PathStep::FormalParam { function, .. } => format!("par:{function}").hash(&mut h),
                PathStep::ReturnToCaller { caller } => format!("back:{caller}").hash(&mut h),
                PathStep::Assignment { .. } => "asn".hash(&mut h),
            }
        }
        format!("{:016x}", h.finish())
    }

    /// Render as an indented multi-line text block (CLI output).
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        for (i, step) in self.steps.iter().enumerate() {
            let _ = writeln!(out, "  {:>2}. {}", i + 1, step.describe());
        }
        out
    }
}

/// Dedup helper: keep one representative per shape, preferring the finding
/// with the most steps (most informative path). Returns indices into `paths`.
pub fn dedup_by_shape(paths: &[TaintPath]) -> Vec<usize> {
    let mut best: FxHashMap<String, usize> = FxHashMap::default();
    for (i, p) in paths.iter().enumerate() {
        match best.get(&p.shape_id()) {
            Some(&j) if paths[j].steps.len() >= p.steps.len() => {}
            _ => {
                best.insert(p.shape_id(), i);
            }
        }
    }
    let mut kept: Vec<usize> = best.into_values().collect();
    kept.sort_unstable();
    kept
}

/// Byte range of the instruction (or param sentinel) a node points at.
pub(crate) fn span_of(ir: &FunctionIR, key: &NodeKey) -> Option<(usize, usize)> {
    let idx = key.instr_idx?;
    let b = ir.blocks.get(&key.block)?;
    let instr = b.instructions.get(idx)?;
    match instr {
        Instruction::CallStatic { dest, .. }
        | Instruction::CallVirtual { dest, .. }
        | Instruction::CallPointer { dest, .. } => dest
            .and_then(|d| ir.var_metadata.get(&d))
            .and_then(|m| m.byte_range)
            .or_else(|| ir.var_metadata.get(&key.var).and_then(|m| m.byte_range)),
        _ => ir.var_metadata.get(&key.var).and_then(|m| m.byte_range),
    }
}

// ---------------------------------------------------------------------------
// Reconstruction of a walked source->sink chain (engine impl lives here so
// rendering stays next to the path types).
// ---------------------------------------------------------------------------

impl<'a> BackwardTaintEngine<'a> {
    /// Classify one walked node as a [`PathStep`] for path reporting.
    fn step_of(&self, cf: usize, key: &NodeKey) -> PathStep {
        let fe = &self.prog.functions[cf];
        let ir = fe.ir;
        let fname = ir.name.clone();
        let Some(node) = fe.svfg.node(key) else {
            return PathStep::Assignment {
                function: fname,
                variable: key.var.0 as u32,
            };
        };
        match &node.kind {
            NodeKind::Phi => PathStep::Phi {
                function: fname,
                variable: key.var.0 as u32,
            },
            NodeKind::FormalParam => {
                let name = ir
                    .var_metadata
                    .get(&key.var)
                    .and_then(|m| m.source_name.clone())
                    .unwrap_or_else(|| format!("v{}", key.var.0));
                PathStep::FormalParam {
                    function: fname,
                    param: name,
                }
            }
            NodeKind::ActualArg {
                call_site,
                arg_index,
            } => PathStep::CallArgument {
                function: fname,
                callee: self.callee_display(ir, call_site),
                slot: *arg_index,
            },
            NodeKind::ActualRet { call_site } => {
                let callee = self.callee_display(ir, call_site);
                let external = !self.prog.functions.iter().any(|f| f.ir.name == callee);
                PathStep::CallReturn {
                    function: fname,
                    callee,
                    external,
                }
            }
            NodeKind::FormalRet => PathStep::ReturnToCaller { caller: fname },
            NodeKind::InstrDef | NodeKind::InstrUse => self.instr_step(ir, key, fname),
        }
    }

    /// Display name of the callee at a call-site node key.
    fn callee_display(&self, ir: &FunctionIR, call_site: &NodeKey) -> String {
        let Some(idx) = call_site.instr_idx else {
            return "?".into();
        };
        match ir
            .blocks
            .get(&call_site.block)
            .and_then(|b| b.instructions.get(idx))
        {
            Some(Instruction::CallStatic { func, .. }) => func.clone(),
            Some(Instruction::CallVirtual { method, .. }) => method.clone(),
            _ => "?".into(),
        }
    }

    /// Instruction-level step: field loads become `FieldLoad`, everything
    /// else a generic `Assignment` (variable-level flow).
    fn instr_step(&self, ir: &FunctionIR, key: &NodeKey, fname: String) -> PathStep {
        let Some(idx) = key.instr_idx else {
            return PathStep::Assignment {
                function: fname,
                variable: key.var.0 as u32,
            };
        };
        let Some(b) = ir.blocks.get(&key.block) else {
            return PathStep::Assignment {
                function: fname,
                variable: key.var.0 as u32,
            };
        };
        match b.instructions.get(idx) {
            Some(Instruction::LoadField { base, field, .. }) => {
                let base_name = ir
                    .var_metadata
                    .get(base)
                    .and_then(|m| m.source_name.clone())
                    .unwrap_or_else(|| format!("v{}", base.0));
                PathStep::FieldLoad {
                    function: fname,
                    base: base_name,
                    field: field.clone(),
                }
            }
            _ => PathStep::Assignment {
                function: fname,
                variable: key.var.0 as u32,
            },
        }
    }

    /// Walk the BFS parent map from the sink argument back to the source and
    /// build the source→sink [`TaintPath`].
    pub(super) fn reconstruct_path(
        &self,
        source_node: Option<(usize, NodeKey)>,
        source_desc: Option<String>,
    ) -> TaintPath {
        let mut chain: Vec<(String, FunctionIR, NodeKey, PathStep)> = Vec::new();
        // The parent map maps each visited node → its BFS parent (the node
        // one step closer to the sink). The chain therefore runs from the
        // source (which has no parent entry, BFS stopped there) to the node
        // just before the sink argument. The sink node itself is not a step:
        // the finding already reports it.
        let Some((sf, skey)) = source_node else {
            return TaintPath::new(chain, source_desc, &self.fn_file);
        };
        let mut cur = (sf, skey);
        for _ in 0..self.current_parents.len() + 1 {
            let (cf, key) = cur;
            let ir = self.prog.functions[cf].ir.clone();
            let step = self.step_of(cf, &key);
            chain.push((ir.name.clone(), ir, key, step));
            match self.current_parents.get(&cur) {
                Some(&parent) => cur = parent,
                None => break,
            }
        }
        TaintPath::new(chain, source_desc, &self.fn_file)
    }
}
