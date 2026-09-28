// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Spatial memory safety checker: buffer overflow and out-of-bounds (OOB) access
//! over lowered IR using value lattice intervals and Steensgaard points-to classes.
//!
//! Catches spatial memory safety violations (Limitation M3):
//! - Buffer write overflows (`StoreElement`, `memset`, `memcpy`, `strncpy`, `snprintf`, etc.)
//! - Out-of-bounds reads (`LoadElement`, `memcpy` src, `memmove` src)
//! - Negative index accesses (`buf[-1]`, `buf[idx]` where `idx < 0`)
//! - Off-by-one errors (e.g. `idx <= size` guard instead of `idx < size`)
//! - Aliased pointer buffer overflows tracked via Steensgaard points-to analysis
//!
//! Zero-FP by construction: only buffers with a provable allocation provenance
//! in the same function (`malloc`, `calloc`, `realloc`, `aligned_alloc`, `valloc`, `alloca`)
//! participate. Pointers from unprovable parameters or externals are skipped.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::analysis::value::{self, ValueInfo};
use crate::checks::CheckerFinding;
use crate::checks::memory_summary::{CapacitySpec, MemorySummaryRegistry};
use crate::graph::steensgaard::{ClassId, Steensgaard};
use crate::ir::function::{BasicBlock, BlockId, FunctionIR, Instruction, Operand, VarId};

/// Callee last segments that allocate memory with a known capacity.
const ALLOC_CALLS: &[&str] = &[
    "malloc",
    "calloc",
    "realloc",
    "aligned_alloc",
    "valloc",
    "alloca",
];

/// Known memory manipulation builtins that copy, write, or fill buffers.
struct BuiltinSpec {
    name: &'static str,
    dst_arg: Option<usize>,
    src_arg: Option<usize>,
    len_arg: usize,
}

const BUILTINS: &[BuiltinSpec] = &[
    BuiltinSpec {
        name: "memset",
        dst_arg: Some(0),
        src_arg: None,
        len_arg: 2,
    },
    BuiltinSpec {
        name: "bzero",
        dst_arg: Some(0),
        src_arg: None,
        len_arg: 1,
    },
    BuiltinSpec {
        name: "memcpy",
        dst_arg: Some(0),
        src_arg: Some(1),
        len_arg: 2,
    },
    BuiltinSpec {
        name: "memmove",
        dst_arg: Some(0),
        src_arg: Some(1),
        len_arg: 2,
    },
    BuiltinSpec {
        name: "strncpy",
        dst_arg: Some(0),
        src_arg: None,
        len_arg: 2,
    },
    BuiltinSpec {
        name: "snprintf",
        dst_arg: Some(0),
        src_arg: None,
        len_arg: 1,
    },
    BuiltinSpec {
        name: "fgets",
        dst_arg: Some(0),
        src_arg: None,
        len_arg: 1,
    },
    BuiltinSpec {
        name: "read",
        dst_arg: Some(1),
        src_arg: None,
        len_arg: 2,
    },
];

fn last_segment(call: &str) -> &str {
    let s = call.rsplit('.').next().unwrap_or(call);
    s.rsplit("::").next().unwrap_or(s)
}

/// A spatial memory safety violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// Memory write past allocated capacity.
    BufferOverflow,
    /// Memory read past allocated capacity.
    OutOfBoundsRead,
    /// Negative subscript index access.
    OutOfBoundsAccess,
}

/// Buffer capacity metadata tracked per points-to class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferInfo {
    /// Guaranteed minimum capacity in bytes/elements.
    pub capacity_lo: i64,
    /// Maximum capacity in bytes/elements.
    pub capacity_hi: i64,
    /// Allocation site byte range, if known.
    pub span: Option<(usize, usize)>,
}

/// Forward path state for tracking buffer provenance and capacities.
#[derive(Default, Clone)]
struct PathState {
    /// Tracked buffers per points-to class.
    buffers: FxHashMap<ClassId, BufferInfo>,
    /// Maps each variable to the specific allocation generation it holds.
    generation: FxHashMap<VarId, ClassId>,
    /// Variables overwritten with non-allocation values.
    dead: FxHashSet<VarId>,
}

impl PathState {
    fn class_for(&self, pts: &Steensgaard, v: VarId) -> Option<ClassId> {
        if self.dead.contains(&v) {
            return None;
        }
        self.generation
            .get(&v)
            .copied()
            .or_else(|| pts.class_of.get(&v).copied())
    }
}

/// Evaluate an integer interval for an operand at a specific basic block.
fn eval_range(op: &Operand, block: BlockId, val_info: &ValueInfo) -> Option<(i64, i64)> {
    match op {
        Operand::IntLiteral(k) => Some((*k, *k)),
        Operand::Var(v) => {
            if let Some((lo, hi)) = val_info.range_at(block, *v) {
                return Some((lo, hi));
            }
            if let Some(c) = val_info.const_int_at(block, *v) {
                return Some((c, c));
            }
            if let Some((lo, hi)) = val_info.range(*v) {
                return Some((lo, hi));
            }
            if let Some(c) = val_info.const_int(*v) {
                return Some((c, c));
            }
            None
        }
        _ => None,
    }
}

/// Evaluate an allocation's size in bytes/elements.
fn eval_alloc_capacity(
    func: &str,
    args: &[Operand],
    block: BlockId,
    val_info: &ValueInfo,
    summaries: &MemorySummaryRegistry,
) -> Option<(i64, i64)> {
    let seg = last_segment(func);
    match seg {
        "malloc" | "valloc" | "alloca" => {
            let (lo, hi) = eval_range(args.first()?, block, val_info)?;
            if lo >= 0 { Some((lo, hi)) } else { None }
        }
        "calloc" => {
            let (n_lo, n_hi) = eval_range(args.first()?, block, val_info)?;
            let (sz_lo, sz_hi) = eval_range(args.get(1)?, block, val_info)?;
            if n_lo >= 0 && sz_lo >= 0 {
                Some((n_lo.saturating_mul(sz_lo), n_hi.saturating_mul(sz_hi)))
            } else {
                None
            }
        }
        "realloc" | "aligned_alloc" => {
            let (lo, hi) = eval_range(args.get(1)?, block, val_info)?;
            if lo >= 0 { Some((lo, hi)) } else { None }
        }
        _ => {
            if let Some(spec) = summaries.return_capacity(func) {
                match spec {
                    CapacitySpec::Exact(k) => Some((*k, *k)),
                    CapacitySpec::Param(p_idx) => {
                        let (lo, hi) = eval_range(args.get(*p_idx)?, block, val_info)?;
                        if lo >= 0 { Some((lo, hi)) } else { None }
                    }
                    CapacitySpec::ParamProduct(p1, p2) => {
                        let (n_lo, n_hi) = eval_range(args.get(*p1)?, block, val_info)?;
                        let (sz_lo, sz_hi) = eval_range(args.get(*p2)?, block, val_info)?;
                        if n_lo >= 0 && sz_lo >= 0 {
                            Some((n_lo.saturating_mul(sz_lo), n_hi.saturating_mul(sz_hi)))
                        } else {
                            None
                        }
                    }
                    CapacitySpec::Unknown => None,
                }
            } else {
                None
            }
        }
    }
}

fn var_name(ir: &FunctionIR, var: VarId) -> String {
    ir.var_metadata
        .get(&var)
        .and_then(|m| m.source_name.clone())
        .unwrap_or_else(|| format!("v{}", var.0))
}

fn var_span(ir: &FunctionIR, var: VarId) -> Option<(usize, usize)> {
    ir.var_metadata.get(&var).and_then(|m| m.byte_range)
}

fn operand_span(ir: &FunctionIR, op: &Operand) -> Option<(usize, usize)> {
    match op {
        Operand::Var(v) => var_span(ir, *v),
        _ => None,
    }
}

fn format_range(lo: i64, hi: i64) -> String {
    if lo == hi {
        format!("{lo}")
    } else {
        format!("[{lo}, {hi}]")
    }
}

fn finding(
    ir: &FunctionIR,
    violation: Violation,
    message: String,
    span: Option<(usize, usize)>,
) -> CheckerFinding {
    let rule = match violation {
        Violation::BufferOverflow => "buffer_overflow",
        Violation::OutOfBoundsRead => "out_of_bounds_read",
        Violation::OutOfBoundsAccess => "out_of_bounds_access",
    };
    CheckerFinding {
        function: ir.name.clone(),
        rule: rule.to_string(),
        message,
        span,
        learned: false,
    }
}

/// Run spatial memory safety checks over one function with default summaries.
pub fn check(ir: &FunctionIR) -> Vec<CheckerFinding> {
    check_with_summaries(ir, &MemorySummaryRegistry::default())
}

/// Run spatial memory safety checks over one function with an interprocedural memory summary registry.
pub fn check_with_summaries(
    ir: &FunctionIR,
    summaries: &MemorySummaryRegistry,
) -> Vec<CheckerFinding> {
    let pts = Steensgaard::analyze(ir);
    let val_info = value::analyze(ir);
    let mut findings: Vec<CheckerFinding> = Vec::new();

    #[allow(clippy::too_many_arguments)]
    fn check_access(
        ir: &FunctionIR,
        findings: &mut Vec<CheckerFinding>,
        base: VarId,
        buf: &BufferInfo,
        idx_lo: i64,
        idx_hi: i64,
        is_write: bool,
        span: Option<(usize, usize)>,
    ) {
        let name = var_name(ir, base);
        if idx_lo < 0 {
            findings.push(finding(
                ir,
                Violation::OutOfBoundsAccess,
                format!(
                    "Out-of-bounds access: index {} for buffer `{}` is negative",
                    format_range(idx_lo, idx_hi),
                    name
                ),
                span,
            ));
        } else if idx_hi >= buf.capacity_lo {
            let (violation, prefix) = if is_write {
                (Violation::BufferOverflow, "Buffer overflow")
            } else {
                (Violation::OutOfBoundsRead, "Out-of-bounds read")
            };
            findings.push(finding(
                ir,
                violation,
                format!(
                    "{}: index {} exceeds buffer `{}` capacity {}",
                    prefix,
                    format_range(idx_lo, idx_hi),
                    name,
                    format_range(buf.capacity_lo, buf.capacity_hi)
                ),
                span,
            ));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn visit_block(
        ir: &FunctionIR,
        pts: &Steensgaard,
        val_info: &ValueInfo,
        summaries: &MemorySummaryRegistry,
        findings: &mut Vec<CheckerFinding>,
        mut ps: PathState,
        block_id: BlockId,
        block: &BasicBlock,
    ) -> Option<PathState> {
        for instr in &block.instructions {
            match instr {
                // --- Allocation provenance ---
                Instruction::CallStatic {
                    func,
                    dest: Some(d),
                    args,
                    ..
                } if ALLOC_CALLS.contains(&last_segment(func)) || summaries.returns_fresh(func) => {
                    let fresh = ClassId(pts.members.len() + ps.generation.len() + d.0 + 1000);
                    if let Some((cap_lo, cap_hi)) =
                        eval_alloc_capacity(func, args, block_id, val_info, summaries)
                    {
                        ps.buffers.insert(
                            fresh,
                            BufferInfo {
                                capacity_lo: cap_lo,
                                capacity_hi: cap_hi,
                                span: var_span(ir, *d),
                            },
                        );
                    }
                    ps.generation.insert(*d, fresh);
                    ps.dead.remove(d);
                }

                // --- Freeing a buffer / Consumed parameters ---
                Instruction::CallStatic { func, args, .. } => {
                    let consumed_slots = if last_segment(func) == "free" {
                        vec![0]
                    } else {
                        summaries.consumes_params(func)
                    };
                    for slot in consumed_slots {
                        if let Some(Operand::Var(v)) = args.get(slot)
                            && let Some(c) = ps.class_for(pts, *v)
                        {
                            ps.buffers.remove(&c);
                            ps.dead.insert(*v);
                        }
                    }
                    let seg = last_segment(func);
                    if let Some(spec) = BUILTINS.iter().find(|b| b.name == seg) {
                        // Check destination write bounds
                        if let Some(dst_idx) = spec.dst_arg
                            && let Some(Operand::Var(dst_var)) = args.get(dst_idx)
                            && let Some(c) = ps.class_for(pts, *dst_var)
                            && let Some(buf) = ps.buffers.get(&c)
                            && let Some(len_op) = args.get(spec.len_arg)
                            && let Some((len_lo, len_hi)) = eval_range(len_op, block_id, val_info)
                            && len_hi > buf.capacity_lo
                        {
                            let name = var_name(ir, *dst_var);
                            let size_desc = format_range(len_lo, len_hi);
                            let cap_desc = format_range(buf.capacity_lo, buf.capacity_hi);
                            let span = var_span(ir, *dst_var).or_else(|| operand_span(ir, len_op));
                            findings.push(finding(
                                                        ir,
                                                        Violation::BufferOverflow,
                                                        format!(
                                                            "Buffer overflow: write size {} exceeds destination buffer `{}` capacity {}",
                                                            size_desc, name, cap_desc
                                                        ),
                                                        span,
                                                    ));
                        }

                        // Check source read bounds
                        if let Some(src_idx) = spec.src_arg
                            && let Some(Operand::Var(src_var)) = args.get(src_idx)
                            && let Some(c) = ps.class_for(pts, *src_var)
                            && let Some(buf) = ps.buffers.get(&c)
                            && let Some(len_op) = args.get(spec.len_arg)
                            && let Some((len_lo, len_hi)) = eval_range(len_op, block_id, val_info)
                            && len_hi > buf.capacity_lo
                        {
                            let name = var_name(ir, *src_var);
                            let size_desc = format_range(len_lo, len_hi);
                            let cap_desc = format_range(buf.capacity_lo, buf.capacity_hi);
                            let span = var_span(ir, *src_var).or_else(|| operand_span(ir, len_op));
                            findings.push(finding(
                                                        ir,
                                                        Violation::OutOfBoundsRead,
                                                        format!(
                                                            "Out-of-bounds read: read size {} exceeds source buffer `{}` capacity {}",
                                                            size_desc, name, cap_desc
                                                        ),
                                                        span,
                                                    ));
                        }
                    }
                }

                // --- StoreElement / StoreField (numeric index): write to base[index] ---
                Instruction::StoreElement {
                    base, index, src, ..
                } => {
                    if let Some(c) = ps.class_for(pts, *base)
                        && let Some(buf) = ps.buffers.get(&c)
                        && let Some((idx_lo, idx_hi)) = eval_range(index, block_id, val_info)
                    {
                        let span = operand_span(ir, index)
                            .or_else(|| var_span(ir, *base))
                            .or_else(|| operand_span(ir, src));
                        check_access(ir, findings, *base, buf, idx_lo, idx_hi, true, span);
                    }
                }

                Instruction::StoreField {
                    base, field, src, ..
                } => {
                    if let Ok(idx) = field.parse::<i64>()
                        && let Some(c) = ps.class_for(pts, *base)
                        && let Some(buf) = ps.buffers.get(&c)
                    {
                        let span = var_span(ir, *base).or_else(|| operand_span(ir, src));
                        check_access(ir, findings, *base, buf, idx, idx, true, span);
                    }
                }

                // --- LoadElement / LoadField (numeric index): read from base[index] ---
                Instruction::LoadElement {
                    dest, base, index, ..
                } => {
                    if let Some(c) = ps.class_for(pts, *base)
                        && let Some(buf) = ps.buffers.get(&c)
                        && let Some((idx_lo, idx_hi)) = eval_range(index, block_id, val_info)
                    {
                        let span = operand_span(ir, index)
                            .or_else(|| var_span(ir, *base))
                            .or_else(|| var_span(ir, *dest));
                        check_access(ir, findings, *base, buf, idx_lo, idx_hi, false, span);
                    }
                }

                Instruction::LoadField {
                    dest, base, field, ..
                } => {
                    if let Ok(idx) = field.parse::<i64>()
                        && let Some(c) = ps.class_for(pts, *base)
                        && let Some(buf) = ps.buffers.get(&c)
                    {
                        let span = var_span(ir, *base).or_else(|| var_span(ir, *dest));
                        check_access(ir, findings, *base, buf, idx, idx, false, span);
                    }
                }

                // --- Pointer alias propagation ---
                Instruction::Assign {
                    dest,
                    src: Operand::Var(src),
                }
                | Instruction::Cast {
                    dest,
                    src: Operand::Var(src),
                    ..
                } => {
                    if let Some(c) = ps.class_for(pts, *src) {
                        if ps.buffers.contains_key(&c) {
                            ps.dead.remove(dest);
                            ps.generation.insert(*dest, c);
                        }
                    } else {
                        ps.generation.remove(dest);
                        ps.dead.insert(*dest);
                    }
                }

                // Dest overwritten with untracked non-var value
                Instruction::Assign { dest, .. } | Instruction::Cast { dest, .. } => {
                    ps.generation.remove(dest);
                    ps.dead.insert(*dest);
                }

                _ => {}
            }
        }
        Some(ps)
    }

    fn join_states(a: &PathState, b: &PathState) -> PathState {
        let mut out = PathState::default();
        for (c, bufa) in &a.buffers {
            if let Some(bufb) = b.buffers.get(c) {
                out.buffers.insert(
                    *c,
                    BufferInfo {
                        capacity_lo: bufa.capacity_lo.min(bufb.capacity_lo),
                        capacity_hi: bufa.capacity_hi.max(bufb.capacity_hi),
                        span: bufa.span.or(bufb.span),
                    },
                );
            }
        }
        for (v, ca) in &a.generation {
            if b.generation.get(v) == Some(ca) {
                out.generation.insert(*v, *ca);
            }
        }
        out
    }

    // Reverse post-order traversal over the CFG reachable from entry.
    let mut rpo: Vec<BlockId> = Vec::new();
    {
        enum Step {
            Enter(BlockId),
            Emit(BlockId),
        }
        let mut visited: FxHashSet<BlockId> = FxHashSet::default();
        let mut stack: Vec<Step> = vec![Step::Enter(ir.entry_block)];
        while let Some(step) = stack.pop() {
            match step {
                Step::Enter(b) => {
                    if visited.insert(b) {
                        stack.push(Step::Emit(b));
                        let succs = ir
                            .blocks
                            .get(&b)
                            .map(|bb| bb.successors.clone())
                            .unwrap_or_default();
                        for s in succs {
                            stack.push(Step::Enter(s));
                        }
                    }
                }
                Step::Emit(b) => rpo.push(b),
            }
        }
        rpo.reverse();
    }

    let mut in_states: FxHashMap<BlockId, Vec<PathState>> = FxHashMap::default();

    if let Some(entry) = ir.blocks.get(&ir.entry_block)
        && let Some(out) = visit_block(
            ir,
            &pts,
            &val_info,
            summaries,
            &mut findings,
            PathState::default(),
            ir.entry_block,
            entry,
        )
    {
        for &s in &entry.successors {
            in_states.entry(s).or_default().push(out.clone());
        }
    }

    for b in rpo.into_iter().skip(1) {
        let Some(block) = ir.blocks.get(&b) else {
            continue;
        };
        let Some(flows) = in_states.remove(&b) else {
            continue;
        };
        let mut it = flows.into_iter();
        let Some(first) = it.next() else {
            continue;
        };
        let joined = it.fold(first, |acc, ps| join_states(&acc, &ps));
        if let Some(out) = visit_block(
            ir,
            &pts,
            &val_info,
            summaries,
            &mut findings,
            joined,
            b,
            block,
        ) {
            for &s in &block.successors {
                in_states.entry(s).or_default().push(out.clone());
            }
        }
    }

    findings.sort_by_key(|f| f.span.map(|s| s.0).unwrap_or(usize::MAX));
    findings.dedup_by(|a, b| a.span == b.span && a.rule == b.rule && a.message == b.message);
    findings
}
