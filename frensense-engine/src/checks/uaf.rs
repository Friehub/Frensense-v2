// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Free-then-use / double-free checker over the Steensgaard points-to
//! classes (RESEARCH.md P1: consume the points-to graph for memory-safety
//! findings).
//!
//! Taint and policy checks never see this bug class: use-after-free is a
//! *temporal* property — the same object must be (1) allocated, (2) freed,
//! and (3) used, in that order. The mechanism is a per-object state machine:
//!
//! ```text
//!   Allocated ──free──▶ Freed ──use──▶ UAF finding
//!        │                 │
//!        │              free (again)
//!        │                 ▼
//!        └──────────── Double-free finding
//! ```
//!
//! "Object" is a pointer-equivalence class from [`Steensgaard`]: every
//! variable that may alias the allocation participates, so `q = p; free(p);
//! use(q)` is caught through aliasing. Only classes with a *provable
//! allocation provenance in the same function* (an `Allocate` instruction
//! or a `malloc`/`calloc`/`realloc` call result) participate — pointers
//! from parameters or unknown sources are skipped, keeping the checker
//! zero-FP by construction on unprovable classes.
//!
//! Path sensitivity: the lifecycle state machine runs as a forward
//! dataflow over the CFG, one state set per abstract path. At CFG joins a
//! freed mark survives only when EVERY incoming path freed the object
//! (must-join), so `if (c) free(p); use(p)` — where the free executes on
//! only one branch — stays silent, while frees that dominate the use
//! (straight-line, both-arms, or pre-loop) still fire. One deliberate
//! must-edge refinement: a branch whose BOTH successors re-converge at a
//! single successor of the branch block treats the free as definite past
//! that merge (the skip-if-loop-back check prevents false definiteness
//! around loop back-edges).
//!
//! Deliberate scope (documented limitations): intraprocedural only; a
//! re-assignment of the pointer var to a fresh allocation starts a new
//! object generation (tracked per var, so `p = malloc(); free(p);
//! p = malloc(); use(p)` is NOT a finding).

use rustc_hash::{FxHashMap, FxHashSet};

use crate::checks::CheckerFinding;
use crate::checks::memory_summary::MemorySummaryRegistry;
use crate::graph::steensgaard::{ClassId, Steensgaard};
use crate::ir::function::{FunctionIR, Instruction, Operand};

/// Callee last segments that release heap memory.
const FREE_CALLS: &[&str] = &["free"];
// Deliberately not in the list: `realloc` moves the object (its result is a
// fresh generation). C++ `delete` arrives once lowering handles it.

/// Callee last segments that allocate heap memory (provable provenance).
const ALLOC_CALLS: &[&str] = &["malloc", "calloc", "realloc", "aligned_alloc"];

fn last_segment(call: &str) -> &str {
    call.rsplit('.').next().unwrap_or(call)
}

/// One pointer object's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectState {
    /// Provable allocation seen for this class, not yet freed.
    Allocated,
    /// A free executed on this class.
    Freed,
}

/// A violation of the object lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Violation {
    /// Memory used after free (read or write through an aliasing var).
    UseAfterFree,
    /// The same object freed twice.
    DoubleFree,
}

/// Run the UAF / double-free check over one function with default summaries.
pub fn check(ir: &FunctionIR) -> Vec<CheckerFinding> {
    check_with_summaries(ir, &MemorySummaryRegistry::default())
}

/// Run the UAF / double-free check over one function with an interprocedural memory summary registry.
pub fn check_with_summaries(
    ir: &FunctionIR,
    summaries: &MemorySummaryRegistry,
) -> Vec<CheckerFinding> {
    let pts = Steensgaard::analyze(ir);
    let mut findings: Vec<CheckerFinding> = Vec::new();

    /// One abstract path's object-lifecycle state. `state` maps a points-to
    /// class to its lifecycle (only classes with a proven in-function
    /// allocation participate); `generation` pins each var to the class
    /// whose object it CURRENTLY holds, so re-assignment to a fresh
    /// allocation un-merges the var from its old (possibly freed) class.
    /// `dead` holds vars re-assigned from an UNTRACKED source (a non-alloc
    /// call result, unknown, or a literal): their old Steensgaard class no
    /// longer describes what they hold, so they lose provenance entirely
    /// (`val = search_key(..)` after `free(val)` must not resurrect the
    /// freed object's class and manufacture a double-free).
    #[derive(Default, Clone)]
    struct PathState {
        state: FxHashMap<ClassId, ObjectState>,
        generation: FxHashMap<crate::ir::function::VarId, ClassId>,
        dead: FxHashSet<crate::ir::function::VarId>,
    }

    impl PathState {
        fn class_for(&self, pts: &Steensgaard, v: crate::ir::function::VarId) -> Option<ClassId> {
            if self.dead.contains(&v) {
                return None;
            }
            if let Some(&c) = self.generation.get(&v) {
                return Some(c);
            }
            pts.class_of.get(&v).copied()
        }
    }

    /// Visit one block: run its instructions over an incoming path state.
    ///
    /// Returns the outgoing state, or `None` when a DEFINITE double-free
    /// was recorded on this path (the same object freed twice along one
    /// path) — outgoing flow is dropped since the finding is already
    /// recorded and a further-freed state is not worth tracking.
    fn visit(
        ir: &FunctionIR,
        pts: &Steensgaard,
        summaries: &MemorySummaryRegistry,
        findings: &mut Vec<CheckerFinding>,
        mut ps: PathState,
        block: &crate::ir::function::BasicBlock,
    ) -> Option<PathState> {
        for instr in &block.instructions {
            match instr {
                // --- Allocation provenance ---
                Instruction::Allocate { dest, .. } => {
                    if let Some(&c) = pts.class_of.get(dest) {
                        ps.state.insert(c, ObjectState::Allocated);
                        ps.generation.insert(*dest, c);
                    }
                }
                Instruction::CallStatic {
                    func,
                    dest: Some(d),
                    ..
                } if ALLOC_CALLS.contains(&last_segment(func)) || summaries.returns_fresh(func) => {
                    // Fresh generation: pin this var to a fresh
                    // generation id, un-merging it from its old class.
                    let fresh = ClassId(pts.members.len() + ps.generation.len() + d.0);
                    ps.state.insert(fresh, ObjectState::Allocated);
                    ps.generation.insert(*d, fresh);
                }

                // --- Free / Consumed parameters ---
                Instruction::CallStatic {
                    func, args, dest, ..
                } => {
                    let consumed_slots = if FREE_CALLS.contains(&last_segment(func)) {
                        vec![0]
                    } else {
                        summaries.consumes_params(func)
                    };
                    for slot in consumed_slots {
                        if let Some(Operand::Var(v)) = args.get(slot)
                            && let Some(c) = ps.class_for(pts, *v)
                        {
                            match ps.state.get(&c) {
                                Some(&ObjectState::Freed) => {
                                    // Second free of the same object on THIS path:
                                    // definite double-free regardless of joins.
                                    findings.push(finding(ir, Violation::DoubleFree, v, None));
                                }
                                Some(&ObjectState::Allocated) => {
                                    // We have provable provenance — mark freed.
                                    ps.state.insert(c, ObjectState::Freed);
                                }
                                None => {
                                    // No provable in-function allocation for this class
                                    // (parameter or unknown source) — skip to keep zero-FP.
                                }
                            }
                        }
                    }
                    if let Some(d) = dest {
                        ps.generation.remove(d);
                        ps.dead.insert(*d);
                    }
                }

                // --- Generation propagation through assignments ---
                // `q = p` must carry p's current generation to q, otherwise
                // the pinned fresh-class for a re-allocated var diverges
                // from the Steensgaard class shared with its aliases.
                Instruction::Assign {
                    dest,
                    src: Operand::Var(src),
                } => {
                    match ps.generation.get(src).copied() {
                        Some(c) => {
                            ps.dead.remove(dest);
                            ps.generation.insert(*dest, c);
                        }
                        // Source holds no tracked object (a temp from a
                        // non-alloc call, a dead var, an untracked
                        // parameter): the destination loses provenance.
                        None => {
                            ps.generation.remove(dest);
                            ps.dead.insert(*dest);
                        }
                    }
                }
                // Any other value-producing def from an untracked source
                // (non-alloc call result, unknown, literal) kills the
                // destination var's provenance.
                Instruction::Assign { dest, .. }
                | Instruction::CallVirtual {
                    dest: Some(dest), ..
                }
                | Instruction::CallPointer {
                    dest: Some(dest), ..
                }
                | Instruction::UnaryOp { dest, .. }
                | Instruction::BinaryOp { dest, .. } => {
                    ps.dead.insert(*dest);
                }

                // --- Uses through the pointer ---
                // Loads are ALSO defs: check the use first (the loaded
                // value flows out of a possibly-freed base), then kill the
                // destination's provenance.
                Instruction::LoadField { dest, base, .. }
                | Instruction::LoadElement { dest, base, .. }
                | Instruction::Dereference {
                    dest,
                    ptr: Operand::Var(base),
                    ..
                } => {
                    if let Some(c) = ps.class_for(pts, *base)
                        && ps.state.get(&c) == Some(&ObjectState::Freed)
                    {
                        findings.push(finding(ir, Violation::UseAfterFree, base, Some(*base)));
                    }
                    ps.dead.insert(*dest);
                }
                Instruction::StoreField { base, .. } | Instruction::StoreElement { base, .. } => {
                    if let Some(c) = ps.class_for(pts, *base)
                        && ps.state.get(&c) == Some(&ObjectState::Freed)
                    {
                        findings.push(finding(ir, Violation::UseAfterFree, base, Some(*base)));
                    }
                }
                _ => {}
            }
        }
        Some(ps)
    }

    /// MUST-join two incoming path states at a CFG merge: a freed mark
    /// survives only when BOTH paths freed the object (must-analysis), and
    /// a generation survives only when both paths agree on the var's
    /// current object (divergent re-assignments collapse to the
    /// Steensgaard class, which is the sound may-approximation).
    fn join(a: &PathState, b: &PathState) -> PathState {
        let mut out = PathState::default();
        for (c, sa) in &a.state {
            if b.state.get(c) == Some(sa) {
                out.state.insert(*c, *sa);
            }
        }
        for (v, ca) in &a.generation {
            if b.generation.get(v) == Some(ca) {
                out.generation.insert(*v, *ca);
            }
        }
        out
    }

    // Reverse post-order over the CFG reachable from entry. Every block
    // processes EXACTLY ONCE with the MUST-join of every incoming flow that
    // has arrived when its turn comes. In RPO all reachable non-back-edge
    // predecessors have already pushed their flow, so diamond merges join
    // both arms. Back-edge flows (loop latches) arrive late and are DROPPED:
    // dropping flow only ever removes freed marks from the join, which can
    // silence a finding but never manufacture one (may-sound).
    let mut rpo: Vec<crate::ir::function::BlockId> = Vec::new();
    {
        // Iterative post-order DFS from entry.
        enum Step {
            Enter(crate::ir::function::BlockId),
            Emit(crate::ir::function::BlockId),
        }
        let mut visited: FxHashSet<crate::ir::function::BlockId> = FxHashSet::default();
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

    let mut in_states: FxHashMap<crate::ir::function::BlockId, Vec<PathState>> =
        FxHashMap::default();

    if let Some(entry) = ir.blocks.get(&ir.entry_block)
        && let Some(out) = visit(
            ir,
            &pts,
            summaries,
            &mut findings,
            PathState::default(),
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
        let joined = it.fold(first, |acc, ps| join(&acc, &ps));
        if let Some(out) = visit(ir, &pts, summaries, &mut findings, joined, block) {
            for &s in &block.successors {
                in_states.entry(s).or_default().push(out.clone());
            }
        }
    }

    // Deterministic order: by span start (falling back to function order is
    // fine — findings come from one function).
    findings.sort_by_key(|f| f.span.map(|s| s.0).unwrap_or(usize::MAX));
    findings.dedup_by(|a, b| a.span == b.span && a.rule == b.rule);
    findings
}

fn finding(
    ir: &FunctionIR,
    violation: Violation,
    var: &crate::ir::function::VarId,
    span_var: Option<crate::ir::function::VarId>,
) -> CheckerFinding {
    let name = ir
        .var_metadata
        .get(var)
        .and_then(|m| m.source_name.clone())
        .unwrap_or_else(|| format!("v{}", var.0));
    let span = span_var.and_then(|v| ir.var_metadata.get(&v).and_then(|m| m.byte_range));
    let (rule, message) = match violation {
        Violation::UseAfterFree => (
            "use_after_free",
            format!(
                "`{name}` is used after the memory it points to was freed in \
                 this function (free-then-use). Remove the use or the free."
            ),
        ),
        Violation::DoubleFree => (
            "double_free",
            format!(
                "`{name}` is freed twice in this function (double-free). \
                 Remove the second free or null the pointer after the first."
            ),
        ),
    };
    CheckerFinding {
        function: ir.name.clone(),
        rule: rule.to_string(),
        message,
        span,
        learned: false,
    }
}
