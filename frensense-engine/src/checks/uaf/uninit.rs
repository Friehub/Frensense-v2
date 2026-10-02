// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use rustc_hash::FxHashSet;

use crate::checks::CheckerFinding;
use crate::ir::function::{BlockId, FunctionIR, Instruction, Operand, Terminator, VarId};

use super::types::{FreeSite, Violation, finding};

/// Check for deallocations where the freed pointer has a feasible path
/// with no reaching definition (e.g. uninitialized stack slot freed on
/// an unchecked error/EOF path).
pub fn check_uninitialized_frees(ir: &FunctionIR, frees: &[FreeSite]) -> Vec<CheckerFinding> {
    let mut findings = Vec::new();

    for f in frees {
        // Parameters cannot be uninitialized stack locals.
        if ir.parameters.contains(&f.var) {
            continue;
        }

        // Pointers loaded from globals are not stack uninitialized pointers.
        if is_derived_from_global(ir, f.var) {
            continue;
        }

        // No definition of the var reaches this free: the local is never
        // written on any path into it, so the freed pointer is
        // indeterminate regardless of error-path shape. Report directly -
        // the `!=`/`< 0` fingerprint below exists to precision-gate only
        // the partially-initialized (phi) case. Only vars bound by a
        // declaration inside this function are eligible: a first-use var is
        // a file/module/header global whose value is initialized elsewhere,
        // so "no reaching def here" is expected, not a bug.
        if has_no_reaching_def(ir, f) && is_declared_in_function(ir, f.var) {
            findings.push(finding(ir, Violation::UninitializedFree, &f.var, None));
            continue;
        }

        // Check if f.var is defined on every path or has an uninitialized path.
        let Some(uninit_blocks) = collect_uninit_paths(ir, f.var) else {
            continue;
        };

        // If uninitialized paths cannot reach this free site, no violation occurs.
        if !can_uninit_reach_free(ir, &uninit_blocks, f.block) {
            continue;
        }

        // Check if there is an unchecked error/return comparison gating this free.
        if is_error_path_unguarded(ir, f.block) {
            findings.push(finding(ir, Violation::UninitializedFree, &f.var, None));
        }
    }

    findings
}

/// Identifies if `var` is loaded from a global or derived from global memory.
fn is_derived_from_global(ir: &FunctionIR, var: VarId) -> bool {
    for block in ir.blocks.values() {
        for instr in &block.instructions {
            if let Instruction::LoadGlobal { dest, .. } = instr
                && *dest == var
            {
                return true;
            }
        }
    }
    false
}

/// True when `var` was bound by a declaration lowered inside this
/// function's body (`char *p;`, `let x;`, destructuring, Python
/// assignment). Vars created at first expression use - file-scope globals,
/// header-declared globals, undeclared names - stay `false`: their values
/// live in other translation units, so an in-function "no reaching
/// definition" says nothing about them.
fn is_declared_in_function(ir: &FunctionIR, var: VarId) -> bool {
    ir.var_metadata.get(&var).is_some_and(|meta| meta.declared)
}

/// True when no definition of `var` reaches the free site: no instruction
/// write, no phi, and no same-block def before the free - i.e. every path
/// into the free reads an uninitialized stack slot (the canonical shape:
/// declare, take the error path, free garbage).
///
/// Conservative: any `AddressOf` of the var anywhere in the function bails
/// out (`false`) - writes through the address may initialize it on paths
/// this scan cannot see, leaving the phi-based analysis as the gate for
/// that case.
fn has_no_reaching_def(ir: &FunctionIR, f: &FreeSite) -> bool {
    let var_name = ir
        .var_metadata
        .get(&f.var)
        .and_then(|m| m.source_name.as_deref());

    for (&bid, block) in &ir.blocks {
        // A phi for the var defines it at block entry; the phi-based
        // analysis owns that case.
        if block.phis.iter().any(|phi| phi.dest == f.var) {
            return false;
        }
        for (idx, instr) in block.instructions.iter().enumerate() {
            if let Instruction::AddressOf { src, .. } = instr {
                let src_name = ir
                    .var_metadata
                    .get(src)
                    .and_then(|m| m.source_name.as_deref());
                if *src == f.var || var_name.is_some_and(|n| src_name == Some(n)) {
                    return false;
                }
            }
            if !instr_defines_var(instr, f.var) {
                continue;
            }
            // The def reaches the free when it precedes the free in the
            // same block, or its block can reach the free's block.
            let reaches = if bid == f.block {
                idx < f.idx
            } else {
                can_reach(ir, bid, f.block)
            };
            if reaches {
                return false;
            }
        }
    }
    true
}

/// Returns the set of predecessor blocks along which `var` arrives uninitialized.
/// Returns `None` if `var` is fully initialized along all paths.
pub(crate) fn collect_uninit_paths(ir: &FunctionIR, var: VarId) -> Option<FxHashSet<BlockId>> {
    let var_name = ir
        .var_metadata
        .get(&var)
        .and_then(|m| m.source_name.as_deref());
    let mut uninit_blocks = FxHashSet::default();
    let mut has_phi = false;

    for block in ir.blocks.values() {
        for phi in &block.phis {
            if phi.dest == var {
                has_phi = true;
                let incoming_preds: FxHashSet<BlockId> =
                    phi.incoming.iter().map(|(b, _)| *b).collect();
                for &pred in &block.predecessors {
                    if !incoming_preds.contains(&pred) {
                        // Check if pred was initialized via address-of out-parameter
                        if let Some(name) = var_name
                            && is_address_taken_on_all_paths(ir, pred, name)
                        {
                            continue;
                        }
                        uninit_blocks.insert(pred);
                    }
                }
            }
        }
    }

    if has_phi && !uninit_blocks.is_empty() {
        Some(uninit_blocks)
    } else {
        None
    }
}

/// Returns true if all CFG paths from `entry_block` to `pred` pass through an
/// `AddressOf` instruction for `var_name` (i.e. out-parameter initialization).
fn is_address_taken_on_all_paths(ir: &FunctionIR, pred: BlockId, var_name: &str) -> bool {
    if block_takes_address_of(ir, pred, var_name) {
        return true;
    }
    let mut visited = FxHashSet::default();
    let mut queue = vec![ir.entry_block];

    while let Some(b) = queue.pop() {
        if b == pred {
            return false;
        }
        if !visited.insert(b) {
            continue;
        }
        if block_takes_address_of(ir, b, var_name) {
            continue;
        }
        if let Some(blk) = ir.blocks.get(&b) {
            for &succ in &blk.successors {
                queue.push(succ);
            }
        }
    }

    true
}

/// Returns true if `bid` contains an `AddressOf` instruction for `var_name`.
fn block_takes_address_of(ir: &FunctionIR, bid: BlockId, var_name: &str) -> bool {
    let Some(block) = ir.blocks.get(&bid) else {
        return false;
    };
    for instr in &block.instructions {
        if let Instruction::AddressOf { src, .. } = instr
            && let Some(meta) = ir.var_metadata.get(src)
            && meta.source_name.as_deref() == Some(var_name)
        {
            return true;
        }
    }
    false
}

/// Returns true if any uninitialized predecessor block can reach the free block.
pub(crate) fn can_uninit_reach_free(
    ir: &FunctionIR,
    uninit_blocks: &FxHashSet<BlockId>,
    free_block: BlockId,
) -> bool {
    for &u in uninit_blocks {
        if can_reach(ir, u, free_block) {
            return true;
        }
    }
    false
}

/// Checks whether the path leading into `free_block` is an unchecked error path:
/// i.e., an inequality comparison (`!=`) on an integer return value without an
/// error check (`< 0`) diverting execution.
pub(crate) fn is_error_path_unguarded(ir: &FunctionIR, free_block: BlockId) -> bool {
    let mut visited = FxHashSet::default();
    let mut queue = vec![free_block];

    while let Some(bid) = queue.pop() {
        if !visited.insert(bid) {
            continue;
        }
        let Some(block) = ir.blocks.get(&bid) else {
            continue;
        };

        for instr in &block.instructions {
            if let Instruction::BinaryOp { op, lhs, rhs, .. } = instr
                && op == "!="
            {
                let checked_var = match (lhs, rhs) {
                    (Operand::Var(v), _) => Some(*v),
                    (_, Operand::Var(v)) => Some(*v),
                    _ => None,
                };
                if let Some(c_var) = checked_var
                    && !is_error_guarded(ir, bid, c_var)
                {
                    return true;
                }
            }
        }

        for &p in &block.predecessors {
            if p.0 < bid.0 || bid == free_block {
                queue.push(p);
            }
        }
    }

    false
}

/// Checks if an SSA variable `c_var` has a dominating `< 0` error exit check
/// between its definition and `target_block`.
fn is_error_guarded(ir: &FunctionIR, target_block: BlockId, c_var: VarId) -> bool {
    // 1. Locate the block where `c_var` was defined (typically a call like get_nonwhite)
    let mut def_block = None;
    for (&bid, block) in &ir.blocks {
        for instr in &block.instructions {
            if instr_defines_var(instr, c_var) {
                def_block = Some(bid);
                break;
            }
        }
        if def_block.is_some() {
            break;
        }
    }

    let Some(def_bid) = def_block else {
        return false;
    };

    // 2. Search all blocks on the CFG path between `def_bid` and `target_block`
    // for a `< 0` check on `c_var` whose true branch branches away / exits.
    for (&bid, block) in &ir.blocks {
        if !can_reach(ir, def_bid, bid) || !can_reach(ir, bid, target_block) {
            continue;
        }

        for instr in &block.instructions {
            if let Instruction::BinaryOp { op, lhs, rhs, .. } = instr
                && op == "<"
                && let (Operand::Var(v), Operand::IntLiteral(0)) = (lhs, rhs)
                && *v == c_var
                && let Terminator::Branch {
                    true_block,
                    false_block,
                    ..
                } = &block.terminator
                && !can_reach(ir, *true_block, target_block)
                && can_reach(ir, *false_block, target_block)
            {
                return true;
            }
        }
    }

    false
}

fn instr_defines_var(instr: &Instruction, var: VarId) -> bool {
    match instr {
        Instruction::Assign { dest, .. }
        | Instruction::LoadField { dest, .. }
        | Instruction::LoadElement { dest, .. }
        | Instruction::LoadGlobal { dest, .. }
        | Instruction::CallStatic {
            dest: Some(dest), ..
        }
        | Instruction::CallVirtual {
            dest: Some(dest), ..
        }
        | Instruction::CallPointer {
            dest: Some(dest), ..
        }
        | Instruction::Allocate { dest, .. }
        | Instruction::AddressOf { dest, .. }
        | Instruction::Dereference { dest, .. }
        | Instruction::Cast { dest, .. }
        | Instruction::ExtractValue { dest, .. }
        | Instruction::BinaryOp { dest, .. }
        | Instruction::UnaryOp { dest, .. }
        | Instruction::Await { dest, .. } => *dest == var,
        _ => false,
    }
}

fn can_reach(ir: &FunctionIR, from: BlockId, to: BlockId) -> bool {
    if from == to {
        return true;
    }
    let mut visited = FxHashSet::default();
    let mut queue = vec![from];
    while let Some(b) = queue.pop() {
        if !visited.insert(b) {
            continue;
        }
        if b == to {
            return true;
        }
        if let Some(blk) = ir.blocks.get(&b) {
            for &succ in &blk.successors {
                queue.push(succ);
            }
        }
    }
    false
}
