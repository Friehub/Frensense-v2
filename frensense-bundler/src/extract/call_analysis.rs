// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use frensense_engine::analysis::taint::facts::FactTable;
use frensense_engine::ir::function::{FunctionIR, Instruction, Operand, Terminator, VarId};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::BTreeSet;

use super::family::Family;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallShape {
    Predicate,
    Transform,
    Other,
}

/// Collect call names + coarse shapes from lowered IR text (cheap: reuses the
/// harness lowering). Shape detection: a call whose result feeds only a
/// Branch/condition is predicate-shaped; a call whose result is re-stored or
/// passed on is transform-shaped.
///
/// `facts` carries the pack vocabulary the lowering consults (route
/// registration patterns since Phase 6.4); pass `None` for bare lowering.
pub fn collect_calls(
    files: &[(String, String, String)],
    facts: Option<&FactTable>,
) -> FxHashMap<String, CallShape> {
    let mut calls: FxHashMap<String, CallShape> = FxHashMap::default();

    for (path, source, ext) in files {
        let Ok(irs) = frensense_engine::harness::lower_source_with_facts(path, source, ext, facts)
        else {
            continue;
        };
        for ir in irs.values() {
            // Vars that flow into a branch condition (directly or via a
            // short def chain, captures `!x.test(y)`).
            let mut cond_vars: FxHashMap<VarId, ()> = FxHashMap::default();
            for block in ir.blocks.values() {
                if let Terminator::Branch { cond, .. } = &block.terminator {
                    if let Operand::Var(c) = cond {
                        cond_vars.insert(*c, ());
                    }
                }
            }
            // Multi-hop up the def chain (unary !, binary &&, ||, cast, assign)
            let mut changed = true;
            let mut hops = 0;
            while changed && hops < 6 {
                changed = false;
                hops += 1;
                for b2 in ir.blocks.values() {
                    for i in &b2.instructions {
                        match i {
                            Instruction::UnaryOp {
                                dest,
                                src: Operand::Var(s),
                                ..
                            }
                            | Instruction::Cast {
                                dest,
                                src: Operand::Var(s),
                                ..
                            }
                            | Instruction::Assign {
                                dest,
                                src: Operand::Var(s),
                            } if cond_vars.contains_key(dest) => {
                                if cond_vars.insert(*s, ()).is_none() {
                                    changed = true;
                                }
                            }
                            Instruction::BinaryOp { dest, lhs, rhs, .. }
                                if cond_vars.contains_key(dest) =>
                            {
                                if let Operand::Var(s) = lhs {
                                    if cond_vars.insert(*s, ()).is_none() {
                                        changed = true;
                                    }
                                }
                                if let Operand::Var(s) = rhs {
                                    if cond_vars.insert(*s, ()).is_none() {
                                        changed = true;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            for block in ir.blocks.values() {
                for instr in &block.instructions {
                    let (name, dest) = match instr {
                        Instruction::CallStatic { func, dest, .. } => (Some(func.clone()), *dest),
                        Instruction::CallVirtual { method, dest, .. } => {
                            (Some(method.clone()), *dest)
                        }
                        _ => (None, None),
                    };
                    if let Some(name) = name {
                        let shape = if dest.map(|d| cond_vars.contains_key(&d)).unwrap_or(false) {
                            CallShape::Predicate
                        } else {
                            CallShape::Other
                        };
                        // Predicate classification wins over Other.
                        calls
                            .entry(name)
                            .and_modify(|e| {
                                if shape == CallShape::Predicate {
                                    *e = shape.clone();
                                }
                            })
                            .or_insert(shape);
                    }
                }
            }
        }
    }
    calls
}

fn defs_of(instr: &Instruction) -> Vec<VarId> {
    let mut v = Vec::with_capacity(2);
    match instr {
        Instruction::Assign { dest, .. }
        | Instruction::LoadField { dest, .. }
        | Instruction::LoadElement { dest, .. }
        | Instruction::LoadGlobal { dest, .. }
        | Instruction::Cast { dest, .. }
        | Instruction::ExtractValue { dest, .. }
        | Instruction::BinaryOp { dest, .. }
        | Instruction::UnaryOp { dest, .. } => v.push(*dest),
        Instruction::CallStatic { dest, .. }
        | Instruction::CallVirtual { dest, .. }
        | Instruction::CallPointer { dest, .. } => {
            if let Some(d) = dest {
                v.push(*d);
            }
        }
        _ => {}
    }
    v
}

/// Cross-function enforcement helper: a function DEFINED in the negatives
/// that positives neither define nor call. The negatives are safe because
/// their module provides the enforcement helper (the definition site is
/// the strongest in-scope evidence - `policy::check_program`'s
/// module-segment rule), while positives execute the trigger with no
/// helper anywhere in scope. The helper must not be defined in positives:
/// if both sides define it, its presence cannot be the separating signal.
pub fn cross_function_helper(
    family: &Family,
    pos_calls: &FxHashMap<String, CallShape>,
    neg_calls: &FxHashMap<String, CallShape>,
    facts: Option<&FactTable>,
) -> Option<String> {
    let pos_defs = defined_function_names(&family.positives, facts);
    let neg_defs = defined_function_names(&family.negatives, facts);
    let trigger = family.declared_check_call.as_deref();
    neg_defs
        .iter()
        .filter(|g| {
            Some(g.as_str()) != trigger
                && !pos_defs.contains(*g)
                && !pos_calls.contains_key(*g)
                && !neg_calls.contains_key(*g)
        })
        .next()
        .cloned()
}

/// Last-segment names of every function DEFINED in the given variants
/// (definition sites, not call sites).
pub fn defined_function_names(
    files: &[(String, String, String)],
    facts: Option<&FactTable>,
) -> FxHashSet<String> {
    let mut out = FxHashSet::default();
    for (path, source, ext) in files {
        let Ok(irs) = frensense_engine::harness::lower_source_with_facts(path, source, ext, facts)
        else {
            continue;
        };
        for name in irs.keys() {
            // Skip synthetic lowering names (`<fn@byte>`, `<path:handler@byte>`):
            // they encode the file position where the function was DECLARED in
            // the corpus variant, so a target program can never contain the
            // same name - a RequireCall fact keyed on one would fire forever.
            if name.starts_with('<') {
                continue;
            }
            let last = name.rsplit('.').next().unwrap_or(name);
            out.insert(last.to_string());
        }
    }
    out
}

/// True when any argument var passed to `call` is compared against a
/// literal with a range operator (<, >, <=, >=) in the variant's IR,
/// inline range enforcement.
pub fn variant_has_range_check_on_call(
    files: &[(String, String, String)],
    call: &str,
    facts: Option<&FactTable>,
) -> bool {
    const RANGE_OPS: &[&str] = &["<", ">", "<=", ">="];
    let Some((path, source, ext)) = files.first() else {
        return false;
    };
    let Ok(irs) = frensense_engine::harness::lower_source_with_facts(path, source, ext, facts)
    else {
        return false;
    };
    for ir in irs.values() {
        // Vars passed as arguments to the trigger call.
        let mut arg_vars: Vec<_> = Vec::new();
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let is_call = match instr {
                    Instruction::CallStatic { func, .. } => func.rsplit('.').next() == Some(call),
                    Instruction::CallVirtual { method, .. } => {
                        method.rsplit('.').next() == Some(call)
                    }
                    _ => false,
                };
                let args = match instr {
                    Instruction::CallStatic { args, .. }
                    | Instruction::CallVirtual { args, .. } => Some(args),
                    _ => None,
                };
                if is_call && args.is_some() {
                    for a in args.unwrap() {
                        if let Operand::Var(v) = a {
                            arg_vars.push(*v);
                        }
                    }
                }
            }
        }
        // Any literal comparison on those vars?
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let op = match instr {
                    Instruction::BinaryOp { op, .. } => op,
                    _ => continue,
                };
                if !RANGE_OPS.contains(&op.as_str()) {
                    continue;
                }
                if let Instruction::BinaryOp { lhs, rhs, .. } = instr {
                    let (a, b) = (lhs, rhs);
                    let var_side = matches!(a, Operand::Var(v) if arg_vars.contains(v))
                        || matches!(b, Operand::Var(v) if arg_vars.contains(v));
                    let lit_side = matches!(
                        b,
                        Operand::StringLiteral(_)
                            | Operand::IntLiteral(_)
                            | Operand::FloatLiteral(_)
                    ) || matches!(
                        a,
                        Operand::StringLiteral(_)
                            | Operand::IntLiteral(_)
                            | Operand::FloatLiteral(_)
                    );
                    if var_side && lit_side {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn extract_call_arg_literals(
    irs: &[FunctionIR],
) -> FxHashMap<(String, usize), BTreeSet<String>> {
    let mut map: FxHashMap<(String, usize), BTreeSet<String>> = FxHashMap::default();
    for ir in irs {
        let values = frensense_engine::analysis::value::analyze(ir);
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let (callee, args) = match instr {
                    Instruction::CallStatic { func, args, .. } => (func, args),
                    Instruction::CallVirtual { method, args, .. } => (method, args),
                    _ => continue,
                };
                let seg = callee.rsplit('.').next().unwrap_or(callee);
                for (slot, arg) in args.iter().enumerate() {
                    let lit = match arg {
                        Operand::StringLiteral(s) => Some(
                            s.trim_matches(|c| c == '\'' || c == '"' || c == '`')
                                .to_string(),
                        ),
                        Operand::IntLiteral(i) => Some(i.to_string()),
                        Operand::BoolLiteral(b) => Some(b.to_string()),
                        Operand::Var(v) => values
                            .const_str(*v)
                            .map(|s| {
                                s.trim_matches(|c| c == '\'' || c == '"' || c == '`')
                                    .to_string()
                            })
                            .or_else(|| values.const_int(*v).map(|i| i.to_string()))
                            .or_else(|| values.const_bool(*v).map(|b| b.to_string())),
                        _ => None,
                    };
                    if let Some(val) = lit {
                        map.entry((seg.to_string(), slot)).or_default().insert(val);
                    }
                }
            }
        }
    }
    map
}
