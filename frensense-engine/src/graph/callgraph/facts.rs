// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The two value-fact passes the call graph needs before it can resolve a
//! single call site: what each var aliases, references or allocates, and
//! which formal parameters are called as function pointers.
//!
//! Split out of `callgraph.rs`: these walk every instruction of every
//! function but never touch call resolution, so they stand on their own.

use rustc_hash::{FxHashMap, FxHashSet};

use crate::ir::function::{AllocationKind, FunctionIR, Instruction, Operand, VarId};

/// Per-function value facts gathered in pass 1.
#[derive(Default)]
pub(super) struct FnFacts {
    /// `dest → src` copy assignments (alias chains).
    pub(super) aliases: FxHashMap<VarId, VarId>,
    /// Vars known to hold a reference to a program function.
    pub(super) fn_refs: FxHashMap<VarId, String>,
    /// Vars known to be instances of a class (`new Class()`).
    pub(super) classes: FxHashMap<VarId, String>,
}

/// Every function's value facts, keyed by program-level function name.
pub(super) fn per_function_facts<'a>(
    irs: &'a FxHashMap<String, &'a FunctionIR>,
    fn_set: &FxHashSet<String>,
) -> FxHashMap<&'a str, FnFacts> {
    let mut facts: FxHashMap<&str, FnFacts> = FxHashMap::default();
    for (fname, ir) in irs {
        let mut f = FnFacts::default();
        for (&v, meta) in &ir.var_metadata {
            if let Some(name) = &meta.source_name
                && fn_set.contains(name.as_str())
            {
                f.fn_refs.insert(v, name.clone());
            }
        }
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                match instr {
                    Instruction::Assign { dest, src, .. } => match src {
                        Operand::Var(s) => {
                            f.aliases.insert(*dest, *s);
                        }
                        Operand::StringLiteral(name) if fn_set.contains(name.as_str()) => {
                            f.fn_refs.insert(*dest, name.clone());
                        }
                        _ => {}
                    },
                    Instruction::AddressOf { dest, src, .. } => {
                        // `&func`, the address-of a parameter can't be a
                        // function; a real fn-ref lowering path lands here
                        // when IR gains named function constants. Track it
                        // as an alias for now (conservative no-op unless
                        // src is later known to be a fn ref).
                        f.aliases.insert(*dest, *src);
                    }
                    Instruction::Allocate {
                        dest,
                        kind: AllocationKind::ClassInstance(class),
                        ..
                    } => {
                        f.classes.insert(*dest, class.clone());
                    }
                    _ => {}
                }
            }
        }
        facts.insert(fname.as_str(), f);
    }

    facts
}

/// Which formal parameters each function CALLS as a function pointer:
/// `(fn_name, param_slot)`, the two-step higher-order treatment.
pub(super) fn called_parameters(
    irs: &FxHashMap<String, &FunctionIR>,
) -> FxHashSet<(String, usize)> {
    let mut called_params: FxHashSet<(String, usize)> = FxHashSet::default();
    for (fname, ir) in irs {
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let func_ptr: Option<&Operand> = match instr {
                    Instruction::CallPointer { func_ptr, .. } => Some(func_ptr),
                    _ => None,
                };
                if let Some(Operand::Var(v)) = func_ptr {
                    for (slot, &pv) in ir.parameters.iter().enumerate() {
                        if pv == *v {
                            called_params.insert(((*fname).clone(), slot));
                        }
                    }
                }
            }
        }
    }
    called_params
}
