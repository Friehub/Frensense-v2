// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::checks::CheckerFinding;
use crate::checks::Provenance;
use crate::ir::function::{BlockId, FunctionIR, VarId};

/// A violation of the object lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// Memory used after free (read or write through an aliasing var).
    UseAfterFree,
    /// The same object freed twice.
    DoubleFree,
    /// Memory freed without guaranteed initialization on all reachable paths.
    UninitializedFree,
}

/// One site that releases the object held by `var`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeSite {
    pub block: BlockId,
    pub idx: usize,
    pub var: VarId,
}

/// How a discovered (free, use) pair must be validated before firing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairCheck {
    /// Free and use are both in the scanned function: must-reach in this CFG.
    Local,
    /// Free lives in the callee entered at `call`; the call must precede the
    /// use AND every normal exit of `callee_fi` must pass a free.
    Callee {
        call: (BlockId, usize),
        callee_fi: usize,
    },
    /// Free lives in the caller that entered *this* function at `call`; the
    /// free must precede the call in the caller's CFG.
    Caller {
        call: (BlockId, usize),
        caller_fi: usize,
    },
}

/// One discovered pair awaiting must-validation.
#[derive(Debug, Clone, Copy)]
pub struct Pair {
    pub violation: Violation,
    pub check: PairCheck,
    /// Location of the free (its block / instruction index).
    pub free_block: BlockId,
    pub free_idx: usize,
}

/// Which function a walk step currently sits in, relative to the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCtx {
    /// Inside the scanned (start) function.
    None,
    /// Inside a callee entered from the start function at `call`.
    InCallee {
        call: (BlockId, usize),
        callee_fi: usize,
    },
    /// Inside the caller that entered the start function at `call`.
    InCaller {
        call: (BlockId, usize),
        caller_fi: usize,
    },
}

pub fn finding(
    ir: &FunctionIR,
    violation: Violation,
    var: &VarId,
    span_var: Option<VarId>,
) -> CheckerFinding {
    let name = ir
        .var_metadata
        .get(var)
        .and_then(|m| m.source_name.clone())
        .unwrap_or_else(|| format!("v{}", var.0));
    let span = span_var.and_then(|v| ir.var_metadata.get(&v).and_then(|m| m.byte_range));
    let (rule, message) = match violation {
        Violation::UseAfterFree => (
            frensense_lang::rules::USE_AFTER_FREE,
            format!(
                "`{name}` is used after the memory it points to was freed \
                 (free-then-use). Remove the use or the free."
            ),
        ),
        Violation::DoubleFree => (
            frensense_lang::rules::DOUBLE_FREE,
            format!(
                "`{name}` is freed twice (double-free). Remove the second \
                 free or null the pointer after the first."
            ),
        ),
        Violation::UninitializedFree => (
            frensense_lang::rules::UNINITIALIZED_FREE,
            format!(
                "`{name}` is freed without guaranteed initialization \
                 (uninitialized pointer free). Initialize before use."
            ),
        ),
    };
    CheckerFinding {
        function: ir.name.clone(),
        rule: rule.to_string(),
        message,
        span,
        severity: String::new(),
        provenance: Provenance::Spec,
    }
}
