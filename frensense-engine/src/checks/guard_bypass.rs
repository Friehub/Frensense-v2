// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Two seed mechanisms for guard/policy bugs taint analysis cannot see:
//!
//! 1. **Substring allowlist guards** (`redirect_challenge` class): a guard
//!    that validates attacker input with `x.includes(item)` / `indexOf(...) >= 0`
//!    over an allowlist is bypassable, `https://evil.com?https://good.com`
//!    contains the allowed substring. The *mechanism* is "validation by
//!    substring containment"; the corpus decides which callees/guards matter.
//!
//! 2. **Password KDF policy** (`weak_password` class): a value flowing into a
//!    credential setter/hasher guarded by nothing but a fast digest wrapper.
//!    Mechanism: "hash-named call in a password-setting function".

use crate::analysis::taint::facts::FactTable;
use crate::checks::CheckerFinding;
use crate::checks::Provenance;
use crate::ir::function::{FunctionIR, Instruction, Operand, Terminator, VarId};
use rustc_hash::FxHashSet;

fn last_segment(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

/// Rule 1: substring-containment guard. Fires on `includes`/`indexOf` calls
/// where the receiver OR the argument is a function parameter named like a
/// URL/redirect target (`url`, `toUrl`, `redirect`, ...), the shape of an
/// allowlist validation over attacker input.
pub fn check(ir: &FunctionIR, facts: &FactTable) -> Vec<CheckerFinding> {
    let mut findings = Vec::new();
    let param_names: Vec<String> = ir
        .parameters
        .iter()
        .filter_map(|p| ir.var_metadata.get(p).and_then(|m| m.source_name.clone()))
        .collect();
    let has_url_param = param_names.iter().any(|n| {
        let l = n.to_ascii_lowercase();
        frensense_lang::policy::bootstrap_url_param_hints()
            .iter()
            .any(|h| l.contains(h))
            || facts.url_param_hints.iter().any(|h| l.contains(h))
    });

    for block in ir.blocks.values() {
        for instr in &block.instructions {
            let (callee, recv, args, dest) = match instr {
                Instruction::CallVirtual {
                    method,
                    receiver,
                    args,
                    dest,
                    ..
                } => (method, Some(receiver), args, dest.as_ref()),
                Instruction::CallStatic {
                    func, args, dest, ..
                } => (func, None, args, dest.as_ref()),
                _ => continue,
            };
            let seg = last_segment(callee);
            let is_builtin = frensense_lang::policy::bootstrap_containment_callees().contains(&seg);
            let is_learned = facts
                .containment_callees
                .iter()
                .any(|c| c.eq_ignore_ascii_case(seg));
            if !is_builtin && !is_learned {
                continue;
            }
            // URL-ish receiver (`url.includes(x)`) or URL-ish argument in a
            // function that also takes a URL parameter, the allowlist-guard
            // shape. Receiver name comes from var metadata when present.
            let recv_is_url = recv
                .and_then(|r| match r {
                    Operand::Var(v) => ir.var_metadata.get(v).and_then(|m| m.source_name.clone()),
                    _ => None,
                })
                .map(|n| {
                    let l = n.to_ascii_lowercase();
                    frensense_lang::policy::bootstrap_url_param_hints()
                        .iter()
                        .any(|h| l.contains(h))
                        || facts.url_param_hints.iter().any(|h| l.contains(h))
                })
                .unwrap_or(false);
            let arg_is_urlish = args.iter().any(|a| match a {
                Operand::Var(v) => ir
                    .var_metadata
                    .get(v)
                    .and_then(|m| m.source_name.clone())
                    .map(|n| {
                        let l = n.to_ascii_lowercase();
                        frensense_lang::policy::bootstrap_url_arg_hints()
                            .iter()
                            .any(|h| l.contains(h))
                            || facts.url_arg_hints.iter().any(|h| l.contains(h))
                    })
                    .unwrap_or(false),
                _ => false,
            });
            if has_url_param && (recv_is_url || arg_is_urlish) {
                // The containment result must actually decide control flow
                // (feed a branch/switch condition or a returned predicate).
                // A value that gates nothing - discarded, only logged - is
                // not a guard, and neither is a statement-form call whose
                // result never exists.
                let Some(d) = dest else { continue };
                if !feeds_predicate(ir, *d) {
                    continue;
                }
                let span = ir.var_metadata.get(d).and_then(|m| m.byte_range);
                findings.push(CheckerFinding {
                    provenance: if is_learned {
                        Provenance::Learned
                    } else {
                        Provenance::Spec
                    },
                    function: ir.name.clone(),
                    rule: frensense_lang::rules::SUBSTRING_ALLOWLIST_GUARD.to_string(),
                    message: String::new(),
                    params: vec![("seg", seg.to_string())],
                    span,
                    severity: String::new(),
                });
            }
        }
    }
    findings
}

/// Forward def-use closure: does `dest` transitively decide control flow -
/// reach a `Branch`/`Switch` condition or a `Return` source? Bounded walk
/// (8 hops, visited-set) over instruction destinations and phi merges;
/// `false` means the value gates nothing.
fn feeds_predicate(ir: &FunctionIR, dest: VarId) -> bool {
    let mut seen: FxHashSet<VarId> = FxHashSet::default();
    seen.insert(dest);
    let mut frontier = vec![dest];
    for _ in 0..8 {
        if frontier.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for v in &frontier {
            for blk in ir.blocks.values() {
                match &blk.terminator {
                    Terminator::Branch {
                        cond: Operand::Var(c),
                        ..
                    }
                    | Terminator::Switch {
                        cond: Operand::Var(c),
                        ..
                    } if *c == *v => return true,
                    Terminator::Return {
                        src: Some(Operand::Var(s)),
                    } if *s == *v => return true,
                    _ => {}
                }
                for phi in &blk.phis {
                    if phi.incoming.iter().any(|(_, iv)| iv == v) && seen.insert(phi.dest) {
                        next.push(phi.dest);
                    }
                }
                for instr in &blk.instructions {
                    if uses_var(instr, *v)
                        && let Some(d) = dest_of(instr)
                        && seen.insert(d)
                    {
                        next.push(d);
                    }
                }
            }
        }
        frontier = next;
    }
    false
}

/// True when `instr` reads `v` in any operand position.
fn uses_var(instr: &Instruction, v: VarId) -> bool {
    let eq = |op: &Operand| matches!(op, Operand::Var(x) if *x == v);
    match instr {
        Instruction::Assign { src, .. }
        | Instruction::Cast { src, .. }
        | Instruction::UnaryOp { src, .. } => eq(src),
        Instruction::BinaryOp { lhs, rhs, .. } => eq(lhs) || eq(rhs),
        Instruction::LoadField { base, .. } => *base == v,
        Instruction::StoreField { base, src, .. } => *base == v || eq(src),
        Instruction::LoadElement { base, index, .. } => *base == v || eq(index),
        Instruction::StoreElement {
            base, index, src, ..
        } => *base == v || eq(index) || eq(src),
        Instruction::LoadGlobal { .. } | Instruction::Allocate { .. } => false,
        Instruction::StoreGlobal { src, .. } => eq(src),
        Instruction::CallStatic { args, .. } => args.iter().any(eq),
        Instruction::CallVirtual { receiver, args, .. } => eq(receiver) || args.iter().any(eq),
        Instruction::CallPointer { func_ptr, args, .. } => eq(func_ptr) || args.iter().any(eq),
        Instruction::AddressOf { src, .. } => *src == v,
        Instruction::Dereference { ptr, .. } => eq(ptr),
        Instruction::ExtractValue { tuple, .. } => eq(tuple),
        Instruction::Await { promise, .. } => eq(promise),
        Instruction::Yield { src, .. } => src.as_ref().is_some_and(eq),
    }
}

/// The variable `instr` defines, when it defines one.
fn dest_of(instr: &Instruction) -> Option<VarId> {
    match instr {
        Instruction::Assign { dest, .. }
        | Instruction::LoadField { dest, .. }
        | Instruction::LoadElement { dest, .. }
        | Instruction::LoadGlobal { dest, .. }
        | Instruction::Cast { dest, .. }
        | Instruction::ExtractValue { dest, .. }
        | Instruction::BinaryOp { dest, .. }
        | Instruction::UnaryOp { dest, .. }
        | Instruction::Await { dest, .. } => Some(*dest),
        Instruction::CallStatic { dest, .. }
        | Instruction::CallVirtual { dest, .. }
        | Instruction::CallPointer { dest, .. }
        | Instruction::Yield { dest, .. } => *dest,
        _ => None,
    }
}

/// Rule 2: credential hashing policy. A call named like a hasher whose
/// argument is (or resolves to) a parameter named like a plaintext password
/// fires the weak-credential-storage rule. Mechanism only: whether the
/// wrapped implementation is acceptable is exactly what corpus facts
/// (wrapper→primitive mappings) refine.
pub fn check_credentials(ir: &FunctionIR, facts: &FactTable) -> Vec<CheckerFinding> {
    let mut findings = Vec::new();
    for block in ir.blocks.values() {
        for instr in &block.instructions {
            let (callee, args, dest) = match instr {
                Instruction::CallVirtual {
                    method, args, dest, ..
                }
                | Instruction::CallStatic {
                    func: method,
                    args,
                    dest,
                    ..
                } => (method, args, dest.as_ref()),
                _ => continue,
            };
            let seg = last_segment(callee);
            let is_builtin_sink =
                frensense_lang::policy::bootstrap_credential_sinks().contains(&seg);
            let is_learned_sink = facts
                .credential_sinks
                .iter()
                .any(|s| s.eq_ignore_ascii_case(seg));
            if !is_builtin_sink && !is_learned_sink {
                continue;
            }
            let mut matched_learned = is_learned_sink;
            let cred_arg = args.iter().any(|a| match a {
                Operand::Var(v) => ir
                    .var_metadata
                    .get(v)
                    .and_then(|m| m.source_name.clone())
                    .map(|n| {
                        let l = n.to_ascii_lowercase();
                        let builtin = frensense_lang::policy::bootstrap_credential_params()
                            .iter()
                            .any(|c| l == c.to_ascii_lowercase());
                        let learned = facts
                            .credential_params
                            .iter()
                            .any(|c| l == c.to_ascii_lowercase());
                        if learned {
                            matched_learned = true;
                        }
                        builtin || learned
                    })
                    .unwrap_or(false),
                _ => false,
            });
            if cred_arg {
                // Verification shape: the digest result is only compared
                // against a stored value (`hash(pw) !== stored`), never
                // stored or passed on - checking a password is not a KDF
                // storage violation.
                if let Some(d) = dest
                    && only_used_in_comparison(ir, *d)
                {
                    continue;
                }
                let span = dest
                    .and_then(|d| ir.var_metadata.get(d))
                    .and_then(|m| m.byte_range);
                findings.push(CheckerFinding {
                    provenance: if matched_learned {
                        Provenance::Learned
                    } else {
                        Provenance::Spec
                    },
                    function: ir.name.clone(),
                    rule: frensense_lang::rules::CREDENTIAL_KDF_POLICY.to_string(),
                    message: String::new(),
                    params: vec![("seg", seg.to_string())],
                    span,
                    severity: String::new(),
                });
            }
        }
    }
    findings
}

/// Program-level rule: when a substring-containment guard exists somewhere
/// in the program AND a static initializer builds an allowlist collection
/// (`new Set([...])` / `new Map(...)`) of URL-ish strings, the *definition*
/// itself is part of the vulnerability, attacker URLs embed allowed
/// entries. One finding per allowlist definition, spanned at the
/// definition.
/// Resolve `var` to the allocation it (transitively) binds through `Assign`
/// copies - `const a = [..]` lowers to `Allocate` + a binding copy, and the
/// allowlist collections are constructed from their stored elements.
fn allocation_of(ir: &FunctionIR, mut var: VarId) -> Option<VarId> {
    for _ in 0..8 {
        let mut next = None;
        'blocks: for blk in ir.blocks.values() {
            for instr in &blk.instructions {
                let dest = match instr {
                    Instruction::Assign { dest, .. }
                    | Instruction::Allocate { dest, .. }
                    | Instruction::Cast { dest, .. }
                    | Instruction::CallStatic {
                        dest: Some(dest), ..
                    }
                    | Instruction::CallVirtual {
                        dest: Some(dest), ..
                    }
                    | Instruction::BinaryOp { dest, .. }
                    | Instruction::UnaryOp { dest, .. } => dest,
                    _ => continue,
                };
                if *dest != var {
                    continue;
                }
                match instr {
                    Instruction::Allocate { .. } => return Some(var),
                    Instruction::Assign {
                        src: Operand::Var(v),
                        ..
                    } => {
                        next = Some(*v);
                        break 'blocks;
                    }
                    _ => return None,
                }
            }
        }
        var = next?;
    }
    None
}

pub fn check_allowlist_definitions(irs: &[&FunctionIR], facts: &FactTable) -> Vec<CheckerFinding> {
    // The definition finding inherits the guards' knowledge source: a
    // program whose substring guards all come from bundle-learned
    // containment callees (none built in) is a learned finding.
    let mut guard_spec = false;
    let mut guard_learned = false;
    for ir in irs {
        for guard in check(ir, facts) {
            match guard.provenance {
                Provenance::Spec | Provenance::Authored => guard_spec = true,
                Provenance::Learned => guard_learned = true,
            }
        }
    }
    if !guard_spec && !guard_learned {
        return Vec::new();
    }
    let guard_provenance = if guard_spec {
        Provenance::Spec
    } else {
        Provenance::Learned
    };
    let mut findings = Vec::new();
    for ir in irs {
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let (callee, args, dest) = match instr {
                    Instruction::CallStatic {
                        func, args, dest, ..
                    } => (func, args, dest),
                    _ => continue,
                };
                let seg = last_segment(callee);
                if !matches!(seg, "Set" | "Map") {
                    continue;
                }
                // Entries may arrive as direct literal args (legacy union
                // lowering) or as stored elements of an allocated
                // collection: `[a, b]` lowers to `Allocate` + `StoreElement`s
                // bound through a copy (`const x = new Set([...])`).
                let mut stored: Vec<&Operand> = Vec::new();
                for a in args {
                    if let Operand::Var(v) = a
                        && let Some(alloc) = allocation_of(ir, *v)
                    {
                        for blk in ir.blocks.values() {
                            for ins in &blk.instructions {
                                if let Instruction::StoreField { base, src, .. }
                                | Instruction::StoreElement { base, src, .. } = ins
                                    && *base == alloc
                                {
                                    stored.push(src);
                                }
                            }
                        }
                    }
                }
                let mut urlish = false;
                let mut first_url_span = None;
                for a in args.iter().chain(stored.iter().copied()) {
                    if let Operand::StringLiteral(s) = a {
                        let l = s.to_ascii_lowercase();
                        if frensense_lang::policy::bootstrap_url_literal_hints()
                            .iter()
                            .any(|h| l.contains(h))
                            || facts.url_literal_hints.iter().any(|h| l.contains(h))
                        {
                            urlish = true;
                            // The entry literal's own span: the concrete
                            // allowlist item an attacker embeds. Prefer it
                            // over the whole-definition span.
                            if first_url_span.is_none() {
                                first_url_span = Some(a);
                            }
                        }
                    }
                }
                if !urlish {
                    continue;
                }
                // Span of the first URL entry's *node*: the StringLiteral
                // operand doesn't carry a span, so fall back through the
                // dest (whole definition). Entry-level precision needs the
                // literal's byte range in Operand metadata, track TODO.
                let _ = first_url_span;
                let span = dest
                    .as_ref()
                    .and_then(|d| ir.var_metadata.get(d))
                    .and_then(|m| m.byte_range);
                findings.push(CheckerFinding {
                    provenance: guard_provenance,
                    function: ir.name.clone(),
                    rule: frensense_lang::rules::ALLOWLIST_DEFINITION_BYPASSABLE.to_string(),
                    message: String::new(),
                    params: Vec::new(),
                    span,
                    severity: String::new(),
                });
            }
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Verification-shape qualification for `credential_kdf_policy`
// ---------------------------------------------------------------------------

fn operand_is_var(op: &Operand, v: VarId) -> bool {
    matches!(op, Operand::Var(x) if *x == v)
}

fn instruction_uses_var(instr: &Instruction, v: VarId) -> bool {
    match instr {
        Instruction::Assign { src, .. } => operand_is_var(src, v),
        Instruction::LoadField { base, .. } => *base == v,
        Instruction::StoreField { base, src, .. } => *base == v || operand_is_var(src, v),
        Instruction::LoadElement { base, index, .. } => *base == v || operand_is_var(index, v),
        Instruction::StoreElement {
            base, index, src, ..
        } => *base == v || operand_is_var(index, v) || operand_is_var(src, v),
        Instruction::StoreGlobal { src, .. } => operand_is_var(src, v),
        Instruction::CallStatic { args, .. } => args.iter().any(|a| operand_is_var(a, v)),
        Instruction::CallVirtual { receiver, args, .. } => {
            operand_is_var(receiver, v) || args.iter().any(|a| operand_is_var(a, v))
        }
        Instruction::CallPointer { func_ptr, args, .. } => {
            operand_is_var(func_ptr, v) || args.iter().any(|a| operand_is_var(a, v))
        }
        Instruction::AddressOf { src, .. } => *src == v,
        Instruction::Dereference { ptr, .. } => operand_is_var(ptr, v),
        Instruction::Cast { src, .. } => operand_is_var(src, v),
        Instruction::ExtractValue { tuple, .. } => operand_is_var(tuple, v),
        Instruction::BinaryOp { lhs, rhs, .. } => operand_is_var(lhs, v) || operand_is_var(rhs, v),
        Instruction::UnaryOp { src, .. } => operand_is_var(src, v),
        Instruction::Await { promise, .. } => operand_is_var(promise, v),
        Instruction::Yield { src, .. } => src.as_ref().is_some_and(|s| operand_is_var(s, v)),
        _ => false,
    }
}

fn terminator_uses_var(t: &Terminator, v: VarId) -> bool {
    match t {
        Terminator::Branch { cond, .. } => operand_is_var(cond, v),
        Terminator::Switch { cond, cases, .. } => {
            operand_is_var(cond, v) || cases.iter().any(|(c, _)| operand_is_var(c, v))
        }
        Terminator::Return { src } => src.as_ref().is_some_and(|s| operand_is_var(s, v)),
        Terminator::Throw { src } => operand_is_var(src, v),
        _ => false,
    }
}

/// True when every use of `v` is an operand of a *comparison* BinaryOp
/// (verification: `security.hash(pw) !== stored`). A value that is stored,
/// passed to another call, returned, or unused fires the policy as before;
/// phi participation counts as a non-comparison use (conservative).
fn only_used_in_comparison(ir: &FunctionIR, v: VarId) -> bool {
    let mut total = 0usize;
    let mut cmp = 0usize;
    for b in ir.blocks.values() {
        for phi in &b.phis {
            if phi.dest == v || phi.incoming.iter().any(|(_, x)| *x == v) {
                total += 1;
            }
        }
        for instr in &b.instructions {
            if !instruction_uses_var(instr, v) {
                continue;
            }
            total += 1;
            let is_cmp = if let Instruction::BinaryOp { op, lhs, rhs, .. } = instr {
                (operand_is_var(lhs, v) || operand_is_var(rhs, v))
                    && matches!(op.as_str(), "==" | "===" | "!=" | "!==" | "in" | "not in")
            } else {
                false
            };
            if is_cmp {
                cmp += 1;
            }
        }
        if terminator_uses_var(&b.terminator, v) {
            total += 1;
        }
    }
    total > 0 && total == cmp
}
