// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! The weak-hash / weak-crypto rule: non-dataflow policy assertions over lowered IR.
//!
//! Taint analysis answers "does attacker-controlled data reach a dangerous
//! API?", but a whole class of vulnerabilities has no taint path at all:
//! weak cryptographic primitives (MD5 for passwords), hardcoded credentials,
//! insecure JWT algorithms (`{ algorithm: 'none' }`), disabled TLS
//! verification. The bug is in *which API / which constant* the developer
//! chose, not in how data flows.
//!
//! Each rule is a function over one [`FunctionIR`] plus the language spec's
//! knowledge tables. A rule fires a [`CheckerFinding`] when its pattern
//! matches; no sources, sinks or sanitizers are consulted. This keeps the
//! checker immune to taint-config drift and free to run per function in
//! parallel.

use crate::analysis::taint::facts::FactTable;
use crate::checks::CheckerFinding;
use crate::checks::Provenance;
use crate::checks::last_segment;
use crate::ir::function::{FunctionIR, Instruction, Operand};

// Weak-hash, key-size and insecure-selector policy tables are FACT DATA:
// the engine reads only `FactTable` fields, seeded by the language spec
// (`fact_table_from_spec`) and extended by `.frc` bundles. No bootstrap
// vocabulary is referenced from this module.

fn strip_quotes(lit: &str) -> &str {
    let lit = lit.trim();
    let bytes = lit.as_bytes();
    let (core, _) = match bytes.first() {
        Some(b'\'') | Some(b'"') | Some(b'`') => {
            let end = bytes.len().saturating_sub(1);
            (&lit[1..end], true)
        }
        _ => (lit, false),
    };
    core
}

/// Security-context qualification for the hash-wrapper rule: the
/// enclosing function's name when it hints at security code
/// (`facts.security_context_hints`), else `None`. A cheap static stand-in
/// for the full receiver-chain walk, which needs cross-function
/// information; the corpus replay gate learns wrapper-to-primitive
/// mappings from pairs instead.
fn receiver_path(ir: &FunctionIR, facts: &FactTable) -> Option<String> {
    let n = ir.name.to_ascii_lowercase();
    if facts.security_context_hints.iter().any(|h| n.contains(h)) {
        return Some(ir.name.clone());
    }
    None
}

/// The weak-hash / weak-crypto rule: scan one function for security-weak
/// primitives.
pub fn check(ir: &FunctionIR, facts: &FactTable) -> Vec<CheckerFinding> {
    check_function(ir, facts)
}

pub fn check_function(ir: &FunctionIR, facts: &FactTable) -> Vec<CheckerFinding> {
    // The value lattice lets selector rules see through constant
    // assignments: `const alg = 'none'; jwt.sign(payload, secret, alg)`
    // must fire even though the selector operand is a var, not a literal.
    let values = crate::analysis::value::analyze(ir);
    let mut findings = Vec::new();
    for block in ir.blocks.values() {
        for instr in &block.instructions {
            match instr {
                Instruction::CallStatic { func, args, .. } => {
                    check_call(
                        ir,
                        func,
                        func,
                        args,
                        instr_span(ir, instr),
                        &values,
                        facts,
                        &mut findings,
                    );
                }
                Instruction::CallVirtual {
                    method,
                    receiver,
                    args,
                    ..
                } => {
                    let path = crate::analysis::forward::receiver_call_path(ir, receiver, method);
                    check_call(
                        ir,
                        method,
                        &path,
                        args,
                        instr_span(ir, instr),
                        &values,
                        facts,
                        &mut findings,
                    );
                }
                _ => {}
            }
        }
    }
    findings
}

/// Resolve an argument operand to its string-literal value: direct literal,
/// or a var whose lattice value is a provable string constant.
fn arg_str_literal<'a>(
    arg: &'a Operand,
    values: &'a crate::analysis::value::ValueInfo,
) -> Option<&'a str> {
    match arg {
        Operand::StringLiteral(s) => Some(strip_quotes(s)),
        // Lattice constants carry the lowering's raw quote characters, same
        // as direct string literals: strip before matching.
        Operand::Var(v) => values.const_str(*v).map(strip_quotes),
        _ => None,
    }
}

/// Resolve an argument operand to its integer-literal value: direct literal,
/// or a var whose lattice value is a provable integer constant.
fn arg_int_literal(arg: &Operand, values: &crate::analysis::value::ValueInfo) -> Option<i64> {
    match arg {
        Operand::IntLiteral(n) => Some(*n),
        Operand::Var(v) => values.const_int(*v),
        _ => None,
    }
}

fn instr_span(ir: &FunctionIR, instr: &Instruction) -> Option<(usize, usize)> {
    // The call result var carries the call expression's byte range (set by
    // the lowering pass). Find the dest of this instruction.
    let dest = match instr {
        Instruction::CallStatic { dest, .. }
        | Instruction::CallVirtual { dest, .. }
        | Instruction::CallPointer { dest, .. } => (*dest)?,
        _ => return None,
    };
    ir.var_metadata.get(&dest)?.byte_range
}

#[allow(clippy::too_many_arguments)] // fact/lattice/out plumbing, no meaningful grouping
fn check_call(
    ir: &FunctionIR,
    callee: &str,
    full_path: &str,
    args: &[Operand],
    span: Option<(usize, usize)>,
    values: &crate::analysis::value::ValueInfo,
    facts: &FactTable,
    out: &mut Vec<CheckerFinding>,
) {
    // Receiver chains are matched by last segment: `security.hash` and bare
    // `hash` both hit the `hash` rule. This is deliberately over-approximate
    // (a user object with an unrelated `.hash` method also fires); the
    // message names the call, and false positives of this class are rare
    // relative to the cost of tracking receiver types through the IR.
    let callee_seg = last_segment(callee);
    let callee_lower = callee_seg.to_ascii_lowercase();

    for rule in &facts.weak_hash_rules {
        let provenance = Provenance::Spec;
        // Selector shape: `createHash('md5')`. Rules with
        // `requires_credential_context` fire only inside credential-named
        // functions or with credential-named parameters (a general-purpose
        // `createHash` doubles as a checksum API); rules without it fire
        // wherever a weak algorithm is named explicitly.
        if (!rule.requires_credential_context || in_credential_context(ir, facts))
            && rule.selector_calls.iter().any(|c| {
                let c = last_segment(c).to_ascii_lowercase();
                c == callee_lower
            })
            && let Some(sel) = args
                .get(rule.selector_slot)
                .and_then(|a| arg_str_literal(a, values))
                .map(str::to_ascii_lowercase)
            && rule.weak_selectors.contains(&sel)
        {
            out.push(CheckerFinding {
                provenance,
                function: ir.name.clone(),
                rule: rule.rule_id.to_string(),
                message: String::new(),
                params: vec![("callee", callee_seg.to_string()), ("sel", sel.to_string())],
                span,
                severity: rule.severity.to_string(),
            });
            return; // one finding per call site
        }
        // Bare shape: `md5(data)`.
        if rule
            .bare_calls
            .iter()
            .any(|c| last_segment(c).to_ascii_lowercase() == callee_lower)
        {
            out.push(CheckerFinding {
                provenance,
                function: ir.name.clone(),
                rule: rule.rule_id.to_string(),
                message: String::new(),
                params: vec![("callee", callee_seg.to_string())],
                span,
                severity: rule.severity.to_string(),
            });
            return;
        }
    }

    // Evaluate corpus-learned weak crypto rules
    for fact in &facts.weak_crypto_rules {
        let fact_call_seg = last_segment(&fact.call).to_ascii_lowercase();
        if fact_call_seg == callee_lower {
            if let Some(slot) = fact.selector_slot {
                if let Some(sel) = args
                    .get(slot)
                    .and_then(|a| arg_str_literal(a, values))
                    .map(str::to_ascii_lowercase)
                    && fact
                        .weak_selectors
                        .iter()
                        .any(|ws| ws.to_ascii_lowercase() == sel)
                {
                    out.push(CheckerFinding {
                        provenance: Provenance::Learned,
                        function: ir.name.clone(),
                        rule: fact.rule_id.clone(),
                        message: String::new(),
                        params: vec![("callee", callee_seg.to_string()), ("sel", sel.to_string())],
                        span,
                        severity: fact.severity.clone(),
                    });
                    return;
                }
            } else {
                out.push(CheckerFinding {
                    provenance: Provenance::Learned,
                    function: ir.name.clone(),
                    rule: fact.rule_id.clone(),
                    message: String::new(),
                    params: vec![("callee", callee_seg.to_string())],
                    span,
                    severity: fact.severity.clone(),
                });
                return;
            }
        }
    }

    // Hash-wrapper heuristic: a call named `hash`/`hashPassword` whose
    // receiver is a security-ish namespace. Matched by last segment of the
    // receiver chain when available; bare `hash(x)` is too generic to flag
    // on its own, so require a known crypto-receiver qualification.
    let spec_wrapper = facts
        .suspicious_hash_wrappers
        .contains(callee_lower.as_str());
    if spec_wrapper && let Some(path) = receiver_path(ir, facts) {
        out.push(CheckerFinding {
            provenance: Provenance::Spec,
            function: ir.name.clone(),
            rule: frensense_lang::rules::WEAK_HASH_WRAPPER.to_string(),
            message: String::new(),
            params: vec![("path", path.clone())],
            span,
            severity: String::new(),
        });
    }

    // Weak key size: a key-generation/parameter call whose bit-length
    // argument is a PROVABLE CONSTANT below the security floor. The value
    // lattice resolves `const bits = 512; generateKey(bits)` the same as a
    // direct literal, so wrapper indirection doesn't hide the weakness.
    for rule in &facts.key_size_rules {
        let provenance = Provenance::Spec;
        if last_segment(rule.call.as_str()).to_ascii_lowercase() != callee_lower {
            continue;
        }
        if let Some(slot) = args.get(rule.slot) {
            let weak = arg_int_literal(slot, values)
                .map(|bits| bits < rule.min_bits)
                .unwrap_or(false);
            if weak {
                out.push(CheckerFinding {
                    provenance,
                    function: ir.name.clone(),
                    rule: rule.rule_id.to_string(),
                    message: String::new(),
                    params: vec![
                        ("callee", callee_seg.to_string()),
                        ("min_bits", rule.min_bits.to_string()),
                        ("kind", rule.kind.to_string()),
                    ],
                    span,
                    severity: rule.severity.to_string(),
                });
                return;
            }
        }
    }

    // Insecure literal selectors (`{ algorithm: 'none' }` shapes land here
    // once object literals are flattened; for now the string form).
    for rule in &facts.insecure_config_selectors {
        let provenance = Provenance::Spec;
        // Match the full dotted call path (`jwt.verify`) or the callee
        // (`jwtChallenge`); only a *verifier* accepting an insecure
        // algorithm is the violation - token issuers that merely embed the
        // literal (`jwtChallenge(id, req, 'none', ...)`) are harness code.
        let path_lower = full_path.to_ascii_lowercase();
        if !(path_lower.starts_with(rule.prefix.as_str())
            || callee_lower.starts_with(rule.prefix.as_str()))
        {
            continue;
        }
        if !jwt_algorithm_context(&path_lower, &callee_lower, facts) {
            continue;
        }
        for arg in args {
            if let Some(lit) = arg_str_literal(arg, values)
                && rule.selectors.contains(&lit.to_ascii_lowercase())
            {
                out.push(CheckerFinding {
                    provenance,
                    function: ir.name.clone(),
                    rule: rule.rule_id.to_string(),
                    message: String::new(),
                    params: vec![("callee", callee_seg.to_string()), ("sel", lit.to_string())],
                    span,
                    severity: rule.severity.to_string(),
                });
                return;
            }
        }
    }
}

/// Algorithm-operation qualification for `insecure_jwt_algorithm`: the
/// callee path must hint at an operation whose algorithm choice matters
/// (verify/decode/sign/...), vocabulary from the default pack
/// (`FactTable::jwt_algorithm_hints`) - harness wrappers
/// that merely embed the literal stay silent.
fn jwt_algorithm_context(path: &str, callee: &str, facts: &FactTable) -> bool {
    let matches = |s: &str| facts.jwt_algorithm_hints.iter().any(|h| s.contains(h));
    matches(path) || matches(callee)
}

/// Credential-context qualification for the selector-shape weak-hash rule:
/// the enclosing function name or a parameter name must hint at a
/// credential context (password/secret/token/...). A generic digest
/// utility (`const digest = (data) => createHash('md5')`) is not a KDF
/// shape; credential-named wrappers (`hashPassword(clearText)`) are.
/// Bare weak calls (`md5(data)`) stay unqualified - they are weak by
/// themselves.
fn in_credential_context(ir: &FunctionIR, facts: &FactTable) -> bool {
    let hint_match = |s: &str| {
        let l = s.to_ascii_lowercase();
        facts.credential_context_hints.iter().any(|h| l.contains(h))
    };
    if hint_match(&ir.name) {
        return true;
    }
    ir.parameters.iter().any(|p| {
        ir.var_metadata
            .get(p)
            .and_then(|m| m.source_name.as_deref())
            .is_some_and(hint_match)
    })
}
