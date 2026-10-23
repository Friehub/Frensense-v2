// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Co-occurrence policy checks: the generalized learned-check evaluator.
//!
//! A [`PolicyFact`] poses a question at every trigger call: do the policy's
//! requirements hold in the trigger's scope? A function violating the policy
//! (trigger present, at least one requirement unsatisfied) yields a
//! [`CheckerFinding`]. This complements and operates alongside
//! `LearnedCheckFact` - `unless_guard` is evaluated as a `GuardCall`
//! requirement, `unless_range_check` as a `RangeCheck` - and adds the
//! presence forms (`RequireCall`, `NotCall`) plus a cross-function scope,
//! so bundles can express "privileged action without its audit log",
//! "dangerous call without any of its sanctioned wrappers", or "trigger
//! helper defined in a sibling module still counts as enforcement".

use rustc_hash::FxHashMap;

use super::CheckerFinding;
use super::Provenance;
use super::learned::{call_segments, is_range_guarded};
use crate::analysis::taint::facts::{FactTable, PolicyFact, PolicyRequirement, PolicyScope};
use crate::graph::module::PackageImport;
use crate::ir::control::{self, DomSets};
use crate::ir::function::{BlockId, FunctionIR, Instruction, Operand, VarId};

/// A taught callable matches a written callee in one of two modes:
///
/// - bare fact (`issue_refund`): matched by the callee's last segment, the
///   dominant learned-check rule that every sink vocabulary shares;
/// - qualified fact (`payments.issue_refund`, `storage::ops::wipe_volume`):
///   matched through the full dotted tail against the callee's written
///   path, so a trigger pinned to one member no longer collides with an
///   unrelated object that happens to share the verb
///   (`billing.issue_refund` stays silent for a `payments.issue_refund`
///   policy).
///
/// Presence-level requirements only see bare segment lists (see
/// `call_segments`), so they keep bare matching; this narrowing applies
/// exactly where instruction-letter callee paths are available.
#[inline]
fn callee_matches(taught: &str, written: &str) -> bool {
    if !taught.contains('.') && !taught.contains("::") {
        return super::last_segment(written) == taught;
    }
    let norm = |s: &str| -> String { s.replace("::", ".") };
    let t = norm(taught);
    let w = norm(written);
    if w == t {
        return true;
    }
    let mut dotted_tail = String::with_capacity(t.len() + 1);
    dotted_tail.push('.');
    dotted_tail.push_str(&t);
    w.ends_with(dotted_tail.as_str())
}

/// Package-import context for policy scoping: which file each function
/// came from, and which external packages each file imports. Policies
/// carrying `package: Some(pkg)` only fire in functions whose file
/// imports `pkg` (mirrors the sink/source package-scoping model).
pub struct PackageScope<'a> {
    /// Function name -> source file path.
    pub fn_file: &'a FxHashMap<String, String>,
    /// File path -> (local import name -> import record).
    pub file_package_imports: &'a FxHashMap<String, FxHashMap<String, PackageImport>>,
}

impl<'a> PackageScope<'a> {
    /// Does the file containing `fn_name` import `pkg`?
    ///
    /// Mirrors the taint engine's single-file fallback
    /// (`walk.rs`): when the map holds exactly one file's imports,
    /// use those regardless of the function's declared file.
    pub fn fn_imports_package(&self, fn_name: &str, pkg: &str) -> bool {
        let imports = self
            .fn_file
            .get(fn_name)
            .and_then(|file| self.file_package_imports.get(file))
            .or_else(|| {
                if self.file_package_imports.len() == 1 {
                    self.file_package_imports.values().next()
                } else {
                    None
                }
            });
        imports.is_some_and(|m| m.values().any(|i| i.package == pkg))
    }
}

/// Evaluate every policy fact in `facts` over the scanned program.
///
/// Function-scoped policies evaluate per function; module-scoped policies
/// evaluate against the union of all scanned functions (the check pipeline
/// passes one scan's IR set here, which is the module the policy author
/// refers to). Active `learned_checks` participate alongside native policies,
/// ensuring both check representations fire harmoniously.
pub fn check_program(irs: &[&FunctionIR], facts: &FactTable) -> Vec<CheckerFinding> {
    check_program_scoped(irs, facts, None)
}

/// [`check_program`] with package-scope filtering: policies carrying
/// `package: Some(pkg)` only fire in functions whose file imports `pkg`.
/// `scope = None` disables filtering (backward-compatible default).
pub fn check_program_scoped(
    irs: &[&FunctionIR],
    facts: &FactTable,
    scope: Option<&PackageScope<'_>>,
) -> Vec<CheckerFinding> {
    if facts.learned_checks.is_empty() && facts.policy_facts.is_empty() {
        return Vec::new();
    }

    // Function index by name for stable ordering; segment sets per function
    // (computed once per function, not per trigger).
    let mut segsets: FxHashMap<&str, Vec<String>> = FxHashMap::default();
    for ir in irs {
        segsets.insert(ir.name.as_str(), call_segments(ir));
    }
    // Program-wide segment set for module-scoped requirements: every call
    // segment anywhere PLUS every defined function name (a sibling module
    // that DEFINES the enforcement helper counts as enforcement available;
    // the definition is the strongest evidence a helper is in scope even if
    // this scan never sees its call site).
    let mut module_segs: Vec<String> = segsets.values().flatten().cloned().collect();
    module_segs.extend(irs.iter().map(|ir| ir.name.clone()));
    module_segs.sort();
    module_segs.dedup();

    // Learned checks evaluate alongside native policies (deduped by rule id:
    // a bundle shipping both shapes of the same rule must not fire twice).
    // Each entry keeps its own provenance so findings report the origin.
    let mut native_rules: Vec<&str> = facts
        .policy_facts
        .iter()
        .map(|(p, _)| p.rule.as_str())
        .collect();
    native_rules.sort();
    native_rules.dedup();
    let mut all_policies: Vec<(PolicyFact, Provenance)> = Vec::new();
    all_policies.extend(facts.policy_facts.iter().cloned());
    for (check, prov) in &facts.learned_checks {
        if native_rules.contains(&check.rule.as_str()) {
            continue;
        }
        all_policies.push((PolicyFact::from_legacy(check), *prov));
    }

    let mut findings = Vec::new();
    // Function-scoped import-alias resolution (`from x import A as B`):
    // a Trigger call spelled with the local alias `B` resolves to the
    // original symbol `A`, so a check taught at the shipped name still
    // fires on renamed callers (WI cross-cut: aliasing is callee
    // resolution, engine-side mechanism, no per-language vocabulary).
    let mut alias_maps: FxHashMap<&str, FxHashMap<String, String>> = FxHashMap::default();
    if let Some(scope) = scope {
        for ir in irs {
            let imports = scope
                .fn_file
                .get(ir.name.as_str())
                .and_then(|file| scope.file_package_imports.get(file))
                .or_else(|| {
                    if scope.file_package_imports.len() == 1 {
                        scope.file_package_imports.values().next()
                    } else {
                        None
                    }
                });
            if let Some(imports) = imports {
                let aliases: FxHashMap<String, String> = imports
                    .iter()
                    .filter_map(|(local, pi)| {
                        pi.symbol
                            .as_deref()
                            .filter(|sym| *sym != local)
                            .map(|sym| (local.to_string(), sym.to_string()))
                    })
                    .collect();
                if !aliases.is_empty() {
                    alias_maps.insert(ir.name.as_str(), aliases);
                }
            }
        }
    }
    // Dominance for function-scoped guard/require presence: cached per
    // function across policies (computed at most once per scanned IR).
    let mut dom_cache: FxHashMap<&str, DomSets> = FxHashMap::default();
    for (policy, policy_provenance) in &all_policies {
        // The FULL taught callee goes into trigger matching: a bare fact
        // matches by last segment, a qualified fact (`payments.issue_refund`)
        // matches the written callee path (see `callee_matches`).
        let trigger_call: &str = &policy.when_call;
        let needs_dom = policy.scope == PolicyScope::Function
            && policy.require.iter().any(|r| {
                matches!(
                    r,
                    PolicyRequirement::GuardCall { .. } | PolicyRequirement::RequireCall { .. }
                )
            });
        for ir in irs {
            let segs = match segsets.get(ir.name.as_str()) {
                Some(s) => s,
                None => continue,
            };
            // Package-scope filter: a policy carrying `package: Some(pkg)`
            // only fires in functions whose file imports `pkg` (mirrors the
            // sink/source package-scoping model). When no scope context is
            // supplied (unit tests, legacy callers) the filter is inert.
            if let (Some(pkg), Some(scope)) = (&policy.package, scope)
                && !scope.fn_imports_package(&ir.name, pkg)
            {
                continue;
            }
            let doms: Option<&DomSets> = if needs_dom {
                let d: &DomSets = dom_cache
                    .entry(ir.name.as_str())
                    .or_insert_with(|| control::dominators(ir));
                Some(d)
            } else {
                None
            };
            let val_info = crate::analysis::value::analyze(ir);
            // Collect every trigger call site in this function with its args.
            for (bid, idx, args, arg_names, span) in
                trigger_sites(ir, trigger_call, alias_maps.get(ir.name.as_str()))
            {
                // A requirement violation is the finding — but a
                // presence-only policy (`require` empty) alerts whenever
                // the trigger call occurs at all: the corpus twins proved
                // the call site itself is the vulnerability (the negative
                // avoids the call, not a guard shape around it).
                let satisfied = !policy.require.is_empty()
                    && policy.require.iter().all(|req| {
                        requirement_holds(
                            req,
                            ir,
                            bid,
                            idx,
                            doms,
                            &val_info,
                            args,
                            arg_names,
                            segs,
                            &module_segs,
                            policy.scope,
                        )
                    });
                if !satisfied {
                    findings.push(CheckerFinding {
                        function: ir.name.clone(),
                        rule: policy.rule.clone(),
                        message: policy.message.clone(),
                        params: Vec::new(),
                        span,
                        severity: policy.severity.clone(),
                        provenance: *policy_provenance,
                    });
                }
            }
        }
    }
    findings
}

/// Every call instruction in `ir` whose callee's last segment is `seg`,
/// as (bid, instr index, args, keyword names, span) tuples. The index
/// orders same-block guard/trigger pairs; `keyword names` is parallel to
/// `args` and may be shorter (missing entry = positional).
type TriggerSite<'a> = (
    BlockId,
    usize,
    &'a [Operand],
    &'a [String],
    Option<(usize, usize)>,
);

fn trigger_sites<'a>(
    ir: &'a FunctionIR,
    seg: &str,
    aliases: Option<&FxHashMap<String, String>>,
) -> Vec<TriggerSite<'a>> {
    let mut out = Vec::new();
    for (&bid, block) in &ir.blocks {
        for (idx, instr) in block.instructions.iter().enumerate() {
            // Written callee path: static calls carry their full path
            // (Rust `storage::ops::wipe_volume`); member calls are
            // reconstructed from the receiver chain (`payments.x` ->
            // `payments.x`), so qualified facts can match the exact
            // member instead of every object sharing the bare verb.
            let name = match instr {
                Instruction::CallStatic { func, .. } => func.clone(),
                Instruction::CallVirtual {
                    method, receiver, ..
                } => crate::analysis::forward::receiver_call_path(ir, receiver, method),
                _ => continue,
            };
            // The callee's bare last segment, or an import alias resolving
            // to `seg` (`refund` -> `issue_refund`), counts as the trigger.
            // A qualified taught name matches the written callee path
            // instead of the bare verb (see `callee_matches`).
            let matches = callee_matches(seg, &name)
                || aliases.is_some_and(|m| {
                    m.get(super::last_segment(&name))
                        .is_some_and(|sym| callee_matches(seg, sym))
                });
            if !matches {
                continue;
            }
            let (args, arg_names) = call_args(instr).unwrap_or((&[], &[]));
            out.push((bid, idx, args, arg_names, instr_span(ir, instr)));
        }
    }
    out
}

/// A call instruction's argument list and its parallel keyword names, for
/// site indexing outside the match arm that already destructures it. The
/// name slice may be shorter than the argument slice; a missing entry is a
/// positional argument.
fn call_args(instr: &Instruction) -> Option<(&[Operand], &[String])> {
    match instr {
        Instruction::CallStatic {
            args, arg_names, ..
        } => Some((args.as_slice(), arg_names.as_slice())),
        Instruction::CallVirtual {
            args, arg_names, ..
        } => Some((args.as_slice(), arg_names.as_slice())),
        _ => None,
    }
}

/// Does one requirement hold for this trigger site?
#[allow(clippy::too_many_arguments)]
fn requirement_holds(
    req: &PolicyRequirement,
    ir: &FunctionIR,
    block: BlockId,
    trigger_idx: usize,
    doms: Option<&DomSets>,
    val_info: &crate::analysis::value::ValueInfo,
    args: &[Operand],
    arg_names: &[String],
    fn_segs: &[String],
    module_segs: &[String],
    scope: PolicyScope,
) -> bool {
    match req {
        PolicyRequirement::GuardCall { call } => {
            // Enforcement by a named helper. Function scope is spatial: the
            // guard must EXECUTE before the trigger on every path (its block
            // dominates the trigger's, or same block with the guard first) -
            // a call that may be skipped enforces nothing. Module scope
            // stays presence (the helper exists somewhere in the module).
            let seg = super::last_segment(call);
            if is_entry_guarded(ir, seg) {
                return true;
            }
            if scope == PolicyScope::Module {
                module_segs.iter().any(|s| s == seg)
            } else {
                // Spatial matching sees the full taught guard name so a
                // qualified helper matches its member-call sites exactly.
                guard_executes_before(ir, call, block, trigger_idx, doms)
            }
        }
        PolicyRequirement::RequireCall { any_of } => {
            if scope == PolicyScope::Module {
                let wanted: Vec<&str> = any_of.iter().map(|c| super::last_segment(c)).collect();
                return module_segs.iter().any(|s| wanted.contains(&s.as_str()));
            }
            any_of.iter().any(|c| {
                is_entry_guarded(ir, super::last_segment(c))
                    || guard_executes_before(ir, c, block, trigger_idx, doms)
            })
        }
        PolicyRequirement::NotCall { call } => {
            let seg = super::last_segment(call);
            !scope_segs(scope, fn_segs, module_segs)
                .iter()
                .any(|s| s == seg)
        }
        PolicyRequirement::RangeCheck { ops } => args.iter().any(|a| match a {
            Operand::Var(v) => is_range_guarded(ir, *v, ops, block, val_info),
            _ => false,
        }),
        PolicyRequirement::BannedArgLiteral { slot, values } => {
            if let Some(arg) = args.get(*slot)
                && let Some(s) = extract_literal_string(arg, ir, val_info)
            {
                let s_lower = s.to_ascii_lowercase();
                return !values.iter().any(|v| v.to_ascii_lowercase() == s_lower);
            }
            true
        }
        PolicyRequirement::RequiredArgLiteral { slot, values } => {
            if let Some(arg) = args.get(*slot)
                && let Some(s) = extract_literal_string(arg, ir, val_info)
            {
                let s_lower = s.to_ascii_lowercase();
                return values.iter().any(|v| v.to_ascii_lowercase() == s_lower);
            }
            false
        }
        PolicyRequirement::RequireArgKey { slot, keys } => {
            if *slot == usize::MAX {
                args.iter().any(|a| match a {
                    Operand::Var(v) => arg_has_key(ir, *v, keys),
                    _ => false,
                })
            } else {
                args.get(*slot).is_some_and(|arg| match arg {
                    Operand::Var(v) => arg_has_key(ir, *v, keys),
                    _ => false,
                })
            }
        }
        PolicyRequirement::RequireNamedArgLiteral { name, values } => {
            let Some(idx) = arg_names.iter().position(|n| n.eq_ignore_ascii_case(name)) else {
                // The caller never set the flag: the violation the policy
                // exists to catch.
                return false;
            };
            match args
                .get(idx)
                .and_then(|a| extract_literal_string(a, ir, val_info))
            {
                // A provable literal must be one of the required values.
                Some(s) => values.iter().any(|v| v.eq_ignore_ascii_case(&s)),
                // Unresolvable value: literal-only proof, so not a
                // violation. This is the conservative direction - it can
                // miss `secure=flag`, never invent it.
                None => true,
            }
        }
    }
}

/// True when the function's own definition carries a decorator/attribute
/// whose call name is `seg` (`@guard`, `#[guard]`). A decorator executes
/// before ANY statement of the body, so it dominates every trigger in the
/// function by construction - the caller-side enforcement shape.
fn is_entry_guarded(ir: &FunctionIR, seg: &str) -> bool {
    ir.entry_guards
        .iter()
        .any(|g| super::last_segment(g) == seg)
}

/// The bundler's fact extractor consults the SAME guard model the scanner
/// uses, so a corpus twin can teach a check whose negative suppresses the
/// trigger dominantly (a bare `guard(x);` statement before the trigger,
/// same block earlier or in a dominating block) even when no dataflow
/// connects the guard's value to the trigger's arguments. Argument-nested
/// calls (`new Date()` inside a `where: { lt: ... }` literal) are excluded,
/// as their span lies inside the trigger's argument span. Mechanism only;
/// conclusions stay bundle data.
pub fn guard_dominates_trigger_call(ir: &FunctionIR, guard_seg: &str, trigger_seg: &str) -> bool {
    let doms = control::dominators(ir);
    let call_span = |bid: BlockId, idx: usize| -> Option<(usize, usize)> {
        ir.blocks
            .get(&bid)
            .and_then(|b| b.instructions.get(idx))
            .and_then(|instr| match instr {
                Instruction::CallStatic { dest, .. }
                | Instruction::CallVirtual { dest, .. }
                | Instruction::CallPointer { dest, .. } => *dest,
                _ => None,
            })
            .and_then(|d| ir.var_metadata.get(&d).and_then(|m| m.byte_range))
    };
    for (&tb, block) in &ir.blocks {
        for (tidx, instr) in block.instructions.iter().enumerate() {
            let name = match instr {
                Instruction::CallStatic { func, .. } => func,
                Instruction::CallVirtual { method, .. } => method,
                _ => continue,
            };
            if super::last_segment(name) != trigger_seg {
                continue;
            }
            // Guard sites that execute before this trigger, with the
            // argument-nested coincidence excluded by span containment.
            for (&gb, gblock) in &ir.blocks {
                for (gi, ginstr) in gblock.instructions.iter().enumerate() {
                    let gname = match ginstr {
                        Instruction::CallStatic { func, .. } => func,
                        Instruction::CallVirtual { method, .. } => method,
                        _ => continue,
                    };
                    if super::last_segment(gname) != guard_seg {
                        continue;
                    }
                    let prev = if gb == tb {
                        gi < tidx
                    } else {
                        doms.get(&tb).is_some_and(|d| d.contains(&gb))
                    };
                    if !prev {
                        continue;
                    }
                    // Exclude guards nested inside the trigger's own
                    // argument lowering.
                    if let (Some(gs), Some(ts)) = (call_span(gb, gi), call_span(tb, tidx))
                        && gs.0 >= ts.0
                        && gs.1 <= ts.1
                    {
                        continue;
                    }
                    return true;
                }
            }
        }
    }
    false
}

/// Does `start` trace to an object construction carrying any of `keys`?
/// Fully-keyed object literals lower to `Allocate(kind: Object)` plus one
/// `StoreField { base, field }` per key, and the lowering records the pair
/// keys on the composite var's metadata (shorthand/mixed composites carry
/// the metadata without stores). Both paths are checked; plain `Assign`
/// hops are followed like the shape classifier in `forward/predicates.rs`
/// (`arg_is_idor_shape`), depth-bounded.
fn arg_has_key(ir: &FunctionIR, start: VarId, keys: &[String]) -> bool {
    let mut frontier = vec![start];
    let mut seen: rustc_hash::FxHashSet<VarId> = rustc_hash::FxHashSet::default();
    seen.insert(start);
    for _ in 0..8 {
        let mut next = Vec::new();
        for v in frontier.drain(..) {
            // (1) Metadata path: the composite var remembers its pair keys.
            if ir
                .var_metadata
                .get(&v)
                .is_some_and(|m| m.object_keys.iter().any(|k| keys.contains(k)))
            {
                return true;
            }
            for b in ir.blocks.values() {
                for instr in &b.instructions {
                    match instr {
                        // (2) Store path: the literal's own per-key store
                        // (`where: ...`), checked by field name.
                        Instruction::StoreField {
                            base, field, src, ..
                        } if *base == v => {
                            if keys.iter().any(|k| k == field) {
                                return true;
                            }
                            // (3) Recurse into stored member objects:
                            // a nested `{ lt: ... }` is a fresh Allocate
                            // reached through the outer object's store.
                            if let Operand::Var(s) = src
                                && seen.insert(*s)
                            {
                                next.push(*s);
                            }
                        }
                        // (4) Plain assign hop keeps the shape identity.
                        Instruction::Assign {
                            dest,
                            src: Operand::Var(s),
                        } if *dest == v && seen.insert(*s) => {
                            next.push(*s);
                        }
                        _ => {}
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    false
}

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

/// Extract constant literal string/bool/int representation from an operand.
fn extract_literal_string(
    op: &Operand,
    ir: &FunctionIR,
    val_info: &crate::analysis::value::ValueInfo,
) -> Option<String> {
    match op {
        Operand::StringLiteral(s) => Some(strip_quotes(s).to_string()),
        Operand::IntLiteral(i) => Some(i.to_string()),
        Operand::BoolLiteral(b) => Some(b.to_string()),
        Operand::Var(v) => {
            if let Some(s) = val_info.const_str(*v) {
                return Some(strip_quotes(s).to_string());
            }
            if let Some(c) = val_info.const_int(*v) {
                return Some(c.to_string());
            }
            if let Some(b) = val_info.const_bool(*v) {
                return Some(b.to_string());
            }
            for block in ir.blocks.values() {
                for instr in &block.instructions {
                    match instr {
                        Instruction::Assign { dest, src } if dest == v => {
                            return extract_literal_string(src, ir, val_info);
                        }
                        Instruction::Cast { dest, src, .. } if dest == v => {
                            return extract_literal_string(src, ir, val_info);
                        }
                        _ => {}
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// The segment set a requirement is evaluated against.
fn scope_segs<'a>(
    scope: PolicyScope,
    fn_segs: &'a [String],
    module_segs: &'a [String],
) -> &'a [String] {
    match scope {
        PolicyScope::Function => fn_segs,
        PolicyScope::Module => module_segs,
    }
}

/// True when some call to `seg` provably executes before the trigger:
/// its block dominates the trigger's block, or both share a block with the
/// guard at a lower instruction index. Falls back to mere presence when no
/// dominance information was computed (caller contract: function-scoped
/// guard/require requirements always pass one).
fn guard_executes_before(
    ir: &FunctionIR,
    seg: &str,
    trigger_block: BlockId,
    trigger_idx: usize,
    doms: Option<&DomSets>,
) -> bool {
    let mut sites: Vec<(BlockId, usize)> = Vec::new();
    for (&bid, block) in &ir.blocks {
        for (idx, instr) in block.instructions.iter().enumerate() {
            let matched = match instr {
                Instruction::CallStatic { func, .. } => callee_matches(seg, func),
                Instruction::CallVirtual {
                    method, receiver, ..
                } => {
                    let path = crate::analysis::forward::receiver_call_path(ir, receiver, method);
                    callee_matches(seg, &path)
                }
                _ => false,
            };
            if matched {
                sites.push((bid, idx));
            }
        }
    }
    if sites.is_empty() {
        return false;
    }
    let Some(doms) = doms else {
        return true;
    };
    sites.iter().any(|&(gb, gi)| {
        if gb == trigger_block {
            gi < trigger_idx
        } else {
            doms.get(&trigger_block).is_some_and(|d| d.contains(&gb))
        }
    })
}

fn instr_span(ir: &FunctionIR, instr: &Instruction) -> Option<(usize, usize)> {
    let dest = match instr {
        Instruction::CallStatic { dest, .. }
        | Instruction::CallVirtual { dest, .. }
        | Instruction::CallPointer { dest, .. } => (*dest)?,
        _ => return None,
    };
    ir.var_metadata.get(&dest)?.byte_range
}
