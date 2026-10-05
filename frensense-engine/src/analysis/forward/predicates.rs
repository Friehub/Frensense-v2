// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

// ---------------------------------------------------------------------------
// Shared IR predicates (same semantics as the single-function engine)
// ---------------------------------------------------------------------------

/// True if the node is a definition whose instruction is a configured source.
pub(crate) fn is_source(ir: &FunctionIR, config: &TaintConfig, key: &NodeKey) -> bool {
    let NodeKey {
        block,
        instr_idx: Some(idx),
        var,
    } = *key
    else {
        return false;
    };
    let Some(b) = ir.blocks.get(&block) else {
        return false;
    };
    if idx >= b.instructions.len() {
        // Sentinel node: function parameter. A parameter whose conventional
        // name is a configured source (e.g. "req", "input", "body") is itself
        // a taint source, the language spec's request_param_names.
        if let Some(meta) = ir.var_metadata.get(&var)
            && let Some(name) = &meta.source_name
        {
            return config.sources.contains(name);
        }
        return false;
    }
    match &b.instructions[idx] {
        Instruction::CallStatic {
            func,
            dest: Some(d),
            ..
        } => config.sources.contains(func) && *d == var,
        Instruction::CallVirtual {
            method,
            dest: Some(d),
            receiver,
            ..
        } if *d == var => {
            // Module-qualified calls (`random.randint(...)`) lower as
            // CallVirtual with the module as receiver, while verb-named
            // methods (`res.json(...)`) carry an object receiver. Match the
            // full member path `receiver.method` against dotted source
            // facts first, then the bare method name (same over-approximate
            // last-segment semantics as sinks).
            if config.sources.contains(method) {
                return true;
            }
            if let Operand::Var(r) = receiver
                && let Some(root) = FactTable::receiver_root(ir, *r)
            {
                let path = format!("{root}.{method}");
                if config.sources.contains(&path)
                    || config.sources.iter().any(|s| {
                        path.starts_with(s.as_str()) && path.as_bytes().get(s.len()) == Some(&b'.')
                    })
                {
                    return true;
                }
            }
            false
        }
        Instruction::LoadField { base, field, .. } => {
            // Member-expression source: `req.body` lowers to LoadField
            // chains, the *dest* of each link has no source_name, so the
            // access path must be reconstructed by walking the base chain
            // through the IR until a named root var is reached:
            //   LoadField(dest2, base1, "args"); LoadField(dest1, req, "body")
            // reconstructs "req.body.args".
            let path = member_access_path(ir, *base, field);
            let root = path.split('.').next().unwrap_or("");
            crate::dbg_trace!(
                crate::debug_flags::DebugFlags::get().is_source,
                "[is_source] path={path:?} hit={}",
                config.sources.contains(&path)
            );
            source_path_matches(config, &path, root)
        }
        _ => false,
    }
}

/// Reconstruct a member-access path like `req.body.args` by walking
/// LoadField base chains backwards to a named root variable. Bounded to
/// prevent pathological IR from looping (alias chains are acyclic by SSA
/// construction, but the bound is cheap insurance).
pub(crate) fn member_access_path(ir: &FunctionIR, mut base: VarId, last_field: &str) -> String {
    let mut segments = vec![last_field.to_string()];
    for _ in 0..16 {
        match ir
            .var_metadata
            .get(&base)
            .and_then(|m| m.source_name.clone())
        {
            Some(name) => {
                segments.push(name);
                break;
            }
            None => {
                // Find the instruction that defines `base`.
                let mut found = None;
                'outer: for b in ir.blocks.values() {
                    for (idx, instr) in b.instructions.iter().enumerate() {
                        if let Instruction::LoadField {
                            dest: d,
                            base: b2,
                            field,
                            ..
                        } = instr
                            && *d == base
                        {
                            found = Some((*b2, field.clone(), idx));
                            break 'outer;
                        }
                    }
                }
                match found {
                    Some((b2, field, _)) => {
                        segments.push(field);
                        base = b2;
                    }
                    None => break,
                }
            }
        }
    }
    segments.reverse();
    // Drop leading mem-state artifacts if any leaked in.
    while segments.len() > 1 && segments[0] == crate::ir::function::INITIAL_HEAP_STATE {
        segments.remove(0);
    }
    segments.join(".")
}

/// Does a reconstructed member-access `path` (whose first segment is `root`)
/// match a configured source rule?
///
/// Exact matches and prefix-subtree rules ("req.body" covers "req.body.args")
/// apply unconditionally. A whole-value registration of the bare root ("ctx")
/// covers its subtree only while the config declares no granular field rules
/// for that root ("ctx.state"): the granular list is the intended precise set,
/// so a bare root must not silently re-widen it - otherwise `ctx.env.SECRET`
/// becomes a source just because `ctx.state` was registered.
///
/// (The previous `sources.contains(root)` clause was redundant with the
/// prefix rule for dotted paths and would defeat this suppression, so it is
/// not carried over; dot-less paths hit `sources.contains(path)` exactly.)
pub(crate) fn source_path_matches(config: &TaintConfig, path: &str, root: &str) -> bool {
    config.sources.contains(path)
        || config.sources.iter().any(|s| {
            if !path.starts_with(s.as_str()) || path.as_bytes().get(s.len()) != Some(&b'.') {
                return false;
            }
            if s.as_str() != root {
                // Sub-path prefix rule ("ctx.request" → "ctx.request.body").
                return true;
            }
            // Whole-value root registration: live only when no granular
            // field rules exist for that root.
            !config
                .sources
                .iter()
                .any(|g| g.starts_with(root) && g.as_bytes().get(root.len()) == Some(&b'.'))
        })
}

/// True if the node is a use inside a configured sanitizer call.
pub(crate) fn is_sanitizer_use(ir: &FunctionIR, config: &TaintConfig, key: &NodeKey) -> bool {
    let NodeKey {
        block,
        instr_idx: Some(idx),
        ..
    } = *key
    else {
        return false;
    };
    let Some(b) = ir.blocks.get(&block) else {
        return false;
    };
    if idx >= b.instructions.len() {
        return false;
    }
    match &b.instructions[idx] {
        Instruction::CallStatic { func, .. } => config.sanitizers.contains(func),
        Instruction::CallVirtual { method, .. } => config.sanitizers.contains(method),
        _ => false,
    }
}

/// Fact-table-aware sanitizer check: configured sanitizers PLUS any call with
/// a [`SanitizerFact`] in the table (e.g. `.replace()`, `.test()` guard
/// methods learned from `frensense-lang` tables or a bundle).
pub(crate) fn is_sanitizer_use_with_facts(
    ir: &FunctionIR,
    config: &TaintConfig,
    facts: &FactTable,
    key: &NodeKey,
) -> bool {
    if is_sanitizer_use(ir, config, key) {
        return true;
    }
    let NodeKey {
        block,
        instr_idx: Some(idx),
        ..
    } = *key
    else {
        return false;
    };
    let Some(b) = ir.blocks.get(&block) else {
        return false;
    };
    if idx >= b.instructions.len() {
        return false;
    }
    match &b.instructions[idx] {
        Instruction::CallStatic { func, .. } => facts.sanitizer_fact(func).is_some(),
        Instruction::CallVirtual {
            method, receiver, ..
        } => {
            if facts.sanitizer_fact(method).is_some() {
                return true;
            }
            // Session-store accessor trust: `store.get(token)` returns a
            // server-issued session object (undefined for unknown tokens),
            // so values derived from its result are not attacker-controlled.
            // Receiver-aware: only declared session roots qualify.
            if let Operand::Var(r) = receiver {
                let path = FactTable::receiver_access_path(ir, *r);
                return facts.is_session_path(method, path.as_deref());
            }
            false
        }
        _ => false,
    }
}

/// A structured sink alert: which sink fired, in which function, in which
/// argument slot, and how it classifies. Consumers render their own prose;
/// the engine never formats messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkAlert {
    /// Sink name as configured (`db.execute`, `res.send`, ...).
    pub sink: String,
    /// Formal slot of the tainted argument (`usize::MAX` = receiver).
    pub slot: usize,
    /// Function in which the sink call lives.
    pub function: String,
    /// Shape classification (Idor for identity-payload query objects).
    pub class: crate::analysis::taint::engine::FindingClass,
}

/// Alert if the node is a tainted use inside a configured sink call.
/// Honours [`FactTable`] sink signatures when one matches: a tainted arg in a
/// *non-dangerous* slot (e.g. a parameterized query's binding array) does not
/// alert. Callers build the [`FactTable`] once and pass it in.
pub(crate) fn sink_alert_with_facts(
    ir: &FunctionIR,
    config: &TaintConfig,
    facts: &FactTable,
    key: &NodeKey,
) -> Option<SinkAlert> {
    let NodeKey {
        block,
        instr_idx: Some(idx),
        var,
    } = *key
    else {
        return None;
    };
    let b = ir.blocks.get(&block)?;
    if idx >= b.instructions.len() {
        return None;
    }
    let slot_and_name = match &b.instructions[idx] {
        Instruction::CallStatic { func, args, .. }
            if config.sinks.contains(func) || facts.is_sink_call(func, None) =>
        {
            args.iter()
                .position(|a| *a == Operand::Var(var))
                .map(|pos| (pos, func))
        }
        Instruction::CallVirtual {
            method,
            args,
            receiver,
            ..
        } if config.sinks.contains(method) || {
            let root = match receiver {
                Operand::Var(r) => FactTable::receiver_root(ir, *r),
                _ => None,
            };
            facts.is_sink_call(method, root.as_deref())
        } =>
        {
            if receiver == &Operand::Var(var) {
                Some((usize::MAX, method)) // receiver slot
            } else {
                args.iter()
                    .position(|a| *a == Operand::Var(var))
                    .map(|pos| (pos, method))
            }
        }
        _ => None,
    };
    let (slot, name) = slot_and_name?;
    // Source-accessor precedence (RECEIVER-TAINT ALERTS ONLY): when the
    // alert comes from a tainted *receiver* and the method name is the last
    // segment of a configured dotted source pattern, the call READS taint
    // rather than consuming it, Go's canonical `r.URL.Query().Get("id")`
    // (both `Query` and `Get` are also sink names) must not alert just
    // because its receiver carries taint.
    //
    // This must NOT apply to argument-slot alerts: `req.query` is a source
    // pattern, so a blanket rule would suppress `pool.query(sql)`, a real
    // sink, because the sink name matches a source-pattern segment.
    if slot == usize::MAX {
        if is_source(ir, config, key) {
            return None;
        }
        {
            let is_source_accessor = config
                .sources
                .iter()
                .any(|s| s.rsplit('.').next() == Some(name));
            if is_source_accessor {
                return None;
            }
        }
    }
    // Receiver-taint rule: for a slot-restricted sink (dangerous_args
    // non-empty), a tainted RECEIVER is the object being read (the DB
    // handle, the request object), not data being consumed, no alert.
    // Only all-args sinks keep receiver taint dangerous.
    if slot == usize::MAX
        && let Some(sig) = facts.sink_signature(name)
        && !sig.dangerous_args.is_empty()
    {
        return None;
    }
    // Sink-signature check: dangerous slot (or receiver) only.
    if let Some(sig) = facts.sink_signature(name)
        && slot != usize::MAX
        && !sig.is_dangerous(slot)
    {
        return None; // safe binding channel, no alert
    }
    // Identity-payload emission policy: an IDOR-class finder sink (vocabulary
    // from the spec's `known_idor_sinks` or a `.frc` bundle) reports ONLY
    // when the tainted argument IS an identity payload - a top-level key from
    // the identity set answers "which record". Leaf values inside
    // parameterized clauses (`{ where: { id: taint } }`), non-identity object
    // fields and bare scalars are not provable access-control violations and
    // are not reported at all (zero-FP: structurally unprovable findings
    // never fire).
    if let Some(sig) = facts.sink_signature(name)
        && slot != usize::MAX
        && !sig.idor_keys.is_empty()
        && !arg_is_idor_shape(ir, var, &sig.idor_keys)
    {
        return None;
    }
    // Arg-shape classification: a tainted identity payload at an
    // IDOR-class sink is an access-control query, not an injection - the
    // driver parameterizes object values. Reported with the Idor class so
    // consumers rank it below Critical. (Non-identity shapes at these sinks
    // never reach here - the emission gate above returned already.)
    let class = if let Some(sig) = facts.sink_signature(name)
        && !sig.idor_keys.is_empty()
        && slot != usize::MAX
        && arg_is_idor_shape(ir, var, &sig.idor_keys)
    {
        // Auth-guarded handlers: an identity query behind an early-return
        // branch over an auth-vocab call only executes for authenticated
        // callers - not an access-control violation (Idor class only;
        // injection findings are never suppressed here).
        if idor_suppressed_by_auth_guard(ir, facts, block) {
            return None;
        }
        crate::analysis::taint::engine::FindingClass::Idor
    } else {
        crate::analysis::taint::engine::FindingClass::Injection
    };
    Some(SinkAlert {
        sink: name.to_string(),
        slot,
        function: ir.name.clone(),
        class,
    })
}

/// Does the tainted var originate from an object literal whose pair keys
/// intersect `idor_keys`? Follows plain `Assign` chains (composite merge
/// vars, destructuring temps) but stops at anything else.
fn arg_is_idor_shape(ir: &FunctionIR, mut var: VarId, idor_keys: &[String]) -> bool {
    for _ in 0..8 {
        if let Some(meta) = ir.var_metadata.get(&var)
            && meta
                .object_keys
                .iter()
                .any(|k| idor_keys.iter().any(|ik| ik == k))
        {
            return true;
        }
        // Follow one Assign hop back (composite merge chain).
        let mut next = None;
        for b in ir.blocks.values() {
            for instr in &b.instructions {
                if let Instruction::Assign { dest, src } = instr
                    && *dest == var
                    && let Operand::Var(v) = src
                {
                    next = Some(*v);
                }
            }
        }
        match next {
            Some(v) => var = v,
            None => return false,
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Auth-guard suppression for the IDOR emission gate
// ---------------------------------------------------------------------------

/// Dotted path of a virtual call: receiver chain + method
/// (`security.authenticatedUsers.from`). Used by the auth-guard gate and by
/// policy checks that need more than the last segment.
pub(crate) fn receiver_call_path(ir: &FunctionIR, recv: &Operand, method: &str) -> String {
    let base = operand_member_path(ir, recv);
    if base.is_empty() {
        method.to_string()
    } else {
        format!("{base}.{method}")
    }
}

/// Resolve an operand to a member path through its defining instructions.
fn operand_member_path(ir: &FunctionIR, op: &Operand) -> String {
    match op {
        Operand::Var(v) => var_member_path(ir, *v, 0),
        _ => String::new(),
    }
}

/// Walk `LoadField`/`LoadGlobal`/`Assign` definitions to rebuild the dotted
/// path a receiver expression denotes (`security.authenticatedUsers`).
fn var_member_path(ir: &FunctionIR, v: VarId, depth: usize) -> String {
    if depth > 16 {
        return String::new();
    }
    for b in ir.blocks.values() {
        for instr in &b.instructions {
            match instr {
                Instruction::Assign { dest, src } if *dest == v => {
                    return operand_member_path(ir, src);
                }
                Instruction::LoadField {
                    dest, base, field, ..
                } if *dest == v => {
                    let p = var_member_path(ir, *base, depth + 1);
                    return if p.is_empty() {
                        field.clone()
                    } else {
                        format!("{p}.{field}")
                    };
                }
                Instruction::LoadGlobal { dest, name, .. } if *dest == v => {
                    return name.clone();
                }
                _ => {}
            }
        }
    }
    ir.var_metadata
        .get(&v)
        .and_then(|m| m.source_name.clone())
        .unwrap_or_default()
}

/// Push the operand onto the worklist when it is a variable reference.
fn push_var(work: &mut Vec<VarId>, op: &Operand) {
    if let Operand::Var(s) = op {
        work.push(*s);
    }
}

/// The instruction defining `v`, if any (first match - IR is SSA-shaped).
fn def_of(ir: &FunctionIR, v: VarId) -> Option<&Instruction> {
    for b in ir.blocks.values() {
        for instr in &b.instructions {
            let defines = match instr {
                Instruction::Assign { dest, .. } => *dest == v,
                Instruction::LoadField { dest, .. } => *dest == v,
                Instruction::StoreField { .. } => false,
                Instruction::LoadElement { dest, .. } => *dest == v,
                Instruction::LoadGlobal { dest, .. } => *dest == v,
                Instruction::CallStatic { dest, .. } => *dest == Some(v),
                Instruction::CallVirtual { dest, .. } => *dest == Some(v),
                Instruction::CallPointer { dest, .. } => *dest == Some(v),
                Instruction::Allocate { dest, .. } => *dest == v,
                Instruction::Dereference { dest, .. } => *dest == v,
                Instruction::Cast { dest, .. } => *dest == v,
                Instruction::ExtractValue { dest, .. } => *dest == v,
                Instruction::BinaryOp { dest, .. } => *dest == v,
                Instruction::UnaryOp { dest, .. } => *dest == v,
                Instruction::Await { dest, .. } => *dest == v,
                Instruction::Yield { dest, .. } => *dest == Some(v),
                _ => false,
            };
            if defines {
                return Some(instr);
            }
        }
    }
    None
}

/// True when `path` names an auth call per the spec/bundle vocabulary
/// (`facts.auth_guard_hints`, seeded by `fact_table_from_spec`).
fn auth_path_matches(path: &str, facts: &FactTable) -> bool {
    let lower = path.to_ascii_lowercase();
    facts.auth_guard_hints.iter().any(|h| lower.contains(h))
}

/// Does the branch condition derive (through unary/binary/assign/await/
/// field chains) from a call to an auth-vocabulary callee?
fn cond_derives_from_auth_call(ir: &FunctionIR, cond: &Operand, facts: &FactTable) -> bool {
    let Operand::Var(start) = cond else {
        return false;
    };
    let mut work = vec![*start];
    let mut seen = FxHashSet::default();
    while let Some(v) = work.pop() {
        if !seen.insert(v) || seen.len() > 64 {
            continue;
        }
        let Some(instr) = def_of(ir, v) else {
            continue;
        };
        match instr {
            Instruction::CallStatic { func, dest, .. }
                if *dest == Some(v) && auth_path_matches(func, facts) =>
            {
                return true;
            }
            Instruction::CallVirtual {
                method,
                receiver,
                dest,
                ..
            } if *dest == Some(v) => {
                let path = receiver_call_path(ir, receiver, method);
                if auth_path_matches(&path, facts) {
                    return true;
                }
            }
            Instruction::UnaryOp { dest, src, .. } if *dest == v => push_var(&mut work, src),
            Instruction::BinaryOp { dest, lhs, rhs, .. } if *dest == v => {
                push_var(&mut work, lhs);
                push_var(&mut work, rhs);
            }
            Instruction::Assign { dest, src } if *dest == v => push_var(&mut work, src),
            Instruction::Cast { dest, src, .. } if *dest == v => push_var(&mut work, src),
            Instruction::Await { dest, promise, .. } if *dest == v => push_var(&mut work, promise),
            Instruction::LoadField { dest, base, .. } if *dest == v => {
                work.push(*base);
            }
            _ => {}
        }
    }
    false
}

/// Can `start` reach a Return/Throw without ever entering `avoid`?
fn exit_reachable_avoiding(ir: &FunctionIR, start: BlockId, avoid: BlockId) -> bool {
    if start == avoid {
        return false;
    }
    let mut stack = vec![start];
    let mut seen = FxHashSet::default();
    while let Some(b) = stack.pop() {
        if b == avoid || !seen.insert(b) {
            continue;
        }
        let Some(block) = ir.blocks.get(&b) else {
            continue;
        };
        match &block.terminator {
            Terminator::Return { .. } | Terminator::Throw { .. } => return true,
            Terminator::Jump(t) => stack.push(*t),
            Terminator::Branch {
                true_block,
                false_block,
                ..
            } => {
                stack.push(*true_block);
                stack.push(*false_block);
            }
            Terminator::Switch {
                cases,
                default_block,
                ..
            } => {
                for (_, t) in cases {
                    stack.push(*t);
                }
                stack.push(*default_block);
            }
            _ => {}
        }
    }
    false
}

/// Suppress an IDOR-class candidate at `sink_block` when the function has
/// an *auth guard*: a branch whose condition derives from an
/// auth-vocabulary call, which dominates the sink (the query is only
/// reachable through the check) and which has a rejecting path
/// (Return/Throw) that never reaches the sink. Vocabulary:
/// `facts.auth_guard_hints` ∪ lang bootstrap defaults.
pub(crate) fn idor_suppressed_by_auth_guard(
    ir: &FunctionIR,
    facts: &FactTable,
    sink_block: BlockId,
) -> bool {
    let doms = crate::ir::control::dominators(ir);
    for (bid, block) in &ir.blocks {
        let Terminator::Branch {
            cond,
            true_block,
            false_block,
        } = &block.terminator
        else {
            continue;
        };
        // The guard must be a distinct block: a branch in the sink's own
        // block comes after the sink instruction (terminators end blocks),
        // so it cannot gate it.
        if *bid == sink_block {
            continue;
        }
        if !cond_derives_from_auth_call(ir, cond, facts) {
            continue;
        }
        // `dominators[sink]` = blocks that dominate the sink: the guard
        // block must be one of them (reflexive sets, so the `bid ==
        // sink_block` case above already excluded).
        let Some(guard_doms) = doms.get(&sink_block) else {
            continue;
        };
        if !guard_doms.contains(bid) {
            continue;
        }
        if exit_reachable_avoiding(ir, *true_block, sink_block)
            || exit_reachable_avoiding(ir, *false_block, sink_block)
        {
            return true;
        }
    }
    false
}
