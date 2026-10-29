// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

// ---------------------------------------------------------------------------
// Shared IR predicates (same semantics as the single-function engine)
// ---------------------------------------------------------------------------

/// The source vocabulary visible at one call site: the language-agnostic
/// `TaintConfig` set plus the call site's own language section.
///
/// Source facts are declared per language (TypeScript's `req`/`input`
/// parameter names, Rust's `std::env::var`, ...) and a bare name is not
/// portable between them: `input` is caller data in TypeScript and an
/// unrelated local in Rust. Sharing one set across a mixed-language scan
/// seeds taint from names that mean nothing in the file being analyzed.
pub(crate) struct SourceScope<'a> {
    universal: &'a rustc_hash::FxHashSet<String>,
    language: Option<&'a rustc_hash::FxHashSet<String>>,
    /// Names that are sources only in the program's entry point, withheld
    /// here because this function is not it (see [`ENTRY_ONLY_PARAMS`]).
    withheld: &'static [&'static str],
}

impl<'a> SourceScope<'a> {
    pub(crate) fn for_ir(config: &'a TaintConfig, facts: &'a FactTable, ir: &FunctionIR) -> Self {
        Self {
            universal: &config.sources,
            language: facts.language_sources(&ir.language),
            withheld: entry_only_names_withheld_for(ir),
        }
    }

    /// True when `name` is, or is a field path under, a withheld name.
    fn is_withheld(&self, name: &str) -> bool {
        self.withheld.iter().any(|w| {
            name == *w || (name.starts_with(w) && name.as_bytes().get(w.len()) == Some(&b'.'))
        })
    }

    pub(crate) fn contains(&self, name: &str) -> bool {
        !self.is_withheld(name)
            && (self.universal.contains(name)
                || self.language.is_some_and(|set| set.contains(name)))
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &'a String> {
        self.universal
            .iter()
            .chain(self.language.into_iter().flatten())
            .filter(|s| !self.is_withheld(s))
    }
}

/// Entry-point-only parameter names, per language family.
///
/// `argv`/`argc` are the process's command line only in the program's entry
/// point. Everywhere else the same name is an ordinary parameter: redis
/// alone has `robj **argv` (a client command), `sds *argv` (a config line)
/// and `char *argv[]` (a test) in functions that never see the process
/// arguments, and treating every one as attacker input produced 48
/// path-traversal findings with the wrong source. Reached from `main`, the
/// value arrives through the call-argument edge instead, which keeps the
/// real flow and drops the name-only ones.
const ENTRY_ONLY_PARAMS: &[(&str, &[&str], &str)] = &[
    ("c", &["argc", "argv"], "main"),
    ("cpp", &["argc", "argv"], "main"),
];

/// The entry-only names this function must NOT treat as sources (empty for
/// the entry point itself and for languages with no such rule).
fn entry_only_names_withheld_for(ir: &FunctionIR) -> &'static [&'static str] {
    for (lang, names, entry) in ENTRY_ONLY_PARAMS {
        if ir.language == *lang {
            let base = ir.name.rsplit("::").next().unwrap_or(&ir.name);
            return if base == *entry { &[] } else { names };
        }
    }
    &[]
}

/// True if the node is a definition whose instruction is a configured source.
pub(crate) fn is_source(
    ir: &FunctionIR,
    config: &TaintConfig,
    facts: &FactTable,
    key: &NodeKey,
) -> bool {
    let sources = SourceScope::for_ir(config, facts, ir);
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
        // Sentinel node: function parameter. Two pack-driven ways a parameter
        // is a source:
        //   1. its conventional NAME is a source ("req", "input", "body");
        //   2. its TYPE annotation names one of the framework's request
        //      value types (`Query<P>`, `web::Query<P>`, `*http.Request`).
        // (2) exists because for typed languages the extractor type - not
        // the author's variable name - decides that the argument carries
        // attacker input. Matching the type keeps the knowledge in the
        // pack's source vocabulary while the mechanism stays name-agnostic.
        if let Some(meta) = ir.var_metadata.get(&var) {
            if let Some(name) = &meta.source_name
                && sources.contains(name)
            {
                return true;
            }
            return meta.type_name.as_deref().is_some_and(|ty| {
                source_path_matches(&sources, ty, ty.split("::").next().unwrap_or(ty))
            });
        }
        return false;
    }
    match &b.instructions[idx] {
        Instruction::CallStatic {
            func,
            dest: Some(d),
            ..
        } => {
            sources.contains(func)
                && !config.sinks.contains(func)
                && !facts.is_sink_call_scoped(
                    func,
                    None,
                    None,
                    (!ir.language.is_empty()).then_some(ir.language.as_str()),
                )
                && *d == var
        }
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
            if sources.contains(method) {
                return true;
            }
            if let Operand::Var(r) = receiver
                && let Some(path_sans_method) = FactTable::receiver_access_path(ir, *r)
            {
                let path = format!("{path_sans_method}.{method}");
                let root = path_sans_method.split('.').next().unwrap_or("");
                // Use `source_path_matches` (not a raw prefix rule): it
                // suppresses bare-root re-widening when granular field
                // rules exist for that root, so `req.replace(...)` (a
                // String method) is NOT a source just because `req` is
                // registered as a bare root. The raw prefix rule matched
                // `req.replace` because `"req.replace".starts_with("req")`.
                //
                // The receiver's FULL access path is reconstructed (not
                // just its root): `request.args.get('cmd')` must match the
                // granular fact `request.args.get`, which the truncated
                // root (`request` + method → `request.get`) can never
                // reach, and the bare-root widening suppression would
                // then correctly refuse to re-widen `request` over its
                // granular children.
                return source_path_matches(&sources, &path, root);
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
                sources.contains(&path)
            );
            source_path_matches(&sources, &path, root)
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
                // Continue through the LoadField that defines `base`.
                match ir.loadfield_def(base) {
                    Some((b2, field)) => {
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
pub(crate) fn source_path_matches(sources: &SourceScope<'_>, path: &str, root: &str) -> bool {
    sources.contains(path)
        || sources.iter().any(|s| {
            if !path.starts_with(s.as_str()) || path.as_bytes().get(s.len()) != Some(&b'.') {
                return false;
            }
            if s.as_str() != root {
                // Sub-path prefix rule ("ctx.request" → "ctx.request.body").
                return true;
            }
            // Whole-value root registration: live only when no granular
            // field rules exist for that root.
            !sources
                .iter()
                .any(|g| g.starts_with(root) && g.as_bytes().get(root.len()) == Some(&b'.'))
        })
}

/// C calls whose result does not carry the taint of their arguments:
/// lengths (`strlen`), and allocators in every spelling the C ecosystem uses
/// (`malloc`, `calloc`, `alloca`, `zmalloc`, `s_trymalloc_usable`,
/// `xcalloc`, `g_malloc`). `realloc` is excluded: its result is the old
/// object's contents.
pub(crate) fn c_result_is_independent_of_args(func: &str) -> bool {
    let last = func.rsplit(['.', ':']).next().unwrap_or(func);
    let l = last.to_ascii_lowercase();
    if matches!(l.as_str(), "strlen" | "strnlen" | "wcslen" | "alloca") {
        return true;
    }
    if l.contains("realloc") {
        return false;
    }
    let l = l.strip_suffix("_usable").unwrap_or(&l);
    l.ends_with("malloc") || l.ends_with("calloc")
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

use crate::analysis::taint::role::SinkRole;
use frensense_lang::severity::SanitizerKind;

/// Fact-table-aware sanitizer check qualified by the sink's role and label.
/// Returns true if this node is inside a sanitizer that actually defeats the candidate sink.
///
/// Package-scoped sanitizer facts additionally require `origin_package`
/// to name their package (import resolution) — pass `None` when no
/// origin is known; scoped facts then stay inert (recall-safe: they may
/// only cut a flow under a confirmed origin).
pub(crate) fn is_sanitizer_effective_for_role(
    ir: &FunctionIR,
    config: &TaintConfig,
    facts: &FactTable,
    key: &NodeKey,
    role: SinkRole,
    label: Option<&str>,
    origin_package: Option<&str>,
) -> bool {
    // `config` is retained for API stability with callers; the legacy
    // flat `config.sanitizers` fallback was removed (it cut sink-
    // agnostically, bypassing role checks). Fact-table sanitizers
    // carry a `kind` slug that `from_slug` resolves.
    let _ = config;
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
        Instruction::CallStatic { func, .. } => {
            // A fresh allocation or a length is not the data it was sized
            // from. Allocator wrappers carry project-specific names
            // (`zmalloc`, `s_trymalloc_usable`, `xcalloc`), so the shape of
            // the name decides rather than a per-project list.
            if matches!(ir.language.as_str(), "c" | "cpp") && c_result_is_independent_of_args(func)
            {
                return true;
            }
            if let Some(fact) = facts.sanitizer_fact_scoped(func, origin_package) {
                if let Some(kind) = SanitizerKind::from_slug(&fact.kind) {
                    return kind.defeats_role_and_label(role, label);
                }
                // Unknown kind slug: do NOT cut sink-agnostically. The
                // previous `return true` fallback let any unrecognized
                // label defeat every role (residual #15: "encode" from
                // from_config silenced Execution sinks). Legacy
                // "encode"/"allowlist" are now mapped to Full in
                // `from_slug`; anything else is genuinely unknown.
                return false;
            }
            false
        }
        Instruction::CallVirtual {
            method, receiver, ..
        } => {
            if let Operand::Var(r) = receiver {
                let path = FactTable::receiver_access_path(ir, *r);
                if let Some(ref p) = path {
                    let full = format!("{p}.{method}");
                    if let Some(fact) = facts.sanitizer_fact_scoped(&full, origin_package) {
                        if let Some(kind) = SanitizerKind::from_slug(&fact.kind) {
                            return kind.defeats_role_and_label(role, label);
                        }
                        return false;
                    }
                }
                if facts.is_session_path(method, path.as_deref()) {
                    return true;
                }
            }
            if let Some(fact) = facts.sanitizer_fact_scoped(method, origin_package) {
                if let Some(kind) = SanitizerKind::from_slug(&fact.kind) {
                    return kind.defeats_role_and_label(role, label);
                }
                return false;
            }
            false
        }
        _ => false,
    }
}

/// Fact-table-aware sanitizer check: configured sanitizers PLUS any call with
/// a [`SanitizerFact`] in the table (e.g. `.replace()`, `.test()` guard
/// methods learned from `frensense-lang` tables or a bundle).
///
/// Fact lookups pass no import origin (this path serves the forward
/// relevance engine and summaries, which carry no per-file import
/// context), so package-scoped sanitizer facts are inert here — the
/// recall-safe direction: universal sanitizers still cut, a bundle-
/// scoped one never silences a flow it was not proven on.
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
            if let Operand::Var(r) = receiver {
                let path = FactTable::receiver_access_path(ir, *r);
                if let Some(ref p) = path {
                    let full = format!("{p}.{method}");
                    if facts.sanitizer_fact(&full).is_some() {
                        return true;
                    }
                }
                if facts.is_session_path(method, path.as_deref()) {
                    return true;
                }
            }
            if facts.sanitizer_fact(method).is_some() {
                return true;
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
/// alert. Callers build the [`FactTable`] once and pass it in. Package-scoped
/// sink facts additionally require `origin_package` to name their package
/// (import resolution) — pass `None` when no origin is known.
pub(crate) fn sink_alert_with_facts(
    ir: &FunctionIR,
    config: &TaintConfig,
    facts: &FactTable,
    key: &NodeKey,
    origin_package: Option<&str>,
    language: Option<&str>,
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
            if facts.sink_name_armed(
                &config.sinks,
                func,
                None,
                origin_package,
                language,
                false,
            ) =>
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
        } if {
            let root = match receiver {
                Operand::Var(r) => FactTable::receiver_root(ir, *r),
                _ => None,
            };
            facts.sink_name_armed(
                &config.sinks,
                method,
                root.as_deref(),
                origin_package,
                language,
                true,
            )
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
    // Arguments to a call on a prepared statement are bound parameters: the
    // statement text was fixed when the handle was created, so `stmt.Exec(a,
    // b)` carries values, not SQL. The creating call (`db.Prepare(query)`)
    // is judged on its own.
    if slot != usize::MAX
        && let Instruction::CallVirtual {
            receiver: Operand::Var(r),
            ..
        } = &b.instructions[idx]
        && receiver_is_prepared_handle(ir, *r, facts)
    {
        return None;
    }
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
        if is_source(ir, config, facts, key) {
            return None;
        }
        {
            let is_source_accessor = SourceScope::for_ir(config, facts, ir)
                .iter()
                .any(|s| s.rsplit('.').next() == Some(name));
            if is_source_accessor {
                return None;
            }
        }
    }
    // Slot layout is a property of the CALLED API, not of the shared
    // method name. A package-scoped fact (declared for the call's import
    // origin) carries the correct slots; without this lookup the engine
    // arms a call through its scoped fact (`is_sink_call_scoped`) but then
    // applies whatever bare-name signature shares the method name. The
    // Go case is concrete: `http.Get(url)` (slot 0) and `db.Get(&dest, sql)`
    // (slot 1, sqlx) both lower to `Get`, and the bare entry silently
    // dropped the SSRF finding. `sink_signature_scoped` falls back to the
    // universal tables when no scoped entry applies, so behaviour for
    // unresolved origins is unchanged.
    let signature = facts.sink_signature_scoped(name, origin_package, language);
    // Receiver-taint rule: for a slot-restricted sink (dangerous_args
    // non-empty), a tainted RECEIVER is the object being read (the DB
    // handle, the request object), not data being consumed, no alert.
    // Only all-args sinks keep receiver taint dangerous.
    if slot == usize::MAX
        && let Some(sig) = signature
        && !sig.dangerous_args.is_empty()
    {
        return None;
    }
    // Sink-signature check: dangerous slot (or receiver) only.
    if let Some(sig) = signature
        && slot != usize::MAX
        && !sig.is_dangerous(slot)
    {
        return None; // safe binding channel, no alert
    }
    // Identity-payload emission policy: an IDOR-class finder sink (vocabulary
    // from the default pack or a `.frc` bundle) reports ONLY
    // when the tainted argument IS an identity payload - a top-level key from
    // the identity set answers "which record". Leaf values inside
    // parameterized clauses (`{ where: { id: taint } }`), non-identity object
    // fields and bare scalars are not provable access-control violations and
    // are not reported at all (zero-FP: structurally unprovable findings
    // never fire). The signature must be the same language-scoped one the
    // match used: reading the shared table here would miss a language-keyed
    // IDOR fact (a TypeScript `update`) and emit every write it guards.
    if let Some(sig) = signature
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
    let class = if let Some(sig) = signature
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
    operand_member_path_at(ir, op, 0)
}

/// [`operand_member_path`] continuing an existing depth budget.
///
/// The budget must travel through EVERY edge of the walk. `Assign` used to
/// call the entry point above, which restarts at depth 0, so a cycle of
/// assignments (`v_a := v_b`, `v_b := v_a` - Python's `try`/`except` lowering
/// emits these) recursed between `var_member_path` and
/// `operand_member_path` forever and overflowed the stack instead of
/// returning the empty path the depth guard promises.
fn operand_member_path_at(ir: &FunctionIR, op: &Operand, depth: usize) -> String {
    match op {
        Operand::Var(v) => var_member_path(ir, *v, depth),
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
                    return operand_member_path_at(ir, src, depth + 1);
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
/// (`facts.auth_guard_hints`, seeded by the default pack).
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
/// `facts.auth_guard_hints`.
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

/// True when `var` is (an alias or tuple field of) the result of a call the
/// pack declares a statement factory: the handle then executes text fixed at
/// creation, and its call arguments are bindings.
///
/// Which names prepare a statement is pack knowledge
/// ([`FactTable::prepared_statement_prefixes`], taught by the default pack or
/// a bundle); the engine only walks the def chain and matches the prefix. An
/// empty set recognises nothing, so a config that teaches nothing never
/// suppresses a flow.
fn receiver_is_prepared_handle(
    ir: &FunctionIR,
    var: crate::ir::function::VarId,
    facts: &FactTable,
) -> bool {
    let prefixes = &facts.prepared_statement_prefixes;
    if prefixes.is_empty() {
        return false;
    }
    let mut cur = var;
    for _ in 0..6 {
        let mut next = None;
        for blk in ir.blocks.values() {
            for instr in &blk.instructions {
                match instr {
                    Instruction::Assign {
                        dest,
                        src: Operand::Var(s),
                        ..
                    } if *dest == cur => next = Some(*s),
                    Instruction::ExtractValue {
                        dest,
                        tuple: Operand::Var(t),
                        ..
                    } if *dest == cur => next = Some(*t),
                    Instruction::CallVirtual {
                        dest: Some(d),
                        method,
                        ..
                    }
                    | Instruction::CallStatic {
                        dest: Some(d),
                        func: method,
                        ..
                    } if *d == cur => {
                        let seg = method.rsplit('.').next().unwrap_or(method);
                        let seg = seg.to_ascii_lowercase();
                        return prefixes.iter().any(|p| seg.starts_with(p.as_str()));
                    }
                    _ => {}
                }
            }
        }
        match next {
            Some(n) => cur = n,
            None => return false,
        }
    }
    false
}
