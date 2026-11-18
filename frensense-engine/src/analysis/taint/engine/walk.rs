// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

use std::collections::VecDeque;

use crate::analysis::forward::{is_sanitizer_effective_for_role, is_source, sink_alert_with_facts};
use crate::dbg_trace;
use crate::debug_flags::DebugFlags;
use crate::graph::svfg::NodeKind;

// ---------------------------------------------------------------------------
// Constant evaluation + branch feasibility
// ---------------------------------------------------------------------------

/// Constant-fold a variable's definition chain to an integer value.
///
/// Handles the literal-arithmetic shapes that decide ternary/if branches:
/// `Assign` from an `IntLiteral`, and `BinaryOp` arithmetic over literal
/// operands (`7 * 18 + num > 200` folds bottom-up). Bounded hops keep
/// pathological chains cheap. `None` = not a constant.
fn const_eval(ir: &FunctionIR, var: VarId) -> Option<i64> {
    fn operand_const(ir: &FunctionIR, op: &Operand, hops: u8) -> Option<i64> {
        match op {
            Operand::IntLiteral(i) => Some(*i),
            Operand::Var(v) => const_eval_hops(ir, *v, hops),
            _ => None,
        }
    }
    fn const_eval_hops(ir: &FunctionIR, var: VarId, hops: u8) -> Option<i64> {
        if hops == 0 {
            return None;
        }
        let def = defs_of_var(ir, var)?;
        match def {
            Instruction::Assign {
                src: Operand::IntLiteral(i),
                ..
            } => Some(*i),
            Instruction::BinaryOp { op, lhs, rhs, .. } => {
                let l = operand_const(ir, lhs, hops - 1)?;
                let r = operand_const(ir, rhs, hops - 1)?;
                // The lowering maps `+` to op "concat" (the generic
                // additive fold); arithmetic on IntLiterals is still
                // integer addition there.
                Some(match op.as_str() {
                    "concat" | "+" => l.wrapping_add(r),
                    "-" => l.wrapping_sub(r),
                    "*" => l.wrapping_mul(r),
                    "/" => {
                        if r == 0 {
                            return None;
                        }
                        l.wrapping_div(r)
                    }
                    "%" => {
                        if r == 0 {
                            return None;
                        }
                        l.wrapping_rem(r)
                    }
                    _ => return None,
                })
            }
            _ => None,
        }
    }
    const_eval_hops(ir, var, 8)
}

/// Find the single instruction defining `var` (bounded scan).
fn defs_of_var(ir: &FunctionIR, var: VarId) -> Option<&Instruction> {
    for b in ir.blocks.values() {
        for i in &b.instructions {
            let dests: Vec<VarId> = match i {
                Instruction::Assign { dest, .. }
                | Instruction::BinaryOp { dest, .. }
                | Instruction::UnaryOp { dest, .. }
                | Instruction::LoadField { dest, .. }
                | Instruction::LoadElement { dest, .. }
                | Instruction::LoadGlobal { dest, .. }
                | Instruction::Cast { dest, .. } => vec![*dest],
                Instruction::CallStatic { dest: Some(d), .. }
                | Instruction::CallVirtual { dest: Some(d), .. } => vec![*d],
                _ => Vec::new(),
            };
            if dests.contains(&var) {
                return Some(i);
            }
        }
    }
    None
}

/// Evaluate a comparison over two constant operands.
fn compare_consts(op: &str, l: i64, r: i64) -> Option<bool> {
    Some(match op {
        ">" => l > r,
        "<" => l < r,
        ">=" => l >= r,
        "<=" => l <= r,
        "==" => l == r,
        "!=" => l != r,
        _ => return None,
    })
}

/// Record a silent stop site on the current root's exploration, keeping
/// the list free of duplicates (a walk can hit the same cut on many nodes).
fn record_cut(cuts: &mut Vec<&'static str>, reason: &'static str) {
    if !cuts.contains(&reason) {
        cuts.push(reason);
    }
}

/// Most stop sites kept per sink argument: enough to name the blind spot,
/// bounded so a wide fan-in cannot bloat every finding.
const MAX_CUT_SITES: usize = 4;

/// [`CutSite::kind`] for a call with no analysed callee that the walk flowed
/// *through* (its arguments were followed, assuming the result carries them).
const PASSED_THROUGH: &str = "passed-through";

/// Standard-library adapters, sorted: they are defined to forward their
/// operands into the result, so naming one as a pass-through tells a reader
/// nothing. Keeping them out leaves the list to calls the engine genuinely
/// has no model for (`mystery.read(req.params)`), which is the point of it.
/// Detection never consults this: it only filters the explanation.
const STD_FORWARDERS: &[&str] = &[
    "and_then",
    "any",
    "as_deref",
    "as_mut",
    "as_ref",
    "as_str",
    "clone",
    "collect",
    "filter",
    "filter_map",
    "flat_map",
    "fold",
    "into",
    "into_iter",
    "iter",
    "iter_mut",
    "keys",
    "map",
    "map_err",
    "ok_or",
    "ok_or_else",
    "or",
    "or_else",
    "take",
    "then",
    "then_some",
    "unwrap_or",
    "unwrap_or_default",
    "unwrap_or_else",
    "values",
];

/// Whether `callee` is a standard-library adapter (see [`STD_FORWARDERS`]).
fn is_std_forwarder(callee: &str) -> bool {
    STD_FORWARDERS.binary_search(&callee).is_ok()
}

/// Keep stop sites distinct and bounded.
fn record_cut_site(sites: &mut Vec<CutSite>, site: CutSite) {
    // Pass-throughs are context, not stops: they get their own budget so a
    // long chain of them cannot crowd out the stop that made the verdict.
    let same_class = |s: &&CutSite| (s.kind == PASSED_THROUGH) == (site.kind == PASSED_THROUGH);
    if sites.iter().filter(same_class).count() < MAX_CUT_SITES
        && !sites
            .iter()
            .any(|s| s.kind == site.kind && s.function == site.function && s.detail == site.detail)
    {
        sites.push(site);
    }
}

/// For the Phi `dest_var` in `merge_block`, return the incoming edges whose
/// arm block is unreachable because the branch condition is a constant
/// comparison with a decided outcome. Empty = nothing prunable.
fn phi_infeasible_incoming(
    ir: &FunctionIR,
    merge_block: BlockId,
    dest_var: VarId,
) -> Vec<(BlockId, VarId)> {
    let block = match ir.blocks.get(&merge_block) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let Some(phi) = block.phis.iter().find(|p| p.dest == dest_var) else {
        return Vec::new();
    };
    // An incoming (pred_block, var) is infeasible when pred_block is
    // reached by a Branch whose condition is a decided constant and the
    // edge taken is the OTHER side.
    let mut out = Vec::new();
    for &(pred_block, inc_var) in &phi.incoming {
        // Find the branch that targets pred_block.
        for b in ir.blocks.values() {
            let (cond, true_block, false_block) = match &b.terminator {
                Terminator::Branch {
                    cond: Operand::Var(c),
                    true_block,
                    false_block,
                } => (*c, *true_block, *false_block),
                _ => continue,
            };
            if true_block != pred_block && false_block != pred_block {
                continue;
            }
            let taken = match defs_of_var(ir, cond) {
                Some(Instruction::BinaryOp { op, lhs, rhs, .. }) => {
                    let l = match lhs {
                        Operand::IntLiteral(i) => Some(*i),
                        Operand::Var(v) => const_eval(ir, *v),
                        _ => None,
                    };
                    let r = match rhs {
                        Operand::IntLiteral(i) => Some(*i),
                        Operand::Var(v) => const_eval(ir, *v),
                        _ => None,
                    };
                    match (l, r) {
                        (Some(l), Some(r)) => compare_consts(op, l, r),
                        _ => None,
                    }
                }
                Some(Instruction::Assign {
                    src: Operand::IntLiteral(i),
                    ..
                }) => Some(*i != 0),
                _ => None,
            };
            let Some(taken) = taken else {
                continue;
            };
            let feasible_block = if taken { true_block } else { false_block };
            if feasible_block != pred_block {
                out.push((pred_block, inc_var));
            }
            break;
        }
    }
    out
}

/// What the engine knows about one sink site before exploring its arguments.
#[derive(Clone, Copy)]
struct SinkSite<'a> {
    /// Sink name as configured or declared (`innerHTML`, `send`, `write`).
    name: &'a str,
    /// Role the finding is ranked under.
    role: crate::analysis::taint::role::SinkRole,
    /// Human-readable label from the vocabulary, when one is declared.
    label: Option<&'a str>,
    /// Package the sink signature was scoped to, when known.
    origin_package: Option<&'a str>,
    /// Language of the site, for language-keyed sink facts.
    language: Option<&'a str>,
}

impl<'a> BackwardTaintEngine<'a> {
    /// Package an imported symbol name resolves to, when `armed` accepts it.
    /// The first dotted segment is the binding: `unzipper.Open` is written on
    /// the `unzipper` binding.
    fn imported_symbol_package(
        &self,
        symbol: &str,
        file: &str,
        armed: &impl Fn(&str) -> bool,
    ) -> Option<String> {
        let root = symbol.split('.').next().unwrap_or(symbol);
        let pkg = self
            .file_package_imports
            .get(file)?
            .get(root)?
            .package
            .clone();
        armed(&pkg).then_some(pkg)
    }

    /// Package a variable's provenance traces back to, when `armed` accepts
    /// it.
    ///
    /// [`FactTable::receiver_root`] answers "what is this expression *written*
    /// as", which is enough only when the call is written on the import
    /// itself (`unzipper.extract(..)`). Real code unwraps or aliases first:
    ///
    /// ```text
    /// const directory = await unzipper.Open.buffer(buf);  // chained call
    /// const zip = unzipper;                               // plain alias
    /// await directory.extract(path);
    /// ```
    ///
    /// There the binding's own name (`directory`, `zip`) is no import, so the
    /// root lookup misses and every package-scoped sink fact goes inert - the
    /// false negative that made corpus-taught sinks undeliverable outside the
    /// replay gate. Walk the producer chain instead (member load -> base, call
    /// result -> its receiver, alias -> source) and accept the first name the
    /// file's import table resolves to an armed package. A local helper
    /// (`const d = getDirectory(..)`) still has no origin, so unrelated code
    /// keeps matching only universal facts.
    fn var_package_origin(
        &self,
        ir: &crate::ir::function::FunctionIR,
        var: VarId,
        file: &str,
        depth: u8,
        armed: &impl Fn(&str) -> bool,
    ) -> Option<String> {
        if let Some(name) = ir
            .var_metadata
            .get(&var)
            .and_then(|m| m.source_name.clone())
            && let Some(pkg) = self.imported_symbol_package(&name, file, armed)
        {
            return Some(pkg);
        }
        if depth == 0 {
            return None;
        }
        if let Some((base, _)) = ir.loadfield_def(var) {
            return self.var_package_origin(ir, base, file, depth - 1, armed);
        }
        if let Some(recv) = ir.call_receiver_def(var) {
            return self.var_package_origin(ir, recv, file, depth - 1, armed);
        }
        // Constructor / factory producer: `const zip = new AdmZip(buf)` -
        // the callee's symbol is what the import table can name.
        for b in ir.blocks.values() {
            for instr in &b.instructions {
                if let Instruction::CallStatic {
                    dest: Some(dest),
                    func,
                    ..
                } = instr
                    && *dest == var
                {
                    let last = func.rsplit('.').next().unwrap_or(func);
                    if let Some(pkg) = self.imported_symbol_package(last, file, armed) {
                        return Some(pkg);
                    }
                }
            }
        }
        for b in ir.blocks.values() {
            for instr in &b.instructions {
                if let Instruction::Assign {
                    dest,
                    src: Operand::Var(src),
                } = instr
                    && *dest == var
                {
                    return self.var_package_origin(ir, *src, file, depth - 1, armed);
                }
            }
        }
        None
    }

    /// Package of the call that produced the receiver var, when `armed`
    /// accepts the resolved package.
    ///
    /// Covers the singleton client shape `const prisma = new PrismaClient()`
    /// (or any `... = PrismaClient(...)` / `.create()` / `.extend()` call):
    /// the receiver itself is not an import alias, but its defining call names
    /// a symbol resolved through the file's import table, so the package
    /// origin arms (`@prisma/client`). The caller decides which packages are
    /// worth arming for - sink origins arm on scoped sink packages, sanitizer
    /// origins on scoped sanitizer packages - no-op for unrelated packages,
    /// mirroring the receiver-root fallback.
    fn factory_call_package_for(
        &self,
        ir: &crate::ir::function::FunctionIR,
        recv: VarId,
        file: &str,
        armed: impl Fn(&str) -> bool,
    ) -> Option<String> {
        if let Some(pkg) = self.var_package_origin(ir, recv, file, 4, &armed) {
            return Some(pkg);
        }
        // Module-scope def: `const prisma = new PrismaClient()` at file top
        // level lowers into a pseudo-function named after the binding, so
        // the receiver in a consuming function has no def in its own IR.
        // Locate the same-file pseudo-function by the receiver's source
        // name and resolve the initializer inside it.
        let root = ir
            .var_metadata
            .get(&recv)
            .and_then(|m| m.source_name.clone())?;
        for f in &self.prog.functions {
            if (f.name == root
                || f.name
                    .strip_suffix(root.as_str())
                    .is_some_and(|p| p.ends_with(':')))
                && self.fn_file.get(&f.name).map(|s| s.as_str()) == Some(file)
            {
                for b in f.ir.blocks.values() {
                    for instr in &b.instructions {
                        match instr {
                            Instruction::CallStatic { func, .. } => {
                                let last = func.rsplit('.').next().unwrap_or(func);
                                if let Some(pkg) = self.imported_symbol_package(last, file, &armed)
                                {
                                    return Some(pkg);
                                }
                            }
                            // Factory wrappers and namespace member calls at
                            // module scope: `const client = axios.create(..)`
                            // and `const dir = unzipper.Open.buffer(..)` both
                            // lower as CallVirtual, and the module-scope path
                            // only matched CallStatic, losing the origin
                            // (mre01).
                            Instruction::CallVirtual {
                                receiver: Operand::Var(cr),
                                ..
                            } => {
                                if let Some(pkg) =
                                    self.var_package_origin(f.ir, *cr, file, 4, &armed)
                                {
                                    return Some(pkg);
                                }
                            }
                            // Module-level alias: `const zip = unzipper;`
                            // lowers to an Assign in the binding's own
                            // pseudo-function, so follow the source.
                            Instruction::Assign {
                                src: Operand::Var(src),
                                ..
                            } => {
                                if let Some(pkg) =
                                    self.var_package_origin(f.ir, *src, file, 4, &armed)
                                {
                                    return Some(pkg);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        None
    }

    /// Package of the factory call that produced the receiver var, when a
    /// package-scoped sink fact exists for it.
    fn factory_call_package(
        &self,
        ir: &crate::ir::function::FunctionIR,
        recv: VarId,
        file: &str,
    ) -> Option<String> {
        self.factory_call_package_for(ir, recv, file, |pkg| {
            self.facts
                .scoped_sink_signatures
                .keys()
                .any(|(p, _)| p == pkg)
        })
    }

    /// Import origin for a call node, for package-scoped sanitizer gating.
    ///
    /// The sanitizer-side mirror of the sink origin chain: a static call
    /// resolves through the file's package-import table, a receiver call
    /// through its receiver root (import alias, then a root naming a
    /// package that carries scoped sanitizer facts, then the factory
    /// singleton). `None` means unknown origin, package-scoped
    /// sanitizer facts then stay inert at the cut (recall-safe: they may
    /// only silence a flow under a confirmed origin).
    fn sanitizer_origin_package(
        &self,
        cf: usize,
        key: &crate::graph::svfg::NodeKey,
    ) -> Option<String> {
        let ir = self.prog.functions[cf].ir;
        let ins = ir
            .blocks
            .get(&key.block)?
            .instructions
            .get(key.instr_idx?)?;
        let fn_name = &self.prog.functions[cf].name;
        let imports = crate::graph::module::imports_for_function(
            &self.fn_file,
            &self.file_package_imports,
            fn_name,
        );
        match ins {
            Instruction::CallStatic { func, .. } => {
                imports.and_then(|m| m.get(func)).map(|p| p.package.clone())
            }
            Instruction::CallVirtual {
                receiver: Operand::Var(r),
                ..
            } => {
                let root = FactTable::receiver_root(ir, *r)?;
                if let Some(pkg) = imports
                    .and_then(|m| m.get(&root))
                    .map(|p| p.package.clone())
                {
                    return Some(pkg);
                }
                let root_is_scoped = self
                    .facts
                    .scoped_sanitizer_facts
                    .keys()
                    .any(|(pkg, _)| *pkg == root);
                if root_is_scoped {
                    return Some(root);
                }
                let file = self.fn_file.get(fn_name).map(|s| s.as_str());
                file.and_then(|file| {
                    self.factory_call_package_for(ir, *r, file, |pkg| {
                        self.facts
                            .scoped_sanitizer_facts
                            .keys()
                            .any(|(p, _)| p == pkg)
                    })
                })
            }
            _ => None,
        }
    }

    /// Does `name` resolve to a function defined in this program?
    ///
    /// Direct check via the call graph's exact-name index; the fallback
    /// catches collision-rekeyed twins (`app/b.ts::helper`, built in
    /// [`crate::scan::prepare_with_facts`]) and namespace-qualified keys.
    /// Only absolute suffixes (a prefix ending in `:`) count, so
    /// `execute_helper` is not a match for the name `helper`.
    fn is_program_local(&self, name: &str) -> bool {
        if self.prog.function_index(name).is_some() {
            return true;
        }
        self.prog.functions.iter().any(|f| {
            f.name.ends_with(name) && f.name.strip_suffix(name).is_some_and(|p| p.ends_with(':'))
        })
    }

    /// Explore one call site if it is a configured sink.
    pub(super) fn explore_call_site(
        &mut self,
        fi: usize,
        block: BlockId,
        idx: usize,
        instr: &Instruction,
    ) {
        // A property assignment is a write, not a call: `el.innerHTML = x`
        // reaches no call sink, so dispatch it to the store path.
        if let Instruction::StoreField {
            base,
            field,
            src: Operand::Var(value),
            span,
            ..
        } = instr
        {
            self.explore_store_sink(
                fi,
                *base,
                field,
                *value,
                *span,
                NodeKey::instr(block, idx, *value),
            );
            return;
        }
        let (name, receiver, args, call_dest): (
            &str,
            Option<&Operand>,
            &Vec<Operand>,
            Option<VarId>,
        ) = match instr {
            Instruction::CallStatic {
                func, args, dest, ..
            } => (func, None, args, dest.as_ref().copied()),
            Instruction::CallVirtual {
                method,
                receiver,
                args,
                dest,
                ..
            } => (method, Some(receiver), args, dest.as_ref().copied()),
            _ => return,
        };
        self.funnel.calls_examined += 1;
        let ir = self.prog.functions[fi].ir;
        let pkg_import = if receiver.is_none() {
            self.fn_file
                .get(&self.prog.functions[fi].name)
                .and_then(|file| self.file_package_imports.get(file))
                .and_then(|imports| imports.get(name))
                .or_else(|| {
                    if self.file_package_imports.len() == 1 {
                        self.file_package_imports
                            .values()
                            .next()
                            .and_then(|m| m.get(name))
                    } else {
                        None
                    }
                })
        } else {
            None
        };

        if receiver.is_none() && pkg_import.is_none() {
            // A static call to a local variable/closure defined in this function
            // is not an external sink.
            if ir
                .var_metadata
                .values()
                .any(|m| m.source_name.as_deref() == Some(name))
            {
                self.funnel.skipped_local_callable += 1;
                return;
            }
            // A static call resolving to a function defined in this program is
            // not an external sink either, even when the name matches a library
            // sink (a user helper named `run` is not `subprocess.run`; a package
            // import of that name short-circuits this guard above via
            // `pkg_import`). The callee's own configured sinks report once with
            // the full caller→callee path; arming the call site itself would
            // emit the same bug twice - once as a shorter path prefix (WI-41).
            if self.is_program_local(name) {
                self.funnel.skipped_program_local += 1;
                return;
            }
            // Verb sinks that strictly require a receiver object (get, post, render, etc.);
            // a bare static call without package import is not a client method invocation.
            if is_receiver_only_verb(name) {
                self.funnel.skipped_receiver_only_verb += 1;
                return;
            }
        }
        // Receiver-aware sink match: verb-named sinks (get/post/...) from
        // dotted client entries only fire when the receiver root is a known
        // client, `map.get(t)` is a Map accessor, `got.get(t)` is SSRF.
        let recv_var = match receiver {
            Some(Operand::Var(r)) => Some(*r),
            _ => None,
        };
        // Factory-resolved receiver roots must clear the same bar the
        // sink matcher applies: the root is a declared client (client_roots),
        // it carries a dotted entry for THIS method (receiver_roles), or it
        // names a package carrying package-scoped sink facts
        // (scoped_sink_signatures - the `axios.get` family lives here and
        // populates neither of the other two sets). Gating factories on
        // client_roots alone rejected `const client = axios.create(...)` ->
        // `client.get(...)` even though `axios.get` is a declared sink
        // (mre01 instance-alias false negative): the receiver resolved to
        // its own source name ("client") and the sink stayed suppressed.
        let factory_root_arms = |root: &str| {
            self.facts.client_roots.contains(root)
                || self
                    .facts
                    .receiver_roles
                    .contains_key(&(root.to_string(), name.to_string()))
                || self
                    .facts
                    .scoped_sink_signatures
                    .keys()
                    .any(|(pkg, _)| pkg == root)
        };
        let receiver_root = match receiver {
            Some(Operand::Var(r)) => {
                let direct = FactTable::receiver_root(ir, *r);
                if let Some(ref d) = direct {
                    // Name-collision guard: a variable merely *named* like a
                    // declared client root (a factory instance called
                    // `client`) must not short-circuit before the factory
                    // fallback - for a verb sink whose (root, method) pair is
                    // not declared, the direct name cannot arm the call, so
                    // fall through to import/factory resolution (which may
                    // recover the real root, e.g. `axios` from
                    // `axios.create(...)`) and only then default to `direct`
                    // (`resolved.or(direct)` below keeps the old result when
                    // nothing resolves). mre01 instance-alias false negative.
                    if self.facts.client_roots.contains(d)
                        && (!self.facts.verb_sinks.contains(name)
                            || self
                                .facts
                                .receiver_roles
                                .contains_key(&(d.clone(), name.to_string())))
                    {
                        direct
                    } else {
                        // Check if d was imported as a package namespace (e.g. import cp from "child_process")
                        let pkg_root = self
                            .fn_file
                            .get(&self.prog.functions[fi].name)
                            .and_then(|file| self.file_package_imports.get(file))
                            .and_then(|imports| imports.get(d))
                            .or_else(|| {
                                if self.file_package_imports.len() == 1 {
                                    self.file_package_imports
                                        .values()
                                        .next()
                                        .and_then(|m| m.get(d))
                                } else {
                                    None
                                }
                            })
                            .and_then(|pkg| {
                                if self.facts.client_roots.contains(&pkg.package) {
                                    Some(pkg.package.clone())
                                } else {
                                    None
                                }
                            });
                        if pkg_root.is_some() {
                            pkg_root
                        } else {
                            // Check if r is defined locally by a factory call
                            let mut resolved = None;
                            for b in ir.blocks.values() {
                                for instr in &b.instructions {
                                    match instr {
                                        Instruction::CallVirtual {
                                            dest: Some(d_var),
                                            method,
                                            receiver: Operand::Var(cr),
                                            ..
                                        } if *d_var == *r
                                            && (method == "create" || method == "extend") =>
                                        {
                                            if let Some(cr_root) = FactTable::receiver_root(ir, *cr)
                                                && factory_root_arms(&cr_root)
                                            {
                                                resolved = Some(cr_root);
                                            }
                                        }
                                        Instruction::CallStatic {
                                            dest: Some(d_var),
                                            func,
                                            ..
                                        } if *d_var == *r
                                            && (func.ends_with(".create")
                                                || func.ends_with(".extend")) =>
                                        {
                                            if let Some(prefix) = func.split('.').next()
                                                && factory_root_arms(prefix)
                                            {
                                                resolved = Some(prefix.to_string());
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            if resolved.is_none() {
                                // Check if d matches a module-level function / binding in prog
                                for f in &self.prog.functions {
                                    if f.name == *d
                                        || f.name
                                            .strip_suffix(d.as_str())
                                            .is_some_and(|p| p.ends_with(':'))
                                    {
                                        for b in f.ir.blocks.values() {
                                            for instr in &b.instructions {
                                                if let Instruction::CallVirtual {
                                                    method,
                                                    receiver: Operand::Var(cr),
                                                    ..
                                                } = instr
                                                    && (method == "create" || method == "extend")
                                                    && let Some(cr_root) =
                                                        FactTable::receiver_root(f.ir, *cr)
                                                    && factory_root_arms(&cr_root)
                                                {
                                                    resolved = Some(cr_root);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            resolved.or(direct)
                        }
                    }
                } else {
                    None
                }
            }
            _ => pkg_import.map(|pkg| pkg.package.clone()),
        };
        let effective_name = pkg_import.and_then(|p| p.symbol.as_deref()).unwrap_or(name);
        // Factory-call package origin (owned): the receiver var was
        // produced by a call to a symbol imported from a package with
        // scoped sink facts (`const prisma = new PrismaClient()` with
        // `import { PrismaClient } from '@prisma/client'`). Computed as an
        // owned value before the origin chain so no borrow of `self`
        // outlives it into the exploration loop.
        let factory_origin = recv_var.and_then(|rv| {
            let file = self.fn_file.get(&self.prog.functions[fi].name)?;
            self.factory_call_package(ir, rv, file)
        });
        // Origin chain, resolved to an OWNED string: the borrows of
        // `self` (import table, scoped-fact keys) end here, so the value
        // can be consulted inside the per-slot exploration loop where
        // `&mut self` borrows (guard state, stats) are live.
        let origin_owned: Option<String> = pkg_import
            .map(|pkg| pkg.package.clone())
            .or_else(|| {
                receiver_root.as_deref().and_then(|root| {
                    self.fn_file
                        .get(&self.prog.functions[fi].name)
                        .and_then(|file| self.file_package_imports.get(file))
                        .and_then(|imports| imports.get(root))
                        .map(|pkg| pkg.package.clone())
                })
            })
            .or_else(|| {
                receiver_root
                    .as_deref()
                    .filter(|root| {
                        self.facts
                            .scoped_sink_signatures
                            .keys()
                            .any(|(pkg, _)| pkg == *root)
                    })
                    .map(|root| root.to_string())
            })
            .or_else(|| factory_origin.clone());
        let origin_package = origin_owned.as_deref();
        // The call site's own language: sink facts are language-keyed, so a
        // Rust `File::create` signature must not arm a TypeScript `create`
        // call in the same mixed-language scan.
        let language = (!ir.language.is_empty()).then_some(ir.language.as_str());
        let has_receiver = recv_var.is_some();
        if !self.facts.is_recv_sink_call_scoped(
            effective_name,
            receiver_root.as_deref(),
            origin_package,
            language,
            has_receiver,
        ) && !self.facts.is_recv_sink_call_scoped(
            name,
            receiver_root.as_deref(),
            origin_package,
            language,
            has_receiver,
        ) {
            self.funnel.record_unmatched(effective_name);
            return;
        }
        self.funnel.sink_calls += 1;
        // Receiver-aware role: `kv.put(t)` resolves Storage (dotted
        // KVNamespace.put) while `axios.put(t)` stays Ssrf, the
        // receiver root is the disambiguator, mirroring verb-sink
        // matching above.
        let role = self
            .facts
            .role_for_call_scoped(
                effective_name,
                receiver_root.as_deref(),
                origin_package,
                language,
            )
            .or_else(|| {
                self.facts.role_for_call_scoped(
                    name,
                    receiver_root.as_deref(),
                    origin_package,
                    language,
                )
            })
            .unwrap_or_default();
        let label = self.facts.label_for_call_scoped(
            effective_name,
            receiver_root.as_deref(),
            origin_package,
            language,
        );
        let label = label.or_else(|| {
            self.facts.label_for_call_scoped(
                name,
                receiver_root.as_deref(),
                origin_package,
                language,
            )
        });
        // Engine purity: every fact-declared sink is explored and reported
        // when tainted data reaches it, regardless of role. Severity policy
        // (Response/Validation rank at `info`) is lang-declared ranking
        // applied when findings become advisories - it must never gate the
        // analysis itself, or no bundle knowledge can ever unblock a sink
        // the built-in tables happen to rank low.

        // Collect (slot, var, arg-node) triplets. For virtual calls the
        // receiver is slot usize::MAX (matching the forward engine's arg_slots convention).
        let mut triplets: Vec<(usize, VarId, NodeKey)> = Vec::new();
        if let Some(Operand::Var(r)) = receiver {
            triplets.push((usize::MAX, *r, NodeKey::instr(block, idx, *r)));
        }
        for (slot, a) in args.iter().enumerate() {
            if let Operand::Var(v) = a {
                triplets.push((slot, *v, NodeKey::instr(block, idx, *v)));
            }
        }
        if triplets.is_empty() {
            return;
        }
        self.explore_sink_args(
            fi,
            SinkSite {
                name,
                role,
                label: label.as_deref(),
                origin_package,
                language,
            },
            triplets,
            call_dest.and_then(|d| ir.var_span(d)),
        );
    }

    /// Explore a property-assignment sink if its field is armed.
    ///
    /// `el.innerHTML = user` names the DOM sink in the field and carries the
    /// untrusted data in the stored value; the write's own byte range places
    /// the finding on the vulnerable statement.
    fn explore_store_sink(
        &mut self,
        fi: usize,
        base: VarId,
        field: &str,
        value: VarId,
        span: Option<(usize, usize)>,
        node_key: NodeKey,
    ) {
        let Some(ir) = self.prog.functions.get(fi).map(|f| f.ir) else {
            return;
        };
        let language = (!ir.language.is_empty()).then_some(ir.language.as_str());
        let root = FactTable::receiver_root(ir, base);
        if !self.facts.sink_name_armed(
            &self.config.sinks,
            field,
            root.as_deref(),
            None,
            language,
            true,
        ) {
            return;
        }
        let role = self
            .facts
            .role_for_call_scoped(field, root.as_deref(), None, language)
            .unwrap_or_default();
        let label = self
            .facts
            .label_for_call_scoped(field, root.as_deref(), None, language);
        let slot_triplet = (0usize, value, node_key);
        self.explore_sink_args(
            fi,
            SinkSite {
                name: field,
                role,
                label: label.as_deref(),
                origin_package: None,
                language,
            },
            vec![slot_triplet],
            span,
        );
    }

    /// Dump one sink walk's shape and memory cost under `--debug-mem`.
    fn log_sink_mem(
        &self,
        fi: usize,
        name: &str,
        state: &ExploreState,
        rss_pre: u64,
        rss_walk: u64,
    ) {
        let mut fns: FxHashSet<usize> = FxHashSet::default();
        for (f, _) in state.seen_nodes.iter() {
            fns.insert(*f);
        }
        let mut ctxs: FxHashSet<u32> = FxHashSet::default();
        for (_, _, _, _, c) in state.visited.iter() {
            ctxs.insert(*c);
        }
        eprintln!(
            "[mem]     walk sink={} fn={} visited={} seen_nodes={} fns={} ctxs={} chains={} cuts={} rss_pre={} rss_after_explore={}",
            name,
            self.prog.functions[fi].name,
            state.visited.len(),
            state.seen_nodes.len(),
            fns.len(),
            ctxs.len(),
            self.ctx_chains.len(),
            state.cuts.len(),
            rss_pre,
            rss_walk
        );
    }

    /// Explore one configured sink's arguments. A call passes its argument
    /// triplets; a property store passes the single value it writes.
    fn explore_sink_args(
        &mut self,
        fi: usize,
        site: SinkSite<'_>,
        triplets: Vec<(usize, VarId, NodeKey)>,
        explicit_span: Option<(usize, usize)>,
    ) {
        let Some(ir) = self.prog.functions.get(fi).map(|f| f.ir) else {
            return;
        };
        self.stats.sink_args_explored += triplets.len();
        let mem_probe = crate::debug_flags::DebugFlags::get().mem;
        let mem_entry = if mem_probe {
            crate::debug_flags::rss_kb()
        } else {
            0
        };

        for (arg_slot, var, arg_node) in triplets {
            let Some(alert_info) = sink_alert_with_facts(
                ir,
                self.config,
                &self.facts,
                &arg_node,
                site.origin_package,
                site.language,
            ) else {
                continue;
            };
            let finding_class = alert_info.class;
            let mut state = ExploreState {
                sink_role: site.role,
                sink_label: site.label.map(str::to_string),
                ..Default::default()
            };
            state.seen_nodes.insert((fi, arg_node));
            self.current_parents.clear();
            self.current_root = Some((fi, arg_node));
            let rss_pre = if crate::debug_flags::DebugFlags::get().mem {
                crate::debug_flags::rss_kb()
            } else {
                0
            };
            self.explore_from(fi, arg_node, &mut state);
            let rss_walk = if crate::debug_flags::DebugFlags::get().mem {
                crate::debug_flags::rss_kb()
            } else {
                0
            };

            if mem_probe
                && (state.visited.len() > 50_000 || rss_walk.saturating_sub(rss_pre) > 1_000)
            {
                self.log_sink_mem(fi, site.name, &state, rss_pre, rss_walk);
            }

            let verdict = if state.saw_source {
                BackwardVerdict::Vulnerable
            } else if state.saw_unknown {
                BackwardVerdict::Unknown
            } else if state.saw_sanitized_root_only {
                BackwardVerdict::Sanitized
            } else {
                BackwardVerdict::Clean
            };

            // Bookkeeping for stats.
            self.stats.nodes_visited += state.seen_nodes.len();
            let mut fns: FxHashSet<usize> = FxHashSet::default();
            for (f, _) in state.seen_nodes.iter() {
                fns.insert(*f);
            }
            self.stats.functions_visited += fns.len();

            match verdict {
                BackwardVerdict::Vulnerable => self.stats.vulnerable += 1,
                BackwardVerdict::Sanitized => self.stats.sanitized += 1,
                BackwardVerdict::Unknown => self.stats.unknown += 1,
                BackwardVerdict::Clean => self.stats.clean += 1,
            }

            let alert = if verdict == BackwardVerdict::Vulnerable {
                Some(alert_info)
            } else {
                None
            };

            // Reconstruct the source→sink chain for vulnerable findings.
            let path = if verdict == BackwardVerdict::Vulnerable && self.capture_paths {
                self.reconstruct_path(state.source_node, state.source_desc.clone())
            } else {
                TaintPath::default()
            };

            self.findings.push(SinkFinding {
                function: ir.name.clone(),
                sink: site.name.to_string(),
                arg_slot,
                alert,
                verdict,
                finding_class,
                role: site.role,
                label: site.label.map(str::to_string),
                source_desc: state.source_desc.clone(),
                path,
                cut_reasons: state.cuts.clone(),
                cut_sites: state.cut_sites.clone(),
                // Span of the SINK CALL itself, not the tainted operand's
                // definition: reports must point at the line the user fixes.
                // (Reporting the operand's def site put `search.ts` SQLi at
                // line 18 instead of the vulnerable `query(...)` on line 21.)
                sink_span: explicit_span
                    .or_else(|| ir.var_metadata.get(&var).and_then(|m| m.byte_range)),
            });
            let _ = var;
        }
        if mem_probe {
            let now = crate::debug_flags::rss_kb();
            if now.saturating_sub(mem_entry) > 1_000 {
                eprintln!(
                    "[mem]     site_total fn={} sink={} nroots={} findings={} rss_delta_kb={}",
                    self.prog.functions[fi].name,
                    site.name,
                    self.stats.sink_args_explored,
                    self.findings.len(),
                    now - mem_entry
                );
            }
        }
    }

    /// Does the root argument's own definition read one specific
    /// field/element? Such walks carry *field demand*: the value they seek
    /// can only come from field-matching stores, never from the
    /// whole-container fill edges of an allocation.
    fn root_reads_field(&self, fi: usize, root: &NodeKey) -> bool {
        let ir = self.prog.functions[fi].ir;
        for b in ir.blocks.values() {
            for phi in &b.phis {
                if phi.dest == root.var {
                    return false;
                }
            }
            for ins in &b.instructions {
                if ins.dest() == Some(root.var) {
                    return matches!(
                        ins,
                        Instruction::LoadField { .. } | Instruction::LoadElement { .. }
                    );
                }
            }
        }
        false
    }

    /// Is `cur` the defining node of an `Allocate` instruction?
    fn def_is_allocation(&self, fi: usize, cur: &NodeKey) -> bool {
        let NodeKey {
            block,
            instr_idx: Some(i),
            var,
            ..
        } = *cur
        else {
            return false;
        };
        self.prog.functions[fi]
            .ir
            .blocks
            .get(&block)
            .and_then(|b| b.instructions.get(i))
            .is_some_and(|ins| matches!(ins, Instruction::Allocate { dest, .. } if *dest == var))
    }

    /// Backward BFS from `root` within one root's exploration state.
    fn explore_from(&mut self, fi: usize, root: NodeKey, state: &mut ExploreState) {
        // Field demand at the root: the sink argument's own definition reads
        // one specific field/element, so whole-container fill edges stay off
        // limits for this whole walk (see the allocation stop below).
        let root_field = self.root_reads_field(fi, &root);
        let root_ctx: u32 = 0;
        state
            .visited
            .insert((fi, root, root.block, root_field, root_ctx));
        let mut queue: VecDeque<(usize, NodeKey, BlockId, bool, u32)> = VecDeque::new();
        queue.push_back((fi, root, root.block, root_field, root_ctx));

        let dbg = DebugFlags::get();
        while let Some((cf, cur, use_block, field_demand, ctx)) = queue.pop_front() {
            // Classify `cur` once for the k=1 transitions below: formal
            // params filter their cross preds by the entry call site; a call
            // destination (ActualRet) pushes its site when the walk steps
            // into the callee.
            let (is_formal_param, enter_call) =
                match self.prog.functions[cf].svfg.node(&cur).map(|n| &n.kind) {
                    Some(NodeKind::FormalParam) => (true, None),
                    Some(NodeKind::ActualRet { call_site }) => (false, Some((cf, *call_site))),
                    _ => (false, None),
                };
            dbg_trace!(
                dbg.walk,
                "[walk] cf={cf} key={cur:?} kind={:?}",
                self.prog.functions[cf].svfg.node(&cur).map(|n| &n.kind)
            );
            let ir = self.prog.functions[cf].ir;

            // Stop: guard check. If this node's variable is checked by a
            // guard-style call (`.test(x)` / `includes(x)`) whose branch
            // dominates the block where the value is (re)used, the value was
            // validated on every path reaching here, sanitized (task 8.3
            // guard map). Pure value-flow cannot see this: the guard is a
            // sibling use, not a link in the chain.
            if let Some(gm) = self.guard_maps.get(&cf)
                && (gm.is_guarded(cur.var, use_block)
                    || (cf == fi && gm.is_guarded(cur.var, root.block)))
            {
                state.saw_sanitized_root_only = true;
                record_cut(&mut state.cuts, "guard");
                continue;
            }

            // Stop: source reached, vulnerable path confirmed.
            if is_source(ir, self.config, &self.facts, &cur) {
                state.saw_source = true;
                if state.source_node.is_none() {
                    state.source_node = Some((cf, cur));
                    state.source_desc = source_description(ir, self.config, &self.facts, &cur);
                }
                continue;
            }

            // Stop: provably attacker-independent value (constant, string
            // literal, boolean, or bounded integer range from the
            // per-function value lattice). Every non-`Top` lattice value
            // derives from literals, literal arithmetic, or branch
            // sharpening - no source payload can be hiding behind this
            // node - so the branch is cut as clean (unrealizable-path
            // elimination) instead of exploring its predecessors, which may
            // include over-approximated edges. Gated on fixpoint
            // convergence: a truncated fixpoint may hold
            // narrower-than-true values, and pruning on those could drop a
            // real flow.
            let provably_independent = self
                .value_info_for(cf)
                .is_some_and(|info| info.converged && info.values.contains_key(&cur.var));
            if provably_independent {
                record_cut(&mut state.cuts, "value-const");
                continue;
            }

            // Stop: sanitizer use, this branch is clean. Fact-table aware:
            // includes learned methods like .replace()/.test() guards,
            // qualified by sink role. Package-scoped sanitizer facts
            // additionally require the call's own import origin to name
            // their package; unknown origin leaves them inert.
            let san_origin = self.sanitizer_origin_package(cf, &cur);
            if is_sanitizer_effective_for_role(
                ir,
                self.config,
                &self.facts,
                &cur,
                state.sink_role,
                state.sink_label.as_deref(),
                san_origin.as_deref(),
            ) {
                state.saw_sanitized_root_only = true;
                record_cut(&mut state.cuts, "sanitizer");
                continue;
            }

            // Stop: a field-demand walk that reached a container's allocation.
            // The requested field's value can only arrive through
            // field-matching store edges, entered directly at the load's
            // destination (same-function Pass 3, cross-function heap edges).
            // Following the whole-container fill edges here would union every
            // stored property - `sink(p.other)` must not see the store of
            // `p.data` in the caller just because both share the container.
            if field_demand && self.def_is_allocation(cf, &cur) {
                continue;
            }

            // Local predecessors (optionally honouring suppression).
            let mut local_preds: Vec<NodeKey> = if self.honour_suppression {
                self.prog.local_predecessors(cf, &cur)
            } else {
                match self.prog.functions[cf].svfg.node(&cur) {
                    Some(n) => n.predecessors(),
                    None => Vec::new(),
                }
            };

            // Branch feasibility at phis: a Phi merges values from sibling
            // arms; when the branch condition is a constant comparison, the
            // infeasible arm never executes and its definition must not feed
            // the merge (`bar = const if 7*18+106 > 200 else param` - the
            // tainted else arm is dead). Filter phi predecessors here rather
            // than in the SVFG: feasibility is a walk-time question and the
            // graph stays a pure value-flow structure.
            let is_phi = self.prog.functions[cf]
                .svfg
                .node(&cur)
                .is_some_and(|n| n.kind == NodeKind::Phi);
            if is_phi {
                let infeasible = phi_infeasible_incoming(ir, cur.block, cur.var);
                if !infeasible.is_empty() {
                    local_preds.retain(|pk| {
                        // Post-SSA each incoming var is defined in its arm
                        // block; the def node key carries that block.
                        !infeasible
                            .iter()
                            .any(|(blk, var)| *blk == pk.block && *var == pk.var)
                    });
                }
            }

            // Cross predecessors (reverse index): who feeds this node from
            // another function? For a FormalParam that means actual-args at
            // caller call sites; for an ActualRet that means the callee's
            // FormalRet nodes.
            let mut cross_preds: Vec<(usize, NodeKey)> = self
                .reverse_cross
                .get(&(cf, cur))
                .cloned()
                .unwrap_or_default();

            // k=1 call-site context (phase 5): a formal parameter's value
            // arrived through ONE invocation - the call site the walk entered
            // this function by. Only that site's actual arguments explain it;
            // sibling callers' args are a different invocation entirely.
            // Empty context (root function, heap-edge entry, cap collapse):
            // no filter - the sound k=0 over-approximation.
            if is_formal_param && let Some((f_expect, site_expect)) = self.ctx_last(ctx) {
                cross_preds.retain(|(pf, pk)| {
                    *pf == f_expect
                        && matches!(
                            self.prog.functions[*pf].svfg.node(pk).map(|n| &n.kind),
                            Some(NodeKind::ActualArg { call_site, .. })
                                if *call_site == site_expect
                        )
                });
            }

            if local_preds.is_empty() && cross_preds.is_empty() {
                dbg_trace!(
                    dbg.deadend,
                    "[deadend] cf={cf} key={cur:?} kind={:?}",
                    self.prog.functions[cf].svfg.node(&cur).map(|n| &n.kind)
                );
                // Dead end. Classify: unresolvable roots (formal params never
                // fed by an analysed call site, or environment-defined values
                // like LoadGlobal / Dereference / CallPointer) are "unknown",
                // we can't prove them clean. Everything else (literals,
                // allocations) is a genuinely clean root.
                if self.node_is_unresolvable(cf, &cur) {
                    state.saw_unknown = true;
                    record_cut(&mut state.cuts, "unresolvable");
                    if let Some(site) = self.cut_site(cf, &cur) {
                        record_cut_site(&mut state.cut_sites, site);
                    }
                }
                // Otherwise: clean root, stop.
                continue;
            }

            // An external call whose result the walk follows into its
            // arguments: sound only as an assumption (the library might
            // sanitise or might not propagate), so name it.
            if enter_call.is_some()
                && cross_preds.is_empty()
                && !local_preds.is_empty()
                && let Some(mut site) = self.cut_site(cf, &cur)
                && site.kind == "external-call"
                && !is_std_forwarder(&site.detail)
            {
                site.kind = PASSED_THROUGH;
                record_cut_site(&mut state.cut_sites, site);
            }

            for (pf, pk) in cross_preds {
                // Context transition for the k=1 stack:
                //  - landing on an ActualArg unwinds out of a callee → pop;
                //  - leaving an ActualRet steps into a callee → push its site;
                //  - any other cross jump (heap edges) has no call/return
                //    shape → reset to the empty context (k=0 where it lands,
                //    sound: never wrong-strict).
                let pred_is_actual_arg = self.prog.functions[pf]
                    .svfg
                    .node(&pk)
                    .is_some_and(|n| matches!(n.kind, NodeKind::ActualArg { .. }));
                let new_ctx = if pred_is_actual_arg {
                    self.ctx_exit(ctx)
                } else if let Some((caller_fn, site)) = enter_call {
                    self.ctx_enter(ctx, caller_fn, site)
                } else {
                    0
                };
                if state
                    .visited
                    .insert((pf, pk, pk.block, field_demand, new_ctx))
                {
                    state.seen_nodes.insert((pf, pk));
                    if self.capture_paths {
                        self.record_parent((pf, pk), (cf, cur));
                    }
                    queue.push_back((pf, pk, pk.block, field_demand, new_ctx));
                }
            }
            for pk in local_preds {
                if state.visited.insert((cf, pk, cur.block, field_demand, ctx)) {
                    state.seen_nodes.insert((cf, pk));
                    if self.capture_paths {
                        self.record_parent((cf, pk), (cf, cur));
                    }
                    queue.push_back((cf, pk, cur.block, field_demand, ctx));
                }
            }
        }
    }

    /// Describe an unresolvable dead-end node (see [`Self::node_is_unresolvable`])
    /// as a [`CutSite`]: what the engine could not see, and where.
    fn cut_site(&self, fi: usize, key: &NodeKey) -> Option<CutSite> {
        let ir = self.prog.functions[fi].ir;
        let span = ir.var_metadata.get(&key.var).and_then(|m| m.byte_range);
        let named = |kind: &'static str, detail: String| CutSite {
            kind,
            function: ir.name.clone(),
            detail,
            span,
        };
        let node = self.prog.functions[fi].svfg.node(key)?;
        if node.kind == crate::graph::svfg::NodeKind::FormalParam {
            let name = ir
                .var_metadata
                .get(&key.var)
                .and_then(|m| m.source_name.clone())
                .unwrap_or_default();
            return Some(named("param-no-caller", name));
        }
        let idx = key.instr_idx?;
        let ins = ir.blocks.get(&key.block)?.instructions.get(idx)?;
        Some(match ins {
            Instruction::CallStatic { func, .. } => named("external-call", func.clone()),
            Instruction::CallVirtual { method, .. } => named("external-call", method.clone()),
            Instruction::CallPointer { .. } => named("indirect-call", String::new()),
            Instruction::LoadGlobal { name, .. } => named("global", name.clone()),
            Instruction::Dereference { .. } => named("pointer-deref", String::new()),
            _ => return None,
        })
    }

    /// A node is unresolvable if we cannot prove its value clean within the
    /// analysed program:
    ///   * a `FormalParam` with no cross-edge feeders (external entry point,
    ///     or called only with literal args), or
    ///   * a def produced by an environment-read instruction (`LoadGlobal`,
    ///     `Dereference`, `CallPointer`), its value comes from outside the
    ///     local value-flow graph.
    fn node_is_unresolvable(&self, fi: usize, key: &NodeKey) -> bool {
        let fe = &self.prog.functions[fi];
        let Some(node) = fe.svfg.node(key) else {
            return false;
        };
        if node.kind == crate::graph::svfg::NodeKind::FormalParam {
            // Unresolvable iff there are no cross edges feeding it.
            return !self.reverse_cross.contains_key(&(fi, *key));
        }
        // A call result with no cross-edge feeding it is a call to an
        // unknown/external callee (library API): its semantics are unknown,
        // so "clean" would be unsound, classify as unknown. Resolved
        // internal callees have ActualRet→FormalRet reverse edges and never
        // reach this dead-end classification.
        if matches!(node.kind, crate::graph::svfg::NodeKind::ActualRet { .. }) {
            dbg_trace!(
                DebugFlags::get().unres,
                "[unresolvable] ActualRet key={key:?} has_cross={} block={:?} idx={:?}",
                self.reverse_cross.contains_key(&(fi, *key)),
                key.block,
                key.instr_idx
            );
            let NodeKey {
                block,
                instr_idx: Some(idx),
                var,
            } = *key
            else {
                return false;
            };
            if let Some(b) = fe.ir.blocks.get(&block)
                && idx < b.instructions.len()
                && matches!(
                    &b.instructions[idx],
                    Instruction::CallStatic { dest: Some(d), .. }
                        | Instruction::CallVirtual { dest: Some(d), .. }
                        | Instruction::CallPointer { dest: Some(d), .. }
                    if *d == var
                )
            {
                return true;
            }
            return false;
        }
        if node.kind == crate::graph::svfg::NodeKind::InstrDef {
            let Some(instr) = key.instruction(fe.ir) else {
                return false;
            };
            if matches!(
                instr,
                Instruction::LoadGlobal { .. }
                    | Instruction::Dereference { .. }
                    | Instruction::CallPointer { .. }
            ) {
                return true;
            }
            // A call result with no cross-edge feeding it is a call to an
            // unknown/external callee (library API): its semantics are
            // unknown, so "clean" would be unsound, classify as unknown.
            // Resolved internal callees have ActualRet→FormalRet reverse
            // edges and never reach this dead-end classification.
            if matches!(node.kind, crate::graph::svfg::NodeKind::ActualRet { .. })
                && matches!(
                    instr,
                    Instruction::CallStatic { dest: Some(d), .. }
                        | Instruction::CallVirtual { dest: Some(d), .. }
                    if *d == key.var
                )
            {
                return true;
            }
        }
        false
    }
}

#[inline]
fn is_receiver_only_verb(name: &str) -> bool {
    matches!(
        name,
        "get"
            | "post"
            | "put"
            | "delete"
            | "patch"
            | "head"
            | "options"
            | "request"
            | "set"
            | "render"
            | "aggregate"
    )
}

#[cfg(test)]
mod forwarder_tests {
    use super::{STD_FORWARDERS, is_std_forwarder};

    /// `is_std_forwarder` binary-searches [`STD_FORWARDERS`], so an entry
    /// inserted out of order (or duplicated) is not a compile error - the
    /// lookup just stops finding it, and std adapters creep back into the
    /// pass-through list. `windows(2)` with a strict `<` fails on both.
    #[test]
    fn the_std_forwarder_list_is_sorted_and_unique() {
        for pair in STD_FORWARDERS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "`{}` must sort before `{}`; binary_search silently stops \
                 filtering once the list is out of order",
                pair[0],
                pair[1]
            );
        }
    }

    /// The list is the whole answer: every entry is found, and a call the
    /// engine has no model for is not treated as an adapter.
    #[test]
    fn every_entry_is_found_and_unknown_calls_are_not() {
        for name in STD_FORWARDERS {
            assert!(is_std_forwarder(name), "`{name}` is in the list");
        }
        assert!(is_std_forwarder("iter"));
        assert!(!is_std_forwarder("mystery.read"));
        assert!(!is_std_forwarder(""));
    }
}
