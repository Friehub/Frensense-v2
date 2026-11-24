// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
//! Sink dispatch: which call is a sink, which slots carry data, and the
//! per-slot backward walk it starts.
//!
//! Split out of `walk.rs`. Resolving one call site is the composition of
//! `skip_unanchored_static`, `receiver_root_for`, `sink_origin`, `arms_sink`
//! and `sink_role_label` rather than one 386-line body.

use super::*;

use crate::analysis::taint::role::SinkRole;

impl<'a> BackwardTaintEngine<'a> {
    /// Explore one call site if it is a configured sink.
    pub(crate) fn explore_call_site(
        &mut self,
        fi: usize,
        block: BlockId,
        idx: usize,
        instr: &Instruction,
    ) {
        if self.explore_store_field(fi, block, idx, instr) {
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
            self.import_of(fi, name)
        } else {
            None
        };

        if self.dispatch_runs_program_code(fi, block, idx) {
            self.funnel.skipped_program_local += 1;
            return;
        }

        if self.skip_unanchored_static(ir, name, receiver.is_none(), pkg_import.is_some()) {
            return;
        }

        // Receiver-aware sink match: verb-named sinks (get/post/...) from
        // dotted client entries only fire when the receiver root is a known
        // client, `map.get(t)` is a Map accessor, `got.get(t)` is SSRF.
        let recv_var = match receiver {
            Some(Operand::Var(r)) => Some(*r),
            _ => None,
        };
        let pkg_name = pkg_import.as_ref().map(|(pkg, _)| pkg.as_str());
        let receiver_root = self.receiver_root_for(fi, ir, name, receiver, pkg_name);
        let effective_name = pkg_import
            .as_ref()
            .and_then(|(_, symbol)| symbol.as_deref())
            .unwrap_or(name);
        // Factory-call package origin (owned): the receiver var was produced by
        // a call to a symbol imported from a package with scoped sink facts
        // (`const prisma = new PrismaClient()` with `import { PrismaClient }
        // from '@prisma/client'`). Computed as an owned value before the origin
        // chain so no borrow of `self` outlives it into the exploration loop.
        let factory_origin = recv_var.and_then(|rv| {
            let file = self.fn_file.get(&self.prog.functions[fi].name)?;
            self.factory_call_package(ir, rv, file)
        });
        // The call site's own language: sink facts are language-keyed, so a
        // Rust `File::create` signature must not arm a TypeScript `create` call
        // in the same mixed-language scan.
        let language = (!ir.language.is_empty()).then_some(ir.language.as_str());
        let origin = self.sink_origin(fi, pkg_name, receiver_root.as_deref(), factory_origin);
        let call = SinkCall {
            name,
            effective_name,
            receiver_root,
            origin,
            language,
            has_receiver: recv_var.is_some(),
        };
        if !self.arms_sink(&call) {
            self.funnel.record_unmatched(effective_name);
            return;
        }
        self.funnel.sink_calls += 1;
        // Receiver-aware role: `kv.put(t)` resolves Storage (dotted
        // KVNamespace.put) while `axios.put(t)` stays Ssrf, the receiver root is
        // the disambiguator, mirroring verb-sink matching above.
        let (role, label) = self.sink_role_label(&call);
        // Engine purity: every fact-declared sink is explored and reported when
        // tainted data reaches it, regardless of role. Severity policy
        // (Response/Validation rank at `info`) is lang-declared ranking applied
        // when findings become advisories - it must never gate the analysis
        // itself, or no bundle knowledge can ever unblock a sink the built-in
        // tables happen to rank low.
        let origin_package = call.origin.as_deref();
        let triplets = sink_triplets(block, idx, receiver, args);
        let site = SinkSite {
            name,
            role,
            label: label.as_deref(),
            origin_package,
            language,
        };
        // Slot of the first argument that is a literal rather than a value:
        // nothing to walk, but the call still has a verdict.
        let literal_arg_slot = args.iter().position(|a| !matches!(a, Operand::Var(_)));
        let findings_before = self.findings.len();
        let no_triplets = triplets.is_empty();
        if !no_triplets {
            self.explore_sink_args(fi, site, triplets, call_dest.and_then(|d| ir.var_span(d)));
        }
        // A sink whose data operands are all literals has nothing to walk:
        // `os.system("echo hi")` contributes only its receiver triplet, and a
        // clean receiver is deliberately not reported (#100, #133). The call
        // then left no finding at all, so coverage counted the file as one
        // that contained "no sink site the engine models" and `--explain`
        // stayed silent about a call the engine had in fact matched.
        // Recognition is a verdict, not reportability: record the Clean one.
        if self.findings.len() == findings_before && (no_triplets || literal_arg_slot.is_some()) {
            let arg_slot = literal_arg_slot.unwrap_or(0);
            self.findings.push(SinkFinding {
                function: ir.name.clone(),
                sink: name.to_string(),
                arg_slot,
                alert: None,
                verdict: BackwardVerdict::Clean,
                finding_class: FindingClass::Injection,
                role: site.role,
                label: site.label.map(str::to_string),
                source_desc: None,
                path: TaintPath::default(),
                cut_reasons: vec!["value-const"],
                cut_sites: Vec::new(),
                suppressions: Vec::new(),
                sink_span: call_dest.and_then(|d| ir.var_span(d)),
            });
        }
    }

    /// A property assignment is a write, not a call: `el.innerHTML = x` reaches
    /// no call sink, so dispatch it to the store path. Returns whether `instr`
    /// was such a write.
    fn explore_store_field(
        &mut self,
        fi: usize,
        block: BlockId,
        idx: usize,
        instr: &Instruction,
    ) -> bool {
        let Instruction::StoreField {
            base,
            field,
            src: Operand::Var(value),
            span,
            ..
        } = instr
        else {
            return false;
        };
        self.explore_store_sink(
            fi,
            *base,
            field,
            *value,
            *span,
            NodeKey::instr(block, idx, *value),
        );
        true
    }

    /// The package (and imported symbol) a local name is bound to by an import
    /// in this function's file, owned so the caller can keep mutating `self`.
    ///
    /// Falls back to the only import table when the file map has a single
    /// entry: synthetic modules do not always carry a resolvable path key.
    fn import_of(&self, fi: usize, symbol: &str) -> Option<(String, Option<String>)> {
        self.fn_file
            .get(&self.prog.functions[fi].name)
            .and_then(|file| self.file_package_imports.get(file))
            .and_then(|imports| imports.get(symbol))
            .or_else(|| {
                if self.file_package_imports.len() == 1 {
                    self.file_package_imports
                        .values()
                        .next()
                        .and_then(|m| m.get(symbol))
                } else {
                    None
                }
            })
            .map(|pkg| (pkg.package.clone(), pkg.symbol.clone()))
    }

    /// Whether a receiver root can arm a sink for `name`: a declared client, a
    /// dotted entry for THIS method, or a package carrying package-scoped sink
    /// facts.
    ///
    /// Factories must clear the same bar the sink matcher applies.
    /// `scoped_sink_signatures` is where the `axios.get` family lives: it
    /// populates neither `client_roots` nor `receiver_roles`, so gating
    /// factories on `client_roots` alone rejected `const client =
    /// axios.create(...)` -> `client.get(...)` even though `axios.get` is a
    /// declared sink (mre01 instance-alias false negative).
    fn root_arms(&self, name: &str, root: &str) -> bool {
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
    }

    /// Resolve the receiver root of a call: the variable's own root, the
    /// package it was imported from, the factory that built it, or the import
    /// of a bare callee name.
    fn receiver_root_for(
        &self,
        fi: usize,
        ir: &FunctionIR,
        name: &str,
        receiver: Option<&Operand>,
        pkg_name: Option<&str>,
    ) -> Option<String> {
        match receiver {
            Some(Operand::Var(r)) => {
                let direct = FactTable::receiver_root(ir, *r)?;
                self.direct_receiver_root(fi, ir, name, *r, &direct)
            }
            _ => pkg_name.map(str::to_string),
        }
    }

    /// Root for a receiver variable that already resolved to a name `d`.
    fn direct_receiver_root(
        &self,
        fi: usize,
        ir: &FunctionIR,
        name: &str,
        r: VarId,
        d: &str,
    ) -> Option<String> {
        // Name-collision guard: a variable merely *named* like a declared
        // client root (a factory instance called `client`) must not
        // short-circuit before the factory fallback - for a verb sink whose
        // (root, method) pair is not declared, the direct name cannot arm the
        // call, so fall through to import/factory resolution (which may recover
        // the real root, e.g. `axios` from `axios.create(...)`) and only then
        // default to `d` (`resolved.or(direct)` below keeps the old result when
        // nothing resolves). mre01 instance-alias false negative.
        if self.facts.client_roots.contains(d)
            && (!self.facts.verb_sinks.contains(name)
                || self
                    .facts
                    .receiver_roles
                    .contains_key(&(d.to_string(), name.to_string())))
        {
            return Some(d.to_string());
        }
        // `d` as an imported package namespace (e.g. `import cp from
        // "child_process"`); an import only rebinds to a declared client.
        let pkg_root = self
            .import_of(fi, d)
            .and_then(|(pkg, _)| self.facts.client_roots.contains(&pkg).then_some(pkg));
        if pkg_root.is_some() {
            return pkg_root;
        }
        self.factory_root_of(ir, r, d, name)
            .or_else(|| Some(d.to_string()))
    }

    /// Root of the factory call that produced `target`: `<root>.create(..)` /
    /// `.extend(..)` in this function, then a module-level binding of the same
    /// name (the factory that builds a shared client).
    fn factory_root_of(
        &self,
        ir: &FunctionIR,
        target: VarId,
        root_name: &str,
        name: &str,
    ) -> Option<String> {
        for b in ir.blocks.values() {
            for instr in &b.instructions {
                match instr {
                    Instruction::CallVirtual {
                        dest: Some(d_var),
                        method,
                        receiver: Operand::Var(cr),
                        ..
                    } if *d_var == target && (method == "create" || method == "extend") => {
                        if let Some(cr_root) = FactTable::receiver_root(ir, *cr)
                            && self.root_arms(name, &cr_root)
                        {
                            return Some(cr_root);
                        }
                    }
                    Instruction::CallStatic {
                        dest: Some(d_var),
                        func,
                        ..
                    } if *d_var == target
                        && (func.ends_with(".create") || func.ends_with(".extend")) =>
                    {
                        if let Some(prefix) = func.split('.').next()
                            && self.root_arms(name, prefix)
                        {
                            return Some(prefix.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        for f in &self.prog.functions {
            let is_binding = f.name == root_name
                || f.name
                    .strip_suffix(root_name)
                    .is_some_and(|p| p.ends_with(':'));
            if !is_binding {
                continue;
            }
            for b in f.ir.blocks.values() {
                for instr in &b.instructions {
                    if let Instruction::CallVirtual {
                        method,
                        receiver: Operand::Var(cr),
                        ..
                    } = instr
                        && (method == "create" || method == "extend")
                        && let Some(cr_root) = FactTable::receiver_root(f.ir, *cr)
                        && self.root_arms(name, &cr_root)
                    {
                        return Some(cr_root);
                    }
                }
            }
        }
        None
    }

    /// Origin chain of a sink call, resolved to an OWNED string: the borrows of
    /// `self` (import table, scoped-fact keys) end here, so the value can be
    /// consulted inside the per-slot exploration loop where `&mut self` borrows
    /// (guard state, stats) are live.
    fn sink_origin(
        &self,
        fi: usize,
        pkg_name: Option<&str>,
        receiver_root: Option<&str>,
        factory_origin: Option<String>,
    ) -> Option<String> {
        if let Some(pkg) = pkg_name {
            return Some(pkg.to_string());
        }
        if let Some(root) = receiver_root {
            if let Some((pkg, _)) = self.import_of(fi, root) {
                return Some(pkg);
            }
            if self
                .facts
                .scoped_sink_signatures
                .keys()
                .any(|(pkg, _)| pkg == root)
            {
                return Some(root.to_string());
            }
        }
        factory_origin
    }

    /// Whether the configured sink facts arm this call at all.
    fn arms_sink(&self, call: &SinkCall<'_>) -> bool {
        self.arms_sink_named(call.effective_name, call)
            || (call.effective_name != call.name && self.arms_sink_named(call.name, call))
    }

    /// [`Self::arms_sink`] for one candidate name (the imported symbol first,
    /// then the source-level call name).
    fn arms_sink_named(&self, last: &str, call: &SinkCall<'_>) -> bool {
        self.facts.is_recv_sink_call_scoped(
            last,
            call.receiver_root.as_deref(),
            call.origin.as_deref(),
            call.language,
            call.has_receiver,
        )
    }

    /// Receiver-scoped role and label of the armed sink, resolved under the
    /// imported symbol first and the source-level call name second.
    fn sink_role_label(&self, call: &SinkCall<'_>) -> (SinkRole, Option<String>) {
        let scoped = |last: &str| {
            (
                self.facts.role_for_call_scoped(
                    last,
                    call.receiver_root.as_deref(),
                    call.origin.as_deref(),
                    call.language,
                ),
                self.facts.label_for_call_scoped(
                    last,
                    call.receiver_root.as_deref(),
                    call.origin.as_deref(),
                    call.language,
                ),
            )
        };
        let (role, label) = scoped(call.effective_name);
        let (fallback_role, fallback_label) = if call.effective_name == call.name {
            (None, None)
        } else {
            scoped(call.name)
        };
        (
            role.or(fallback_role).unwrap_or_default(),
            label.or(fallback_label),
        )
    }
}

/// A resolved sink call: the names, origins and language the matcher and the
/// per-slot walk consult.
struct SinkCall<'a> {
    /// Call name as written at the site.
    name: &'a str,
    /// Imported symbol when the call goes through a package import.
    effective_name: &'a str,
    /// Resolved receiver root, if the call had a receiver.
    receiver_root: Option<String>,
    /// Resolved package origin of the call.
    origin: Option<String>,
    /// Source language of the call site.
    language: Option<&'a str>,
    /// Whether the call had a receiver operand.
    has_receiver: bool,
}

/// The (slot, var, arg-node) triplets a call site contributes to the walk.
///
/// For virtual calls the receiver is slot `usize::MAX` (matching the forward
/// engine's arg_slots convention). It is still walked - a `new Package(taint)`
/// object carries its constructor's data into every method that acts on it -
/// but only a tainted receiver becomes a finding (#100, #133).
fn sink_triplets(
    block: BlockId,
    idx: usize,
    receiver: Option<&Operand>,
    args: &[Operand],
) -> Vec<(usize, VarId, NodeKey)> {
    let mut triplets: Vec<(usize, VarId, NodeKey)> = Vec::new();
    if let Some(Operand::Var(r)) = receiver {
        triplets.push((usize::MAX, *r, NodeKey::instr(block, idx, *r)));
    }
    for (slot, a) in args.iter().enumerate() {
        if let Operand::Var(v) = a {
            triplets.push((slot, *v, NodeKey::instr(block, idx, *v)));
        }
    }
    triplets
}

impl<'a> BackwardTaintEngine<'a> {
    /// Explore a property-assignment sink if its field is armed.
    ///
    /// `el.innerHTML = user` names the DOM sink in the field and carries the
    /// untrusted data in the stored value; the write's own byte range places
    /// the finding on the vulnerable statement.
    pub(super) fn explore_store_sink(
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
    pub(super) fn log_sink_mem(
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
    pub(super) fn explore_sink_args(
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
                sink_name: site.name.to_string(),
                sink_class: frensense_lang::severity::resolved_sink_class(
                    site.role,
                    site.label,
                    Some(site.name),
                )
                .map(str::to_string),
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

            // A method call's receiver is not an argument (#100, #133). Its
            // tainted provenance still reaches the sink - `new AdmZip(taint)`
            // hands the data to `zip.extractAllTo(..)`, whose own arguments
            // are literals - so a Vulnerable receiver is reported. A clean or
            // undecided receiver says nothing about the data the call
            // consumes, so it must not become a finding: `res.write("hello")`
            // writes a constant, and listing `res` as an argument made the
            // call "1 site undecided" while every all-args sink over-counted
            // `findings`/`located` by one Clean entry per call.
            if arg_slot == crate::graph::svfg::RECEIVER_ARG_INDEX
                && verdict != BackwardVerdict::Vulnerable
            {
                continue;
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
                suppressions: state.suppressions.clone(),
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
}
