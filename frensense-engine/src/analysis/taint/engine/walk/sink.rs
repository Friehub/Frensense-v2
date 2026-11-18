// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
//! Sink dispatch: which call is a sink, which slots carry data, and the
//! per-slot backward walk it starts.
//!
//! Split out of `walk.rs` unchanged.

use super::*;

impl<'a> BackwardTaintEngine<'a> {
    /// Explore one call site if it is a configured sink.
    pub(crate) fn explore_call_site(
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
        // receiver is slot usize::MAX (matching the forward engine's arg_slots
        // convention). It is still walked - a `new Package(taint)` object
        // carries its constructor's data into every method that acts on it -
        // but only a tainted receiver becomes a finding (#100, #133).
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
