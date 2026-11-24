// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
//! Package-origin resolution: which package a receiver root, a factory
//! result or a sanitizer handle came from.
//!
//! Split out of `walk.rs` unchanged; the engine's `impl` is spread across
//! these submodules so no single file carries the whole backward walk.

use super::*;

impl<'a> BackwardTaintEngine<'a> {
    /// Package an imported symbol name resolves to, when `armed` accepts it.
    /// The first dotted segment is the binding: `unzipper.Open` is written on
    /// the `unzipper` binding.
    pub(super) fn imported_symbol_package(
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
    pub(super) fn var_package_origin(
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
    pub(super) fn factory_call_package_for(
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
    pub(super) fn factory_call_package(
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
    pub(super) fn sanitizer_origin_package(
        &self,
        cf: usize,
        key: &crate::graph::svfg::NodeKey,
    ) -> Option<String> {
        // Origin resolution is a pure function of the SVFG and the file's
        // import table, and a sanitizer cut site is revisited once per sink
        // walk that reaches it. One authoritative record per call site,
        // computed once and memoised on `(fn, block, instruction)`.
        let Some(idx) = key.instr_idx else {
            return self.sanitizer_origin_package_uncached(cf, key);
        };
        let site = (cf, key.block.0, idx);
        if let Some(hit) = self.call_site_origins.borrow().get(&site) {
            return hit.clone();
        }
        let origin = self.sanitizer_origin_package_uncached(cf, key);
        self.call_site_origins
            .borrow_mut()
            .insert(site, origin.clone());
        origin
    }

    fn sanitizer_origin_package_uncached(
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
}
