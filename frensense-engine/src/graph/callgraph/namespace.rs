// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Namespace bindings in the call graph: `import * as ns from "./m"` and
//! `export * as ns from "./m"` bind a whole module, so `ns.member()` names a
//! function declared in that file rather than an unknown receiver's method.
//!
//! The binding carries its module, so this is a named lookup - never the
//! bare-name guess the unknown-receiver path refuses to make.

use super::CallGraphBuilder;
use crate::graph::module::NamespaceBindings;
use crate::ir::function::{FunctionIR, Operand};

/// The name a receiver is written under, when it has one.
pub(super) fn receiver_root<'a>(ir: &'a FunctionIR, receiver: &Operand) -> Option<&'a str> {
    match receiver {
        Operand::Var(v) => ir.var_metadata.get(v)?.source_name.as_deref(),
        _ => None,
    }
}

impl<'a> CallGraphBuilder<'a> {
    /// Supplies per-file namespace bindings (`import * as ns from "./m"`,
    /// `export * as ns from "./m"` and their barrel chains), so `ns.member()`
    /// resolves to the function the module declares.
    pub(crate) fn with_namespace_aliases(
        mut self,
        namespaces: Option<&'a NamespaceBindings>,
    ) -> Self {
        self.namespaces = namespaces;
        self
    }

    /// The program function a namespace member call names, if the binding's
    /// module declares it.
    ///
    /// The binding carries the module, so this is a named lookup rather than
    /// the bare-name guess the unknown-receiver path refuses to make: a module
    /// that does not export `member` resolves to nothing and the site stays
    /// external.
    pub(super) fn resolve_namespace_member(
        &self,
        fname: &str,
        root: &str,
        method: &str,
    ) -> Option<String> {
        let file = self.fn_file?.get(fname)?;
        let module = self.namespaces?.get(file)?.get(root)?;
        // A lookup key, not prose: built without `format!` so the purity
        // ratchet's engine prose-format count stays flat.
        let mut target = String::with_capacity(module.len() + method.len() + 2);
        target.push_str(module);
        target.push_str("::");
        target.push_str(method);
        self.irs.contains_key(&target).then_some(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::callgraph::{CallGraphBuilder, CallTarget};
    use crate::ir::function::{Instruction, Terminator, VarMetadata};
    use rustc_hash::FxHashMap;

    fn meta(name: &str) -> VarMetadata {
        VarMetadata {
            source_name: Some(name.to_string()),
            type_name: None,
            byte_range: None,
            is_memory_state: false,
            object_keys: Vec::new(),
            declared: false,
        }
    }

    /// `ns.declared()` is program code and `ns.missing()` does not become
    /// `util.ts::missing`: the binding carries the module, so only a member
    /// that module declares resolves through it.
    #[test]
    fn a_binding_resolves_declared_members_only() {
        let mut declared = FunctionIR::new("util.ts::declared".into());
        declared.set_terminator(declared.entry_block, Terminator::Return { src: None });
        let mut stray = FunctionIR::new("missing".into());
        stray.set_terminator(stray.entry_block, Terminator::Return { src: None });

        let mut caller = FunctionIR::new("app.ts::main".into());
        {
            let b = caller.entry_block;
            let ns = caller.new_var(meta("util"));
            for method in ["declared", "missing"] {
                let dest = caller.new_var(meta("r"));
                let mem = caller.new_var(meta("m"));
                caller.push_instruction(
                    b,
                    Instruction::CallVirtual {
                        dest: Some(dest),
                        mem_out: mem,
                        mem_in: caller.initial_memory_state,
                        receiver: Operand::Var(ns),
                        method: method.into(),
                        args: Vec::new(),
                        arg_names: Vec::new(),
                    },
                );
            }
            caller.set_terminator(b, Terminator::Return { src: None });
        }

        let declared: &'static FunctionIR = Box::leak(Box::new(declared));
        let stray: &'static FunctionIR = Box::leak(Box::new(stray));
        let caller: &'static FunctionIR = Box::leak(Box::new(caller));
        let mut irs: FxHashMap<String, &'static FunctionIR> = FxHashMap::default();
        irs.insert("util.ts::declared".into(), declared);
        irs.insert("app.ts::main".into(), caller);
        // A program function that merely shares the member's bare name: the
        // namespace rule must not fall back to it.
        irs.insert("missing".into(), stray);

        let mut fn_file: FxHashMap<String, String> = FxHashMap::default();
        fn_file.insert("app.ts::main".into(), "app.ts".into());
        fn_file.insert("util.ts::declared".into(), "util.ts".into());
        let mut bindings: NamespaceBindings = FxHashMap::default();
        bindings.insert(
            "app.ts".into(),
            [("util".to_string(), "util.ts".to_string())]
                .into_iter()
                .collect(),
        );

        let graph = CallGraphBuilder::new(&irs)
            .with_aliases(None, Some(&fn_file))
            .with_namespace_aliases(Some(&bindings))
            .build();

        let block = caller.entry_block.0;
        assert_eq!(
            graph.targets_at("app.ts::main", block, 0),
            [CallTarget::Function("util.ts::declared".into())],
            "a declared member must resolve into its module"
        );
        assert!(
            !graph
                .targets_at("app.ts::main", block, 1)
                .iter()
                .any(|t| matches!(t, CallTarget::Function(f) if f == "util.ts::missing")),
            "a member the module lacks must not resolve inside it"
        );
    }
}
