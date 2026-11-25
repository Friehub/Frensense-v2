// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Dispatch resolution must not read a file qualifier as a class (#193).
//!
//! Lowered names are file-qualified (`app.ts::main`). Deriving the enclosing
//! class from such a name fabricated a class `app`, which made every call on
//! an unknown receiver take the "class known" arm and fall back to binding by
//! bare method name - the fabricated interprocedural edge the
//! unknown-receiver arm refuses to make.

#[cfg(test)]
pub(super) mod tests {
    use crate::graph::callgraph::{CallGraphBuilder, CallTarget};
    use crate::ir::function::*;
    use rustc_hash::FxHashMap;

    fn dummy_meta(name: &str) -> VarMetadata {
        VarMetadata {
            source_name: Some(name.to_string()),
            type_name: None,
            byte_range: None,
            is_memory_state: false,
            object_keys: Vec::new(),
            declared: false,
        }
    }

    fn build_graph(irs: Vec<FunctionIR>) -> FxHashMap<String, &'static FunctionIR> {
        let mut map = FxHashMap::default();
        for ir in irs {
            let leaked: &'static FunctionIR = Box::leak(Box::new(ir));
            map.insert(leaked.name.clone(), leaked);
        }
        map
    }

    /// One `CallVirtual` on a receiver whose class cannot be resolved.
    fn caller_with_unknown_receiver(name: &str, method: &str) -> FunctionIR {
        let mut caller = FunctionIR::new(name.into());
        let b = caller.entry_block;
        let client = caller.new_var(dummy_meta("client"));
        let r = caller.new_var(dummy_meta("r"));
        let mem = caller.new_var(dummy_meta("m"));
        caller.push_instruction(
            b,
            Instruction::CallVirtual {
                dest: Some(r),
                mem_out: mem,
                mem_in: caller.initial_memory_state,
                receiver: Operand::Var(client),
                method: method.into(),
                args: vec![],
                arg_names: Vec::new(),
            },
        );
        caller.set_terminator(b, Terminator::Return { src: None });
        caller
    }

    /// `app.ts::main` is a top-level function in a file whose name has a dot.
    /// `client.missing()` must stay external instead of binding to the
    /// unrelated program function `missing`.
    #[test]
    fn a_file_qualified_caller_does_not_bind_by_bare_name() {
        let mut missing = FunctionIR::new("missing".into());
        {
            let b = missing.entry_block;
            missing.set_terminator(b, Terminator::Return { src: None });
        }

        let irs = build_graph(vec![
            missing,
            caller_with_unknown_receiver("app.ts::main", "missing"),
        ]);
        let cg = CallGraphBuilder::new(&irs).build();

        let block = irs["app.ts::main"].entry_block.0;
        let sites = cg.targets_at("app.ts::main", block, 0);
        assert!(
            sites.is_empty(),
            "a file-qualified enclosing name must not fabricate a class, so the\n\
             unknown receiver cannot bind the unrelated `missing` function; got {:?}",
            sites
        );
        assert_eq!(
            cg.unresolved
                .get(&("app.ts::main".to_string(), (block, 0)))
                .map(String::as_str),
            Some("missing"),
            "the site must be recorded as an unresolved external call"
        );
    }

    /// The positive control: a genuine `Class.method` enclosing name still
    /// resolves a `this`-style call to that class's own method.
    #[test]
    fn a_qualified_method_caller_still_binds_its_own_method() {
        let mut check = FunctionIR::new("User.check".into());
        {
            let b = check.entry_block;
            check.set_terminator(b, Terminator::Return { src: None });
        }

        let irs = build_graph(vec![
            check,
            caller_with_unknown_receiver("User.save", "check"),
        ]);
        let cg = CallGraphBuilder::new(&irs).build();

        let sites = cg.targets_at("User.save", irs["User.save"].entry_block.0, 0);
        assert!(
            sites.contains(&CallTarget::Method {
                class: "User".into(),
                method: "check".into(),
            }),
            "`this` inside `User.save` must still reach `User.check`; got {:?}",
            sites
        );
    }
}
