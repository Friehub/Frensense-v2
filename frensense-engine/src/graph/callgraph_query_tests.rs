// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Query-surface regressions: what the resolver records for a call site the
//! taint matcher reads afterwards.

#[cfg(test)]
pub(super) mod query_tests {
    use crate::graph::callgraph::CallGraphBuilder;
    use crate::ir::function::*;
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

    fn build_graph(irs: Vec<FunctionIR>) -> FxHashMap<String, &'static FunctionIR> {
        let mut map = FxHashMap::default();
        for ir in irs {
            let leaked: &'static FunctionIR = Box::leak(Box::new(ir));
            map.insert(leaked.name.clone(), leaked);
        }
        map
    }

    /// The taint matcher asks the graph two questions it used to answer from
    /// text: which external symbol a site resolved to, and which functions
    /// dispatch to a symbol. Both are recorded at build time and were read by
    /// nobody.
    #[test]
    fn test_external_name_and_reverse_edge_queries() {
        let mut helper = FunctionIR::new("helper".into());
        {
            let b = helper.entry_block;
            helper.set_terminator(b, Terminator::Return { src: None });
        }

        let mut caller = FunctionIR::new("caller".into());
        {
            let b = caller.entry_block;
            let mem = caller.new_var(meta("mem"));
            caller.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: mem,
                    mem_in: caller.initial_memory_state,
                    func: "helper".into(),
                    args: vec![],
                    arg_names: Vec::new(),
                },
            );
            caller.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: mem,
                    mem_in: caller.initial_memory_state,
                    func: "libraryFetch".into(),
                    args: vec![],
                    arg_names: Vec::new(),
                },
            );
            caller.set_terminator(b, Terminator::Return { src: None });
        }

        let irs = build_graph(vec![helper, caller]);
        let cg = CallGraphBuilder::new(&irs).build();
        let block = irs["caller"].entry_block.0;

        // The site with no program target records the callee the resolver
        // picked; a program-local site records none.
        assert_eq!(cg.external_name("caller", block, 1), Some("libraryFetch"));
        assert_eq!(cg.external_name("caller", block, 0), None);

        // Reverse edges answer "who references this symbol" as a lookup.
        assert_eq!(cg.callers_of("helper").len(), 1);
        assert_eq!(cg.callers_of("helper")[0], "caller");
        assert!(cg.callers_of("libraryFetch").is_empty());
        // The external site contributes no internal edge in either direction.
        assert!(cg.edges.get("caller").is_some_and(|v| v.len() == 1));
    }
}
