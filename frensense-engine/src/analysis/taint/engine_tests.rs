// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the demand-driven backward taint engine (task 4.4).

#[cfg(test)]
pub mod demand_tests {
    use crate::analysis::forward::ProgramSvfg;
    use crate::analysis::taint::config::TaintConfig;
    use crate::analysis::taint::engine::{BackwardTaintEngine, BackwardVerdict};
    use crate::ir::function::*;
    use rustc_hash::FxHashMap;

    fn dummy_meta(name: &str) -> VarMetadata {
        VarMetadata {
            source_name: Some(name.to_string()),
            type_name: None,
            byte_range: None,
            is_memory_state: false,
            object_keys: Vec::new(),
        }
    }

    fn mem_meta(name: &str) -> VarMetadata {
        VarMetadata {
            source_name: Some(name.to_string()),
            type_name: None,
            byte_range: None,
            is_memory_state: true,
            object_keys: Vec::new(),
        }
    }

    fn config() -> TaintConfig {
        TaintConfig {
            sources: ["getSource".to_string()].into_iter().collect(),
            sinks: ["db.execute".to_string()].into_iter().collect(),
            sanitizers: ["escapeHtml".to_string()].into_iter().collect(),
        }
    }

    /// Create a variable, register it as a formal parameter, and return it.
    fn add_param(ir: &mut FunctionIR, name: &str) -> VarId {
        let v = ir.new_var(dummy_meta(name));
        ir.parameters.push(v);
        v
    }

    fn build_program(irs: Vec<FunctionIR>) -> ProgramSvfg<'static> {
        let map: FxHashMap<String, &'static FunctionIR> = irs
            .into_iter()
            .map(|ir| {
                let leaked: &'static FunctionIR = Box::leak(Box::new(ir));
                (leaked.name.clone(), leaked)
            })
            .collect();
        ProgramSvfg::new(&map, &config())
    }

    type RunOut = (
        Vec<crate::analysis::taint::engine::SinkFinding>,
        crate::analysis::taint::engine::BackwardStats,
    );

    fn run_backward(cfg: &TaintConfig, prog: &ProgramSvfg) -> RunOut {
        let mut engine = BackwardTaintEngine::new(prog, cfg);
        engine.run();
        (engine.findings, engine.stats)
    }

    // -----------------------------------------------------------------------
    // Test 1: backward walk through cross edges finds the source, a
    // sink in a leaf function whose taint comes from a caller.
    //
    //   fn main() { v = getSource(); helper(v); }
    //   fn helper(p) { db.execute(p); }
    //
    // Seeding at helper's sink and walking backward must cross
    // formal-param → actual-arg and reach getSource.
    // -----------------------------------------------------------------------
    #[test]
    fn test_backward_finds_source_through_arg_edge() {
        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let v = main.new_var(dummy_meta("v"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            let m2 = main.new_var(mem_meta("m2"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "helper".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let mut helper = FunctionIR::new("helper".into());
        let p0 = add_param(&mut helper, "p");
        {
            let b = helper.entry_block;
            let mem0 = helper.initial_memory_state;
            let m1 = helper.new_var(mem_meta("m1"));
            helper.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m1,
                    mem_in: mem0,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(p0)],
                },
            );
            helper.set_terminator(b, Terminator::Return { src: None });
        }

        let cfg = config();
        let prog = build_program(vec![main, helper]);
        let (findings, stats) = run_backward(&cfg, &prog);

        let vulns: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert_eq!(
            vulns.len(),
            1,
            "expected 1 vulnerable sink arg; got {:?}",
            findings
        );
        assert_eq!(vulns[0].function, "helper");
        assert_eq!(vulns[0].sink, "db.execute");
        assert!(vulns[0].alert.as_deref().unwrap().contains("[in helper]"));

        // Demand-driven cost: helper must be visited, main must be entered
        // only via the backward walk from its own sink... main has no sink,
        // so total functions visited should be small (helper only).
        assert!(
            stats.sink_args_explored >= 1,
            "at least one sink arg explored"
        );
    }

    // -----------------------------------------------------------------------
    // Test 2: backward through a return edge.
    //
    //   fn get() { return getSource(); }
    //   fn main() { v = get(); db.execute(v); }
    //
    // Walking back from main's sink must cross actual-ret → formal-ret.
    // -----------------------------------------------------------------------
    #[test]
    fn test_backward_finds_source_through_ret_edge() {
        let mut get = FunctionIR::new("get".into());
        {
            let b = get.entry_block;
            let mem0 = get.initial_memory_state;
            let v = get.new_var(dummy_meta("v"));
            let m1 = get.new_var(mem_meta("m1"));
            get.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            get.set_terminator(
                b,
                Terminator::Return {
                    src: Some(Operand::Var(v)),
                },
            );
        }

        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let v = main.new_var(dummy_meta("v"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "get".into(),
                    args: vec![],
                },
            );
            let m2 = main.new_var(mem_meta("m2"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let cfg = config();
        let prog = build_program(vec![get, main]);
        let (findings, _stats) = run_backward(&cfg, &prog);

        let vulns: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert_eq!(vulns.len(), 1, "expected 1 vulnerable; got {:?}", findings);
        assert_eq!(vulns[0].function, "main");
    }

    // -----------------------------------------------------------------------
    // Test 3: sanitizer-cut path → Sanitized, not Vulnerable.
    //
    //   fn main() { v = getSource(); w = escapeHtml(v); db.execute(w); }
    // -----------------------------------------------------------------------
    #[test]
    fn test_backward_sanitized_path() {
        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let v = main.new_var(dummy_meta("v"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            let w = main.new_var(dummy_meta("w"));
            let m2 = main.new_var(mem_meta("m2"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(w),
                    mem_out: m2,
                    mem_in: m1,
                    func: "escapeHtml".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            let m3 = main.new_var(mem_meta("m3"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m3,
                    mem_in: m2,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(w)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let cfg = config();
        let prog = build_program(vec![main]);
        let (findings, _stats) = run_backward(&cfg, &prog);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].verdict,
            BackwardVerdict::Sanitized,
            "sanitizer-cut path must be Sanitized; got {:?}",
            findings
        );
        assert!(findings[0].alert.is_none());
    }

    // -----------------------------------------------------------------------
    // Test 4: pure-literal argument → Clean.
    //
    //   fn main() { db.execute("SELECT 1"); }
    // -----------------------------------------------------------------------
    #[test]
    fn test_backward_clean_literal() {
        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m1,
                    mem_in: mem0,
                    func: "db.execute".into(),
                    args: vec![Operand::StringLiteral("SELECT 1".into())],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let cfg = config();
        let prog = build_program(vec![main]);
        let (findings, stats) = run_backward(&cfg, &prog);

        // Literal args are not Var operands → nothing to explore.
        assert_eq!(stats.sink_args_explored, 0);
        assert!(findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test 5: unresolvable param → Unknown (callee never analysed).
    //
    //   fn main() { v = LoadGlobal("input"); db.execute(v); }, no source,
    //   and the value comes from an external/unresolvable root.
    // -----------------------------------------------------------------------
    #[test]
    fn test_backward_unknown_root() {
        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let v = main.new_var(dummy_meta("v"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::LoadGlobal {
                    dest: v,
                    mem_in: mem0,
                    name: "userInput".into(),
                },
            );
            let m2 = main.new_var(mem_meta("m2"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let cfg = config();
        let prog = build_program(vec![main]);
        let (findings, _stats) = run_backward(&cfg, &prog);

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].verdict,
            BackwardVerdict::Unknown,
            "externally-defined value must classify as Unknown; got {:?}",
            findings
        );
    }

    // -----------------------------------------------------------------------
    // Test 6: demand-driven cost model, functions NOT on any sink's backward
    // path are never visited. 10 functions; only main/helper touch the sink;
    // the 8 noise functions contain sources but no sinks.
    // -----------------------------------------------------------------------
    #[test]
    fn test_demand_driven_visits_only_relevant_functions() {
        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let v = main.new_var(dummy_meta("v"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            let m2 = main.new_var(mem_meta("m2"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "helper".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let mut helper = FunctionIR::new("helper".into());
        let p0 = add_param(&mut helper, "p");
        {
            let b = helper.entry_block;
            let mem0 = helper.initial_memory_state;
            let m1 = helper.new_var(mem_meta("m1"));
            helper.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m1,
                    mem_in: mem0,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(p0)],
                },
            );
            helper.set_terminator(b, Terminator::Return { src: None });
        }

        let mut irs = vec![main, helper];
        for i in 0..8 {
            let mut noise = FunctionIR::new(format!("noise_{}", i));
            let b = noise.entry_block;
            let mem0 = noise.initial_memory_state;
            let v = noise.new_var(dummy_meta("n"));
            let m1 = noise.new_var(mem_meta("m1"));
            // Sources everywhere, forward engines seed and traverse these;
            // the demand-driven engine must never touch them.
            noise.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            noise.set_terminator(b, Terminator::Return { src: None });
            irs.push(noise);
        }

        let cfg = config();
        let prog = build_program(irs);
        let (findings, stats) = run_backward(&cfg, &prog);

        assert_eq!(prog.functions.len(), 10);
        // Vulnerable path found despite noise.
        let vulns: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert_eq!(vulns.len(), 1);

        // Backward exploration touched at most main+helper, never the noise.
        assert!(
            stats.functions_visited <= 2,
            "demand-driven exploration must skip noise functions; visited {}",
            stats.functions_visited
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: default mode honours summary suppression, so a sanitizing
    // callee produces Sanitized, matching the forward engine. The opt-out
    // over-approximating mode (`without_suppression`) leaks through the local
    // pass-through edge and reports Vulnerable, documenting the difference.
    //
    //   fn clean(x) { return escapeHtml(x); }
    //   fn main() { v = getSource(); w = clean(v); db.execute(w); }
    // -----------------------------------------------------------------------
    #[test]
    fn test_backward_matches_forward_on_sanitizing_callee() {
        let mut clean = FunctionIR::new("clean".into());
        let x0 = add_param(&mut clean, "x");
        {
            let b = clean.entry_block;
            let mem0 = clean.initial_memory_state;
            let r = clean.new_var(dummy_meta("r"));
            let m1 = clean.new_var(mem_meta("m1"));
            clean.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(r),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "escapeHtml".into(),
                    args: vec![Operand::Var(x0)],
                },
            );
            clean.set_terminator(
                b,
                Terminator::Return {
                    src: Some(Operand::Var(r)),
                },
            );
        }

        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let v = main.new_var(dummy_meta("v"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            let w = main.new_var(dummy_meta("w"));
            let m2 = main.new_var(mem_meta("m2"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(w),
                    mem_out: m2,
                    mem_in: m1,
                    func: "clean".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            let m3 = main.new_var(mem_meta("m3"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m3,
                    mem_in: m2,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(w)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let cfg = config();
        let prog = build_program(vec![clean, main]);

        // Default mode: suppression honoured → Sanitized, no alert.
        let (f1, _) = run_backward(&cfg, &prog);
        assert_eq!(f1.len(), 1, "one sink arg explored; got {:?}", f1);
        assert!(
            f1.iter().all(|f| f.alert.is_none()),
            "no alert in default mode; got {:?}",
            f1
        );
        assert_eq!(
            f1[0].verdict,
            BackwardVerdict::Sanitized,
            "default (suppression-honouring) mode must classify as Sanitized; got {:?}",
            f1
        );

        // Over-approximating mode: leaks past the sanitizer via the local
        // pass-through edge → Vulnerable. Documented unsound-by-nature mode.
        let mut e2 = BackwardTaintEngine::new(&prog, &cfg).without_suppression();
        e2.run();
        assert_eq!(
            e2.findings[0].verdict,
            BackwardVerdict::Vulnerable,
            "over-approximating mode leaks past the sanitizing callee; got {:?}",
            e2.findings
        );
    }

    // -----------------------------------------------------------------------
    // Test 8: backward agrees with forward on a plain vulnerable chain.
    // -----------------------------------------------------------------------
    #[test]
    fn test_backward_agrees_with_forward() {
        use crate::analysis::forward::InterproceduralTaintEngine;

        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let v = main.new_var(dummy_meta("v"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            let m2 = main.new_var(mem_meta("m2"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let prog = build_program(vec![main]);

        // Forward.
        let cfg = config();
        let mut fwd = InterproceduralTaintEngine::new(&prog, &cfg);
        fwd.run();

        // Backward.
        let cfg = config();
        let (bwd, _stats) = run_backward(&cfg, &prog);
        let bwd_alerts: Vec<String> = bwd.iter().filter_map(|f| f.alert.clone()).collect();

        assert_eq!(fwd.alerts.len(), 1);
        assert_eq!(bwd_alerts.len(), 1);
        // Same alert text modulo the message wording (both mention the sink).
        assert!(fwd.alerts[0].contains("db.execute"));
        assert!(bwd_alerts[0].contains("db.execute"));
    }

    // -----------------------------------------------------------------------
    // Learned dotted source fact on a module-qualified CallVirtual.
    //
    //   fn main() { v = random.randint(0, 10); eval(v); }
    //
    // `random.randint` lowers as CallVirtual (receiver `random`, method
    // `randint`), NOT CallStatic, so a bare-method-name match misses it.
    // The dotted source fact (`random.randint`) must resolve via the
    // receiver root. Without the fact, the path is Unknown/Clean.
    // -----------------------------------------------------------------------
    #[test]
    fn test_backward_learned_module_qualified_source() {
        use crate::analysis::taint::facts::{LearnedFactEntry, fact_table_from_entries};

        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let random_mod = main.new_var(dummy_meta("random"));
            let v = main.new_var(dummy_meta("v"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallVirtual {
                    dest: Some(v),
                    mem_out: m1,
                    mem_in: mem0,
                    method: "randint".into(),
                    receiver: Operand::Var(random_mod),
                    args: vec![Operand::IntLiteral(0), Operand::IntLiteral(10)],
                },
            );
            let m2 = main.new_var(mem_meta("m2"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "eval".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let prog = build_program(vec![main]);
        let cfg = TaintConfig {
            sources: [].into_iter().collect(),
            sinks: ["eval".to_string()].into_iter().collect(),
            sanitizers: [].into_iter().collect(),
        };

        // No learned facts: no source, so the walk bottoms out Unknown →
        // not reported as a Vulnerable advisory.
        let empty = crate::analysis::taint::facts::FactTable::default();
        let mut engine = BackwardTaintEngine::new(&prog, &cfg).with_fact_table(&empty);
        engine.run();
        assert!(
            engine
                .findings
                .iter()
                .all(|f| f.verdict != BackwardVerdict::Vulnerable),
            "no learned source fact → no Vulnerable finding, got {:?}",
            engine.findings
        );

        // With the dotted learned Source fact, the flow is Vulnerable.
        let facts = fact_table_from_entries(&[LearnedFactEntry::Source {
            pattern: "random.randint".into(),
        }]);
        let mut cfg2 = cfg.clone();
        cfg2.sources.extend(facts.learned_sources.iter().cloned());
        let mut engine2 = BackwardTaintEngine::new(&prog, &cfg2).with_fact_table(&facts);
        engine2.run();
        assert_eq!(engine2.findings.len(), 1, "learned source fact must fire");
        assert_eq!(engine2.findings[0].verdict, BackwardVerdict::Vulnerable);
    }

    // -----------------------------------------------------------------------
    // Guard quality: containment guard on a tainted var cuts the path.
    //
    //   fn handler(request) {
    //     bar = request.form.get("p");
    //     if "../" in bar { return; }
    //     open(bar);            // sink, guarded
    //   }
    //
    // The containment test is a *sibling use* of `bar`: the backward walk
    // never passes through it, so the GuardMap must register it
    // structurally (cond BinaryOp with a literal sibling). The guard block
    // dominates the sink block, so the flow is Sanitized, not Vulnerable.
    // -----------------------------------------------------------------------
    #[test]
    fn test_containment_guard_cuts_path() {
        let mut handler = FunctionIR::new("handler".into());
        {
            let b0 = handler.entry_block;
            let mem0 = handler.initial_memory_state;

            // bar = request.form.get("p")
            let req = handler.new_var(dummy_meta("request"));
            let form = handler.new_var(dummy_meta("request.form"));
            handler.push_instruction(
                b0,
                Instruction::LoadField {
                    dest: form,
                    mem_in: mem0,
                    base: req,
                    field: "form".into(),
                },
            );
            let got = handler.new_var(dummy_meta("got"));
            let m1 = handler.new_var(mem_meta("m1"));
            handler.push_instruction(
                b0,
                Instruction::CallVirtual {
                    dest: Some(got),
                    mem_out: m1,
                    mem_in: mem0,
                    method: "get".into(),
                    receiver: Operand::Var(form),
                    args: vec![Operand::StringLiteral("\"p\"".into())],
                },
            );
            let bar = handler.new_var(dummy_meta("bar"));
            handler.push_instruction(
                b0,
                Instruction::Assign {
                    dest: bar,
                    src: Operand::Var(got),
                },
            );
            // cond = "../" in bar
            let cond = handler.new_var(dummy_meta("cond"));
            handler.push_instruction(
                b0,
                Instruction::BinaryOp {
                    dest: cond,
                    op: "in".into(),
                    lhs: Operand::StringLiteral("\"../\"".into()),
                    rhs: Operand::Var(bar),
                },
            );

            let guarded = handler.new_block();
            let merge = handler.new_block();
            handler.set_terminator(
                b0,
                Terminator::Branch {
                    cond: Operand::Var(cond),
                    true_block: guarded,
                    false_block: merge,
                },
            );
            handler.add_edge(b0, guarded);
            handler.add_edge(b0, merge);

            // sink in merge: open(bar)
            let m2 = handler.new_var(mem_meta("m2"));
            handler.push_instruction(
                merge,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "open".into(),
                    args: vec![Operand::Var(bar)],
                },
            );
            handler.set_terminator(merge, Terminator::Return { src: None });
        }

        let cfg = TaintConfig {
            sources: [
                "request.form.get".to_string(),
                "request.form".to_string(),
                "request".to_string(),
            ]
            .into_iter()
            .collect(),
            sinks: ["open".to_string()].into_iter().collect(),
            sanitizers: [].into_iter().collect(),
        };
        let prog = build_program(vec![handler]);
        let (findings, _stats) = run_backward(&cfg, &prog);

        let vulns: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vulns.is_empty(),
            "containment-guarded flow must not be Vulnerable, got {:?}",
            findings
        );
    }

    // -----------------------------------------------------------------------
    // Same flow WITHOUT the guard: Vulnerable (the guard is what makes the
    // difference, proving the test above isn't vacuous).
    // -----------------------------------------------------------------------
    #[test]
    fn test_unguarded_flow_still_vulnerable() {
        let mut handler = FunctionIR::new("handler".into());
        {
            let b0 = handler.entry_block;
            let mem0 = handler.initial_memory_state;
            let req = handler.new_var(dummy_meta("request"));
            let form = handler.new_var(dummy_meta("request.form"));
            handler.push_instruction(
                b0,
                Instruction::LoadField {
                    dest: form,
                    mem_in: mem0,
                    base: req,
                    field: "form".into(),
                },
            );
            let got = handler.new_var(dummy_meta("got"));
            let m1 = handler.new_var(mem_meta("m1"));
            handler.push_instruction(
                b0,
                Instruction::CallVirtual {
                    dest: Some(got),
                    mem_out: m1,
                    mem_in: mem0,
                    method: "get".into(),
                    receiver: Operand::Var(form),
                    args: vec![Operand::StringLiteral("\"p\"".into())],
                },
            );
            let bar = handler.new_var(dummy_meta("bar"));
            handler.push_instruction(
                b0,
                Instruction::Assign {
                    dest: bar,
                    src: Operand::Var(got),
                },
            );
            let merge = handler.new_block();
            handler.set_terminator(b0, Terminator::Jump(merge));
            handler.add_edge(b0, merge);

            let m2 = handler.new_var(mem_meta("m2"));
            handler.push_instruction(
                merge,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "open".into(),
                    args: vec![Operand::Var(bar)],
                },
            );
            handler.set_terminator(merge, Terminator::Return { src: None });
        }

        let cfg = TaintConfig {
            sources: [
                "request.form.get".to_string(),
                "request.form".to_string(),
                "request".to_string(),
            ]
            .into_iter()
            .collect(),
            sinks: ["open".to_string()].into_iter().collect(),
            sanitizers: [].into_iter().collect(),
        };
        let prog = build_program(vec![handler]);
        let (findings, _stats) = run_backward(&cfg, &prog);

        assert!(
            findings
                .iter()
                .any(|f| f.verdict == BackwardVerdict::Vulnerable),
            "unguarded flow must stay Vulnerable, got {:?}",
            findings
        );
    }

    #[test]
    fn test_containment_guard_on_wrong_branch_still_vulnerable() {
        let mut handler = FunctionIR::new("handler".into());
        {
            let b0 = handler.entry_block;
            let mem0 = handler.initial_memory_state;

            let req = handler.new_var(dummy_meta("request"));
            let form = handler.new_var(dummy_meta("request.form"));
            handler.push_instruction(
                b0,
                Instruction::LoadField {
                    dest: form,
                    mem_in: mem0,
                    base: req,
                    field: "form".into(),
                },
            );
            let got = handler.new_var(dummy_meta("got"));
            let m1 = handler.new_var(mem_meta("m1"));
            handler.push_instruction(
                b0,
                Instruction::CallVirtual {
                    dest: Some(got),
                    mem_out: m1,
                    mem_in: mem0,
                    method: "get".into(),
                    receiver: Operand::Var(form),
                    args: vec![Operand::StringLiteral("\"p\"".into())],
                },
            );
            let bar = handler.new_var(dummy_meta("bar"));
            handler.push_instruction(
                b0,
                Instruction::Assign {
                    dest: bar,
                    src: Operand::Var(got),
                },
            );
            let cond = handler.new_var(dummy_meta("cond"));
            handler.push_instruction(
                b0,
                Instruction::BinaryOp {
                    dest: cond,
                    op: "in".into(),
                    lhs: Operand::StringLiteral("\"../\"".into()),
                    rhs: Operand::Var(bar),
                },
            );

            let flawed_sink_block = handler.new_block();
            let safe_exit = handler.new_block();
            // Call is on the TRUE arm of ("../" in bar), so it is vulnerable!
            handler.set_terminator(
                b0,
                Terminator::Branch {
                    cond: Operand::Var(cond),
                    true_block: flawed_sink_block,
                    false_block: safe_exit,
                },
            );
            handler.add_edge(b0, flawed_sink_block);
            handler.add_edge(b0, safe_exit);

            let m2 = handler.new_var(mem_meta("m2"));
            handler.push_instruction(
                flawed_sink_block,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "open".into(),
                    args: vec![Operand::Var(bar)],
                },
            );
            handler.set_terminator(flawed_sink_block, Terminator::Return { src: None });
            handler.set_terminator(safe_exit, Terminator::Return { src: None });
        }

        let cfg = TaintConfig {
            sources: [
                "request.form.get".to_string(),
                "request.form".to_string(),
                "request".to_string(),
            ]
            .into_iter()
            .collect(),
            sinks: ["open".to_string()].into_iter().collect(),
            sanitizers: [].into_iter().collect(),
        };
        let prog = build_program(vec![handler]);
        let (findings, _stats) = run_backward(&cfg, &prog);

        assert!(
            findings
                .iter()
                .any(|f| f.verdict == BackwardVerdict::Vulnerable),
            "sink on flawed branch of denylist guard must stay Vulnerable, got {:?}",
            findings
        );
    }
    // -----------------------------------------------------------------------
    // Branch feasibility: `bar = "safe" if const_true else param` — the
    // tainted else arm is dead, so the flow through the phi is not
    // Vulnerable.
    //
    //   b0: bar_src = get(...); c1 = 7 * 18; c2 = c1 + 106 (as concat);
    //       c3 = c2 > 200; branch c3 ? b1 : b2
    //   b1: t = "safe"; jump merge
    //   b2: e = bar_src; jump merge
    //   merge: phi bar = phi(t@b1, e@b2); open(bar)
    // -----------------------------------------------------------------------
    #[test]
    fn test_const_true_ternary_prunes_tainted_arm() {
        let mut handler = FunctionIR::new("handler".into());
        {
            let b0 = handler.entry_block;
            let mem0 = handler.initial_memory_state;

            let req = handler.new_var(dummy_meta("request"));
            let cookies = handler.new_var(dummy_meta("request.cookies"));
            handler.push_instruction(
                b0,
                Instruction::LoadField {
                    dest: cookies,
                    mem_in: mem0,
                    base: req,
                    field: "cookies".into(),
                },
            );
            let got = handler.new_var(dummy_meta("got"));
            let m1 = handler.new_var(mem_meta("m1"));
            handler.push_instruction(
                b0,
                Instruction::CallVirtual {
                    dest: Some(got),
                    mem_out: m1,
                    mem_in: mem0,
                    method: "get".into(),
                    receiver: Operand::Var(cookies),
                    args: vec![Operand::StringLiteral("\"p\"".into())],
                },
            );

            // c1 = 7 * 18; c2 = c1 + 106; c3 = c2 > 200 (all constants).
            let c1 = handler.new_var(dummy_meta("c1"));
            handler.push_instruction(
                b0,
                Instruction::BinaryOp {
                    dest: c1,
                    op: "*".into(),
                    lhs: Operand::IntLiteral(7),
                    rhs: Operand::IntLiteral(18),
                },
            );
            let c2 = handler.new_var(dummy_meta("c2"));
            handler.push_instruction(
                b0,
                Instruction::BinaryOp {
                    dest: c2,
                    op: "concat".into(),
                    lhs: Operand::Var(c1),
                    rhs: Operand::IntLiteral(106),
                },
            );
            let c3 = handler.new_var(dummy_meta("c3"));
            handler.push_instruction(
                b0,
                Instruction::BinaryOp {
                    dest: c3,
                    op: ">".into(),
                    lhs: Operand::Var(c2),
                    rhs: Operand::IntLiteral(200),
                },
            );

            let then_b = handler.new_block();
            let else_b = handler.new_block();
            let merge = handler.new_block();
            handler.set_terminator(
                b0,
                Terminator::Branch {
                    cond: Operand::Var(c3),
                    true_block: then_b,
                    false_block: else_b,
                },
            );
            handler.add_edge(b0, then_b);
            handler.add_edge(b0, else_b);

            // then arm: t = "safe" (constant)
            let t = handler.new_var(dummy_meta("t"));
            handler.push_instruction(
                then_b,
                Instruction::Assign {
                    dest: t,
                    src: Operand::StringLiteral("safe".into()),
                },
            );
            handler.set_terminator(then_b, Terminator::Jump(merge));
            handler.add_edge(then_b, merge);

            // else arm: e = tainted param
            let e = handler.new_var(dummy_meta("e"));
            handler.push_instruction(
                else_b,
                Instruction::Assign {
                    dest: e,
                    src: Operand::Var(got),
                },
            );
            handler.set_terminator(else_b, Terminator::Jump(merge));
            handler.add_edge(else_b, merge);

            // merge: phi bar = phi(t@then, e@else); open(bar)
            let bar = handler.new_var(dummy_meta("bar"));
            handler.push_phi(
                merge,
                Phi {
                    dest: bar,
                    incoming: vec![(then_b, t), (else_b, e)],
                },
            );
            let m2 = handler.new_var(mem_meta("m2"));
            handler.push_instruction(
                merge,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "open".into(),
                    args: vec![Operand::Var(bar)],
                },
            );
            handler.set_terminator(merge, Terminator::Return { src: None });
        }

        let cfg = TaintConfig {
            sources: [
                "request.cookies.get".to_string(),
                "request.cookies".to_string(),
                "request".to_string(),
            ]
            .into_iter()
            .collect(),
            sinks: ["open".to_string()].into_iter().collect(),
            sanitizers: [].into_iter().collect(),
        };
        let prog = build_program(vec![handler]);
        let (findings, _stats) = run_backward(&cfg, &prog);
        let vulns: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vulns.is_empty(),
            "const-true ternary must prune the tainted else arm, got {:?}",
            findings
        );
    }

    // -----------------------------------------------------------------------
    // Same shape but the condition is NOT decidable: both arms stay live
    // and the tainted arm must still be reported (recall guard).
    // -----------------------------------------------------------------------
    #[test]
    fn test_undecided_ternary_keeps_tainted_arm() {
        let mut handler = FunctionIR::new("handler".into());
        {
            let b0 = handler.entry_block;
            let mem0 = handler.initial_memory_state;

            let req = handler.new_var(dummy_meta("request"));
            let cookies = handler.new_var(dummy_meta("request.cookies"));
            handler.push_instruction(
                b0,
                Instruction::LoadField {
                    dest: cookies,
                    mem_in: mem0,
                    base: req,
                    field: "cookies".into(),
                },
            );
            let got = handler.new_var(dummy_meta("got"));
            let m1 = handler.new_var(mem_meta("m1"));
            handler.push_instruction(
                b0,
                Instruction::CallVirtual {
                    dest: Some(got),
                    mem_out: m1,
                    mem_in: mem0,
                    method: "get".into(),
                    receiver: Operand::Var(cookies),
                    args: vec![Operand::StringLiteral("\"p\"".into())],
                },
            );

            // cond = got.length-ish? Use a NON-constant comparison:
            // cond = (unknown_var > 200) where unknown_var has no def.
            let unknown = handler.new_var(dummy_meta("unknown"));
            let cond = handler.new_var(dummy_meta("cond"));
            handler.push_instruction(
                b0,
                Instruction::BinaryOp {
                    dest: cond,
                    op: ">".into(),
                    lhs: Operand::Var(unknown),
                    rhs: Operand::IntLiteral(200),
                },
            );

            let then_b = handler.new_block();
            let else_b = handler.new_block();
            let merge = handler.new_block();
            handler.set_terminator(
                b0,
                Terminator::Branch {
                    cond: Operand::Var(cond),
                    true_block: then_b,
                    false_block: else_b,
                },
            );
            handler.add_edge(b0, then_b);
            handler.add_edge(b0, else_b);

            let t = handler.new_var(dummy_meta("t"));
            handler.push_instruction(
                then_b,
                Instruction::Assign {
                    dest: t,
                    src: Operand::StringLiteral("safe".into()),
                },
            );
            handler.set_terminator(then_b, Terminator::Jump(merge));
            handler.add_edge(then_b, merge);

            let e = handler.new_var(dummy_meta("e"));
            handler.push_instruction(
                else_b,
                Instruction::Assign {
                    dest: e,
                    src: Operand::Var(got),
                },
            );
            handler.set_terminator(else_b, Terminator::Jump(merge));
            handler.add_edge(else_b, merge);

            let bar = handler.new_var(dummy_meta("bar"));
            handler.push_phi(
                merge,
                Phi {
                    dest: bar,
                    incoming: vec![(then_b, t), (else_b, e)],
                },
            );
            let m2 = handler.new_var(mem_meta("m2"));
            handler.push_instruction(
                merge,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "open".into(),
                    args: vec![Operand::Var(bar)],
                },
            );
            handler.set_terminator(merge, Terminator::Return { src: None });
        }

        let cfg = TaintConfig {
            sources: [
                "request.cookies.get".to_string(),
                "request.cookies".to_string(),
                "request".to_string(),
            ]
            .into_iter()
            .collect(),
            sinks: ["open".to_string()].into_iter().collect(),
            sanitizers: [].into_iter().collect(),
        };
        let prog = build_program(vec![handler]);
        let (findings, _stats) = run_backward(&cfg, &prog);
        assert!(
            findings
                .iter()
                .any(|f| f.verdict == BackwardVerdict::Vulnerable),
            "undecided ternary must keep the tainted arm live, got {:?}",
            findings
        );
    }
}
