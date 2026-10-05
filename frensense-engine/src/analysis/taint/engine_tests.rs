// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the demand-driven backward taint engine (task 4.4).

#[cfg(test)]
pub mod demand_tests {
    use crate::analysis::forward::ProgramSvfg;
    use crate::analysis::taint::config::TaintConfig;
    use crate::analysis::taint::engine::{BackwardTaintEngine, BackwardVerdict};
    use crate::analysis::taint::facts::FactTable;
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

    fn mem_meta(name: &str) -> VarMetadata {
        VarMetadata {
            source_name: Some(name.to_string()),
            type_name: None,
            byte_range: None,
            is_memory_state: true,
            object_keys: Vec::new(),
            declared: false,
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

    /// [`run_backward`] with the path-traversal denylist pattern explicitly
    /// attached: denylist-guard vocabulary is spec/bundle-owned now, and a
    /// hand-built test program has no spec to seed it from.
    fn run_backward_with_denylist(cfg: &TaintConfig, prog: &ProgramSvfg) -> RunOut {
        let mut facts = FactTable::default();
        crate::analysis::taint::facts::LearnedFactEntry::GuardDenylistPattern {
            pattern: "..".into(),
        }
        .apply(&mut facts);
        let mut engine = BackwardTaintEngine::new(prog, cfg).with_fact_table(&facts);
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
        assert!(
            vulns[0]
                .alert
                .as_ref()
                .is_some_and(|a| a.function == "helper")
        );

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
        use crate::analysis::forward::{InterproceduralTaintEngine, SinkAlert};

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
        let bwd_alerts: Vec<SinkAlert> = bwd.iter().filter_map(|f| f.alert.clone()).collect();

        assert_eq!(fwd.alerts.len(), 1);
        assert_eq!(bwd_alerts.len(), 1);
        // Same alert (sink, slot, function, class) from both directions.
        assert!(fwd.alerts[0].sink == "db.execute");
        assert!(bwd_alerts[0].sink == "db.execute");
        assert_eq!(fwd.alerts[0], bwd_alerts[0]);
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
        let (findings, _stats) = run_backward_with_denylist(&cfg, &prog);

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
        let (findings, _stats) = run_backward_with_denylist(&cfg, &prog);

        assert!(
            findings
                .iter()
                .any(|f| f.verdict == BackwardVerdict::Vulnerable),
            "sink on flawed branch of denylist guard must stay Vulnerable, got {:?}",
            findings
        );
    }
    // -----------------------------------------------------------------------
    // Branch feasibility: `bar = "safe" if const_true else param` - the
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

    // -----------------------------------------------------------------------
    // Test: RegExp.test guard sanitizes taint flow before sink
    // -----------------------------------------------------------------------
    #[test]
    fn test_regex_test_guard_sanitizes_flow() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "search.ts".to_string(),
            r#"
const INDEX_NAME_RE = /^[a-zA-Z0-9_]{1,64}$/;

export function handleSearch(c: any) {
  const index = c.req.query("index");
  if (!INDEX_NAME_RE.test(index)) {
    return c.json({ error: "invalid" }, 400);
  }
  const db = c.env.friehub_db;
  return db.prepare("SELECT * FROM " + index).all();
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vulns.is_empty(),
            "guarded flow via RegExp.test must be sanitized, got: {:?}",
            vulns
        );
    }

    // -----------------------------------------------------------------------
    // Test: DB prepare receiver is suppressed (only argument is checked)
    // -----------------------------------------------------------------------
    #[test]
    fn test_db_prepare_receiver_suppression() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "query.ts".to_string(),
            r#"
export function handleDb(c: any) {
  const db = c.env.friehub_db;
  return db.prepare("SELECT 1 FROM users WHERE id = ?").bind(1).all();
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vulns.is_empty(),
            "parameterized db.prepare must not alert on receiver or binding channel, got: {:?}",
            vulns
        );
    }

    // -----------------------------------------------------------------------
    // Test: Context c.set(...) does not alert as a prototype pollution sink
    // -----------------------------------------------------------------------
    #[test]
    fn test_context_set_not_flagged_as_sink() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "middleware.ts".to_string(),
            r#"
export function middleware(c: any) {
  const rid = c.req.header("X-Request-Id");
  c.set("requestId", rid);
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let set_findings: Vec<_> = result.findings.iter().filter(|f| f.sink == "set").collect();
        assert!(
            set_findings.is_empty(),
            "c.set must not be treated as a sink, got: {:?}",
            set_findings
        );
    }

    // -----------------------------------------------------------------------
    // FP class: bare multer/IO names ("file") in the source vocabulary made
    // ANY parameter or phi named `file` a taint source, so plain helpers
    // like `validateFile(file)` / `retrieveCustomFile(...)` alerted on every
    // readFile/exec use. Request-param names (req, input, ...) keep their
    // sentinel semantics; dotted patterns (req.file) keep theirs.
    // -----------------------------------------------------------------------
    #[test]
    fn test_plain_file_param_is_not_a_source() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "validate.ts".to_string(),
            r#"
export function run (file: string) {
  require('fs').readFile(file)
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vulns.is_empty(),
            "a plain parameter named `file` must not be a taint source, got: {:?}",
            vulns
        );
    }

    #[test]
    fn test_request_param_is_still_a_source() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "handler.ts".to_string(),
            r#"
export function run (req: any) {
  require('fs').readFile(req.body.path)
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(!vulns.is_empty(), "req.body must remain a taint source");
    }

    // -----------------------------------------------------------------------
    // Per-slot sink signatures (lang vocabulary): only the view name of
    // res.render(view, locals) is template-executed - tainted locals data is
    // not SSTI, tainted view names are.
    // -----------------------------------------------------------------------
    #[test]
    fn test_render_locals_argument_not_dangerous() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "render.ts".to_string(),
            r#"
export function render (req: any, res: any) {
  res.render('view', req.body)
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vulns.is_empty(),
            "tainted locals data in res.render(view, locals) must not alert, got: {:?}",
            vulns
        );
    }

    #[test]
    fn test_render_view_name_argument_dangerous() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "render.ts".to_string(),
            r#"
export function render (req: any, res: any) {
  res.render(req.body.theme, {})
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            !vulns.is_empty(),
            "a tainted view name in res.render(view, locals) must alert"
        );
    }

    // -----------------------------------------------------------------------
    // writeFile(path, buffer): PathTraversal labels the path slot - a
    // tainted upload buffer written to a fixed path is not traversal.
    // -----------------------------------------------------------------------
    #[test]
    fn test_write_file_content_argument_not_dangerous() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "upload.ts".to_string(),
            r#"
export function save (req: any) {
  require('fs').writeFile('/tmp/out', req.body.content)
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vulns.is_empty(),
            "tainted buffer content in writeFile(path, buffer) must not alert, got: {:?}",
            vulns
        );
    }

    #[test]
    fn test_write_file_path_argument_dangerous() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "upload.ts".to_string(),
            r#"
export function save (req: any) {
  require('fs').writeFile(req.body.path, 'x')
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            !vulns.is_empty(),
            "a tainted path in writeFile(path, buffer) must alert"
        );
    }

    // -----------------------------------------------------------------------
    // Object-destructured handler params (const { query } / ({ query })) stay
    // live sources via the bare "query"/"params"/... patterns - the
    // routes/redirect.ts handler shape depends on it.
    // -----------------------------------------------------------------------
    #[test]
    fn test_destructured_query_root_still_a_source() {
        let mut config = TaintConfig::default();
        let mut facts = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = crate::analysis::taint::facts::config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            facts.merge(&crate::analysis::taint::facts::fact_table_from_spec(spec));
        }

        let files = vec![(
            "redirect.ts".to_string(),
            r#"
export const redirect = ({ query }: any, res: any) => {
  const toUrl = query.to
  res.redirect(toUrl)
}
"#
            .to_string(),
            "ts".to_string(),
        )];

        let result = crate::scan::scan(&files, &config, &facts);
        let vulns: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            !vulns.is_empty(),
            "a destructure-rooted query.to flow must remain a source"
        );
    }

    // -----------------------------------------------------------------------
    // Regression: a shared heap-store source use is first visited with the
    // guard's *safe* arm as context (guard-stop fires, node never expands),
    // and the later visit with the *unsafe* arm context - the one that leads
    // to the source - must not be deduplicated away.
    //
    //   b0:    bar = request.form.get("p")        // source
    //          obj = {}
    //          obj.data = bar                     // store: shared use(bar) node
    //          cond = bar == "ok"                 // guard: safe arm = true arm
    //          branch cond ? armSafe : armOther
    //   armSafe:  v1 = obj.data                   // heap edge → shared use
    //   armOther: v2 = obj.data                   // heap edge → shared use
    //   merge:    v = phi(v1, v2); open(v)
    //
    // Backward: phi → v1 def (ctx=merge) expands first (lower block id) and
    // pushes use(bar)@store with ctx=armSafe → guard-stop on pop. The v2-def
    // expansion then tries to push the *same* node with ctx=armOther; that
    // context is the unguarded path through which the source must be found.
    // -----------------------------------------------------------------------
    #[test]
    fn test_guard_stop_on_shared_store_does_not_hide_unguarded_path() {
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

            // obj = {} - clean allocation root for the load bases.
            let obj = handler.new_var(dummy_meta("obj"));
            let ma = handler.new_var(mem_meta("ma"));
            handler.push_instruction(
                b0,
                Instruction::Allocate {
                    dest: obj,
                    mem_out: ma,
                    mem_in: mem0,
                    kind: AllocationKind::Object,
                },
            );

            // obj.data = bar - the shared store whose src-use node feeds
            // both arm loads via heap edges.
            let ms = handler.new_var(mem_meta("ms"));
            handler.push_instruction(
                b0,
                Instruction::StoreField {
                    mem_out: ms,
                    mem_in: ma,
                    base: obj,
                    field: "data".into(),
                    src: Operand::Var(bar),
                },
            );

            // cond = bar == "ok" - non-denylist comparison: the true arm
            // is the guard's safe block.
            let cond = handler.new_var(dummy_meta("cond"));
            handler.push_instruction(
                b0,
                Instruction::BinaryOp {
                    dest: cond,
                    op: "==".into(),
                    lhs: Operand::Var(bar),
                    rhs: Operand::StringLiteral("\"ok\"".into()),
                },
            );

            // Safe arm created first → lower block id → its phi incoming
            // sorts first, so the guard-stopped context wins the shared node.
            let arm_safe = handler.new_block();
            let arm_other = handler.new_block();
            let merge = handler.new_block();
            handler.set_terminator(
                b0,
                Terminator::Branch {
                    cond: Operand::Var(cond),
                    true_block: arm_safe,
                    false_block: arm_other,
                },
            );
            handler.add_edge(b0, arm_safe);
            handler.add_edge(b0, arm_other);

            let v1 = handler.new_var(dummy_meta("v1"));
            handler.push_instruction(
                arm_safe,
                Instruction::LoadField {
                    dest: v1,
                    mem_in: ms,
                    base: obj,
                    field: "data".into(),
                },
            );
            handler.set_terminator(arm_safe, Terminator::Jump(merge));
            handler.add_edge(arm_safe, merge);

            let v2 = handler.new_var(dummy_meta("v2"));
            handler.push_instruction(
                arm_other,
                Instruction::LoadField {
                    dest: v2,
                    mem_in: ms,
                    base: obj,
                    field: "data".into(),
                },
            );
            handler.set_terminator(arm_other, Terminator::Jump(merge));
            handler.add_edge(arm_other, merge);

            let v = handler.new_var(dummy_meta("v"));
            handler.push_phi(
                merge,
                Phi {
                    dest: v,
                    incoming: vec![(arm_safe, v1), (arm_other, v2)],
                },
            );
            let m2 = handler.new_var(mem_meta("m2"));
            handler.push_instruction(
                merge,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: ms,
                    func: "open".into(),
                    args: vec![Operand::Var(v)],
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
            "unguarded heap path through the store must reach the source \
             even when the safe-arm context guard-stopped the shared node, \
             got {:?}",
            findings
        );
    }

    // -----------------------------------------------------------------------
    // Phase 3: boolean-producing comparisons are not taint channels.
    //
    //   fn main() { t = getSource(); flag = (t == "admin"); db.execute(flag); }
    //
    // `flag` is a BOOLEAN: its printable payload is "true"/"false", which
    // carries no attacker bytes to the sink. The generic intra-instruction
    // operand→dest edge manufactures a source→sink path that cannot exist
    // at runtime, and the value lattice cannot see it (a comparison of a
    // tainted operand folds to `Top`).
    // -----------------------------------------------------------------------
    #[test]
    fn comparison_dest_is_not_a_taint_channel() {
        let cfg = TaintConfig {
            sources: ["getSource".to_string()].into_iter().collect(),
            sinks: ["db.execute".to_string()].into_iter().collect(),
            sanitizers: Default::default(),
        };

        // fn main() { t = getSource(); flag = (t == "admin"); db.execute(flag); }
        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let t = main.new_var(dummy_meta("t"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(t),
                    mem_out: m1,
                    mem_in: main.initial_memory_state,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            let flag = main.new_var(dummy_meta("flag"));
            main.push_instruction(
                b,
                Instruction::BinaryOp {
                    dest: flag,
                    op: "==".into(),
                    lhs: Operand::Var(t),
                    rhs: Operand::StringLiteral("admin".to_string()),
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
                    args: vec![Operand::Var(flag)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let mut statics = rustc_hash::FxHashMap::default();
        let leaked: &'static FunctionIR = Box::leak(Box::new(main));
        statics.insert(leaked.name.clone(), leaked);
        let prog = ProgramSvfg::new(&statics, &cfg);
        let mut engine = BackwardTaintEngine::new(&prog, &cfg);
        engine.run();
        assert_eq!(engine.findings.len(), 1, "the sink must be explored");
        assert_ne!(
            engine.findings[0].verdict,
            BackwardVerdict::Vulnerable,
            "a boolean comparison result must not transport taint to a sink, \
             got {:?}",
            engine.findings[0].verdict
        );
        assert_eq!(
            engine.stats.nodes_visited, 2,
            "walk stops at the comparison def with its operand edges cut \
             (root + def), visited: {}",
            engine.stats.nodes_visited
        );
    }

    /// Phase-3 guard: value-returning operators keep their operand edges -
    /// string concatenation and `||` both yield the operand's payload, so
    /// source flows through them must stay Vulnerable.
    #[test]
    fn value_returning_operators_keep_their_edges() {
        let cfg = TaintConfig {
            sources: ["getSource".to_string()].into_iter().collect(),
            sinks: ["db.execute".to_string()].into_iter().collect(),
            sanitizers: Default::default(),
        };

        // fn main() {
        //   t = getSource();
        //   y = t + "lit";  db.execute(y);   // concat carries the payload
        //   x = t || "alt"; db.execute(x);   // || yields t when truthy
        // }
        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let t = main.new_var(dummy_meta("t"));
            let m1 = main.new_var(mem_meta("m1"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: Some(t),
                    mem_out: m1,
                    mem_in: main.initial_memory_state,
                    func: "getSource".into(),
                    args: vec![],
                },
            );
            let y = main.new_var(dummy_meta("y"));
            main.push_instruction(
                b,
                Instruction::BinaryOp {
                    dest: y,
                    op: "+".into(),
                    lhs: Operand::Var(t),
                    rhs: Operand::StringLiteral("lit".to_string()),
                },
            );
            let x = main.new_var(dummy_meta("x"));
            main.push_instruction(
                b,
                Instruction::BinaryOp {
                    dest: x,
                    op: "||".into(),
                    lhs: Operand::Var(t),
                    rhs: Operand::StringLiteral("alt".to_string()),
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
                    args: vec![Operand::Var(y), Operand::Var(x)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let mut statics = rustc_hash::FxHashMap::default();
        let leaked: &'static FunctionIR = Box::leak(Box::new(main));
        statics.insert(leaked.name.clone(), leaked);
        let prog = ProgramSvfg::new(&statics, &cfg);
        let mut engine = BackwardTaintEngine::new(&prog, &cfg);
        engine.run();
        let vulnerable = engine
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .count();
        assert_eq!(
            vulnerable,
            2,
            "concat and || operands must both keep reaching the source, got {:?}",
            engine
                .findings
                .iter()
                .map(|f| (&f.sink, f.arg_slot, &f.verdict))
                .collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // Phase 4: object/array literals lower to allocation + field stores.
    // -----------------------------------------------------------------------

    /// Field-sensitive reads: taint in one property must not pollute reads
    /// of another property of the same literal, while the tainted property
    /// and the whole container must still reach the source.
    #[test]
    fn object_literal_fields_are_read_separately() {
        let src = r#"
declare const db: any
declare const req: any
export function run () {
  const o = { clean: "literal", q: req.body.x }
  db.execute(o.clean)
  db.execute(o.q)
  db.execute(o)
}
"#;
        let cfg = TaintConfig {
            sources: ["req.body".to_string()].into_iter().collect(),
            sinks: ["execute".to_string()].into_iter().collect(),
            sanitizers: Default::default(),
        };
        let fns = crate::harness::lower_source("t.ts", src, "ts").expect("lower");
        let mut statics = rustc_hash::FxHashMap::default();
        for (name, ir) in fns {
            let leaked: &'static FunctionIR = Box::leak(Box::new(ir));
            statics.insert(name, leaked);
        }
        let prog = ProgramSvfg::new(&statics, &cfg);
        let mut engine = BackwardTaintEngine::new(&prog, &cfg);
        engine.run();
        let verdicts: Vec<BackwardVerdict> = engine
            .findings
            .iter()
            .filter(|f| f.arg_slot != usize::MAX)
            .map(|f| f.verdict.clone())
            .collect();
        assert_eq!(
            verdicts.len(),
            3,
            "all three sink calls must be explored: {verdicts:?}"
        );
        assert_ne!(
            verdicts[0],
            BackwardVerdict::Vulnerable,
            "o.clean is a literal field - must not transport taint: {verdicts:?}"
        );
        assert_eq!(
            verdicts[1],
            BackwardVerdict::Vulnerable,
            "o.q carries the source - must stay Vulnerable: {verdicts:?}"
        );
        assert_eq!(
            verdicts[2],
            BackwardVerdict::Vulnerable,
            "the whole container must still see its stored source: {verdicts:?}"
        );
    }

    /// Array literals allocate too: a tainted element must reach the source
    /// through the element store.
    #[test]
    fn array_literal_element_reaches_the_source() {
        let src = r#"
declare const db: any
declare const req: any
export function run () {
  const a = [req.body.x, "lit"]
  db.execute(a[0])
}
"#;
        let cfg = TaintConfig {
            sources: ["req.body".to_string()].into_iter().collect(),
            sinks: ["execute".to_string()].into_iter().collect(),
            sanitizers: Default::default(),
        };
        let fns = crate::harness::lower_source("t.ts", src, "ts").expect("lower");
        let mut statics = rustc_hash::FxHashMap::default();
        for (name, ir) in fns {
            let leaked: &'static FunctionIR = Box::leak(Box::new(ir));
            statics.insert(name, leaked);
        }
        let prog = ProgramSvfg::new(&statics, &cfg);
        let mut engine = BackwardTaintEngine::new(&prog, &cfg);
        engine.run();
        let args: Vec<_> = engine
            .findings
            .iter()
            .filter(|f| f.arg_slot != usize::MAX)
            .collect();
        assert_eq!(args.len(), 1, "one argument-slot finding expected");
        assert_eq!(
            args[0].verdict,
            BackwardVerdict::Vulnerable,
            "tainted array element must reach the source"
        );
    }

    /// Spread objects keep the legacy union lowering (conservative):
    /// `{...req.body, safe}` must still taint reads through the container.
    #[test]
    fn spread_object_keeps_union_lowering() {
        let src = r#"
declare const db: any
declare const req: any
export function run () {
  const o = { ...req.body, safe: "lit" }
  db.execute(o.safe)
}
"#;
        let cfg = TaintConfig {
            sources: ["req.body".to_string()].into_iter().collect(),
            sinks: ["execute".to_string()].into_iter().collect(),
            sanitizers: Default::default(),
        };
        let fns = crate::harness::lower_source("t.ts", src, "ts").expect("lower");
        let mut statics = rustc_hash::FxHashMap::default();
        for (name, ir) in fns {
            let leaked: &'static FunctionIR = Box::leak(Box::new(ir));
            statics.insert(name, leaked);
        }
        let prog = ProgramSvfg::new(&statics, &cfg);
        let mut engine = BackwardTaintEngine::new(&prog, &cfg);
        engine.run();
        let args: Vec<_> = engine
            .findings
            .iter()
            .filter(|f| f.arg_slot != usize::MAX)
            .collect();
        assert_eq!(args.len(), 1, "one argument-slot finding expected");
        assert_eq!(
            args[0].verdict,
            BackwardVerdict::Vulnerable,
            "spread union stays conservative (tainted container taints reads)"
        );
    }

    // -----------------------------------------------------------------------
    // Phase 5: k=1 call-site context at FormalParam crossings.
    // -----------------------------------------------------------------------

    /// Two call sites of the same callee: the clean caller must not absorb
    /// the tainted caller's argument through the shared FormalParam node.
    #[test]
    fn call_site_context_separates_sibling_callers() {
        let src = r#"
function sanitize(x: any): any { return x }
export function a(req: any): void {
  sink(sanitize(req.body.x))
}
export function b(id: any): void {
  sink(sanitize(id))
}
"#;
        let cfg = TaintConfig {
            sources: ["req.body".to_string()].into_iter().collect(),
            sinks: ["sink".to_string()].into_iter().collect(),
            sanitizers: Default::default(),
        };
        let fns = crate::harness::lower_source("t.ts", src, "ts").expect("lower");
        let mut statics = rustc_hash::FxHashMap::default();
        for (name, ir) in fns {
            let leaked: &'static FunctionIR = Box::leak(Box::new(ir));
            statics.insert(name, leaked);
        }
        let prog = ProgramSvfg::new(&statics, &cfg);
        let mut engine = BackwardTaintEngine::new(&prog, &cfg);
        engine.run();

        let a_finding = engine
            .findings
            .iter()
            .find(|f| f.function == "a")
            .expect("sink in a is explored");
        let b_finding = engine
            .findings
            .iter()
            .find(|f| f.function == "b")
            .expect("sink in b is explored");
        assert_eq!(
            a_finding.verdict,
            BackwardVerdict::Vulnerable,
            "the tainted caller must stay Vulnerable: {:?}",
            a_finding
        );
        assert_ne!(
            b_finding.verdict,
            BackwardVerdict::Vulnerable,
            "the clean caller must not inherit the sibling caller's taint \
             through the shared callee: {:?}",
            b_finding
        );
    }

    // -----------------------------------------------------------------------
    // Engine purity: EVERY fact-declared sink is explored and reported when
    // tainted data reaches it, regardless of role. Response/Validation sinks
    // (`res.json`, `jwt.decode`) rank at `info` in advisory severity - that
    // ranking is lang-declared policy applied at report time, never an
    // analysis gate (a gate would let low-ranked built-in roles veto any
    // bundler-learned knowledge about the same sink).
    //
    //   fn main() {
    //     v = getSource();
    //     res.json(v);      // role=Response  -> explored, reported
    //     jwt.decode(v);    // role=Validation -> explored, reported
    //     db.execute(v);    // role=Other      -> reported
    //   }
    // -----------------------------------------------------------------------
    #[test]
    fn all_role_sinks_are_explored_and_reported() {
        use crate::analysis::taint::facts::SinkSignature;
        use crate::analysis::taint::role::SinkRole;

        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let mem0 = main.initial_memory_state;
            let v = main.new_var(dummy_meta("v"));
            let res = main.new_var(dummy_meta("res"));
            let jwt = main.new_var(dummy_meta("jwt"));
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
                Instruction::CallVirtual {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    method: "json".into(),
                    receiver: Operand::Var(res),
                    args: vec![Operand::Var(v)],
                },
            );
            let m3 = main.new_var(mem_meta("m3"));
            main.push_instruction(
                b,
                Instruction::CallVirtual {
                    dest: None,
                    mem_out: m3,
                    mem_in: m2,
                    method: "decode".into(),
                    receiver: Operand::Var(jwt),
                    args: vec![Operand::Var(v)],
                },
            );
            let m4 = main.new_var(mem_meta("m4"));
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m4,
                    mem_in: m3,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(v)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let cfg = config();
        let prog = build_program(vec![main]);
        let mut facts = FactTable::from_config(&cfg);
        for (name, role) in [
            ("json", SinkRole::Response),
            ("decode", SinkRole::Validation),
        ] {
            let mut sig = SinkSignature::all_args(name);
            sig.role = role;
            facts.sink_signatures.insert(name.to_string(), sig);
        }
        let mut engine = BackwardTaintEngine::new(&prog, &cfg).with_fact_table(&facts);
        engine.run();

        let reported: Vec<_> = engine.findings.iter().collect();
        for (sink, role) in [
            ("json", SinkRole::Response),
            ("decode", SinkRole::Validation),
            ("db.execute", SinkRole::Other),
        ] {
            let f = reported
                .iter()
                .find(|f| f.sink == sink && f.verdict == BackwardVerdict::Vulnerable)
                .unwrap_or_else(|| {
                    panic!("{sink} must yield a Vulnerable finding; got {reported:?}")
                });
            assert_eq!(f.role, role, "role must survive into the finding: {f:?}");
        }
        // Every slot of every fact-declared sink is explored: json (receiver
        // + arg) + decode (receiver + arg) + db.execute (arg).
        assert_eq!(
            engine.stats.sink_args_explored, 5,
            "role must never gate exploration: {:?}",
            engine.stats
        );
    }
}
