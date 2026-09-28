// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the constant/interval value lattice (`analysis::value`), its
//! checker consumers (weak key size, constant selectors through vars), and
//! the taint engine's Clean-verdict promotion for provable constants.

#[cfg(test)]
pub mod value_spec {
    use crate::analysis::value::{Value, analyze};
    use crate::harness::lower_source;

    fn var_of<'a>(
        info: &'a crate::analysis::value::ValueInfo,
        ir: &'a crate::ir::function::FunctionIR,
        name: &str,
    ) -> crate::ir::function::VarId {
        // Metadata can carry duplicate names (a let re-declaration lowers to
        // a second var with the same source_name); prefer a var the lattice
        // actually has a non-Top value for, else the last one (defs run
        // forward, the last is the newest binding).
        let candidates: Vec<_> = ir
            .var_metadata
            .iter()
            .filter(|(_, m)| m.source_name.as_deref() == Some(name))
            .map(|(v, _)| *v)
            .collect();
        candidates
            .iter()
            .copied()
            .find(|v| info.values.contains_key(v))
            .or_else(|| candidates.last().copied())
            .unwrap_or_else(|| panic!("var {name} not found"))
    }

    /// The newest binding of `name` (last metadata entry): for loop-carried
    /// or branch-merged vars the initial binding is also a live const, so
    /// name lookup must not stop at the first candidate.
    fn last_var(ir: &crate::ir::function::FunctionIR, name: &str) -> crate::ir::function::VarId {
        ir.var_metadata
            .iter()
            .filter(|(_, m)| m.source_name.as_deref() == Some(name))
            .map(|(v, _)| *v)
            .max_by_key(|v| v.0)
            .unwrap_or_else(|| panic!("var {name} not found"))
    }

    fn ir_of(src: &str) -> crate::ir::function::FunctionIR {
        let fns = lower_source("t.ts", src, "ts").unwrap();
        // Prefer the test's own function `f`; some lowerings emit helpers.
        fns.into_values()
            .find(|ir| ir.name == "f")
            .unwrap_or_else(|| panic!("function f not lowered"))
    }

    #[test]
    fn literal_assignment_is_int_const() {
        let src = r#"
export function f () {
  const n = 42
  return n
}
"#;
        let ir = ir_of(src);
        let info = analyze(&ir);
        let n = var_of(&info, &ir, "n");
        assert_eq!(info.const_int(n), Some(42));
    }

    #[test]
    fn constant_folding_through_arithmetic() {
        // a = 2, b = a * 3 + 4 => b = 10 (interval arithmetic converges to
        // a point here; the point is reported as an IntConst).
        let src = r#"
export function f () {
  const a = 2
  const b = a * 3 + 4
  return b
}
"#;
        let ir = ir_of(src);
        let info = analyze(&ir);
        let b = var_of(&info, &ir, "b");
        assert_eq!(
            info.const_int(b),
            Some(10),
            "a*3+4 with a=2 must fold to 10"
        );
    }

    #[test]
    fn string_constants_propagate_through_assignment() {
        let src = r#"
export function f () {
  const alg = 'none'
  return alg
}
"#;
        let ir = ir_of(src);
        let info = analyze(&ir);
        let alg = var_of(&info, &ir, "alg");
        // The TS lowering keeps raw quote chars in string literals; consumers
        // strip them (weak_hash::strip_quotes). The lattice preserves the raw form.
        assert_eq!(info.const_str(alg), Some("'none'"));
    }

    #[test]
    fn non_constant_input_yields_top() {
        // A function parameter is never a provable constant.
        let src = r#"
export function f (p: number) {
  const a = p * 2
  return a
}
"#;
        let ir = ir_of(src);
        let info = analyze(&ir);
        let a = var_of(&info, &ir, "a");
        assert_eq!(info.const_int(a), None, "parameter-derived values stay Top");
    }

    #[test]
    fn join_at_branch_widens_to_range() {
        // Both arms assign constants; the phi at the merge joins to a range.
        // b = x<0 ? 1 : 9  →  b ∈ {1,9}; our phi join reports the hull or
        // Top depending on lowering shape, but must NEVER claim a wrong
        // single constant.
        let src = r#"
export function f (x: number) {
  let b = 0
  if (x < 0) {
    b = 1
  } else {
    b = 9
  }
  return b
}
"#;
        let ir = ir_of(src);
        let info = analyze(&ir);
        // `b` is rebound in both arms; the lattice's view of the FINAL
        // binding is the phi result (newest metadata entry).
        let b = last_var(&ir, "b");
        if let Some((lo, hi)) = info.range(b) {
            assert!(
                lo <= 1 && 9 <= hi,
                "interval must contain both arms: {lo}..{hi}"
            );
            assert!(
                lo >= 1 && hi <= 9,
                "interval must not exceed both arms: {lo}..{hi}"
            );
        } // Top is also sound here
        assert_ne!(
            info.const_int(b),
            Some(0),
            "0 is the pre-branch value, not b's value"
        );
    }

    /// The lattice join must be monotone-safe on loops (no crash, no bogus
    /// constants): the induction variable stays Top.
    #[test]
    fn loop_induction_var_stays_top() {
        let src = r#"
export function f (n: number) {
  let s = 0
  for (let i = 0; i < n; i++) {
    s = s + i
  }
  return s
}
"#;
        let ir = ir_of(src);
        let info = analyze(&ir);
        let s = last_var(&ir, "s");
        assert_eq!(
            info.const_int(s),
            None,
            "loop accumulator must not fold to its initial value"
        );
    }

    /// Checker consumer 1: weak key size through a constant var.
    #[test]
    fn weak_key_size_through_const_var_fires() {
        use crate::checks::weak_hash;
        let src = r#"
export function makeKey () {
  const bits = 512
  return generateKeyPair(bits)
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = crate::analysis::taint::facts::FactTable::default();
        let hits: Vec<_> = fns.values().flat_map(|ir| weak_hash::check(ir, &facts)).collect();
        assert_eq!(hits.len(), 1, "512-bit key must fire: {:?}", hits);
        assert_eq!(hits[0].rule, "weak_rsa_key_size");
    }

    #[test]
    fn strong_key_size_stays_silent() {
        use crate::checks::weak_hash;
        let src = r#"
export function makeKey () {
  const bits = 4096
  return generateKeyPair(bits)
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = crate::analysis::taint::facts::FactTable::default();
        let hits: Vec<_> = fns.values().flat_map(|ir| weak_hash::check(ir, &facts)).collect();
        assert!(hits.is_empty(), "4096-bit key is fine: {:?}", hits);
    }

    #[test]
    fn non_constant_key_size_stays_silent() {
        use crate::checks::weak_hash;
        let src = r#"
export function makeKey (bits: number) {
  return generateKeyPair(bits)
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = crate::analysis::taint::facts::FactTable::default();
        let hits: Vec<_> = fns.values().flat_map(|ir| weak_hash::check(ir, &facts)).collect();
        assert!(
            hits.is_empty(),
            "unknown size must stay silent (soundness): {:?}",
            hits
        );
    }

    /// Checker consumer 2: selector literal through a constant var.
    /// (`const alg = 'none'; jwtSign(payload, secret, alg)` — the checker
    /// matches callee last segments, so the call must carry the jwt prefix
    /// itself; `jwt.sign` lowers to last segment `sign` and is invisible to
    /// this rule until receiver-chain matching lands.)
    #[test]
    fn jwt_none_selector_through_const_var_fires() {
        use crate::checks::weak_hash;
        let src = r#"
export function signToken (payload: string, secret: string) {
  const alg = 'none'
  return jwtSign(payload, secret, alg)
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let facts = crate::analysis::taint::facts::FactTable::default();
        let hits: Vec<_> = fns.values().flat_map(|ir| weak_hash::check(ir, &facts)).collect();
        assert!(
            hits.iter().any(|h| h.rule == "insecure_jwt_algorithm"),
            "jwt 'none' via const var must fire: {:?}",
            hits.iter().map(|h| &h.rule).collect::<Vec<_>>()
        );
    }

    /// Taint consumer: a sink argument whose entire backward chain is
    /// constant is promoted to Clean, not Vulnerable. The ts config's
    /// request_param_names make parameters named like `req` sources, but a
    /// value that never flows from them stays clean. Direct check: a sink
    /// fed ONLY a string literal must have verdict Clean (the walk dead-ends
    /// at a constant root, no source reachable).
    #[test]
    fn constant_sink_argument_is_not_vulnerable() {
        use crate::analysis::taint::{
            engine::BackwardVerdict,
            facts::{config_from_spec, fact_table_from_spec},
        };
        use crate::scan::{prepare, scan_prepared};

        let src = r#"
declare const pool: any
export function runQuery () {
  const safe = 'SELECT 1'
  return pool.query(safe)
}
"#;
        let files = vec![("t.ts".to_string(), src.to_string(), "ts".to_string())];
        let spec = frensense_lang::spec_for_ext("ts").unwrap();
        let config = config_from_spec(spec);
        let facts = fact_table_from_spec(spec);
        let prepared = prepare(&files).unwrap();
        let result = scan_prepared(&prepared, &config, &facts);
        assert!(
            result
                .findings
                .iter()
                .all(|f| f.verdict != BackwardVerdict::Vulnerable),
            "constant-fed sink must not be vulnerable: {:?}",
            result
                .findings
                .iter()
                .map(|f| (&f.sink, &f.verdict))
                .collect::<Vec<_>>()
        );
    }

    /// The engine promotion path: a source-named variable holding a provable
    /// constant must NOT create a Vulnerable verdict. Built at the IR level
    /// with a config where `getSource` is a source, then a constant assigned
    /// over it — the lattice proves the value, the walk promotes to Clean.
    #[test]
    fn const_source_promotion_keeps_real_sources_vulnerable() {
        use crate::analysis::taint::config::TaintConfig;
        use crate::analysis::taint::engine::BackwardTaintEngine;
        use crate::ir::function::*;

        let cfg = TaintConfig {
            sources: ["getSource".to_string()].into_iter().collect(),
            sinks: ["db.execute".to_string()].into_iter().collect(),
            sanitizers: Default::default(),
        };
        let dummy = |ir: &mut FunctionIR, name: &str| {
            ir.new_var(VarMetadata {
                source_name: Some(name.to_string()),
                type_name: None,
                byte_range: None,
                is_memory_state: false,
                object_keys: Vec::new(),
            })
        };
        let mem = |ir: &mut FunctionIR, name: &str| {
            ir.new_var(VarMetadata {
                source_name: Some(name.to_string()),
                type_name: None,
                byte_range: None,
                is_memory_state: true,
                object_keys: Vec::new(),
            })
        };

        // fn main() { t = getSource(); a = "safe"; db.execute(a); }
        // The walk from db.execute's arg reaches `a` whose def is a literal:
        // Clean without ever exploring toward `t`.
        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let t = dummy(&mut main, "t");
            let m1 = mem(&mut main, "m1");
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
            let a = dummy(&mut main, "a");
            main.push_instruction(
                b,
                Instruction::Assign {
                    dest: a,
                    src: Operand::StringLiteral("safe".to_string()),
                },
            );
            let m2 = mem(&mut main, "m2");
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(a)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let mut statics = rustc_hash::FxHashMap::default();
        let leaked: &'static FunctionIR = Box::leak(Box::new(main));
        statics.insert(leaked.name.clone(), leaked);
        let prog = crate::analysis::forward::ProgramSvfg::new(&statics, &cfg);
        let mut engine = BackwardTaintEngine::new(&prog, &cfg);
        engine.run();
        assert!(
            engine
                .findings
                .iter()
                .all(|f| f.verdict != crate::analysis::taint::engine::BackwardVerdict::Vulnerable),
            "constant-fed sink must stay non-vulnerable: {:?}",
            engine
                .findings
                .iter()
                .map(|f| &f.verdict)
                .collect::<Vec<_>>()
        );
    }

    /// Soundness guard: a REAL source (call-shaped) must still be
    /// Vulnerable — the promotion only fires on provable constants.
    #[test]
    fn real_source_still_vulnerable_after_promotion_wiring() {
        use crate::analysis::taint::config::TaintConfig;
        use crate::analysis::taint::engine::{BackwardTaintEngine, BackwardVerdict};
        use crate::ir::function::*;

        let cfg = TaintConfig {
            sources: ["getSource".to_string()].into_iter().collect(),
            sinks: ["db.execute".to_string()].into_iter().collect(),
            sanitizers: Default::default(),
        };
        let dummy = |ir: &mut FunctionIR, name: &str| {
            ir.new_var(VarMetadata {
                source_name: Some(name.to_string()),
                type_name: None,
                byte_range: None,
                is_memory_state: false,
                object_keys: Vec::new(),
            })
        };
        let mem = |ir: &mut FunctionIR, name: &str| {
            ir.new_var(VarMetadata {
                source_name: Some(name.to_string()),
                type_name: None,
                byte_range: None,
                is_memory_state: true,
                object_keys: Vec::new(),
            })
        };

        let mut main = FunctionIR::new("main".into());
        {
            let b = main.entry_block;
            let t = dummy(&mut main, "t");
            let m1 = mem(&mut main, "m1");
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
            let m2 = mem(&mut main, "m2");
            main.push_instruction(
                b,
                Instruction::CallStatic {
                    dest: None,
                    mem_out: m2,
                    mem_in: m1,
                    func: "db.execute".into(),
                    args: vec![Operand::Var(t)],
                },
            );
            main.set_terminator(b, Terminator::Return { src: None });
        }

        let mut statics = rustc_hash::FxHashMap::default();
        let leaked: &'static FunctionIR = Box::leak(Box::new(main));
        statics.insert(leaked.name.clone(), leaked);
        let prog = crate::analysis::forward::ProgramSvfg::new(&statics, &cfg);
        let mut engine = BackwardTaintEngine::new(&prog, &cfg);
        engine.run();
        assert!(
            engine
                .findings
                .iter()
                .any(|f| f.verdict == BackwardVerdict::Vulnerable),
            "real source flow must stay Vulnerable: {:?}",
            engine
                .findings
                .iter()
                .map(|f| &f.verdict)
                .collect::<Vec<_>>()
        );
    }

    /// Lattice algebra sanity: join laws.
    #[test]
    fn join_is_idempotent_commutative_absorbing() {
        let a = Value::IntConst(3);
        let b = Value::IntConst(5);
        let r = Value::Range(0, 10);
        let top = Value::Top;
        assert_eq!(a.join(&a), a, "idempotent");
        assert_eq!(a.join(&b), b.join(&a), "commutative");
        assert_eq!(a.join(&top), top, "Top absorbs");
        assert_eq!(a.join(&r), Value::Range(0, 10), "point inside range");
        assert_eq!(
            Value::IntConst(3).join(&Value::Range(3, 3)),
            Value::Range(3, 3)
        );
    }

    /// Branch sharpening: conditional branch narrows integer intervals along true and false arms.
    #[test]
    fn branch_sharpening_narrows_intervals_on_true_and_false_arms() {
        let src = r#"
export function f (x: number) {
  if (x < 10) {
    return 1
  } else {
    return 2
  }
}
"#;
        let ir = ir_of(src);
        let info = analyze(&ir);
        let x = var_of(&info, &ir, "x");

        let entry_blk = ir.blocks.get(&ir.entry_block).unwrap();
        if let crate::ir::function::Terminator::Branch {
            true_block,
            false_block,
            ..
        } = &entry_blk.terminator
        {
            assert_eq!(
                info.range_at(*true_block, x),
                Some((i64::MIN, 9)),
                "x < 10 true block must have upper bound 9"
            );
            assert_eq!(
                info.range_at(*false_block, x),
                Some((10, i64::MAX)),
                "x < 10 false block must have lower bound 10"
            );
        } else {
            panic!("expected entry block terminator to be a Branch");
        }
    }

    /// Branch sharpening: equality check refines to exact constant on true arm.
    #[test]
    fn branch_sharpening_equality_refines_to_exact_constant() {
        let src = r#"
export function f (k: number) {
  if (k === 42) {
    return 100
  }
  return 200
}
"#;
        let ir = ir_of(src);
        let info = analyze(&ir);
        let k = var_of(&info, &ir, "k");

        let entry_blk = ir.blocks.get(&ir.entry_block).unwrap();
        if let crate::ir::function::Terminator::Branch { true_block, .. } = &entry_blk.terminator {
            assert_eq!(
                info.const_int_at(*true_block, k),
                Some(42),
                "k === 42 true branch must narrow to exact constant 42"
            );
        } else {
            panic!("expected entry block terminator to be a Branch");
        }
    }
}

