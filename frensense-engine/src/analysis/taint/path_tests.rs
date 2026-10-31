// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for taint-path capture (R3c).

#[cfg(test)]
mod path_capture_tests {
    use crate::analysis::forward::ProgramSvfg;
    use crate::analysis::taint::config::TaintConfig;
    use crate::analysis::taint::engine::{BackwardTaintEngine, BackwardVerdict};
    use crate::analysis::taint::path::{PathStep, dedup_by_shape};
    use crate::harness::lower_source;
    use crate::ir::function::FunctionIR;
    use rustc_hash::FxHashMap;

    const CROSS_FILE: &str = r#"
import { Pool } from "pg";
const pool = new Pool();

function buildQuery(id: string): string {
  return "SELECT * FROM users WHERE id = '" + id + "'";
}

function handler(req: any): void {
  const q = buildQuery(req.body.id);
  pool.query(q);
}
"#;

    fn run(src: &str) -> Vec<super::super::engine::SinkFinding> {
        let fns = lower_source("t.ts", src, "ts").expect("lower");
        let owned: Vec<FunctionIR> = fns.into_values().collect();
        let mut statics: FxHashMap<String, &FunctionIR> = FxHashMap::default();
        for ir in &owned {
            statics.insert(ir.name.clone(), ir);
        }
        let mut config = TaintConfig::default();
        config.sinks.insert("query".into());
        config.sources.insert("req.body".into());
        config.sources.insert("req".into());
        let prog = ProgramSvfg::new(&statics, &config);
        let mut engine = BackwardTaintEngine::new(&prog, &config);
        engine.run();
        engine.findings
    }

    #[test]
    fn interprocedural_path_source_to_sink() {
        let findings = run(CROSS_FILE);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(!vuln.is_empty(), "probe must produce a vulnerable finding");

        let p = &vuln[0].path;
        // First step describes the source.
        assert!(
            matches!(&p.steps[0], PathStep::Source { description } if description.contains("req.body")),
            "first step must be the source, got {:?}",
            p.steps[0]
        );
        // The path crosses into buildQuery and returns.
        assert!(
            p.steps.iter().any(
                |s| matches!(s, PathStep::CallReturn { callee, .. } if callee == "buildQuery")
            ),
            "path must include the call-return hop, got {p:?}"
        );
        assert!(
            p.steps.iter().any(
                |s| matches!(s, PathStep::FormalParam { function, .. } if function == "buildQuery")
            ),
            "path must include entering the callee as a parameter"
        );
        // Source-first ordering.
        assert!(p.steps.len() >= 3, "path should have multiple steps");
        assert_eq!(p.spans.len(), p.steps.len(), "spans must align with steps");
    }

    #[test]
    fn non_vulnerable_findings_have_empty_path() {
        let findings = run(CROSS_FILE);
        for f in &findings {
            if f.verdict != BackwardVerdict::Vulnerable {
                assert!(
                    f.path.steps.is_empty(),
                    "non-vulnerable findings must not carry a path"
                );
            }
        }
    }

    #[test]
    fn same_shape_dedups_to_one() {
        let findings = run(CROSS_FILE);
        let paths: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .map(|f| f.path.clone())
            .collect();
        // Identical shape paths (same flow reported once) dedup to one.
        let kept = dedup_by_shape(&paths);
        assert!(!kept.is_empty());
        // Deduping a single path returns itself.
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn shape_id_ignores_variable_numbering() {
        let a = super::super::path::TaintPath {
            steps: vec![
                PathStep::Source {
                    description: "req.body".into(),
                },
                PathStep::Assignment {
                    function: "f".into(),
                    variable: 7,
                },
            ],
            spans: vec![None, None],
        };
        let b = super::super::path::TaintPath {
            steps: vec![
                PathStep::Source {
                    description: "req.body".into(),
                },
                PathStep::Assignment {
                    function: "f".into(),
                    variable: 99,
                },
            ],
            spans: vec![None, None],
        };
        assert_eq!(a.shape_id(), b.shape_id());
    }
}

#[cfg(test)]
mod idor_classification_tests {
    use crate::analysis::forward::ProgramSvfg;
    use crate::analysis::taint::config::TaintConfig;
    use crate::analysis::taint::engine::{BackwardTaintEngine, BackwardVerdict, FindingClass};
    use crate::harness::lower_source;
    use crate::ir::function::FunctionIR;
    use rustc_hash::FxHashMap;

    fn run(src: &str) -> Vec<crate::analysis::taint::engine::SinkFinding> {
        let fns = lower_source("t.ts", src, "ts").expect("lower");
        let owned: Vec<FunctionIR> = fns.into_values().collect();
        let mut statics: FxHashMap<String, &FunctionIR> = FxHashMap::default();
        for ir in &owned {
            statics.insert(ir.name.clone(), ir);
        }
        let mut config = TaintConfig::default();
        config.sinks.insert("findOne".into());
        config.sinks.insert("query".into());
        config.sources.insert("req.body".into());
        config.sources.insert("req".into());
        let prog = ProgramSvfg::new(&statics, &config);
        let facts = crate::analysis::taint::facts::seeded_tables(["ts"]).1;
        let mut engine = BackwardTaintEngine::new(&prog, &config).with_fact_table(&facts);
        engine.run();
        engine.findings
    }

    /// `findOne({ where: { id: req.body.x } })`: `where` is a clause
    /// wrapper, not an identity key - the driver parameterizes the leaf
    /// value, nothing here proves which-record control. Not reported
    /// (zero-FP: structurally unprovable findings never fire).
    #[test]
    fn where_wrapped_clause_is_not_a_finding() {
        let src = r#"
export function updateProfile(req: any, db: any): void {
  db.User.findOne({ where: { id: req.body.userId } });
}
"#;
        let findings = run(src);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some())
            .collect();
        assert!(
            vuln.is_empty(),
            "where-wrapped clause must not alert, got {:?}",
            vuln.iter()
                .map(|f| (&f.sink, f.finding_class))
                .collect::<Vec<_>>()
        );
    }

    /// `findOne({ _id: req.body.x })`: a top-level identity key marks the
    /// payload as which-record control → still reported as Idor.
    #[test]
    fn identity_payload_is_idor_class() {
        let src = r#"
export function updateProfile(req: any, db: any): void {
  db.User.findOne({ _id: req.body.userId });
}
"#;
        let findings = run(src);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some())
            .collect();
        assert!(!vuln.is_empty(), "identity payload must be detected");
        assert!(
            vuln.iter().any(|f| f.finding_class == FindingClass::Idor),
            "identity-payload flow must classify as Idor, got {:?}",
            vuln.iter().map(|f| f.finding_class).collect::<Vec<_>>()
        );
    }

    /// Auth-guarded handler: an early-return branch over an auth-vocab call
    /// (`security.authenticatedUsers.from(req)` → `if (!user) return`)
    /// dominates the sink and has a rejecting path that never reaches it -
    /// the query only executes for authenticated callers, so the identity
    /// payload is not an access-control violation. Suppressed (Idor class
    /// only).
    #[test]
    fn auth_guarded_identity_payload_is_suppressed() {
        let src = r#"
export function likeReview(req: any, db: any): void {
  const user = security.authenticatedUsers.from(req);
  if (!user) {
    return;
  }
  db.Reviews.findOne({ _id: req.body.id });
}
"#;
        let findings = run(src);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some())
            .collect();
        assert!(
            vuln.is_empty(),
            "auth-guarded identity query must be suppressed, got {:?}",
            vuln.iter()
                .map(|f| (&f.sink, f.finding_class))
                .collect::<Vec<_>>()
        );
    }

    /// Auth *presence* without a guard branch must NOT suppress: the forged
    /// review TP shape fetches `user` but queries before (or without) any
    /// auth check - the identity query is unguarded and stays reported.
    #[test]
    fn auth_call_without_guard_branch_still_reports() {
        let src = r#"
export function updateReview(req: any, db: any): void {
  const user = security.authenticatedUsers.from(req);
  db.Reviews.findOne({ _id: req.body.id });
  if (user) {
    audit(user);
  }
}
"#;
        let findings = run(src);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some())
            .collect();
        assert!(
            vuln.iter().any(|f| f.finding_class == FindingClass::Idor),
            "unguarded identity query must still report as Idor, got {:?}",
            vuln.iter()
                .map(|f| (&f.sink, f.finding_class))
                .collect::<Vec<_>>()
        );
    }

    /// `query("SELECT..." + req.body.x)`, raw string concat → Injection.
    #[test]
    fn raw_string_is_injection_class() {
        let src = r#"
export function getUser(req: any, pool: any): void {
  pool.query("SELECT * FROM users WHERE id = '" + req.body.id + "'");
}
"#;
        let findings = run(src);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some())
            .collect();
        assert!(!vuln.is_empty(), "flow must be detected");
        assert!(
            vuln.iter()
                .all(|f| f.finding_class == FindingClass::Injection),
            "raw string flow must classify as Injection, got {:?}",
            vuln.iter().map(|f| f.finding_class).collect::<Vec<_>>()
        );
    }

    /// Custom taught IDOR finder sink and custom key: misses at baseline, detects as Idor with learned facts.
    #[test]
    fn custom_teachable_idor_finder_and_key() {
        let src = r#"
export function getAccount(req: any, repo: any): void {
  repo.fetchRecord({ org_identifier: req.body.orgId });
}
"#;
        // 1. Baseline: fetchRecord is unknown, 0 findings
        let baseline_findings = run(src);
        let baseline_vuln: Vec<_> = baseline_findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some())
            .collect();
        assert!(
            baseline_vuln.is_empty(),
            "custom sink must not alert at baseline"
        );

        // 2. With learned IDOR finder sink and custom key
        let files = vec![("test.ts".to_string(), src.to_string(), "ts".to_string())];
        let mut facts = crate::analysis::taint::facts::seeded_tables(["ts"]).1;
        let fact = crate::analysis::taint::facts::LearnedFactEntry::IdorFinderSink {
            call: "fetchRecord".to_string(),
            keys: vec!["org_identifier".to_string()],
        };
        fact.apply(&mut facts);

        let mut sources = rustc_hash::FxHashSet::default();
        sources.insert("req.body".to_string());
        let config = TaintConfig {
            sources,
            sinks: rustc_hash::FxHashSet::default(),
            sanitizers: rustc_hash::FxHashSet::default(),
        };

        let res = crate::scan::scan(&files, &config, &facts);
        let taught_vuln: Vec<_> = res
            .findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some())
            .collect();

        assert!(
            !taught_vuln.is_empty(),
            "custom IDOR finder must alert with learned fact"
        );
        assert!(
            taught_vuln
                .iter()
                .any(|f| f.finding_class == FindingClass::Idor),
            "must classify as Idor finding class, got {:?}",
            taught_vuln
                .iter()
                .map(|f| f.finding_class)
                .collect::<Vec<_>>()
        );
    }

    /// A tainted value that circulates through mutually recursive helpers and
    /// a loop reaches the same graph node several times (different call
    /// context). The recorded parent must stay the first discovery; a later
    /// arrival used to overwrite it, chaining nodes into a cycle that
    /// `reconstruct_path` walked for `len + 1` steps (98 000-step paths and a
    /// 350 MB report on redis).
    #[test]
    fn path_through_recursion_stays_short_and_acyclic() {
        // A ring of 14 functions, each calling its successor and the one 3
        // ahead: every function is reachable under many call contexts.
        let k = 14;
        let mut src = String::from("import { Pool } from \"pg\";\nconst pool = new Pool();\n");
        for i in 0..k {
            src.push_str(&format!(
                "function f{i}(s: string, n: number): string {{ if (n > 0) {{ return f{}(s + \"a\", n - 1) + f{}(s, n - 1); }} return s; }}\n",
                (i + 1) % k,
                (i + 3) % k
            ));
        }
        src.push_str(
            "function handler(req: any): void { const q = f0(req.body.id, 5); pool.query(q); const r = f5(req.body.id, 5); pool.query(r); }\n",
        );
        let findings = run(&src);
        let vuln: Vec<_> = findings
            .iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(!vuln.is_empty(), "probe must produce a vulnerable finding");
        for f in vuln {
            assert!(
                f.path.steps.len() < 40,
                "path must be the shortest chain, got {} steps",
                f.path.steps.len()
            );
        }
    }

    /// `argv` is the process command line only in `main`. In any other
    /// function it is an ordinary parameter (redis: `robj **argv` of a client
    /// command, `sds *argv` of a config line), and treating it as attacker
    /// input produced path-traversal findings with the wrong source.
    fn run_c(src: &str) -> Vec<super::super::engine::SinkFinding> {
        let fns = lower_source("t.c", src, "c").expect("lower");
        let owned: Vec<FunctionIR> = fns.into_values().collect();
        let mut statics: FxHashMap<String, &FunctionIR> = FxHashMap::default();
        for ir in &owned {
            statics.insert(ir.name.clone(), ir);
        }
        let (mut config, facts) = crate::analysis::taint::facts::seeded_tables(["c"]);
        config.sinks.insert("system".into());
        config.sinks.insert("open".into());
        config.sources.insert("argv".into());
        let prog = ProgramSvfg::new_with_facts(&statics, &config, &facts);
        let mut engine = BackwardTaintEngine::new(&prog, &config).with_fact_table(&facts);
        engine.run();
        engine.findings
    }

    fn vulnerable(f: &[super::super::engine::SinkFinding]) -> usize {
        f.iter()
            .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
            .count()
    }

    #[test]
    fn c_argv_is_a_source_only_in_main() {
        let src = "void helper(char **argv) { system(argv[1]); }\n\
                   int main(int argc, char **argv) { return 0; }\n";
        assert_eq!(
            vulnerable(&run_c(src)),
            0,
            "non-main `argv` is a plain parameter"
        );
    }

    #[test]
    fn c_main_argv_reaches_a_sink_through_a_call() {
        let src = "static void run(char *c) { system(c); }\n\
                   int main(int argc, char **argv) { run(argv[1]); return 0; }\n";
        assert_eq!(
            vulnerable(&run_c(src)),
            1,
            "main's argv must still flow to the sink"
        );
    }

    #[test]
    fn c_length_and_fresh_allocation_do_not_carry_taint() {
        let src = "char *copy(const char *s) { return malloc(strlen(s) + 1); }\n\
                   int main(int argc, char **argv) {\n\
                     char *a = copy(argv[1]);\n\
                     open(a, 0);\n\
                     return 0;\n\
                   }\n";
        assert_eq!(
            vulnerable(&run_c(src)),
            0,
            "a new buffer sized from argv is not argv"
        );
    }

    #[test]
    fn c_strcpy_destination_preserves_taint_for_later_use() {
        let src = r#"
            int system(const char *command);
            char *strcpy(char *dst, const char *src);
            int main(int argc, char **argv) {
                char dst[128];
                strcpy(dst, argv[1]);
                system(dst);
                return 0;
            }
        "#;
        let findings = run_c(src);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    finding.verdict == BackwardVerdict::Vulnerable && finding.sink == "system"
                })
                .count(),
            1,
            "strcpy must taint dst's later use: {findings:?}"
        );
    }

    #[test]
    fn c_strcat_destination_preserves_taint() {
        let src = r#"
            int system(const char *command);
            char *strcat(char *dst, const char *src);
            int main(int argc, char **argv) {
                char dst[256];
                strcat(dst, argv[1]);
                system(dst);
                return 0;
            }
        "#;
        let findings = run_c(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.sink == "system")
                .count(),
            1,
            "c_strcat_destination_preserves_taint: {findings:?}"
        );
    }

    #[test]
    fn c_snprintf_source_argument_taints_destination() {
        let src = r#"
            int system(const char *command);
            int snprintf(char *dst, unsigned long n, const char *fmt, ...);
            int main(int argc, char **argv) {
                char dst[256];
                snprintf(dst, sizeof dst, "ls %s", argv[1]);
                system(dst);
                return 0;
            }
        "#;
        let findings = run_c(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.sink == "system")
                .count(),
            1,
            "c_snprintf_source_argument_taints_destination: {findings:?}"
        );
    }

    #[test]
    fn c_copy_into_offset_destination_preserves_taint() {
        let src = r#"
            int system(const char *command);
            char *strcpy(char *dst, const char *src);
            int main(int argc, char **argv) {
                char dst[256];
                strcpy(dst + 3, argv[1]);
                system(dst);
                return 0;
            }
        "#;
        let findings = run_c(src);
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.verdict == BackwardVerdict::Vulnerable && f.sink == "system")
                .count(),
            1,
            "c_copy_into_offset_destination_preserves_taint: {findings:?}"
        );
    }

    #[test]
    fn unknown_verdict_names_the_value_the_engine_could_not_resolve() {
        let src = r#"
            int system(const char *command);
            char *mystery(void);
            void run(void) {
                char *p = mystery();
                system(p);
            }
        "#;
        let findings = run_c(src);
        let sink = findings
            .iter()
            .find(|f| f.sink == "system" && f.verdict == BackwardVerdict::Unknown)
            .unwrap_or_else(|| panic!("expected an unknown system sink: {findings:?}"));
        assert!(
            sink.cut_sites
                .iter()
                .any(|c| c.kind == "external-call" && c.detail == "mystery"),
            "stop site must name the external callee: {:?}",
            sink.cut_sites
        );
    }
}
