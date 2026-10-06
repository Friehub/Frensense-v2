// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Regression gate for the extract-vs-inline restructure.
//!
//! Each nested-function flow shape must yield the same detection before and
//! after the restructure that gives every function body exactly one owning IR.
//! Assertions are keyed on (line, verdict) only - never on `function`
//! attribution, which the fix is *expected* to change (inline copies currently
//! win with the enclosing function's name).
//!
//! Since the extract-only restructure landed, each shape must yield
//! EXACTLY ONE finding, attributed to the function that owns the body
//! (`inner`, `report`, `h`) - locking both halves of the contract: no
//! detection may disappear (missed closure edge) and no duplicate may
//! survive (inlined copy). The sanitizer gate pins the other direction:
//! conservative closure edges must not resurrect sanitized flows.

#[cfg(test)]
pub mod nested_flow_gate {
    use crate::analysis::taint::engine::BackwardVerdict;
    use crate::analysis::taint::facts::{
        FactTable, PolicyFact, PolicyRequirement, PolicyScope, Provenance, seeded_tables_all,
    };
    use crate::checks::policy;
    use crate::harness::lower_source;
    use crate::ir::function::FunctionIR;
    use crate::scan::{ScanResult, scan};

    fn scan_ts(src: &str) -> ScanResult {
        let (config, facts) = seeded_tables_all();
        let files = vec![("app.ts".to_string(), src.to_string(), "ts".to_string())];
        scan(&files, &config, &facts)
    }

    /// 1-based line of the first line containing `needle` (the sink call).
    fn sink_line(src: &str, needle: &str) -> u32 {
        src.lines()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("needle {needle:?} not found in source")) as u32
            + 1
    }

    fn vulnerable_at(res: &ScanResult, line: u32) -> Vec<&str> {
        res.located
            .iter()
            .filter(|f| f.line == line && f.finding.verdict == BackwardVerdict::Vulnerable)
            .map(|f| f.finding.function.as_str())
            .collect()
    }

    // ------------------------------------------------------------------
    // Positive gates: the detection must exist (count may shrink from
    // today's duplicates to 1 after the fix, never to 0).
    // ------------------------------------------------------------------

    #[test]
    fn gate_nested_named_fn_param_flow() {
        let src = r#"
export function outer(c: any, db: any) {
  function inner(x: any) {
    return db.prepare("SELECT " + x).all()
  }
  return inner(c.req.query("q"))
}
"#;
        let res = scan_ts(src);
        let hits = vulnerable_at(&res, sink_line(src, "db.prepare"));
        assert_eq!(
            hits,
            vec!["inner"],
            "exactly one finding, owned by the function that writes the sink: {:?}",
            hits
        );
    }

    #[test]
    fn gate_nested_named_fn_closure_flow() {
        let src = r#"
export function outer(c: any, db: any) {
  const q = c.req.query("q")
  function report() {
    return db.prepare("SELECT " + q).all()
  }
  return report()
}
"#;
        let res = scan_ts(src);
        let hits = vulnerable_at(&res, sink_line(src, "db.prepare"));
        assert_eq!(
            hits,
            vec!["report"],
            "exactly one finding, owned by the closure's owner IR: {:?}",
            hits
        );
    }

    #[test]
    fn gate_nested_named_fn_param_and_closure_flow() {
        // Today: TWO Vulnerable findings on one line (outer via closure q,
        // inner via param x). After the fix: exactly one, owned by inner.
        let src = r#"
export function outer(c: any, db: any) {
  const q = c.req.query("q")
  function inner(x: any) {
    return db.prepare("SELECT " + x + q).all()
  }
  return inner(q)
}
"#;
        let res = scan_ts(src);
        let hits = vulnerable_at(&res, sink_line(src, "db.prepare"));
        assert_eq!(
            hits,
            vec!["inner"],
            "the duplicate pair must collapse to one owner: {:?}",
            hits
        );
    }

    #[test]
    fn gate_bound_arrow_param_flow() {
        let src = r#"
export function outer(c: any, db: any) {
  const h = (x: any) => db.prepare("SELECT " + x).all()
  return h(c.req.query("q"))
}
"#;
        let res = scan_ts(src);
        let hits = vulnerable_at(&res, sink_line(src, "db.prepare"));
        assert_eq!(
            hits,
            vec!["h"],
            "bound-arrow param flow: one finding under the binding name: {:?}",
            hits
        );
    }

    #[test]
    fn gate_bound_arrow_closure_flow() {
        let src = r#"
export function outer(c: any, db: any) {
  const q = c.req.query("q")
  const h = () => db.prepare("SELECT " + q).all()
  return h()
}
"#;
        let res = scan_ts(src);
        let hits = vulnerable_at(&res, sink_line(src, "db.prepare"));
        assert_eq!(
            hits,
            vec!["h"],
            "bound-arrow closure flow: one finding under the binding name: {:?}",
            hits
        );
    }

    #[test]
    fn gate_deep_nesting_param_flow() {
        let src = r#"
export function a(c: any, db: any) {
  function b(src: any) {
    function inner(x: any) {
      return db.prepare("SELECT " + x).all()
    }
    return inner(src)
  }
  return b(c.req.query("q"))
}
"#;
        let res = scan_ts(src);
        let hits = vulnerable_at(&res, sink_line(src, "db.prepare"));
        assert_eq!(
            hits,
            vec!["inner"],
            "3-level nested param flow: one finding at the innermost owner: {:?}",
            hits
        );
    }

    #[test]
    fn gate_deep_nesting_closure_flow() {
        let src = r#"
export function a(c: any, db: any) {
  const q = c.req.query("q")
  function b() {
    function inner() {
      return db.prepare("SELECT " + q).all()
    }
    return inner()
  }
  return b()
}
"#;
        let res = scan_ts(src);
        let hits = vulnerable_at(&res, sink_line(src, "db.prepare"));
        assert_eq!(
            hits,
            vec!["inner"],
            "3-level nested closure flow (chained closure edges): {:?}",
            hits
        );
    }

    // ------------------------------------------------------------------
    // Negative gate: sanitizers must keep holding inside nested bodies.
    // The new closure/callback edges are conservative over-approximations -
    // they must not resurrect a flow that escapeHtml already cut.
    // ------------------------------------------------------------------

    #[test]
    fn gate_sanitizer_inside_nested_fn_holds() {
        let src = r#"
export function outer(c: any, db: any) {
  function inner(x: any) {
    return db.prepare("SELECT " + escapeHtml(x)).all()
  }
  return inner(c.req.query("q"))
}
"#;
        let res = scan_ts(src);
        let hits = vulnerable_at(&res, sink_line(src, "db.prepare"));
        assert!(
            hits.is_empty(),
            "sanitized nested flow must not become vulnerable: {:?}",
            res.located
        );
    }

    // ------------------------------------------------------------------
    // Policy gate: nested named fn fires today for both IR copies
    // (outer + inner, same span). Detection must exist; tighten to == 1
    // when the extract-only fix lands.
    // ------------------------------------------------------------------

    #[test]
    fn gate_nested_named_fn_policy_detection() {
        let src = r#"
export function outer (cmd: string) {
  function inner (x: string) { return runTool(x) }
  return inner(cmd)
}
"#;
        let fns = lower_source("t.ts", src, "ts").unwrap();
        let irs: Vec<&'static FunctionIR> = fns
            .into_values()
            .map(|ir| Box::leak(Box::new(ir)) as &'static FunctionIR)
            .collect();
        let mut facts = FactTable::default();
        facts.policy_facts.push((
            PolicyFact {
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![PolicyRequirement::GuardCall {
                    call: "checkPermission".into(),
                }],
                scope: PolicyScope::Function,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            Provenance::Learned,
        ));
        let hits = policy::check_program(&irs, &facts);
        assert_eq!(
            hits.len(),
            1,
            "the outer/inner duplicate pair must collapse to one hit: {:?}",
            hits
        );
        assert_eq!(hits[0].rule, "policy_run_tool");
        assert_eq!(
            hits[0].function, "inner",
            "policy must be attributed to the function that writes the call"
        );
    }
}

#[cfg(test)]
pub mod duplicate_result_gate {
    use crate::analysis::taint::engine::BackwardVerdict;
    use crate::analysis::taint::facts::{FactTable, seeded_tables_all};
    use crate::checks::policy;
    use crate::scan::scan;

    #[test]
    fn no_duplicate_findings_across_shapes() {
        let (config, facts) = seeded_tables_all();
        let scan_ts = |src: &str| {
            scan(
                &[("app.ts".to_string(), src.to_string(), "ts".to_string())],
                &config,
                &facts,
            )
        };

        // ── Probe 1 (was: 2 alerts, inner+outer, same line) ────────────
        let p1 = r#"
export function outer(c: any, db: any) {
  const q = c.req.query("q")
  function inner(x: any) {
    return db.prepare("SELECT " + x + q).all()
  }
  return inner(q)
}
"#;
        let r = scan_ts(p1);
        let v: Vec<_> = r
            .located
            .iter()
            .filter(|f| f.finding.verdict == BackwardVerdict::Vulnerable)
            .collect();
        eprintln!(
            "PROBE1 (param+closure, was 2 dupes): {} Vulnerable -> {:?}",
            v.len(),
            v.iter()
                .map(|f| (&f.finding.function, f.line))
                .collect::<Vec<_>>()
        );

        // ── Probe 2 (was: 1 alert misattributed to outer) ──────────────
        let p2 = r#"
export function outer(c: any, db: any) {
  const q = c.req.query("q")
  function report() {
    return db.prepare("SELECT " + q).all()
  }
  return report()
}
"#;
        let r = scan_ts(p2);
        let v: Vec<_> = r
            .located
            .iter()
            .filter(|f| f.finding.verdict == BackwardVerdict::Vulnerable)
            .collect();
        eprintln!(
            "PROBE2 (closure, was fn=outer): {} Vulnerable -> {:?}",
            v.len(),
            v.iter()
                .map(|f| (&f.finding.function, f.line))
                .collect::<Vec<_>>()
        );
        assert_eq!(v.len(), 1, "probe2 must not duplicate: {v:?}");
        assert_eq!(v[0].finding.function, "report");

        // helper: leak IRs for policy checks
        fn leak_irs(src: &str) -> Vec<&'static crate::ir::function::FunctionIR> {
            let fns = crate::harness::lower_source("t.ts", src, "ts").unwrap();
            fns.into_values()
                .map(|ir| Box::leak(Box::new(ir)) as &'static crate::ir::function::FunctionIR)
                .collect()
        }
        let mut pfacts = FactTable::default();
        pfacts.policy_facts.push((
            crate::analysis::taint::facts::PolicyFact {
                rule: "policy_run_tool".into(),
                when_call: "runTool".into(),
                require: vec![
                    crate::analysis::taint::facts::PolicyRequirement::GuardCall {
                        call: "checkPermission".into(),
                    },
                ],
                scope: crate::analysis::taint::facts::PolicyScope::Function,
                message: "tool executed without policy check".into(),
                severity: "warning".into(),
            },
            crate::analysis::taint::facts::Provenance::Learned,
        ));

        // ── Probe 3: policy nested named (was: 2 hits outer+inner) ─────
        let hits = policy::check_program(
            &leak_irs(
                r#"
export function outer (cmd: string) {
  function inner (x: string) { return runTool(x) }
  return inner(cmd)
}
"#,
            ),
            &pfacts,
        );
        eprintln!(
            "PROBE3 (policy nested, was 2 hits): {} hits -> {:?}",
            hits.len(),
            hits.iter().map(|h| &h.function).collect::<Vec<_>>()
        );
        assert_eq!(hits.len(), 1, "probe3 duplicate: {hits:?}");

        // ── Probe 4: bound arrow inside handler (was: helper+handler) ───
        let hits = policy::check_program(
            &leak_irs(
                r#"
export function handler (cmd: string) {
  const helper = (x: string) => runTool(x)
  return helper(cmd)
}
"#,
            ),
            &pfacts,
        );
        eprintln!(
            "PROBE4 (bound arrow, was helper+handler): {} hits -> {:?}",
            hits.len(),
            hits.iter().map(|h| &h.function).collect::<Vec<_>>()
        );
        assert_eq!(hits.len(), 1, "probe4 duplicate: {hits:?}");

        // ── Probe 5: phantom const r (original bug) ────────────────────
        let fns = crate::harness::lower_source(
            "t.ts",
            r#"
export function handler (cmd: string) {
  const r = runTool(cmd)
  return r
}
"#,
            "ts",
        )
        .unwrap();
        let ks: Vec<_> = fns.keys().cloned().collect();
        let irs: Vec<&'static crate::ir::function::FunctionIR> = fns
            .into_values()
            .map(|ir| Box::leak(Box::new(ir)) as &'static crate::ir::function::FunctionIR)
            .collect();
        let hits = policy::check_program(&irs, &pfacts);
        eprintln!(
            "PROBE5 (phantom const r): IRs={ks:?} {} hits -> {:?}",
            hits.len(),
            hits.iter().map(|h| &h.function).collect::<Vec<_>>()
        );
        assert_eq!(hits.len(), 1, "probe5 duplicate: {hits:?}");

        // ── Probe 6: returned-arrow handler (was inlined into orderHistory)
        let fns = crate::harness::lower_source(
            "t.ts",
            r#"
export function orderHistory () {
  return async (req: any) => runTool(req.body)
}
"#,
            "ts",
        )
        .unwrap();
        let p6_keys: Vec<_> = fns.keys().cloned().collect();
        let irs: Vec<&'static crate::ir::function::FunctionIR> = fns
            .into_values()
            .map(|ir| Box::leak(Box::new(ir)) as &'static crate::ir::function::FunctionIR)
            .collect();
        let hits = policy::check_program(&irs, &pfacts);
        eprintln!(
            "PROBE6 (returned arrow): IRs={p6_keys:?} {} hits -> {:?}",
            hits.len(),
            hits.iter().map(|h| &h.function).collect::<Vec<_>>()
        );
        assert_eq!(hits.len(), 1, "probe6 duplicate: {hits:?}");
    }
}

#[cfg(test)]
pub mod c_taint_gate {
    use crate::analysis::taint::engine::BackwardVerdict;
    use crate::analysis::taint::facts::seeded_tables_all;
    use crate::scan::{ScanResult, scan};

    fn scan_c(src: &str) -> ScanResult {
        let (config, facts) = seeded_tables_all();
        let files = vec![("t.c".to_string(), src.to_string(), "c".to_string())];
        scan(&files, &config, &facts)
    }

    fn vulnerable_at<'a>(res: &'a ScanResult, needle: &str, src: &str) -> Vec<&'a str> {
        let line = src
            .lines()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("needle {needle:?} not found")) as u32
            + 1;
        res.located
            .iter()
            .filter(|f| f.line == line && f.finding.verdict == BackwardVerdict::Vulnerable)
            .map(|f| f.finding.function.as_str())
            .collect()
    }

    /// alsa-lib `_snd_config_path`: getenv-driven buffer sized from strlen,
    /// passed as sprintf's destination. The destination slot is not the
    /// format string - must stay silent (was Critical on every slot).
    #[test]
    fn gate_getenv_sprintf_destination_stays_silent() {
        let src = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void build(void) {
    const char *root = getenv("ALSA_CONFIG_DIR");
    char *path = malloc(strlen(root) + 16);
    if (!path) return;
    sprintf(path, "%s/%s", root, "alsa.conf");
}
"#;
        let res = scan_c(src);
        let hits = vulnerable_at(&res, "sprintf(path", src);
        assert!(
            hits.is_empty(),
            "tainted destination/content into sprintf must stay silent: {hits:?}"
        );
    }

    /// A genuinely tainted FORMAT argument is a format-string bug and must
    /// still alert (the slot restriction narrows sinks, it never silences them).
    #[test]
    fn gate_tainted_format_string_still_fires() {
        let src = r#"
#include <stdio.h>
#include <stdlib.h>
void f(void) {
    char buf[64];
    char *fmt = getenv("FMT");
    sprintf(buf, fmt);
}
"#;
        let res = scan_c(src);
        let hits = vulnerable_at(&res, "sprintf(buf", src);
        assert!(
            !hits.is_empty(),
            "tainted format string must still alert as Vulnerable"
        );
    }

    /// Sized copies carry an explicit length: copying getenv-derived text is
    /// normal I/O (alsa `snd_config_update_r` memcpy of config paths) and is
    /// checked spatially, not as a taint sink.
    #[test]
    fn gate_memcpy_tainted_content_stays_silent() {
        let src = r#"
#include <string.h>
#include <stdlib.h>
void f(void) {
    char name[64];
    char *c = getenv("ALSA_CONFIG_PATH");
    memcpy(name, c, 8);
}
"#;
        let res = scan_c(src);
        let hits = vulnerable_at(&res, "memcpy(name", src);
        assert!(
            hits.is_empty(),
            "memcpy of tainted content with explicit length must stay silent: {hits:?}"
        );
    }
}

#[cfg(test)]
pub mod spec_acceptance_gate {
    use crate::analysis::taint::engine::BackwardVerdict;
    use crate::analysis::taint::facts::seeded_tables_all;
    use crate::scan::{ScanResult, scan};

    /// Full production pipeline: config + tables assembled for every
    /// registered language, exactly as the CLI scanner assembles them.
    fn scan_ts(src: &str) -> ScanResult {
        let (config, facts) = seeded_tables_all();
        scan(
            &[("app.ts".to_string(), src.to_string(), "ts".to_string())],
            &config,
            &facts,
        )
    }

    /// Spec §4.2 (Verification & Acceptance): test cases containing
    /// `env.SECRET_KEY -> createHmac` must produce **0 findings**. Env
    /// vars are developer-controlled config, never attacker input - the
    /// field path must not fall back to the `process`/root prefix, and the
    /// param-sentinel source list must not cover it either.
    #[test]
    fn env_secret_key_into_create_hmac_stays_silent() {
        let src = r#"
const { createHmac } = require("crypto")
export function sign(process: any, algo: string): string {
  return createHmac(algo, process.env.SECRET_KEY)
}
"#;
        let res = scan_ts(src);
        let vuln: Vec<_> = res
            .located
            .iter()
            .filter(|f| f.finding.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            vuln.is_empty(),
            "env.SECRET_KEY -> createHmac must yield 0 findings, got {vuln:?}"
        );
    }

    /// Companion negative control: the same sink with genuine request
    /// input still fires (the silent case above is not silent because the
    /// sink stopped matching).
    #[test]
    fn request_input_into_create_hmac_still_fires() {
        let src = r#"
const { createHmac } = require("crypto")
export function sign(req: any, algo: string): string {
  return createHmac(algo, req.body.key)
}
"#;
        let res = scan_ts(src);
        let vuln: Vec<_> = res
            .located
            .iter()
            .filter(|f| f.finding.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert!(
            !vuln.is_empty(),
            "request body into createHmac must stay Vulnerable (control)"
        );
    }
}
