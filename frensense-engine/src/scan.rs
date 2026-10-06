// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! The stable scan API (`8.10`): source text + facts → findings.
//!
//! Everything downstream (CLI, bundler replay gate, benchmarks) calls this;
//! nothing touches engine internals. The fact table is the *teaching*
//! interface: built-ins from `frensense-lang`, merged with `.frc` bundle
//! facts.

use rustc_hash::FxHashMap;

use crate::analysis::forward::ProgramSvfg;
use crate::analysis::taint::config::TaintConfig;
use crate::analysis::taint::engine::{BackwardTaintEngine, SinkFinding};
use crate::analysis::taint::facts::FactTable;
use crate::checks::{self, CheckerFinding};
use crate::harness::lower_source_with_facts;
use crate::ir::function::FunctionIR;

/// Scan a set of source files under a config and fact table.
///
/// `sources` maps file path → extension (used to pick the language spec).
pub fn scan(
    files: &[(String, String, String)], // (path, source, ext)
    config: &TaintConfig,
    facts: &FactTable,
) -> ScanResult {
    match prepare_with_facts(files, Some(facts)) {
        Ok(p) => scan_prepared(&p, config, facts),
        Err(e) => ScanResult {
            findings: Vec::new(),
            located: Vec::new(),
            located_checker: Vec::new(),
            checker: Vec::new(),
            errors: vec![e],
        },
    }
}

/// A program lowered once, ready for repeated scans under different fact
/// tables. The replay gate lowers each family exactly once and re-scans it
/// per candidate fact, lowering dominates scan cost, so this turns the
/// gate's O(candidates × families) lowerings into O(families).
pub struct PreparedProgram {
    irs: FxHashMap<String, FunctionIR>,
    fn_file: FxHashMap<String, String>,
    file_source: FxHashMap<String, String>,
}

/// Lower every file once, remembering which file each function came from
/// (functions are keyed by name; first file wins on collision).
///
/// # Errors
/// Returns the first lowering error, if any.
pub fn prepare(files: &[(String, String, String)]) -> Result<PreparedProgram, String> {
    prepare_with_facts(files, None)
}

/// Lower every file once with dynamic bundle facts.
pub fn prepare_with_facts(
    files: &[(String, String, String)],
    facts: Option<&FactTable>,
) -> Result<PreparedProgram, String> {
    let mut irs: FxHashMap<String, FunctionIR> = FxHashMap::default();
    let mut fn_file: FxHashMap<String, String> = FxHashMap::default();
    let mut file_source: FxHashMap<String, String> = FxHashMap::default();
    // Deterministic merge order (path-sorted): which twin of a colliding
    // name keeps the bare key must not depend on directory walk order.
    let mut ordered: Vec<&(String, String, String)> = files.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, source, ext) in ordered {
        let fns = lower_source_with_facts(path, source, ext, facts)?;
        for (name, mut ir) in fns {
            file_source
                .entry(path.clone())
                .or_insert_with(|| source.clone());
            // Function keys are only unique per file: byte-offset names
            // (`<fn@505>`) and common method names (`set`) collide across
            // files. First-wins dropped the other file's whole function
            // silently (the forgedReview/noSqlReviews miss); rekey the
            // incoming twin under its file instead. `ir.name` tracks the
            // key so findings, `fn_file`, and checker locations stay in
            // lockstep.
            let key = if irs.contains_key(&name) {
                format!("{path}::{name}")
            } else {
                name
            };
            ir.name = key.clone();
            fn_file.entry(key.clone()).or_insert_with(|| path.clone());
            irs.insert(key, ir);
        }
    }
    Ok(PreparedProgram {
        irs,
        fn_file,
        file_source,
    })
}

impl PreparedProgram {
    /// Borrow the IRs for the program graph's lifetime.
    fn ir_views(&self) -> FxHashMap<String, &FunctionIR> {
        self.irs
            .iter()
            .map(|(name, ir)| (name.clone(), ir))
            .collect()
    }
}

/// Scan a [`PreparedProgram`] under a config and fact table. Same semantics
/// as [`scan`]; the lowering is reused across calls.
pub fn scan_prepared(
    prepared: &PreparedProgram,
    config: &TaintConfig,
    facts: &FactTable,
) -> ScanResult {
    // Bundle-learned source patterns widen the config: a `.frc` bundle
    // teaches new framework sources without touching the built-in tables.
    // Local mutable copy; the caller's config stays shared and unchanged.
    let mut config = config.clone();
    config.sources.extend(facts.learned_sources.iter().cloned());
    let config = &config;

    // The program graph borrows the program's own IRs for the duration of
    // this scan. No `Box::leak`: a leaked IR set accumulated per program in
    // every long-lived consumer (MCP/LSP servers build one `PreparedProgram`
    // per scan; the bundler's replay gate holds one per family, re-scanned
    // per candidate fact), so resident memory grew without bound across
    // scans. Borrowing is scoped to the call instead.
    let statics = prepared.ir_views();
    let statics = &statics;

    // The program graph is built first: non-dataflow checks that walk
    // interprocedural value flow (UAF free/use pairs) reuse it, and the
    // taint engine below gets the same instance.
    let prog = ProgramSvfg::new_with_facts(statics, config, facts);

    // Non-dataflow policy checks run on the same lowered IR, no taint
    // needed, so weak-crypto/config bugs surface even with zero taint paths.
    // `facts` also carries corpus-learned checks installed by the bundle.
    let checker_findings =
        checks::check_all_with_graph(statics.values().copied(), facts, Some(&prog));

    let fn_file = &prepared.fn_file;
    let file_source = &prepared.file_source;
    let mut engine = BackwardTaintEngine::new(&prog, config)
        .with_fact_table(facts)
        .with_fn_file(fn_file);
    engine.run();

    // Resolve each finding to a file + line/column from the sink's byte span.
    let located: Vec<LocatedFinding> = engine
        .findings
        .iter()
        .filter_map(|f| {
            let file = fn_file.get(&f.function)?;
            let source = file_source.get(file)?;
            let (line, col) = f
                .sink_span
                .map(|(start, _)| {
                    let before = &source[..start.min(source.len())];
                    let line = before.matches('\n').count() as u32 + 1;
                    let col = before
                        .rfind('\n')
                        .map_or(before.len(), |i| before.len() - i - 1)
                        as u32
                        + 1;
                    (line, col)
                })
                .unwrap_or((0, 0));
            Some(LocatedFinding {
                finding: f.clone(),
                file: file.clone(),
                line,
                column: col,
            })
        })
        .collect();

    // Locate checker findings the same way: function → file, span → line/col.
    let located_checker: Vec<LocatedChecker> = checker_findings
        .iter()
        .filter_map(|c| {
            let file = fn_file.get(&c.function)?;
            let source = file_source.get(file)?;
            let (line, col, end_line) = c
                .span
                .map(|(start, end)| {
                    let before = &source[..start.min(source.len())];
                    let line = before.matches('\n').count() as u32 + 1;
                    let col = before
                        .rfind('\n')
                        .map_or(before.len(), |i| before.len() - i - 1)
                        as u32
                        + 1;
                    let end_before = &source[..end.min(source.len())];
                    let end_line = end_before.matches('\n').count() as u32 + 1;
                    (line, col, end_line)
                })
                .unwrap_or((0, 0, 0));
            Some(LocatedChecker {
                finding: c.clone(),
                file: file.clone(),
                line,
                column: col,
                end_line: end_line.max(line),
            })
        })
        .collect();

    ScanResult {
        findings: engine.findings,
        located,
        located_checker,
        checker: checker_findings,
        errors: Vec::new(),
    }
}

/// The result of one scan: vulnerable findings + non-fatal errors.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// All sink findings (every verdict); filter on [`ScanResult::alerts`]
    /// semantics.
    pub findings: Vec<SinkFinding>,
    /// The same findings resolved to source locations (file/line/column).
    pub located: Vec<LocatedFinding>,
    /// Non-dataflow policy violations (weak crypto, insecure config),
    /// resolved to file/line/column.
    pub located_checker: Vec<LocatedChecker>,
    /// Non-dataflow policy violations (weak crypto, insecure config).
    /// These have no taint path by definition; they are policy assertions
    /// over the API/constant choices in the lowered IR.
    pub checker: Vec<CheckerFinding>,
    pub errors: Vec<String>,
}

/// A [`CheckerFinding`] pinned to its source location.
#[derive(Debug, Clone)]
pub struct LocatedChecker {
    pub finding: CheckerFinding,
    /// Path of the file containing the violating call.
    pub file: String,
    /// 1-based line of the violating call (0 when no span recorded).
    pub line: u32,
    /// 1-based column (0 when no span recorded).
    pub column: u32,
    /// 1-based last line of the finding's span (>= `line`). Multi-line
    /// spans (allowlist definitions) report their full extent.
    pub end_line: u32,
}

/// A [`SinkFinding`] pinned to its source location.
#[derive(Debug, Clone)]
pub struct LocatedFinding {
    pub finding: SinkFinding,
    /// Path of the file containing the sink call.
    pub file: String,
    /// 1-based line of the sink call (0 when the lowering recorded no span).
    pub line: u32,
    /// 1-based column of the sink call (0 when no span recorded).
    pub column: u32,
}

#[cfg(test)]
mod collision_tests {
    use super::scan;
    use crate::analysis::taint::facts::seeded_tables;

    fn ts_tables() -> (
        crate::analysis::taint::config::TaintConfig,
        crate::analysis::taint::facts::FactTable,
    ) {
        seeded_tables(["ts"])
    }

    /// Same prefix in both files => the nameless nested arrows start at the
    /// same byte offset => both lower to the identical `<fn@N>` key.
    /// Whole-program merge must keep BOTH functions (first-wins dropped the
    /// second file's entire handler: forgedReview/noSqlReviews miss).
    #[test]
    fn cross_file_closure_offset_collision_keeps_both_functions() {
        const PREFIX: &str = "export function wrap () {\n  return";
        let a = format!("{PREFIX} (req) => {{\n    noop(1)\n  }}\n}}\n");
        let b = format!("{PREFIX} (req) => {{\n    exec(req)\n  }}\n}}\n");
        let (config, facts) = ts_tables();
        let result = scan(
            &[
                ("app/a.ts".to_string(), a, "ts".to_string()),
                ("app/b.ts".to_string(), b, "ts".to_string()),
            ],
            &config,
            &facts,
        );
        assert!(result.errors.is_empty(), "scan errors: {:?}", result.errors);
        let b_hits: Vec<_> = result
            .located
            .iter()
            .filter(|l| l.file == "app/b.ts")
            .collect();
        assert!(
            b_hits.iter().any(|l| l.finding.sink == "exec"),
            "second file's `<fn@N>` twin was dropped by the name-keyed merge; \
             located: {:?}",
            result
                .located
                .iter()
                .map(|l| (&l.file, &l.finding.sink))
                .collect::<Vec<_>>()
        );
    }

    /// Four object-literal setters share the name `set`; the password setter
    /// holds the `hash(clearTextPassword)` call. Same-name collapse within
    /// one file dropped it (weakPassword miss). Every setter must survive.
    #[test]
    fn within_file_method_name_collision_keeps_all_setters() {
        let src = "export const init = () => {\n  const attrs = {\n    first: {\n      set (v: string) {\n        keep(v)\n      }\n    },\n    second: {\n      set (v: string) {\n        keep(v)\n      }\n    },\n    password: {\n      set (clearTextPassword: string) {\n        hash(clearTextPassword)\n      }\n    }\n  }\n  return attrs\n}\n";
        let (config, facts) = ts_tables();
        let result = scan(
            &[("app/user.ts".to_string(), src.to_string(), "ts".to_string())],
            &config,
            &facts,
        );
        assert!(result.errors.is_empty(), "scan errors: {:?}", result.errors);
        assert!(
            result
                .located_checker
                .iter()
                .any(|c| c.finding.rule == "credential_kdf_policy"),
            "password setter dropped by same-name collapse; checker findings: {:?}",
            result
                .located_checker
                .iter()
                .map(|c| (&c.finding.rule, &c.finding.function, c.line))
                .collect::<Vec<_>>()
        );
    }
}
