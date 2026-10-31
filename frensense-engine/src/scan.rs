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
use std::time::Instant;

use crate::analysis::forward::ProgramSvfg;
use crate::analysis::taint::config::TaintConfig;
use crate::analysis::taint::engine::{BackwardTaintEngine, SinkFinding};
use crate::analysis::taint::facts::FactTable;
use crate::checks::{self, CheckerFinding};
use crate::ir::function::FunctionIR;
use crate::telemetry::{
    CapHit, FileTiming, FunctionTiming, InputAccounting, PhaseTiming, ScanTelemetry, millis_since,
};
use frensense_lang::spec::{Export, Import, ModuleItem};

/// Scan a set of source files under a config and fact table.
///
/// `sources` maps file path → extension (used to pick the language spec).
pub fn scan(
    files: &[(String, String, String)], // (path, source, ext)
    config: &TaintConfig,
    facts: &FactTable,
) -> ScanResult {
    let started = Instant::now();
    match prepare_with_facts(files, Some(facts)) {
        Ok(p) => {
            let mut result = scan_prepared(&p, config, facts);
            result.telemetry.phases.push(PhaseTiming {
                phase: "total".into(),
                ms: millis_since(started),
            });
            result
        }
        Err(e) => {
            let mut telemetry = ScanTelemetry::default();
            telemetry.errors.push(e.clone());
            ScanResult {
                findings: Vec::new(),
                located: Vec::new(),
                located_checker: Vec::new(),
                checker: Vec::new(),
                errors: vec![e],
                analysis_incomplete: Vec::new(),
                telemetry,
            }
        }
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
    pub file_aliases: FxHashMap<String, FxHashMap<String, String>>,
    pub file_package_imports:
        FxHashMap<String, FxHashMap<String, crate::graph::module::PackageImport>>,
    /// Import declarations per file (see [`ModuleResolution`]).
    ///
    /// [`ModuleResolution`]: crate::graph::module::ModuleResolution
    pub file_imports: FxHashMap<String, Vec<Import>>,
    /// Export/re-export declarations per file, with visibility and kind.
    pub file_exports: FxHashMap<String, Vec<Export>>,
    /// Every top-level declaration per file, exported or not.
    pub file_module_items: FxHashMap<String, Vec<ModuleItem>>,
    /// Files that could not be lowered, with the reason. The scan continues
    /// without them and says so; it never drops one silently.
    pub lower_errors: Vec<String>,
    /// Files whose parse tree contained errors, so they were analyzed from
    /// whatever tree-sitter recovered rather than from an intact tree.
    pub parse_partial: Vec<String>,
    /// Number of source inputs attempted by this prepared program.
    pub submitted: usize,
    /// Safety cap events that happened during per-file lowering.
    pub lower_caps: Vec<CapHit>,
    /// Paths that failed lowering, independent of error message formatting.
    pub lower_failed_files: Vec<String>,
    /// Lowering cost per file, feeding the slowest-file report.
    pub file_timings: Vec<FileTiming>,
}

/// Stack size for the per-file lowering thread (the default 4 MiB overflows
/// on deeply nested real-world functions; one such overflow used to abort the
/// process and lose every file's findings).
const LOWER_STACK_BYTES: usize = 32 * 1024 * 1024;

/// Lower one file on its own thread with a larger stack.
///
/// Returns the extracted functions and whether the file only partially
/// parsed. A panic is contained here and reported as that file's error.
type IsolatedLowering = (FxHashMap<String, FunctionIR>, bool, Vec<CapHit>);

fn lower_isolated(
    path: &str,
    source: &str,
    ext: &str,
    facts: Option<&FactTable>,
) -> Result<IsolatedLowering, String> {
    type Lowered = Result<(FxHashMap<String, FunctionIR>, bool), String>;
    type JoinOutcome = Result<(Lowered, Vec<CapHit>), Box<dyn std::any::Any + Send + 'static>>;
    let outcome: Result<JoinOutcome, std::io::Error> = std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .stack_size(LOWER_STACK_BYTES)
            .spawn_scoped(scope, || {
                let lowered = crate::harness::lower_source_detailed(path, source, ext, facts);
                let caps = crate::telemetry::drain_caps();
                (lowered, caps)
            })?;
        Ok(handle.join())
    });
    match outcome {
        Ok(Ok((Ok((functions, partial)), caps))) => Ok((functions, partial, caps)),
        Ok(Ok((Err(error), _))) => Err(error),
        Ok(Err(_)) => Err("lowering worker panicked; see the file path in scan accounting".into()),
        Err(_) => Err("failed to spawn lowering worker".into()),
    }
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
    let mut lower_errors: Vec<String> = Vec::new();
    let mut lower_failed_files: Vec<String> = Vec::new();
    let mut lower_caps: Vec<CapHit> = Vec::new();
    let mut parse_partial: Vec<String> = Vec::new();
    let submitted = ordered.len();
    let mut file_timings: Vec<FileTiming> = Vec::new();
    for (path, source, ext) in ordered {
        let started = Instant::now();
        let lowered = lower_isolated(path, source, ext, facts);
        let (fns, parse_broken, caps) = match lowered {
            Ok(ok) => ok,
            Err(reason) => {
                lower_failed_files.push(path.clone());
                lower_errors.push(reason);
                continue;
            }
        };
        lower_caps.extend(caps);
        if parse_broken {
            parse_partial.push(path.clone());
        }
        file_timings.push(FileTiming {
            file: path.clone(),
            ms: millis_since(started),
            functions: fns.len(),
        });
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

    let ir_names: rustc_hash::FxHashSet<String> = irs.keys().cloned().collect();
    let res = crate::graph::module::ModuleAliasResolver::build(files, &ir_names, &fn_file);

    Ok(PreparedProgram {
        irs,
        fn_file,
        file_source,
        file_aliases: res.file_aliases,
        file_package_imports: res.file_package_imports,
        file_imports: res.file_imports,
        file_exports: res.file_exports,
        file_module_items: res.file_module_items,
        lower_errors,
        parse_partial,
        submitted,
        lower_caps,
        lower_failed_files,
        file_timings,
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

    /// Every file the program parsed, sorted.
    ///
    /// The module surface is the complete list (every parsed file gets an
    /// entry, even one that declares no function); `file_source` is the
    /// fallback for a program built before that layer ran.
    #[must_use]
    pub fn files(&self) -> Vec<&str> {
        let mut files: Vec<&str> = if self.file_imports.is_empty() {
            self.file_source.keys().map(String::as_str).collect()
        } else {
            self.file_imports.keys().map(String::as_str).collect()
        };
        files.sort_unstable();
        files
    }

    /// The export surface of one file; empty when the file declares none or
    /// its language has no export syntax the spec models.
    #[must_use]
    pub fn exports_of(&self, file: &str) -> &[Export] {
        self.file_exports.get(file).map_or(&[], Vec::as_slice)
    }

    /// Every top-level declaration of one file, exported or not.
    #[must_use]
    pub fn module_items_of(&self, file: &str) -> &[ModuleItem] {
        self.file_module_items.get(file).map_or(&[], Vec::as_slice)
    }

    /// The import declarations of one file.
    #[must_use]
    pub fn imports_of(&self, file: &str) -> &[Import] {
        self.file_imports.get(file).map_or(&[], Vec::as_slice)
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

    // Phase accounting. Every phase below is timed; the reader of a report
    // needs to know where the minutes went, not just that there were some.
    let mut phases: Vec<PhaseTiming> = Vec::new();

    let mem_probe = crate::debug_flags::DebugFlags::get().mem;
    if mem_probe {
        eprintln!(
            "[mem] after_lower files={} irs={} rss_kb={}",
            prepared.files().len(),
            prepared.irs.len(),
            crate::debug_flags::rss_kb()
        );
    }

    // The program graph is built first: non-dataflow checks that walk
    // interprocedural value flow (UAF free/use pairs) reuse it, and the
    // taint engine below gets the same instance.
    let prog = {
        let t = Instant::now();
        let prog = ProgramSvfg::new_with_module_aliases(
            statics,
            config,
            facts,
            Some(&prepared.file_aliases),
            Some(&prepared.fn_file),
        );
        if mem_probe {
            eprintln!(
                "[mem] after_svfg fns={} rss_kb={}",
                prog.functions.len(),
                crate::debug_flags::rss_kb()
            );
        }
        phases.push(PhaseTiming {
            phase: "graph".into(),
            ms: millis_since(t),
        });
        prog
    };
    // Non-dataflow policy checks run on the same lowered IR, no taint
    // needed, so weak-crypto/config bugs surface even with zero taint paths.
    // `facts` also carries corpus-learned checks installed by the bundle.
    // Package-scope context: policies carrying `package: Some(pkg)` only
    // fire in functions whose file imports `pkg`.
    let pkg_scope = checks::policy::PackageScope {
        fn_file: &prepared.fn_file,
        file_package_imports: &prepared.file_package_imports,
    };
    let (checker_findings, check_telemetry) = {
        let t = Instant::now();
        let (found, check_telemetry) = checks::check_all_with_telemetry(
            statics.values().copied(),
            facts,
            Some(&prog),
            Some(&pkg_scope),
        );
        if mem_probe {
            eprintln!(
                "[mem] after_checks findings={} rss_kb={}",
                found.len(),
                crate::debug_flags::rss_kb()
            );
        }
        phases.push(PhaseTiming {
            phase: "checks".into(),
            ms: millis_since(t),
        });
        (found, check_telemetry)
    };

    let fn_file = &prepared.fn_file;
    let file_source = &prepared.file_source;
    let mut engine = BackwardTaintEngine::new(&prog, config)
        .with_fact_table(facts)
        .with_fn_file(fn_file)
        .with_file_package_imports(&prepared.file_package_imports)
        // Route anchoring for per-call-site framing (schema §5.1):
        // consult the same predicate the harness lowered the file with.
        .with_route_registration(crate::harness::is_route_registration);
    let taint_timing = {
        let t = Instant::now();
        engine.run();
        millis_since(t)
    };
    if mem_probe {
        eprintln!(
            "[mem] after_taint findings={} rss_kb={}",
            engine.findings.len(),
            crate::debug_flags::rss_kb()
        );
    }
    phases.push(PhaseTiming {
        phase: "taint".into(),
        ms: taint_timing,
    });

    // Which functions ate the taint phase: the ten slowest, with their file
    // and how many sink arguments each one explored.
    let slowest_functions = slowest_functions(&engine, &prepared.fn_file);

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
            let cut_sites = f
                .cut_sites
                .iter()
                .map(|c| {
                    let cfile = fn_file.get(&c.function).cloned().unwrap_or_default();
                    let cline = c
                        .span
                        .and_then(|(start, _)| {
                            let src = file_source.get(&cfile)?;
                            let before = &src[..start.min(src.len())];
                            Some(before.matches('\n').count() as u32 + 1)
                        })
                        .unwrap_or(0);
                    LocatedCutSite {
                        kind: c.kind,
                        function: c.function.clone(),
                        detail: c.detail.clone(),
                        file: cfile,
                        line: cline,
                    }
                })
                .collect();
            Some(LocatedFinding {
                finding: f.clone(),
                file: file.clone(),
                line,
                column: col,
                cut_sites,
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

    // Functions the per-function work budget pushed into the degraded
    // (flow-insensitive) form during lowering: the report names them under
    // `analysis_incomplete` rather than silently returning weaker results
    // for them. Sorted so the JSON is stable across runs.
    let mut analysis_incomplete: Vec<IncompleteFunction> = prepared
        .irs
        .iter()
        .filter(|(_, ir)| ir.analysis_incomplete)
        .map(|(name, _ir)| IncompleteFunction {
            function: name.clone(),
            file: prepared.fn_file.get(name).cloned().unwrap_or_default(),
        })
        .collect();
    analysis_incomplete.sort_by(|a, b| (&a.file, &a.function).cmp(&(&b.file, &b.function)));

    // Lowering already happened before this function; its cost is carried
    // on the prepared program so `scan` and `scan_prepared` agree.
    phases.insert(
        0,
        PhaseTiming {
            phase: "lower".into(),
            ms: prepared.file_timings.iter().map(|f| f.ms).sum(),
        },
    );

    let failed_files = prepared.lower_failed_files.clone();
    let mut caps = prepared.lower_caps.clone();
    caps.extend(crate::telemetry::drain_caps());
    let mut telemetry = ScanTelemetry {
        phases,
        slowest_files: prepared.file_timings.clone(),
        slowest_functions,
        caps,
        checks: check_telemetry,
        suppressed: Vec::new(),
        errors: prepared.lower_errors.clone(),
        input: InputAccounting {
            submitted: prepared.submitted,
            scanned: prepared.file_timings.len(),
            failed: prepared.lower_failed_files.len(),
            unsupported: 0,
            failed_files,
            parse_partial: prepared.parse_partial.len(),
            parse_partial_files: prepared.parse_partial.clone(),
            functions: prepared.irs.len(),
        },
        taint: engine.stats,
    };
    telemetry
        .slowest_files
        .sort_by_key(|b| std::cmp::Reverse(b.ms));
    telemetry
        .slowest_files
        .truncate(crate::telemetry::SLOW_SAMPLE);
    // Files that failed to lower are errors, not silence: they land in both
    // places so a report with no `errors` key really did read everything.
    let errors = prepared.lower_errors.clone();

    ScanResult {
        findings: engine.findings,
        located,
        located_checker,
        checker: checker_findings,
        errors,
        analysis_incomplete,
        telemetry,
    }
}

/// The `SLOW_SAMPLE` functions whose sink exploration took longest, each
/// with the file it came from.
fn slowest_functions(
    engine: &BackwardTaintEngine<'_>,
    fn_file: &FxHashMap<String, String>,
) -> Vec<FunctionTiming> {
    let mut slowest = engine.fn_timings.clone();
    for entry in &mut slowest {
        if entry.file.is_empty() {
            entry.file = fn_file.get(&entry.function).cloned().unwrap_or_default();
        }
    }
    slowest.sort_by_key(|b| std::cmp::Reverse(b.ms));
    slowest.truncate(crate::telemetry::SLOW_SAMPLE);
    slowest
}

/// A function the per-function analysis budget forced into the degraded
/// (flow-insensitive) form, and the file it came from. Reported as
/// `analysis_incomplete` in the JSON report: the scan stays bounded and
/// never silently hands back a weaker result for such a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompleteFunction {
    /// Function key as the scanner knows it (`handle`, `file::handler`).
    pub function: String,
    /// Path of the file the function was lowered from.
    pub file: String,
}

/// The result of one scan: vulnerable findings + non-fatal errors.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// All sink findings (every verdict); retain only findings whose verdict
    /// is `Vulnerable` to obtain the alert set.
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
    /// Functions analyzed in degraded form because their per-function work
    /// budget expired (see [`IncompleteFunction`]). Empty for a scan in
    /// which every function was analyzed fully.
    pub analysis_incomplete: Vec<IncompleteFunction>,
    /// What the scan measured and what stopped it: phase timings, the files
    /// and functions that ate the time, every safety valve that fired, and
    /// how much of the input was actually readable. See
    /// [`crate::telemetry::ScanTelemetry`].
    pub telemetry: ScanTelemetry,
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

/// A [`crate::analysis::taint::engine::CutSite`] pinned to its file and line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedCutSite {
    pub kind: &'static str,
    pub function: String,
    pub detail: String,
    /// File holding the stop site (empty when the function's file is unknown).
    pub file: String,
    /// 1-based line (0 when no span was recorded).
    pub line: u32,
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
    /// Where the walk met a value it could not resolve (see [`SinkFinding::cut_sites`]).
    pub cut_sites: Vec<LocatedCutSite>,
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
