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
/// `files` maps file path → extension (used to pick the language spec).
/// Files are lowered one at a time through [`ProgramBuilder`] and then
/// analyzed as one interprocedural program.
pub fn scan(
    files: &[(String, String, String)], // (path, source, ext)
    config: &TaintConfig,
    facts: &FactTable,
) -> ScanResult {
    let started = Instant::now();
    let mut builder = ProgramBuilder::new();
    add_sorted(&mut builder, files, Some(facts));
    let mut result = scan_prepared(&builder.finish(), config, facts);
    result.telemetry.phases.push(PhaseTiming {
        phase: "total".into(),
        ms: millis_since(started),
    });
    result
}

/// Scan one source file: the single-file capability.
///
/// Only flows whose source and sink both live in `source` can be found. A
/// flow that starts here and ends in another file is the program
/// capability's job ([`scan`] / [`scan_prepared`]); a frontend picks the one
/// that matches what it has in scope (an editor buffer, one path from
/// `frensense_scan_file`, or a whole repository).
pub fn scan_file(
    path: &str,
    source: &str,
    ext: &str,
    config: &TaintConfig,
    facts: &FactTable,
) -> ScanResult {
    let started = Instant::now();
    let mut builder = ProgramBuilder::new();
    builder.add_file(path, source, ext, Some(facts));
    let mut result = scan_prepared(&builder.finish(), config, facts);
    result.telemetry.phases.push(PhaseTiming {
        phase: "total".into(),
        ms: millis_since(started),
    });
    result
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

impl std::fmt::Debug for PreparedProgram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedProgram")
            .field("files", &self.file_timings.len())
            .field("functions", &self.irs.len())
            .field("lower_errors", &self.lower_errors.len())
            .finish()
    }
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

#[allow(
    clippy::disallowed_methods,
    reason = "lowering runs on a dedicated 32 MiB thread because real-world deeply nested functions overflow the default 4 MiB stack; stacker cannot recover a stack overflow that happens inside the tree-sitter lowering call frames"
)]
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

/// One file lowered by a [`ProgramBuilder`], before the program-wide merge.
#[derive(Debug)]
struct LoweredFile<'a> {
    path: String,
    source: &'a str,
    ext: String,
    functions: FxHashMap<String, FunctionIR>,
    parse_partial: bool,
    caps: Vec<CapHit>,
    ms: u128,
    error: Option<String>,
}

/// Lowering outcome for one file, returned by [`ProgramBuilder::add_file`].
///
/// This is the per-file feedback a frontend renders as progress: which file
/// finished, how many functions it produced, whether the parse tree was
/// broken, and why lowering failed when it did.
#[derive(Debug, Clone)]
pub struct FileReport {
    /// Path exactly as submitted.
    pub path: String,
    /// Functions the file lowered to (`0` when lowering failed).
    pub functions: usize,
    /// Milliseconds spent lowering this file.
    pub ms: u128,
    /// The parse tree had errors; analysis used the recovered tree.
    pub parse_partial: bool,
    /// Why lowering failed. The file is left out of the program and the
    /// reason is recorded in the scan's error accounting too.
    pub error: Option<String>,
}

/// Builds a [`PreparedProgram`] one file at a time.
///
/// This is the per-file capability behind [`scan`]. A frontend submits files
/// itself — so it owns the loop, the counter, any parallelism, and early
/// cancellation — and acts on each [`FileReport`] immediately.
/// [`finish`](Self::finish) then merges the submitted files deterministically
/// and resolves modules. Lowering is local, so submission order does not
/// affect the result.
///
/// The builder borrows each file's source text for the lifetime of the
/// buffer: a scan never keeps a second copy of the corpus in memory.
#[derive(Debug, Default)]
pub struct ProgramBuilder<'a> {
    files: Vec<LoweredFile<'a>>,
}

impl<'a> ProgramBuilder<'a> {
    /// A builder with no files.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lower one source file and remember it for [`finish`](Self::finish).
    ///
    /// A lowering failure is contained here: the file is retained as an
    /// error in the accounting and reported through [`FileReport::error`],
    /// exactly as [`scan`] reports a failed file.
    pub fn add_file(
        &mut self,
        path: &str,
        source: &'a str,
        ext: &str,
        facts: Option<&FactTable>,
    ) -> FileReport {
        let started = Instant::now();
        let lowered = lower_isolated(path, source, ext, facts);
        let ms = millis_since(started);
        match lowered {
            Ok((functions, parse_partial, caps)) => {
                let count = functions.len();
                self.files.push(LoweredFile {
                    path: path.to_owned(),
                    source,
                    ext: ext.to_owned(),
                    functions,
                    parse_partial,
                    caps,
                    ms,
                    error: None,
                });
                FileReport {
                    path: path.to_owned(),
                    functions: count,
                    ms,
                    parse_partial,
                    error: None,
                }
            }
            Err(error) => {
                self.files.push(LoweredFile {
                    path: path.to_owned(),
                    source,
                    ext: ext.to_owned(),
                    functions: FxHashMap::default(),
                    parse_partial: false,
                    caps: Vec::new(),
                    ms,
                    error: Some(error.clone()),
                });
                FileReport {
                    path: path.to_owned(),
                    functions: 0,
                    ms,
                    parse_partial: false,
                    error: Some(error),
                }
            }
        }
    }

    /// Merge every submitted file into one program.
    ///
    /// Submission order does not matter: files are merged path-sorted, so a
    /// colliding function name rekeys the same way on every run.
    #[must_use]
    pub fn finish(mut self) -> PreparedProgram {
        // Deterministic merge order (path-sorted): which twin of a colliding
        // name keeps the bare key must not depend on submission order.
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
        let submitted = self.files.len();
        // Module resolution consumes the whole input list, including files
        // whose lowering failed: a failed twin still declares imports that
        // another file's resolution may need to see. Paths and extensions are
        // owned; sources stay borrowed from the caller's buffers.
        let program: Vec<(String, &'a str, String)> = self
            .files
            .iter()
            .map(|f| (f.path.clone(), f.source, f.ext.clone()))
            .collect();

        let mut irs: FxHashMap<String, FunctionIR> = FxHashMap::default();
        let mut fn_file: FxHashMap<String, String> = FxHashMap::default();
        let mut file_source: FxHashMap<String, String> = FxHashMap::default();
        let mut lower_errors: Vec<String> = Vec::new();
        let mut lower_failed_files: Vec<String> = Vec::new();
        let mut lower_caps: Vec<CapHit> = Vec::new();
        let mut parse_partial_files: Vec<String> = Vec::new();
        let mut file_timings: Vec<FileTiming> = Vec::new();

        for file in self.files {
            if let Some(error) = file.error {
                lower_failed_files.push(file.path);
                lower_errors.push(error);
                continue;
            }
            let LoweredFile {
                path,
                source,
                functions,
                parse_partial,
                caps,
                ms,
                ..
            } = file;
            lower_caps.extend(caps);
            if parse_partial {
                parse_partial_files.push(path.clone());
            }
            file_timings.push(FileTiming {
                file: path.clone(),
                ms,
                functions: functions.len(),
            });
            for (name, mut ir) in functions {
                file_source
                    .entry(path.clone())
                    .or_insert_with(|| source.to_owned());
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
        let program_refs: Vec<(&str, &str, &str)> = program
            .iter()
            .map(|(path, source, ext)| (path.as_str(), *source, ext.as_str()))
            .collect();
        let res = crate::graph::module::ModuleAliasResolver::build_from_refs(
            &program_refs,
            &ir_names,
            &fn_file,
        );

        PreparedProgram {
            irs,
            fn_file,
            file_source,
            file_aliases: res.file_aliases,
            file_package_imports: res.file_package_imports,
            file_imports: res.file_imports,
            file_exports: res.file_exports,
            file_module_items: res.file_module_items,
            lower_errors,
            parse_partial: parse_partial_files,
            submitted,
            lower_caps,
            lower_failed_files,
            file_timings,
        }
    }
}

/// Lower every file once, remembering which file each function came from
/// (functions are keyed by name; first file wins on collision).
///
/// # Errors
/// Lowering failures are recorded in the returned program's error accounting
/// rather than returned: a scan continues without the file and says so.
pub fn prepare(files: &[(String, String, String)]) -> Result<PreparedProgram, String> {
    prepare_with_facts(files, None)
}

/// Lower every file once with dynamic bundle facts.
///
/// # Errors
/// Lowering failures are recorded in the returned program's error accounting
/// rather than returned: a scan continues without the file and says so.
pub fn prepare_with_facts(
    files: &[(String, String, String)],
    facts: Option<&FactTable>,
) -> Result<PreparedProgram, String> {
    let mut builder = ProgramBuilder::new();
    add_sorted(&mut builder, files, facts);
    Ok(builder.finish())
}

/// Submit `files` in path-sorted order, the order the pre-builder lowering
/// loop used. Determinism lives in [`ProgramBuilder::finish`]; this only
/// keeps the convenience entry points byte-for-byte compatible.
fn add_sorted<'a>(
    builder: &mut ProgramBuilder<'a>,
    files: &'a [(String, String, String)],
    facts: Option<&FactTable>,
) {
    let mut ordered: Vec<&'a (String, String, String)> = files.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, source, ext) in ordered {
        builder.add_file(path, source, ext, facts);
    }
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
#[allow(
    clippy::disallowed_macros,
    reason = "the FRENSdbg_MEM probes are process-level debug output, printed only when that debug flag is enabled"
)]
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

#[cfg(test)]
mod program_builder_tests {
    use super::{ProgramBuilder, scan_file, scan_prepared};
    use crate::analysis::taint::facts::seeded_tables;

    fn ts_tables() -> (
        crate::analysis::taint::config::TaintConfig,
        crate::analysis::taint::facts::FactTable,
    ) {
        seeded_tables(["ts"])
    }

    /// Lowering is local and `finish` merges path-sorted, so the order a
    /// frontend submits files in must not change what the scan finds.
    #[test]
    fn submission_order_does_not_change_findings() {
        const PREFIX: &str = "export function wrap () {\n  return";
        let a = format!("{PREFIX} (req) => {{\n    noop(1)\n  }}\n}}\n");
        let b = format!("{PREFIX} (req) => {{\n    exec(req)\n  }}\n}}\n");
        let (config, facts) = ts_tables();

        let mut forward = ProgramBuilder::new();
        forward.add_file("app/a.ts", &a, "ts", Some(&facts));
        forward.add_file("app/b.ts", &b, "ts", Some(&facts));
        let mut reverse = ProgramBuilder::new();
        reverse.add_file("app/b.ts", &b, "ts", Some(&facts));
        reverse.add_file("app/a.ts", &a, "ts", Some(&facts));

        let first = scan_prepared(&forward.finish(), &config, &facts);
        let second = scan_prepared(&reverse.finish(), &config, &facts);
        let coords = |r: &super::ScanResult| {
            r.located
                .iter()
                .map(|l| (l.file.clone(), l.line, l.finding.sink.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(coords(&first), coords(&second));
    }

    /// The single-file capability lowers and scans exactly one file.
    #[test]
    fn scan_file_scans_one_file() {
        let (config, facts) = ts_tables();
        let src = "app.get(\"/x\", (req, res) => { eval(req.body.cmd); });\n";
        let result = scan_file("app/handler.ts", src, "ts", &config, &facts);
        assert!(result.errors.is_empty(), "scan errors: {:?}", result.errors);
        assert!(
            result.located.iter().any(|l| l.finding.sink == "eval"),
            "single-file scan missed the flow: {:?}",
            result
                .located
                .iter()
                .map(|l| (&l.file, &l.finding.sink))
                .collect::<Vec<_>>()
        );
    }

    /// A file that cannot be lowered reports its error on the add_file call
    /// and leaves the rest of the program scannable; it never aborts.
    #[test]
    fn add_file_reports_failure_and_keeps_the_program() {
        let (config, facts) = ts_tables();
        let mut builder = ProgramBuilder::new();
        let good = builder.add_file(
            "app/good.ts",
            "export function f() {}\n",
            "ts",
            Some(&facts),
        );
        assert!(good.error.is_none(), "good file: {good:?}");
        let bad = builder.add_file("app/bad.zzz", "not source", "zzz", Some(&facts));
        assert!(bad.error.is_some(), "unknown extension must fail lowering");

        let result = scan_prepared(&builder.finish(), &config, &facts);
        assert_eq!(result.telemetry.input.failed, 1);
        assert_eq!(result.telemetry.input.scanned, 1);
    }
}
