# Changelog
All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate versions and ships independently of the `frensense` binary: the
binary pins a compatible range (`0.8.x` today), not this release's version.
Built-in vocabulary tables live in `frensense-packgen`; the `.frc` envelope
lives in `frensense-bundler`. Their changes appear here only when they alter
what this crate does.

## [Unreleased]

### Added

- `TaintFunnel` (`ScanTelemetry::funnel`): measured call-site accounting for the
  taint phase — `calls_examined`, the three skip reasons, `not_a_sink` and
  `sink_calls`. The counters partition every call the analysis looked at
  (`calls_examined = skipped + not_a_sink + sink_calls`), so a scan can say how
  much of its input never reached the sink matcher: a large `not_a_sink` is
  vocabulary the engine never walks.
- `TaintFunnel::unmatched_callees` / `record_unmatched`: the callees the sink
  matcher ran on and rejected, with how often each was called, so a large
  `not_a_sink` can name the vocabulary behind it instead of only counting it.
  `top_unmatched` returns the busiest eight in a stable order; the tracked list
  is bounded at 32 distinct names, and calls past that bound still land in
  `not_a_sink`, so the partition is unaffected.
- `GraphSize` (`ScanTelemetry::graph`): functions, value-flow nodes, edges and
  cross-function edges of the program the taint phase walked, counted from the
  graph it actually built rather than inferred from the input.
- `CutSite::kind` `"passed-through"`: an external call with no analysed callee
  whose result the backward walk still followed into its arguments. It records
  an assumption rather than a stop (the library might sanitise, or might not
  carry them), so a silent verdict can name the call that hid the missing
  source. Pass-throughs keep their own budget, so a long chain of them can
  never displace the stop site that decided the verdict.
- `Instruction::dest`, `Instruction::mem_out` and `Instruction::defs`: the single
  definition of which variables an instruction defines. Both matches are
  exhaustive, so a new instruction kind has to be classified.
- `Debug` for the language spec structs, `LanguageRegistry`, `CheckContext`,
  `CheckRegistry`, `LoweringContext`, `GuardMap` and `CtxLink`, required by
  the `missing_debug_implementations` lint.

### Fixed

- **A nested destructuring pattern keeps the name of each part.** `{ body: {
  name } }` is the flat form written twice (`const { body } = x; const { name }
  = body`), but the intermediate part was an anonymous temporary, so name
  vocabulary never saw it: a variable named `body` is the request body, and
  hiding that name left a bare `export function t({ body: { name } }: any)`
  `Undecided` while `const { body } = x; const { name } = body` was reported.
  The intermediate now records its part's name, so the two spellings agree;
  a part whose name is not vocabulary (`{ opts: { cmd } }`) still stays silent.
  Measured on the reported shape: **0 findings before, 1 (code injection)
  after**.
- **Destructured and rest parameters bind the names inside them.** `bind_params`
  bound one variable per parameter node and named it after the node's text, so
  `function run({ h }: Opts)` produced a single parameter named `{ h }` while
  the body's `h` was an undeclared variable: the caller's object never reached
  the sink. `...parts` bound as `...parts`, so `parts` itself did not resolve.
  A pattern now keeps its parameter slot (the call's argument still maps to it)
  and binds through the same `LoweringContext::bind_pattern` a destructured
  declaration uses: one `LoadField` per object member, one `LoadElement` per
  array position, and a rest element takes the whole value. The helper recurses
  through the load it just emitted, so nested patterns (`{ a: { b } }`,
  `{ body: { name } }`) - and the declaration form `const { a: { b } } = obj`,
  which used to bind a variable literally named `{ b }` - keep their flow.
  Measured on the reported reproductions: destructured parameter **0 → 1**
  finding (OS command injection), rest parameter **0 → 1** (code injection via
  `parts.join`), nested declaration **0 → 1**, while a literal argument
  (`run({ h: "localhost" })`) and an untainted rest call stay clean.
  A bare `export function t({ body: { name } }: any)` with no caller is still
  `Undecided`: an exported parameter is not a source by itself, which is a
  source-classification question and not a binding one.
- **Go parameters are bound, with their declared types.** `bind_params` read
  the C `declarator` field for every `parameter_declaration`, and a Go
  declaration has no such field - its shape is one `name` field per binding
  plus `type`. No Go parameter was recorded at all, so a handler body's
  `request.URL.Query()` referenced an undeclared name and
  `classify_param_taint` never received the `*http.Request` / `*gin.Context`
  type it classifies on. Grouped (`a, b string`) and variadic (`rest ...int`)
  names are one declaration each, sharing its type; the C and Go shapes are now
  resolved by which field the grammar emits. Measured on
  `func handle(request *http.Request)` reading
  `request.URL.Query().Get("cmd")` into `exec.Command`: **0 findings before, 1
  (OS command injection) after**, while a scalar parameter (`literal string`)
  stays a non-source.

### Removed

- **Breaking:** `analysis::taint::context` (`ContextSensitiveTaintEngine`,
  `ContextualAlert`, `ContextStats`, `ROOT_CTX`, `CtxId`,
  `MAX_CONTEXTS_PER_FN`), 356 lines plus 483 lines of tests. It layered k=1
  call-site context sensitivity on the old forward engine, which production
  never constructs; the backward engine has its own call contexts and its own
  sibling-caller test (`call_site_context_separates_sibling_callers`).
- `check_all_with_graph` and `check_all_with_graph_scoped`, which had no caller;
  use `check_all_with_telemetry`.
- **Breaking:** the public surface now matches its consumers. 265 declarations
  that no crate outside `frensense-engine` names are `pub(crate)`, and
  `cargo public-api -p frensense-engine` drops from **4,481 to 3,264 lines
  (-27%)**, or 3,149 to 2,310 with `--omit auto-trait-impls`. Eight modules are
  crate-private (`ir::lowering::{control_flow,lvalue}`, `graph::steensgaard`,
  `checks::{int_overflow,noreturn,oob}`, `checks::uaf::{must_exec,uninit}`), and
  with them their internals: `InterproceduralTaintEngine` (the forward engine
  only tests ever constructed, the follow-up to the context-engine removal),
  `CheckRegistry`, `CheckContext`, `CheckScope`, `PackageScope`,
  `NonDataflowCheck`, `DiagnosticSink`/`NoopDiagnosticSink`, `Walker`,
  `CallGraph`/`CallGraphBuilder`/`CallTarget`, `Pair`/`PairCheck`/`FreeSite`/
  `Violation`/`CrossCtx`, `BufferInfo` and `LocId`.
  What stays public is what another crate actually reaches: `ProgramSvfg` and
  its fields, `FactTable`, `SinkFinding`/`SinkAlert`/`SinkFindingBuilder`, the
  check entry points and `scan`. The set was derived mechanically (name absent
  from every `.rs` outside the crate) and then confirmed by the compiler: each
  demotion a consumer needed returned as `private_interfaces`, `E0616`,
  `E0603` or `E0624` and was reverted. `cargo check --workspace --all-features
  --all-targets`, `cargo test --workspace --all-features`, the rustdoc
  `broken_intra_doc_links`/`private_intra_doc_links` gate and the clippy
  ratchet are green.
- 24 intra-doc links that pointed at now-private items became code spans, and
  one pre-existing unresolved link (`scan::ModuleResolution`) was fixed.

### Changed

- `CutSite` `"passed-through"` sites skip standard-library adapters (`iter`,
  `collect`, `map`, `map_err`, ...): they forward their operands by definition,
  so naming them buried the calls the engine genuinely has no model for.
  Detection never consults the filter; only the explanation is narrowed.

- Duplicate logic collapsed into one definition each (no behaviour change
  intended; engine tests unchanged and green):
  `FunctionIR::def_instruction` (3 copies, one of which only knew 6 instruction
  kinds), `graph::module::imports_for_function` (4 copies of the single-file
  import fallback), `NodeKey::instruction` (4 inline lookups),
  `facts::upsert_by_provenance` (7 inserts), lowering `jump_if_open` (11
  inline blocks), `read_modify` (compound assignment and `++`/`--` on fields
  and elements), `new_temp` (7 inline copies), and the doubled `CallPointer`
  fallback in call lowering.

- String-literal unquoting is one function (`ir::function::strip_quotes`,
  crate-private). The `policy` and `weak_hash` checks previously stripped the
  first and last byte of any literal that began with a quote character; they
  now strip only a matching pair, so a lone `"` or a mismatched `'a"` is left
  unchanged instead of being sliced (the lone-quote case could panic).
- Nine hand-written "what does this instruction define" matches (taint guard
  and walk, forward predicates, `guard_bypass`, UAF `uninit`, `leak`, SSA and
  SVFG construction) now call `Instruction::dest`/`defs`. The copies disagreed:
  the guard map ignored `Allocate`/`Dereference`/`Await`/`Yield`, `guard_bypass`
  ignored `Allocate`/`AddressOf`/`Dereference`, and `predicates` ignored
  `AddressOf`. All now cover every value-producing kind.
- Items that no external path could reach are now `pub(crate)`; no
  reachable public item changed.

### Fixed

- **Three safety caps stopped truncating silently.** `MAX_WALK_NODES` and
  `MAX_SCAN_NODES` in the UAF walker returned a partial answer with no trace,
  and the SSA work budget only set `analysis_incomplete` on the function (the
  report named the function but not why or how often). They now record
  `Cap::UafWalkNodes`, `Cap::UafCalleeScanNodes` and `Cap::SsaDegraded`, so a
  scan that dropped a free/use pair or lowered a function flow-insensitively
  says so in `truncations` instead of looking clean.
- **`FRENSdbg_CAPS` announces cap firings.** With the flag set, each cap
  prints one `frensense: cap fired: <id> - <effect>` line to stderr per scan
  (re-armed when the counters are drained), so a silently truncated analysis
  is visible in a debug run without adding a debugger or reading the cap
  sites. The flag is exposed as `DebugFlags::caps_enabled()` rather than a new
  field on the public `DebugFlags` struct.
- **The two learned-check evaluators now report where they disagree.**
  `LearnedChecks` (function-scoped: last-segment matching, a guard anywhere in
  the function suppresses) and `Policies` (program-scoped: the same facts via
  `PolicyFact::from_legacy`, import aliases, the guard must dominate the
  trigger) both consume `facts.learned_checks`, and the driver keeps the union
  of their findings. The paths are not equivalent: a qualified fact
  (`payments.runTool`) fires on a bare `runTool` only through the legacy path,
  while a non-dominating guard suppresses there but fires through the policy
  path. `FRENSdbg_CHECKS` prints `learned-check divergence (legacy only |
  policy only): <function> <rule> @<span>` for every such finding, and
  `checks/divergence_tests.rs` pins both directions. The flag is additive
  (`DebugFlags::checks_enabled()`), so the public `DebugFlags` shape is
  unchanged. This is observability, not a semantic fix: choosing one evaluator
  has to preserve the legacy `unless_range_check` interval logic, which the
  policy requirement does not reproduce.

## [0.8.2]

### Added

- `WeakPrimitiveRule::same_identity`, `InsecureConfigRule::same_identity`,
  and `KeySizeRule::same_identity` / `override_with` are the one definition of
  rule identity both install paths use; they are additive and do not change
  the fact wire shape.

### Fixed

- **Fact-authored severity is no longer dropped.** `CheckerFinding.severity`
  was copied from the driving fact (spec rule, learned check, authored policy)
  and then ignored: `advisory_from_checker` re-derived the level from the
  language registry. A learned `severity: critical` stayed at the registry's
  warning, a corpus `severity: info` became warning, and `health`'s `low`
  became warning. Severity now resolves registry < fact < bundle pattern
  through the shared six-label parser; an unparseable non-empty label warns
  and keeps the registry level instead of silently choosing a tier.
- **Weak-hash, insecure-config and key-size messages are live.** The six
  emissions in `checks/weak_hash.rs` wrote `message: String::new()`, so
  `WeakPrimitiveRule.message`, `WeakCryptoFact.message`, `KeySizeRule.message`
  and `InsecureConfigRule.message` were authored but unread. They are now
  carried verbatim: a bundle's prose wins, and the spec default pack leaves the
  field empty so the `frensense-lang` template renders from `params`.
- **A later fact overrides a rule with the same identity instead of
  appending.** `FactTable::apply_with` / `merge` deduped these tables with a
  whole-struct `contains`, so a consumer bundle overriding severity, message,
  or credential context appended a second rule that the first-match loop never
  reached: the documented "consumer bundle overrides the default pack" order
  was false for weak-hash, insecure-config and key-size rules. Identity is now
  the rule's call coverage (`rule_id` + selector/bare calls, `rule_id` +
  prefix, `rule_id` + call + slot), and the key-size floor is monotone
  (`max(existing, new)`) so a later seed can tighten it but never relax it.

## [0.8.1]

### Added

- **`ProgramBuilder`: per-file lowering as a first-class capability.**
  `add_file(path, source, ext, facts)` lowers exactly one file and returns a
  `FileReport` (functions produced, wall time, partial parse, lowering
  error); `finish()` merges the submitted files path-sorted and resolves
  modules. Lowering is local, so a frontend owns the loop, can parallelize
  or stop early, and gets progress from the call it made — no callback and
  no engine-owned UI state. This is the seam `scan` and
  `prepare_with_facts` are now built on.
- **`scan_file`: the single-file scan capability.** One file in, findings
  whose source and sink both live in that file out. `scan` /
  `scan_prepared` remain the interprocedural capability; the distinction is
  scope, not a second algorithm.

### Changed

- **The scan API is analysis-only again.** `ScanProgress`,
  `ScanProgressCallback`, `scan_with_progress`,
  `prepare_with_facts_with_progress`, `scan_prepared_with_progress` and
  `debug_flags::peak_rss_kb` are gone. They were added after the published
  `0.8.0` to let the CLI render a progress bar, which put terminal and
  process-metric concerns inside the engine crate; the consumer now drives
  `ProgramBuilder` and reads its own RSS. Relative to the published `0.8.0`,
  `0.8.1` is purely additive (the builder and `scan_file`), so dependents
  keep their `^0.8.0` requirement and no sibling manifest moves.
- **Every public item of `frensense-engine` is now documented, and the crate
  enforces it.** `cargo check` with `-W missing_docs` reported 507 undocumented
  public items (IR instructions and terminators, fact and entry kinds, the
  `uaf` check types, SVFG node kinds, taint path steps, lowering visitors,
  scan result types); it now reports 0. `#![warn(missing_docs)]` is set in
  `lib.rs`, so the existing `clippy -D warnings` gate rejects new
  undocumented public items. The `FRENSdbg_STATIC` and `FRENSdbg_PTS` lines in
  the `debug_flags` module docs, which had been merged onto one line, are
  separate again. Where a documented function can panic, a `# Panics` section
  says so (clippy's `missing_panics_doc` fires only on documented items).
  Doc examples run as doctests and assert the behaviour the text claims
  (sink matching and package scoping, `scan` and `scan_file`, SSA phis and the
  budget fallback, dominance, UAF, leak, weak key size, integer overflow,
  policy guards, scan completeness). Corrected docs that did not match the
  code: `ScanResult::findings`, `SSABuilder::work_used`, `InputAccounting::unsupported`,
  `wrap_threshold`. Documentation only: no behaviour or public API change. Measured:
  `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links"
  cargo doc -p frensense-engine --all-features --no-deps` is clean and
  `cargo test -p frensense-engine --all-features` passes (526 passed, 27 ignored); `cargo test -p frensense-engine --all-features --doc` passes.

## [0.8.0]

### Breaking

- **`SinkFinding` and `BackwardStats` are now `#[non_exhaustive]`**, and
  `SinkFinding` gains a `cut_reasons` field (surfaced by `--explain`). Adding a
  field to these previously all-public constructible types is a breaking change
  under Cargo's `0.x` rules; the `0.8.0` line absorbs it and `non_exhaustive`
  keeps future field additions minor-compatible.
- **`FactTable::sink_signature_scoped` and `FactTable::is_sink_call_scoped`
  take an extra language parameter**, and the types they key on
  (`HintKind`, `LearnedFactEntry`, `TeachableNodeRole`, `PolicyRequirement`)
  gained variants. `cargo semver-checks check-release --release-type patch`
  against the published `0.7.0` reports 6 major checks failing: those arity
  changes, the two `non_exhaustive` structs, and the added enum variants.

### Added

- **The harness understands single-file containers: source passing through
  `lower_source_detailed` is now rewritten by the spec's new `preprocess`
  stage before parsing.** The default is the identity, so nothing changes
  for the six existing languages; the new Vue spec uses it to blank
  template/style markup into same-length whitespace, which keeps every byte
  offset — and every sink span and reported line/column — anchored to the
  original `.vue` file. There is exactly one call site, on the shared
  harness path the scanner, MCP, LSP and the bundler's fact extractor all
  lower through.

- **`--explain` support**: surfaces *where the engine stayed silent*. Every
  explored sink argument that did not become an advisory records the reason the
  backward taint walk was cut (`guard`, `value-const`, `sanitizer`,
  `unresolvable`), so a false negative is no longer a black box.
- **Advisory CWE classification**: findings carry their canonical CWE through
  the reporting pipeline.
- **Language-scoped provider facts**: `FunctionIR` carries the language it was
  lowered from, and sink signatures / source vocabulary are keyed by
  `(language, call)` (`FactTable::lang_sink_signatures` / `lang_sources`), so a
  mixed-language scan no longer arms every file with every language's provider
  vocabulary (measured: 78 -> 26 advisories on a mixed TS/Rust/Python/Go repo,
  0 flows lost per language). The shared table keeps only genuinely
  language-agnostic knowledge.
- **Flow steps carry real locations**: the taint origin records its source
  span (declaration fallback for entry parameters), so SARIF's first
  `codeFlow` step is a region instead of `location: null`, and the origin is
  no longer printed twice.
- **`DiagnosticSink` trait on `CheckContext`**: the check context provides a
  diagnostic interface for truncations and skips. The current default driver
  supplies a no-op sink, so this is an extension seam, not yet an emitted
  telemetry source.
- **`catch_unwind` check isolation**: every non-dataflow check (both
  program-scoped and function-scoped) now runs inside
  `std::panic::catch_unwind(AssertUnwindSafe(...))`. A panicking check records
  `CheckOutcome::Panicked(msg)` in telemetry and prints to stderr; all sibling
  checks continue running. This prevents a single malformed function from
  aborting the entire scan.
- **`check_all_with_registry_and_telemetry`**: a new public entry point accepts
  an explicit `CheckRegistry`, enabling unit tests and future plugin scenarios
  to supply a synthetic check set without touching the global registry.
- **32 MiB worker thread stacks**: each language group scan runs on a
  dedicated OS thread spawned with `stack_size(32 * 1024 * 1024)`. File
  lowering also uses a scoped 32 MiB worker per file, containing unwindable
  panics to the affected file. This reduces stack exhaustion on deeply nested
  inputs; Rust stack overflow aborts are not recoverable by `catch_unwind` and
  still cannot be promised to complete normally.
- **`ScanTelemetry.checks`**: per-check telemetry (`id`, `scope`, `ran`,
  `findings`, `millis`, `outcome`) is collected for every registered check and
  exposed in the JSON `analysis` envelope under `analysis.checks`.
- **`ScanStatus` enum** (`Complete | Partial | Failed`): computed from
  `ScanTelemetry` and the `IncompleteFunction` list after every scan. Drives the
  terminal footer and the `--fail-on-incomplete` exit code.
- **`function_complexity` check** (CWE-1121): cyclomatic complexity ceiling per
  function, ceiling configurable through the CLI's `--max-complexity` and
  enabled by `--hygiene`.
- **`FRENSdbg_MEM`: memory attribution from inside the process.** A debug flag
  (off by default, installed like the other `FRENSdbg_*` flags) dumps RSS plus
  graph sizes at every phase boundary - lowering → SVFG → callgraph → bindings
  → summaries → cross edges → checks → taint - and then per-function and
  per-sink-site deltas inside the backward walk, with visited-state,
  reached-function, context and interned-chain counts per walk. `perf`,
  `valgrind` and `gdb` attachment are all unavailable in a restricted-ptrace
  environment, so the scanner now reports its own allocation behaviour; this is
  how the path-reconstruction clone below was found.
- **Fact-vocabulary fingerprint**
  (`FACT_VOCABULARY_FINGERPRINT`, currently `0x4994_27a8_ed94_e470`): a
  reproducible FNV-1a over the ordered serialized vocabulary (hint kinds +
  `LearnedFactEntry` variants). New fact variants are compile-enforced
  (`HintKind::index` / `LearnedFactEntry::wire_index` exhaustive matches), and a
  ratchet test fails until `FACT_VOCABULARY_FINGERPRINT` is updated - which is
  the cue to bump `BUNDLE_VERSION` and regenerate the default pack.

### Changed

- **Fact-table language keys come from `LanguageSpec::fact_language`**
  instead of `spec.name()`. For the six registered languages this is the
  same string (the default), so existing `.ts`/`.py`/`.c`… scans are
  byte-for-byte unchanged; for the new Vue container spec the key is
  `typescript`, which is what makes the default pack's typescript section
  and consumer-bundle facts apply to `.vue` script bodies — before this,
  a `vue` key excluded a `.vue` file from every language-scoped fact table
  (the pack's `eval`, `req.body` and `innerHTML` furniture was silent on
  SFC code). Four call sites moved to the new key: the per-IR `language`
  stamp in both lowering entry points (which drives every scoped fact
  lookup in the backward and forward engines), the route-pattern lookup,
  and `languages_for_exts`, whose seeding-wide debug assertion now checks
  distinct fact languages rather than a 1:1 spec-to-language map.
- **Module-resolution candidate extensions include the container formats
  they resolve**: `import ... from './Comp.vue'` now resolves alongside
  the TS/JS candidates, and the previously missing `.mts`/`.cts` are
  candidates too.

### Fixed

- **Guard denylist matching strips literal quotes before testing patterns.**
  `FactTable::is_guard_denylist` tested raw literal text (`"\"\""`, `"'admin'"`)
  against patterns. When the quote delimiters (`'`, `"`) were added to the
  guard denylist, any quoted literal matched against its own enclosing quotes,
  inverting comparisons like `if v != ""` into false guards that marked the true
  branch sanitized. Unquoting the literal before testing against denylist
  patterns preserves normal string comparisons while recognizing break-out
  delimiter rejections (`if "'" in bar: return`).
- **Module-scope statements are analyzed.** Dataflow and policy checks only
  ever ran over `FunctionIR`s extracted from function bodies, so the same two
  statements were one finding inside `def handler():` and silent at file
  scope: `cmd = request.args.get('c'); os.system("echo " + cmd)` produced **0**
  findings at the top level, under a top-level `if True:`, and as a bare JS
  `execSync('ls ' + process.argv[2])` expression. That left CLI tools,
  ETL/notebook scripts, Django `settings.py`, and
  `if __name__ == "__main__": app.run(debug=True)` outside every analysis
  except the static pseudo-IRs that only carry declaration initializers. The
  harness now lowers the file's root-level executable statements into one
  `<module>` pseudo-function (`is_static_data`, so it is never a call target).
  Functions (their own IRs), imports, and JS/TS `const`/`let`/`var`
  statements - already owned by the binding walk or a static pseudo-IR - are
  skipped, so nothing is lowered twice; a file with no module-level
  instruction gains no pseudo-function. Measured on OWASP BenchmarkPython:
  unchanged at TP **172** / FP **40** / FN **280** / TN **738**, score
  **32.9%** (the corpus is function-only), while the four shapes above went
  from 0 to 1 finding each, and the function/declaration controls still report
  exactly once. Known limit: a module-level binding that feeds a later
  module-level sink (`const input = process.argv[2]; execSync(input)`) spans
  two IRs, so the source is not linked to that sink; the sink is found, the
  flow is not.
- **A branch or `match` arm whose condition is fixed at compile time is no
  longer lowered.** Every arm used to be lowered and merged, so an assignment
  in an arm that can never execute reached the join and the backward walk
  reported taint no execution can produce. A table lookup that selects a fixed
  label is the everyday shape: `possible = "ABC"; guess = possible[1]; match
  guess: case 'A': bar = param; case 'B': bar = 'bob'; ...`, where the dead
  `case 'A'` / `case 'C' | 'D'` assignments tainted `bar` although `guess` is
  `'B'`. A small evaluator (`ir/lowering/const_eval.rs`) now answers for
  literals, variables bound to a literal (or another decidable value) earlier
  in the same straight-line region, and the operators whose result on those
  values is unambiguous (arithmetic, comparison, `in`/`not in`, `is`,
  `and`/`or`). `visit_branch` lowers only the taken arm, and `visit_match`
  lowers only the selected Python arm - literal, union, and `_` patterns, no
  guards; an arm whose pattern is a capture/class/dict/constant reference, or
  any construct the evaluator cannot decide, keeps the old over-approximate
  lowering. Constants are invalidated at every join (`if`, loop, `switch`,
  `match`, ternary, preprocessor chain, `try`), so a variable assigned on one
  path is never treated as constant after the merge. Measured on OWASP
  BenchmarkPython: score **31.0% -> 32.9%** (FP **55 -> 40**, TP unchanged at
  **172**); the 15 fixed cases are lookups broken by an unreachable tainted
  arm. The remaining lookup-shaped alerts have an arm that really is taken
  (`guess = possible[0]`) or come from guard/sink semantics, not folding.
  The classification half (Python `match_statement` reaching `visit_match` at
  all) is in `frensense-lang`.
- **A handler parameter is a source when the language spec classifies it, and
  Python's annotated parameters are bound again.** Two gaps kept framework
  handlers silent. `bind_params` had no arm for Python's `typed_parameter`
  (its binding is the node's first child, not a `name` field) or for the
  defaulted/splat wrappers, so `def h(x: Request)` never recorded `x` as a
  parameter at all and the body reference was lowered as an undeclared name.
  Separately, the hook that answers "is this parameter attacker input?"
  (`LanguageSpec::classify_param_taint`, implemented by every provider) had no
  caller in the engine - only the pack's name/type vocabulary seeded a
  parameter. `SourceScope::classifies_param` now consults the hook with the
  parameter's name and annotation, so FastAPI's `Request` type - which no pack
  source pattern enumerates - starts the flow:
  `def run(x: Request): os.system("echo " + x.query_params.get("c"))` goes from
  **0 findings to 1** with the binding renamed, matching the `request`-named
  shape that already fired. Only `UserInput` origins seed backward taint (the
  environment/filesystem/network categories are not yet distinguished by the
  analysis, and honouring them would turn every parameter named `config` or
  `env` into a source), and entry-only names stay withheld, so the classifier
  cannot re-widen `argv` outside `main`. Scalar handler parameters
  (`def run(cmd: str)`) remain non-sources: whether a scalar carries request
  data depends on route registration, which the spec hook cannot see. Wiring
  the hook also activates the sibling `frensense-lang` fix that keeps the
  borrow marker in the Rust classifier (`&Path` is a filesystem path, not the
  axum `Path` extractor).
- **The points-to fixed point terminates on real code.** `SvfgBuilder` ran
  `while changed { … }` inside `PointsToAnalysis::analyze_inner` with no
  iteration cap, and on real repositories it never converged: a temporary pass
  counter printed `passes=200000 pts=315 fields=4` - the iteration count kept
  doubling while both set sizes stayed frozen, so nothing was being added any
  more. The only non-monotone rule in the loop was the **strong update**: a
  non-variable `StoreField`/`StoreElement` did `set.clear(); changed = true;`
  while other instructions merged the same `(loc, field)` back in - a
  clear-then-merge cycle that can never reach "no change". Field writes are now
  weak (union-only, monotone) for a may-analysis, and the loop carries a hard
  pass budget (`MAX_PASSES`) with a conservative fallback: on expiry the
  analysis stops refining and reports non-convergence instead of looping.
  `PointsToAnalysis::converged()` exposes the outcome to callers and
  `FRENSdbg_PTS=1` prints per-pass `{pass, killed, pts, fields}` traces. The
  three files that hung forever (`libpng/contrib/libtests/pngstest.c`,
  `nextjs/packages/next/src/shared/lib/dynamic.tsx`, `redis/src/server.c`) now
  converge in ≤ 5 passes, and libpng scans end-to-end in **17.6 s / 63
  findings** where it previously never returned.
- **SSA dominance was cubic; it is linear now.** The sequential-if-chain blowup
  (`repros/n10_perf/gen.py N`: N=100 → 0.13 s, N=400 → 6.8 s, N=3000 never
  finished) was not in taint analysis at all: phase taps showed
  `SSABuilder::build()` alone going 184 ms → 1507 ms → 12 044 ms, 8× per
  doubling, while parse+walk stayed in milliseconds. Two defects in
  `frensense-engine/src/ir/ssa.rs`: `compute_immediate_dominators` recomputed
  full dominator *sets* with a naive fixpoint iterated in random hash order
  (O(B³)), and the idom search then rescanned its candidates linearly (O(B²)
  per pass). Rewritten with the Cooper–Harvey–Kennedy iterative algorithm
  (reverse post-order, intersect on the dominator tree): **12 044 ms → 3.4 ms
  at N=400**, and `gen.py 3000` completes in 35.9 s / exit 0.
- **A per-function work budget reports degraded analysis instead of hanging or
  silently weakening it.** SSA construction is bounded by
  `DEFAULT_SSA_BUDGET` (5 000 000 units). On expiry the function falls back to
  its raw flow-insensitive IR, its phi placement is undone, and
  `FunctionIR::analysis_incomplete` is set. That is surfaced end-to-end rather
  than swallowed: the `--json` report gains an `analysis_incomplete` array
  naming each degraded function and its file, and the CLI warns about them on
  stderr. No function is ever dropped or silently scanned with a weaker
  result.
- **Taint-path reconstruction no longer clones a whole `FunctionIR` per
  step - this is what made real C repositories run out of memory.**
  `reconstruct_path` pushed `self.prog.functions[cf].ir.clone()` into the chain
  for every hop, so one deep walk across the program graph retained a full
  function IR (blocks, var metadata, string tables) per path step. On
  `redis/src` a single `fopen` walk from `cliLoadPreferences` allocated
  **1.47 GiB** in that reconstruction, and the whole-directory scan aborted at
  5.65 GiB after 215 s - every individual file in the same tree scanned in
  ≤ 4 s and ≤ 50 MB, so only the multi-file path was affected. The chain now
  borrows the IR and reads only the byte span it needs, which takes that same
  site from 1.47 GiB to 22 MB. Measured after the fix: the 96-file subset that
  aborted at 5.1 GiB / 182 s now runs in **42 s / 845 MB**, `redis/src` (229
  files) in **126 s / 2.68 GB**, and the whole `redis` checkout in **350 s /
  2.64 GB with 64 advisories** - all exit 0.
- **The install-time language merge no longer shares one name space.** Removing
  foreign *entries* from the vocabulary tables was not enough, because the
  install merged every language's vocabulary into one name-keyed table
  (`apply_language_entries` built a per-language temp table and then merged it
  last-wins). Any scan that contained two languages shared one name space:
  adding a single `.rs` file to a TypeScript package took the scan from 6
  findings to 40, every one of them a `prisma.order.create(...)` /
  `catalog.output(...)` / `logger.log(...)` call in `.ts` files armed by Rust's
  `File::create`, `Command::output` and `log` macros. The mirror error existed
  on the source side: Go's `http.ResponseWriter` parameter name `w` seeded
  taint in TypeScript files, and TypeScript's `input` did the same in Rust.
  Sink signatures (`lang_sink_signatures`) and source vocabulary
  (`lang_sources`) are now keyed by `(language, call)` / `language`,
  `FunctionIR` carries the language it was lowered from, and every match site
  (backward walk, forward engine, sink-alert predicates) passes its own
  language; the shared table keeps only genuinely language-agnostic knowledge
  (`"*"` pack group, bundle facts, hand-built configs). A blanket all-args
  placeholder seeded from `TaintConfig::sinks` never shadows the language's own
  slot/identity knowledge. Measured on a mixed TS/Rust/Python/Go repo: 78 -> 26
  advisories (52 removed, 0 added); each language still reports its own flows.
  Two probes that had been passing through the leak were corrected: `probe_57`
  (return-object-field) used a local named `w` and is now an explicit
  `Blind spot:` (a callee-allocated container's field has no cross-function
  heap edge), and the two-phase heap test now hands the engine its fact table.
- **Provider facts are language-scoped** (see above): `FunctionIR::language`,
  `FactTable::lang_sink_signatures` / `lang_sources`, and language-aware
  `is_sink_call_scoped` / `sink_signature_for_language` / `SourceScope`. The
  scoping rule is the second half of the merge-safety rule (all-args never
  widens slot-restricted): a fact that knows a call's slots beats a blanket
  name-only placeholder, whatever lane it sits in.
- **Bare last segments stopped arming unrelated receivers**: a sink
  declared under a module (`pickle.loads`, `subprocess.run`, `yaml.load`)
  publishes a bare shadow of its last segment because the walker matches a
  virtual call by method name, and that shadow used to arm every receiver in
  the program - `json.loads` inherited unsafe deserialization, `f.read(n)`
  inherited path traversal, `Workflow.run` inherited command injection. The
  fact table now records which roots a qualified declaration named
  (`receiver_qualified_sinks`) and which names a language declares bare
  (`bare_sink_names`); a name that is only ever declared qualified arms only
  under its own root or import origin, and a name a language never declares
  bare is verb-gated as well. Measured on four real repositories: 111 -> 93
  findings, every removed finding reviewed as a false positive, OWASP
  BenchmarkPython score unchanged (TPR 38.1%, FPR 7.1%), and the Juice Shop
  scan 3x faster (167s -> 54s) because the call graph no longer fabricates
  same-named interprocedural edges.
- **Minified JavaScript is skipped by content**: a single-line bundle with no
  filename hint was lowered as ordinary source, producing findings no one
  can act on.
- **The last two name-based guesses in the engine are pack facts**: the
  engine no longer assumes a call named `prepare*` creates a bound-parameter
  statement handle, or that a literal `false` argument disclaims security use
  of a weak digest. `HintKind::PreparedStatementPrefix` and
  `HintKind::WeakHashDisclaimer` carry those vocabularies in the default pack
  (and in any bundle that teaches them), so a new driver's factory spelling
  or a codebase's own disclaimer token is taught rather than compiled in. An
  empty set recognises nothing, so a config that teaches nothing never
  suppresses a flow. Behaviour is unchanged on the measured corpora (OWASP
  BenchmarkPython: TPR 38.1% / FPR 7.1%; 92 real-repo findings either side
  of the refactor).
- **Branch-arm-assigned variables survive the merge**: variables assigned only
  inside a `match`/`switch` arm were dropped from the environment at the branch
  merge (`env.pop` without hoisting), so a value defined in one arm and consumed
  after the branch lost its taint. The lowering now hoists per-arm bindings
  through a `hoist_arm_scope` pass, restoring flows that cross an arm boundary.
  CWE-22 class TPR 33.8% -> 35.4%, CWE-78 class TPR 23.1% -> 30.8%.
- **Propagator install is consistently last-wins**: duplicate `join`/`Join`
  propagator entries (a string/array method and a path-builder sharing one bare
  call key) resolved by order-dependent accident. The install used first-wins
  for the last-segment alias and an append-only receiver-block set, so a
  `tainted_receiver: false` entry permanently blocked the receiver edge even
  when a later `true` entry should unblock it - silently dropping the
  string/array-`join` receiver->return flow (Python `sep.join(...)`, JS
  `[...].join(...)`). `propagator_blocks_receiver` is now a two-way map
  (`call -> blocked`), and both the arg slots and the receiver flag install
  last-wins; `merge` matches. The redundant path-join duplicates (Python, Go,
  JS) and a duplicate JS `toString` are removed, with a packgen regression test
  asserting no duplicate propagator keys per language. OWASP score unchanged
  (25.9%).
- **Borrowed parameter types no longer match framework extractors**: the
  type-named source matcher strips the `&` when normalizing a parameter type,
  so `fn load(root: &Path)` no longer matched axum's `Path` extractor and
  reported every file-reading helper as attacker-controlled. The borrow marker
  is kept (`&Path` is `std::path::Path`); by-value extractors (`Path<T>`) still
  fire. New fixtures: `type_source_tests`.

#### C Taint Precision

- **C command-line false positives reduced**: name-only `argv`/`argc` references
  no longer count as attacker-controlled sources, and path-labeled sinks only
  inspect path-carrying arguments, not mode flags, lengths or other slots.
- **BFS parent is now stable across multi-edge nodes**: the backward taint walk
  kept the *last* BFS parent seen for each node rather than the first. On graphs
  where multiple edges reach the same taint node the reported path could diverge
  from the actual flow depending on iteration order. `record_parent` now writes
  only when no entry exists, making the reconstructed path deterministic and
  correct for the first-discovered route.
- **Name-only `argv`/`argc` references are not sources**: the C source matcher
  previously treated any identifier named `argv` or `argc` as attacker-controlled
  input regardless of context. Name-only uses (e.g. passing `argc` as an integer
  count) are now silent; only call-position uses of `argv` that carry a path
  argument continue to taint. Eliminates a class of false positives on C command
  dispatch code.
- **Non-path sink arguments in C are silent**: path-labeled C sinks
  (`fopen`, `open`, `stat`, etc.) previously armed every argument slot. The
  forward predicate now restricts taint alerting to slots that actually carry a
  path value, leaving integer flags, mode bits, and buffer-length arguments
  clean.
- **C destination-buffer writes preserve taint**: calls described by the
  default pack's buffer vocabulary now connect a source argument to later
  reads of an aliased destination buffer. This closes the missed
  `strcpy(buf, argv[1]); system(buf)` flow without treating every call argument
  as a write or adding analysis work to non-C functions.
- **C buffer vocabulary covers appends, copies and formatted writes**: the
  default pack's buffer contract named only `strcpy`, a source-less `strncpy`
  and a source-less `snprintf`, so `strcat(buf, argv[1]); system(buf)` stayed
  silent while the same `strcpy` flow alerted. The vocabulary now carries
  `stpcpy`, `strlcpy`, `strcat`, `strncat`, `strlcat`, `sprintf` and `snprintf`
  with source arguments (`strncat`/`strlcpy`/`strlcat` sourced from argument 1,
  bounded by argument 2; `sprintf`/`snprintf` sourced from the first variadic
  argument, the one the format consumes), so an appending or formatted write
  connects `strcat(dst, argv[1])` to a later `system(dst)`. Separately, a
  destination reached through pointer arithmetic lost its identity:
  `strcpy(dst + 3, src)`, `&dst[i]` and `(char *)dst` lower to a temporary, so
  the write was modelled against that temporary instead of the buffer, and no
  later read of `dst` was tainted. The SVFG now strips `+`, `-`, casts and address-of back to
  the variable naming the object, stopping at the first definition that is not
  one of those, so a pointer loaded from memory is never mistaken for the
  object it points at. The vocabulary half of this change is in
  `frensense-packgen`; three new `path_tests` fixtures (append, formatted write,
  offset destination) report `system(dst)` Clean before the change and
  Vulnerable after, and `cargo test --workspace --all-features` stays green
  (504 engine tests).
