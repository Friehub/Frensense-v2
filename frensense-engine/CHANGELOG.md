# Changelog
All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate versions and ships independently of the `frensense` binary: the
binary pins a compatible range (`0.8.x` today), not this release's version.
Built-in vocabulary tables live in `frensense-packgen`; the `.frc` envelope
lives in `frensense-bundler`. Their changes appear here only when they alter
what this crate does.

## [0.8.0] - 2026-10-30

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

### Fixed

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
