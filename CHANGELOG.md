# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Scope.** This file is the changelog of the `frensense` crate (the binary and
consumer library in `src/`): CLI, MCP, LSP, reporting, policy and build
identity. It is what a release tag (`vX.Y.Z`) points at. Changes inside the
workspace crates are recorded in their own changelogs, which version and ship
independently:

- [`frensense-engine/CHANGELOG.md`](frensense-engine/CHANGELOG.md) — IR, graphs, taint analysis, checks, harness, `scan` API
- [`frensense-lang/CHANGELOG.md`](frensense-lang/CHANGELOG.md) — language specs, rule cards, severities, CWE tables
- [`frensense-bundler/CHANGELOG.md`](frensense-bundler/CHANGELOG.md) — `.frc` format, corpus bundling, `lint`, embedded default pack
- [`frensense-packgen/CHANGELOG.md`](frensense-packgen/CHANGELOG.md) — the generated built-in vocabulary behind the default pack

Sections below `0.8.0` predate that split and are the combined release
narrative of the tagged binaries. `frensense-devtools` is an unpublished
harness and keeps no changelog.

## [0.8.0] - 2026-10-30

### Breaking
- **Version bump to 0.8.0** (from 0.7.0). This release adds fields to public
  types (`CliOptions.explain`, `SinkFinding.cut_reasons`,
  `Candidate::Check.package`). Under Cargo's `0.x` rules any field addition to
  a constructible public type is a breaking change, so the crates that changed
  move to the `0.8.0` line. To keep future additions minor-compatible, the
  evolving output/option DTOs are now `#[non_exhaustive]`: `CliOptions`,
  `Advisory`, `ExplainRecord`, `SinkFinding`, `BackwardStats`, and `Candidate`.
  Consumers read fields (and match `Candidate` with a wildcard arm); they no
  longer construct these types via literals.
- **`reporting` module removed; two helpers moved to `policy`.**
  `frensense::reporting::{reports_finding, apply}` are now
  `frensense::policy::{reports_finding, apply}`, and `print_results` (in
  `cli::print_results` and `cli::reporting::print_results`) takes one more
  parameter (6 instead of 5) for the explain record. Library consumers calling
  either helper must update the path and the call.
- `frensense-engine`, `frensense-lang` and `frensense-bundler` carry their own
  breaking entries. `cargo semver-checks check-release --release-type patch`
  against the published `0.7.0` reports **4** major checks failing for this
  crate (module removed, two functions moved/renamed, arity change,
  `Advisory` now `non_exhaustive`), **6** for the engine, **3** for the language
  specs and **3** for the bundler.

### Added

#### Code Hygiene & Complexity Controls
- **`--hygiene` flag**: enables code hygiene and structural health rules (such
  as `function_complexity`, CWE-1121) under any profile without requiring
  `--profile strict`. Polyglot developers running `--profile default` or
  `--profile recommended` can now monitor structural code health without
  surfacing unproven experimental rules.
- **`--max-complexity <n>` flag**: configures the cyclomatic complexity ceiling
  (default: 25) for the `function_complexity` check directly from the command
  line. Setting `--max-complexity` automatically enables hygiene rules so
  findings are never silently suppressed. Preserves Frensense's zero-config,
  language-agnostic architecture without introducing TOML configuration files.
  The check itself lives in `frensense-engine`.

#### CLI Diagnostics
- **`--explain` flag**: surfaces *where the engine stayed silent*. Every explored
  sink argument that did not become an advisory is recorded with the reason the
  backward taint walk was cut, so a false negative is no longer a black box.
  Silent stop sites are tracked as pure bookkeeping on the walk state
  (`SinkFinding.cut_reasons`): `guard` (a validating guard dominated the use),
  `value-const` (the value folded to an attacker-independent constant),
  `sanitizer` (a sanitizer transformed the value), and `unresolvable` (the flow
  hit a value the engine cannot resolve). The section prints to stderr, so it
  composes with any `--format` and never contaminates the report on stdout.
  Example output for a `match`-statement blind spot:
  ```
  Explain: 1 silent sink argument(s) explored (no advisory)
    clean   BenchmarkTest00160.py:49  exec(arg 0)
        why: the value folded to an attacker-independent constant
  ```
  Debug tracing of the same walk (`FRENSdbg_WALK`, `FRENSdbg_DEADEND`,
  `FRENSdbg_UNRES`, `FRENSdbg_IS_SOURCE`, `FRENSdbg_STATIC`, `FRENSdbg_PTS`,
  `FRENSdbg_MEM`) is installed by the binary at startup and documented in
  `frensense-engine/src/debug_flags.rs`.
- **Benchmark triage tooling**: added `scripts/owasp_mutation_ladder.py`, a
  mutation-ladder triager that rewrites OWASP Benchmark false negatives into
  minimal variants and classifies each cause into a bucket (knowledge gap,
  engine bug, absent rule, harness artifact, unexplained), producing a
  reproducible `--json-out` scorecard and per-case repro files.

#### Corpus Lint (`frensense lint`)
- **`frensense lint <corpus>`**: a corpus pre-flight on the shipped binary (the
  same entry point as `frensense-bundler lint`), so curators need one
  executable. It exits `0` when the corpus is acceptable, `1` when any error
  (or any warning under `--strict`) is found, and `2` on a usage error. The path
  rule matches `watch` and `bundle`: `frensense lint` scans a directory named
  `./lint` when one exists, and `frensense lint <dir>` is always the subcommand;
  `lint` owns its own `--help` because the global help intercept would otherwise
  print scan flags and hide the curation flags. The checks themselves
  (`PU004`, provenance, diversity, coverage) are implemented in
  `frensense-bundler`; see its changelog.
- **`scripts/corpus-lint.sh`** runs the CLI over an authored corpus and is wired
  into the local gate (`./scripts/local-ci.sh`) and the CI corpus step, so a
  corpus that fails curation fails the build before a bundle is produced.

#### Flow Traces & Rule Lookup
- **Flow steps name what the developer wrote**: taint-path steps are rendered
  from the source text at their byte range (`reads `resp.data``,
  `String(req.query.q)`) instead of IR temporaries (`flows through v11`), and
  function names lose their `file::` prefix. A step with no readable span falls
  back to the field or value description, never to an SSA number.
- **The origin step has a location**: the `source:` step now carries the byte
  range of the value it names (falling back to the parameter's declaration for
  entry points), so SARIF's first `codeFlow` step is a real region instead of
  `location: null`, and the origin is no longer printed twice (the walked
  def/use pair above it is dropped).
- **`frensense explain <rule-id>`**: prints a built-in rule's id, title, CWE
  links, tier, why and fix from its rule card; with no id it lists every rule.
  Unknown ids exit `2` instead of guessing. Rule cards are owned by
  `frensense-lang`.
- **`explain` describes bundle-learned rules too**: a learned policy or check
  has no card by design - its knowledge is the trigger, requirements and
  message the bundle taught - so `frensense explain <id> -b <bundle>` renders
  that data straight from the bundle (and from the embedded default pack),
  with no invented CWE. `--list-rules -b <bundle>` lists the bundle's rule
  ids alongside the built-ins, and unknown ids say to pass `-b`.
- **`explain` no longer squats on a path of the same name**: `frensense
  explain` scans a directory literally named `explain`, a rule id wins over a
  same-named path, and the flag forms `--list-rules` / `--explain-rule <id>`
  are always unambiguous.
- **`mcp`, `watch` and `bundle` resolve same-named paths the same way**: a
  repo containing `mcp/`, `watch/` or `bundle/` stays scannable with the bare
  token — `frensense mcp` scans `./mcp`, and the server still starts via
  `frensense --mcp`. Arguments only the subcommand understands keep it
  claimed (`frensense watch <path>`, `frensense bundle <corpus> [out.frc]`),
  only argv[1] is a subcommand slot (`frensense . mcp` scans both paths), and
  `watch` no longer strips every `watch` token from the line — only its own.
  `lsp` is deliberately still literal: editors run it non-interactively, where
  silently scanning an `lsp/` directory would break the editor rather than
  present an ambiguity a human can resolve.
- **Borrowed Rust types are not request extractors**: the type-named source
  matcher strips the `&` when normalizing a parameter type, so `fn load(root:
  &Path)` matched axum's `Path` extractor and every helper that reads a file
  from a borrowed path looked attacker-controlled. The borrow marker is kept
  (`&Path` is `std::path::Path`), which removes that false-discovery class -
  including the path-traversal finding on Frensense's own bundle loader -
  while by-value extractors (`Path<T>`) still fire. The normalization is in
  `frensense-engine`'s harness; the removed finding was on `frensense`'s own
  bundle loader.

- **`--diff-only` reports only findings the diff introduced**: the gate still
  scans each changed file whole (a change can make an old line reachable), but
  a finding whose span touches no added line predates the diff and is
  suppressed with a count, instead of failing the gate for a bug this change
  never touched. Pre-existing debt belongs to the baseline
  (`--emit-baseline` / `--compare-baseline`), not to the diff gate.

#### Reported Identity & Triage
- **Stable rule ids on every finding**: findings report under a stable id
  (`taint.sql-injection`, `check.weak-hash`, `policy.<id>`) instead of the
  message text, so baselines, suppression files and trend reports keep pointing
  at the same rule when the wording changes. SARIF emits one rule per id with
  its CWE `external/cwe/*` tags, help URI and `security-severity`, and the JSON
  report carries a `cwe` array per finding.
- **Rule cards are the single source of rule prose**: one card per sink label
  and built-in checker rule (`frensense_lang::rule_card`) holds the id, title,
  CWE list, why and fix, and `taint_cwe` / `checker_rule_cwe` resolve through
  them, so no built-in rule can ship without a CWE and the terminal, SARIF and
  JSON surfaces cannot drift. Sinks that name no class fall back to the broad
  parent CWE (74 injection, 20 improper input validation) instead of guessing a
  child class.
- **No more "untrusted data reached something" findings**: a flow whose sink
  resolves to a fallback card (unknown label, role that pins no class) is no
  longer reported at all - it named no class to fix, suppress or trend, and
  those were the bulk of the noise burying real flows. `--explain` lists such
  sinks as silent instead, and a corpus family that does know the class teaches
  it as a label on the sink fact.
- **Code frame in the terminal report**: findings print the offending line (and
  the line above it) with a caret under the flagged call, plus the rule id,
  CWE and class-specific why/fix, replacing the repeated
  Details/Impact/Remediation block.

#### Version Identity
- **`frensense --version --json` and `frensense bundle info --json`** now expose
  a machine-readable build identity: engine version, bundle format,
  fact-vocabulary fingerprint, default-pack BLAKE3 digest, and report-schema
  version. The release workflow asserts on `frensense --version --json` before
  tagging and stamps the identity into the annotated tag. The fingerprint
  itself is owned by `frensense-engine` and the envelope by
  `frensense-bundler`; both document their halves.
- **Format contract ratified** in `docs/FORMATS.md` (single table of every
  artifact version and its bump rule) and enforced by
  `scripts/format-ratchet.py` (fails if the vocabulary fingerprint moves
  without a `BUNDLE_VERSION` bump and a note in the *bundler* changelog).

#### Telemetry Surfaces
The engine computes `ScanTelemetry`, `ScanStatus` and per-check outcomes;
`frensense` renders and gates on them.
- **JSON `analysis` object**: every `--json` report now contains a top-level
  `analysis` object alongside `advisories`, carrying `status`, `coverage`
  (files scanned / partial / functions), `verdicts` (vulnerable / sanitized /
  unknown / clean counts), `truncations`, per-check `checks`, phase `timings`,
  `slowest_files`, and `slowest_functions`. Coverage also reports submitted,
  failed, and unsupported inputs; `analysis.errors` exposes failures, and
  `analysis.suppressed` accounts for reportability, duplicate, tier, confidence,
  and severity drops. Schema version is unchanged (additive keys only).
- **SARIF `invocations`**: `--sarif` output now emits an `invocations` array
  with `executionSuccessful` (false when analysis is incomplete) and
  `toolExecutionNotifications` listing caps, partial parses, failed checks,
  failed inputs, and degraded functions. Standalone scan errors are also
  reported in that invocation notification list.
- **`--fail-on-incomplete` flag**: exits with code `2` when the scan status is
  `Partial` or `Failed`, allowing CI to distinguish a clean scan (0), a scan
  with findings (1), and an incomplete scan (2). Default is off to preserve
  backward compatibility.
- **`--profile-output <path>` / `--profile-out <path>` flags**: writes the full
  `ScanTelemetry` as pretty-printed JSON to the specified path. Also accepted
  as `--profile <path.json>` when the argument ends in `.json`, so the existing
  `--profile recommended` call is unaffected.
- **`--trace` flag**: initialises a `tracing-subscriber` with `EnvFilter`
  (defaulting to `info`). Also activated by the `FRENSENSE_LOG` environment
  variable. Spans and log calls emitted by engine internals are now visible
  without recompiling.
- **Accurate scan accounting and bounded reporting**: reports distinguish
  submitted, scanned, failed, and unsupported inputs, surface file
  read/lowering and worker failures, and fail status when submitted inputs
  yield no scanned files. Findings omitted by reportability, exact/shape
  deduplication, tier, confidence, or severity gates are counted separately.
  Failure paths now preserve cap/status information rather than returning a
  misleading clean result. Hot-path reporting avoids cloning finding keys and
  shape dedup uses borrowed file paths; no additional analysis work is
  performed for telemetry.

### Security
- **docs-site lockfile**: `npm audit fix` upgraded `markdown-it` (14.3.2 ->
  14.3.3) and `source-map-js` (1.2.1 -> 1.2.2). An `esbuild` override
  (`^0.25.12`) plus a verified `vitepress build` cleared the esbuild advisory;
  the remaining vite 5 dev-server advisories have no stable fix on the
  vitepress 1.x line, so CI audits `docs-site` with a critical-only gate and
  Dependabot now watches `/docs-site` weekly.

### Changed

#### Benchmarks
- **OWASP Benchmark for Python**: score on this branch improves from **22.4% to
  25.9%** (TPR 23.9% -> 27.7%, FPR held flat at 1.8%) across the fixes recorded
  in `frensense-engine` and `frensense-packgen`. Remaining false negatives are
  dominated by absent non-taint rules (CWE-330 weak randomness, CWE-643 XPath
  injection) rather than dataflow gaps.

#### Repository & Release Tooling
- **CI no longer runs the blog provenance gate.** `scripts/blog_provenance.py
  check --strict` resolves specific historical commits (for example `8a0ef9d`),
  which `actions/checkout`'s shallow clone cannot see, so the `qa` job failed on
  every PR while the same check passed locally ("blog provenance: all posts
  equipped"). The script, the pre-deploy gate in `docs-deploy.yml`, the `make`
  targets and the warn-only pre-commit hook are unchanged; a stale post is still
  caught before the docs site deploys, it just no longer blocks Rust CI.
- **Dropped the unused `Dockerfile` and `server.json`.** Neither was referenced
  by any workflow, script or Makefile target, and the MCP registry manifest had
  drifted to `0.7.1-beta`; removing them keeps the tracked tree to artifacts
  something actually builds or publishes.
- **Per-crate SemVer gate** (`scripts/semver-gate.py`): CI no longer answers
  "is the workspace semver-clean". It discovers the publishable crates from
  `cargo metadata` (`frensense`, `frensense-engine`, `frensense-lang`,
  `frensense-bundler`; `publish = false` crates excluded), closes the changed
  set over workspace dependents (a break in a re-exported engine/lang type
  reaches `frensense`), and runs `cargo semver-checks check-release
  --release-type patch` per crate against the PR base or `HEAD^`. A crate is
  `ok`, `absorbed` (its own version moved a breaking component) or `FAIL` —
  a break with an unchanged version — and a build error is reported as an
  error rather than as a SemVer signal. The previous gate ran the engine only
  and then a workspace-wide `check-release`, which skips every check while a
  middle number moved ("major change, 0 checks, 260 skip") and was therefore
  a no-op for the whole 0.8 line. Run by CI's `semver` job and by
  `scripts/local-ci.sh`.
- **Release publishes every crate by name, and proves it**
  (`scripts/release-matrix.py`): `publish-cargo` now names all four crates in
  dependency order instead of only `frensense`, and the job no longer waits on
  `build-native` — a skipped dependency would silently skip publishing. Before
  publishing, `semver-gate.py --published` asserts each crate's version already
  covers its public-API change; afterwards `release-matrix.py
  --require-published --wait 420` fails unless every publishable crate at its
  manifest version is live on crates.io, so a skipped crate cannot pass on the
  strength of the one crate that did publish. `prepare` also decides per crate
  whether there is anything to release: if a crate version moved while the
  root `vX.Y.Z` is already tagged, the run publishes that crate with **no new
  tag**, and the binary/npm/GitHub-release jobs (which need a tag) stay idle.
  A crate-only release no longer reads as "root version unchanged, nothing to
  do". `ci.yml`'s release-graph dry run names the same crate set.
- **Rust library quality gates**: CI and local CI now reject broken/private
  intra-doc links in `frensense-engine`, audit workspace dependencies with
  `cargo-machete`, and build the engine with each feature independently using
  `cargo-hack`. CI's SemVer job gained an explicit engine gate that compares
  against the previous commit as a patch release - it blocks newly introduced
  breaking changes while the accepted 0.7 -> 0.8 migration breaks stay in the
  changelogs - and local CI runs the same comparison against `HEAD`; the
  existing workspace check against the latest published release is unchanged.
  `cargo deny check` is the local command matching the supply-chain CI check,
  which now runs the complete `cargo deny check` rather than three of its four
  groups. The first dependency audit also removed unused optional `serde_json`
  and `blake3` dependencies from the engine; grammar crates wired through
  `frensense-lang` are narrowly documented as cargo-machete false positives.
- **Per-crate changelogs**: the workspace no longer routes every crate's entry
  through this file. Each shipped crate keeps its own `CHANGELOG.md` and its own
  version, so `frensense` can ship `0.7.1` on top of a `0.8.0` engine instead of
  forcing one version across the workspace. See `AGENTS.md` §7.1 for the rule
  and §7.2 for the bump procedure.
- **Exa web search for knowledge curation**: `scripts/exa-search/` wraps the
  official Exa SDK (`exa-js` 2.26.0) so an agent or contributor can pull the
  advisory, vendor doc or post-mortem behind a sink/source fact without
  fetching whole pages: `node --env-file=.env scripts/exa-search/search.mjs
  "<query>"` issues one `exa.search` call with `contents.highlights` and
  prints each hit's relevant passages (`--num-results`, `--domain`, `--json`
  optional). The key is read from the environment only (`EXA_API_KEY`,
  declared empty in `.env.example`); when it is unset the script exits 1 with
  setup instructions instead of failing with an opaque auth error.
- **docs/mre fixtures relocated**: the 14 deliberately vulnerable minimal
  reproduction examples moved from `docs/mre` to `tests/mre`, the directory
  the engine already classifies as test data, so the repo's own scanner now
  reports 0 findings from that tree (13 findings, 7 critical, gone), while
  each file's CVE-shape header keeps its documentation value.

## [0.7.0] - 2026-10-12

### Added

#### Corpus Authoring & Framework Provenance Scoping (`package:`)
- **Framework Package Declaration**: Added support in corpus metadata blocks for `// package: <framework>`:
  ```typescript
  // [frensense]
  // observation: User-controlled file parameter passed to res.sendFile without directory boundary check
  // package: express
  ```
- **Format v6+ Feature**: Qualified facts carry `package: Option<String>` in `.frc` bundles.
- **Engine Scoping**: The engine binds sinks, sanitizers, and policies to files that explicitly import or declare the specified package. Calls to matching method names in other frameworks (e.g. Next.js, Electron, Hono) remain unaffected.
- **Blast-Radius Quarantine**: The bundler compiler quarantines candidate facts: a candidate carrying a package may only be published if the voting family actually imports or declares that package.

#### Engine Architecture & Fact Table Modularization
- **Fact Table Architecture**: Decomposed monolithic `FactTable` in `frensense-engine` into dedicated submodules (`entries.rs`, `authored.rs`, `table.rs`) for extensible fact storage and clean separation of authored policies from learned entries.
- **Policy Checker Decoupling**: Refactored policy checking in `checks/policy.rs` to evaluate authored policy entries with explicit rule definitions and pattern bindings.
- **Forward Predicate Evaluation**: Refined path-sensitive branch condition evaluation in `analysis/forward/predicates.rs`.

#### Bundle Format v6 & Serialization
- **Package-Scoped Learned Facts**: Extended `LearnedFactEntry` in `frensense-bundler` with optional framework package provenance (`package: Option<String>`) for Sinks, Sanitizers, and Sources.
- **Embedded Default Pack Asset**: Regenerated `frensense-bundler/assets/frensense-default.frc` using Format v6 payload serialization.
- **Corpus Metadata Compiler Extraction**: Added parser support in `frensense-bundler` and `frensense-packgen` for `// package: <framework>` metadata headers during bundle compilation.

#### Engine Dataflow Scoping & Precision
- **Package-Aware Dataflow Resolution**: In `frensense-engine`, member calls and imported sinks/sanitizers are evaluated against module-level import bindings and receiver-root symbols to enforce package isolation.
- **Cross-Framework Blast-Radius Quarantine**: Ensured package-scoped facts fire only when the target file imports or instantiates the declaring package, preventing cross-framework false positives.

### Changed
- **Backward Compatibility**: Preserved reading and deserialization compatibility for legacy Format v4 and v5 `.frc` bundles.

## [0.7.0-preview.5] - 2026-10-09

### Added

#### CLI & Reporting UX
- **Compiler-Grade Diagnostic Formatter**: Redesigned human terminal finding reports with `rustc`-style pointer notation (`--> path:line:col (in 'symbol')`), de-duplicated titles, aligned 15-character metadata columns (`Details:`, `Impact:`, `Remediation:`), and structured numbered taint flow traces with localized line references.
- **File Output Support (`-o, --output <file>`)**: Enabled writing raw machine reports (`--json`, `--sarif`, `--github`) directly to disk while presenting interactive scan banners, duration timing, and summary audit blocks in the terminal. Pure stdout is preserved when piping without `-o`.
- **CLI Flags Audit & Atomic Parsing**: Unified command-line parsing into an atomic single-pass engine, resolving positional path conflicts. Removed deprecated flags (`--min-confidence`, `--config`, `--baseline`), added standardized short aliases (`-o`, `-s`, `-l`, `-b`, `-f`), and added validation for missing arguments and unknown flags.
- **Corpus Intellectual Property Protection**: Scrubbed internal corpus family names (e.g. `ts_express_sendfile_traversal`), training provenance (`(learned from family ...)`), and `Corpus-verified` labels from all findings. Prioritized author-declared `// [frensense] observation:` metadata blocks and added engine-level sanitization across all output formats.
- **Rule Bundles Hub & Capability Datasheets**: Added pointers and documentation to the rule bundles hub (`https://frensense.friehub.cloud/bundles`) and signed CWE Capability Datasheets (`CWE_DATASHEET.md` / `cwe_datasheet.json`) supporting Free Community and Commercial Enterprise distribution tiers.

#### Engine Dataflow & Blindspot Remediations
- **P0 Sink-Agnostic Sanitizer Collapse Remediation (BS-15)**: Re-homed and qualified `SanitizerKind` with `SinkRole` and sink labels (`defeats_role_and_label`) in `frensense-lang`, preventing HTML sanitizers from clearing command and code execution sinks. Threaded role qualifications through `frensense-packgen` and backward taint walks in `walk.rs`.
- **P1 Scoped Identifier Callgraph Dropping in Rust (BS-18)**: Expanded tree-sitter queries in `frensense-lang` to match `(scoped_identifier)` within call expressions and let bindings (`Command::new`, `std::process::Command::new`). Routed `match_expression` to `NodeRole::Match` and delegated trailing expression returns cleanly through `LanguageSpec::implicit_return_node`.
- **97-Probe Industrial Dataflow Consistency Test Bench**: Implemented comprehensive diagnostic probe suite (`dataflow_probes_tests.rs` and `probes/*`) modeling 65 NIST/Juliet syntactic and inter-procedural flow variants, frontier static analysis domains (path sensitivity, async microtasks/emitters, multi-language Go/Rust providers, sanitizer ordering, historic CVE reproductions, and framework IoC), and quantitative finance trading patterns. Known engine blind spots are annotated with diagnostic ignore markers.
- **100% TPR / 0% FPR Held-Out Benchmark Gate**: Resolved remaining detection seams across all 116 held-out production fixtures in `frensense-corpus`, verifying zero false positives on safe control variants.
- **CWE-190/680 Integer-Overflow Heap-Overflow Checker**: Added `checks::int_overflow`, a facts-driven checker for integer overflow reaching a heap write: interval bounds over allocation sizes, index arithmetic and multiplication (rooted in the lang-declared capacity vocabulary) decide whether an overflowed value can reach the size/index of a copy into undersized heap storage; validated 4/4 on the `c_cwe_680_count_mul_wrap` corpus pair plus heldouts.
- **CWE-401 Allocation-Lifetime (Memory Leak) Checker**: Added `checks::leak`, path-sensitive may-leak accounting reporting an allocation still frame-owned at a function exit. Ownership escapes (returned, stored, contract-consumed) remove candidates; null-guard and pointer-identity edges drop allocations bound to the guarded *storage* (every SSA version, stale loop-join bindings included); the exit scan counts only the deepest definition dominating the exit per storage cell, so superseded versions cannot report twice; freshness roots strictly at the declared allocator vocabulary.
- **Break/Continue/Switch Lowering**: Added first-class lowering for `break`, `continue` and `switch`: a `LoopTarget` stack on `LoweringContext` gives both loop exits correct terminators (pre-header and body-end), unlabeled `break`/`continue` jump to them with fresh unreachable blocks, and `switch` lowers to a condition chain with per-case conditions, source-order fall-through bodies and break-to-merge - so case bodies join the CFG instead of orphaning unreachable exits.
- **CVE-2026-56109 Deallocation on Error Path Detection**: Added analysis in `checks::uaf::uninit` detecting deallocation of uninitialized stack pointers along unchecked error/EOF paths (inequality return checks without dominating `< 0` diversion).
- **CFG Jump Resolution for `goto` and Labels**: Added first-class lowering support in `LoweringContext` (`visit_goto`, `visit_labeled_statement`) wiring basic block jump terminators and control flow edges across forward and backward labels.
- **Out-Parameter Address-Taken Initialization Tracking**: Implemented `is_address_taken_on_all_paths` in `uninit.rs` verifying whether all paths reaching a block execute `Instruction::AddressOf` for a local pointer, correctly recognizing out-parameter initialization.

#### Packgen & Bundling (Engine Purity)
- **Standalone `frensense-packgen` Crate**: Introduced standalone compiler crate responsible for extracting language provider vocabularies (JavaScript/TypeScript, Python, Go, Rust, C) and emitting static binary `.frc` packs.
- **Binary Pack Embedded Knowledge**: Embedded default pack (`frensense-bundler/assets/`) serving as the single source of truth for AST semantic knowledge, decoupling language specifics from engine binaries.
- **Bundle Format v5 & Advisory Expansion**: Added version-branched bundle format supporting `policy_pack` integration, rule structs carrying severity and custom advisory templates, and provenance-ordered `FactTable::merge`.
- **Unified `frensense bundle` Subcommand**: Exposed `frensense bundle <corpus_dir> [output.frc]` directly in the primary CLI with rich documentation under `frensense bundle --help`, enabling users to compile positive/negative corpus pairs into `.frc` bundles without internal crate invocations.
- **Modular Bundling Pipeline**: Extracted the bundle compilation, seed facts ingestion, and replay gate verification into `frensense_bundler::run_facts_pipeline` with strictly scoped helper functions (< 40 lines).
- **Corpus-Driven C Memory Contract Learning**: Verified end-to-end learning from upstream C codebases (`alsa-lib`), extracting 11 interprocedural memory contracts (allocators, deallocators, parameter consumers) directly from source deltas and enforcing the Zero False-Positive contract on patched code.

### Changed

#### Engine Architecture (Purity Refactor)
- **Zero Hardcoded Language Knowledge in Engine Core**: Stripped all provider vocabularies, AST node strings, route patterns, and language-specific hint tables from `frensense-engine`. The engine operates exclusively over abstract compiler IR, SSA memory variables, Steensgaard points-to classes, and data-driven `FactTable` facts.
- **Structured Sink Alerts and Observations**: Replaced hardcoded prose and string templates with structured `CheckerFinding` payloads carrying rule IDs, fact-declared severities, and data-driven observation templates.
- **Memory & Lifetime Vocabulary Dataflow**: Memory allocators, deallocators, and parameter consumption contracts now flow exclusively through `FactTable` facts populated from `.frc` packs.
- **Literal Allocations No Longer Root Freshness**: Program-summary inference no longer marks a function returning an object/array literal (`Instruction::Allocate`) as a fresh factory; freshness roots at the declared allocator vocabulary, so GC-managed objects stay out of allocation-lifetime candidates (juice-shop gate holds at TP 12/12 with FP back to 12; OWASP record unchanged at 26.2%).
- **Modularized UAF Engine**: Decomposed the monolithic `uaf.rs` checker into single-responsibility submodules under `checks::uaf/` (`types.rs`, `discovery.rs`, `must_exec.rs`, `walker.rs`, `uninit.rs`, and `mod.rs`), adhering to strict single-purpose function sizing (< 40 lines).

#### Documentation
- **Benchmark Record Refreshed**: The OWASP Benchmark for Python record is re-scored at **26.2%** score (TPR 28.5%, FPR 2.3%, TP/FP/FN/TN 129/18/323/760, 6s scan) against v0.7.0-preview.5 in `README.md` and `docs/BENCHMARKING.md`, with the full per-CWE table updated; CWE-328 (weak hash) now scores 100% (71/71, zero false positives).

### Removed

#### Engine
- **Legacy Taint Engines**: Deleted obsolete `SvfgTaintEngine`, legacy `TaintEngine`, and `SvfgStore`, removing dead synchronization overhead and reducing memory footprint.
- **`policy.rs` Decoupling**: Deleted monolithic `policy.rs`, migrating fact types and rule schemas directly into engine kinds and packgen definitions.
- **Devtools Binary Separation**: Relocated internal debug and benchmarking runners from engine sources into the dedicated `frensense-devtools` workspace crate.

### Fixed

#### Engine
- **Fixture Seam Resolution**: Resolved all remaining fixture seams across the 116 held-out test corpus, eliminating false positives from undecorated routes and untainted receivers while preserving all true positives.
- **Fallthrough Blindness on `goto` Error Exits**: Resolved an engine blindspot where unmodeled `goto` statements in C AST lowering caused error-diverting guard branches to fall through into subsequent code blocks.
- **Out-Parameter Uninitialized False Positives**: Resolved false positive `UninitializedFree` reports on valid C out-parameter patterns (e.g. `snd_config_hook_load`), ensuring full precision on real-world production codebases.
- **Weak-Hash Selector Coverage Regression**: Credential-context qualification of selector-shape weak-hash rules is now declared per rule in `frensense_lang::policy::WeakPrimitiveRule` (`requires_credential_context`) instead of applied uniformly: `crypto.createHash` stays qualified inside credential-named functions (generic digest utilities remain silent), while explicit weak-algorithm selectors (`hashlib.new('md5')`) fire unconditionally - restoring the OWASP CWE-328 class to 71/71 true positives with zero new false positives (juice-shop gate stays at 12 FP, corpus bundles 8/8).

## [0.7.0-preview.5] - 2026-09-30

Preview release adding graph-based UAF validation over the store-aware program SVFG, control-dependence gating for guard bypass and policy checks, bounded interprocedural path re-expansion, single-owner function IRs with closure-edge feeding, and an exactly-once detection regression gate.

### Added

#### Engine
- **Graph-Based UAF Validation**: Added `check_with_prog` and `check_all_with_graph`, validating free-to-use flows against store-aware `ProgramSvfg` paths through scan, so a UAF alert requires an end-to-end path rather than a local two-node pattern.
- **Control Dependence Graph**: Added dominator-based CDG analysis (`ir/control.rs`) exposing the set of predicates controlling each block.
- **Predicate-Feeds Guard Gating**: Guard bypass checks now require the guard's predicate to actually control the sink's block (`feeds_predicate`), silencing predicate-blockers that never control the risky path.
- **Policy Trigger-Site Dominance Caching**: Co-occurrence policy checks evaluate requirement satisfaction at trigger sites with dominance caching, so nested requirements resolve without per-node repetition.
- **Bounded Path Re-Expansion**: Forward taint explores beyond the first call boundary with a bounded interprocedural continuation keyed by (function, node, context-block) and a `seen_nodes` revisit guard, resolving deep parameter-plus-closure chains to the declaring function.
- **Detection Regression Gate**: Added `regression_gate_tests.rs` locking every nested-function flow shape (parameter, closure, bound-arrow, deep nesting, policy, sanitizer-negative) to exactly one finding with correct owner attribution, plus cross-shape duplicate-result probes.

### Changed

#### Engine
- **Single-Owner Function IRs**: Every function body is now lowered into exactly one named IR, linked through a new `enclosing_fn` chain; `NodeRole::Function` no longer contributes body copies to the enclosing IR. This removes duplicate findings, misattribution to outer functions, duplicated policy hits, and the linear IR blow-up that nested extractions previously caused.
- **Closure Edge Feeding**: Free use-nodes inside extracted function bodies are fed from the first enclosing function that defines the name, walking the `enclosing_fn` chain until a defining scope is reached (module scope stops the walk), preserving the flows that previously relied on inlined capture copies; callgraph and callback edges are unchanged.
- **Extraction Identity Tracking**: Function identity tracking via named children and `bound_fns` with a statics-only `inside_function`, so every extraction site resolves an owner name (`<fn@N>` fallback for nameless functions).

### Fixed

#### Engine
- **Phantom Const-Function Duplicate Results**: Unnamed const nested functions no longer produce twin IRs and duplicate `<fn@N>` findings; each function resolves a single owner across all nested shapes (verified by duplicate probes: parameter-plus-closure, closure, nested policy, bound-arrow policy, phantom const handler, and returned-arrow cases all return exactly one attributed result).
- **Receiver Access-Path Attribution**: Session-trust receiver access-path tests now search all IRs, since extracted bodies moved from enclosing IRs to per-function IRs.

## [0.7.0-preview.4] - 2026-09-29

Preview release adding comprehensive verification across all 13 teachable security dimensions, native guard call policy synthesis, candidate guard prioritization and exception filtering, forward taint propagator slot suppression, language-specific receiver sink validation, benchmark CI optimization, and dynamic documentation versioning.

### Added

#### Engine & Verification
- **All 13 Teachable Dimensions Verification**: Implemented comprehensive integration test suite (`tests/all_13_dimensions_test.rs`) verifying that all 13 teachable security analysis dimensions in the engine can be taught via `.frc` bundles: custom sources, custom sinks, custom sanitizers, custom propagators, custom memory allocators, custom memory deallocators, IDOR query keys, IDOR finder sinks, banned argument literals, required argument literals, weak crypto algorithms, guard bypass allowlists, and tool schema policy enforcers.
- **Multi-Language Corpus Verification**: Validated corpus extraction and engine scanning across multi-language implementations (TypeScript, Python, and C).
- **Subsystem Teachability with Built-in Fallbacks**: Extended `FactTable` and `.frc` bundle serialization to teach custom allocators, custom deallocators (wired to `MemorySummaryRegistry`), IDOR query keys and finder sinks, taint propagators, and guard denylist patterns, retaining sound built-in defaults as fallbacks.
- **Bundle-Driven External Wrapper and Policy Detection**: Verified end-to-end detection where opaque external wrappers (such as custom memory deallocators in C causing Use-After-Free and unmodeled execution sinks in TypeScript) that produce zero findings at baseline are successfully flagged with high confidence when taught through a `.frc` bundle, while safe control variants remain cleanly silent.

#### Bundler
- **Native Guard Call Policy Synthesis**: Added candidate generation for `Candidate::Policy` with `PolicyRequirement::GuardCall` for declared triggers, enabling condition branches to teach policy requirements directly.
- **Guard Candidate Ranking**: Added `guard_priority` heuristic to prioritize boolean predicates (such as `test`, `is_*`, and validator calls) over generic function invocations.

#### Docs & Infrastructure
- **Dynamic Docs Versioning**: Configured documentation site to pull live published versions dynamically via registry and GitHub Releases APIs at build time and client runtime with fallback to workspace Cargo metadata.

### Fixed

#### Engine
- **Language-Specific Receiver Sink Filtering**: Restricted IDOR verb sink checks in `is_sink_call` so JavaScript/TypeScript verbs do not trigger false positive sink alerts on native Python dictionary lookups and string operations.
- **Propagator Non-Propagating Argument Suppression**: In `compute_summaries`, suppressed pass-through edges on argument slots not designated as propagating inputs, preventing taint leakage across unrelated parameters in external propagator calls.
- **Backward Taint Engine Receiver Slot Normalization**: Aligned virtual call receiver slots to `usize::MAX` in `BackwardTaintEngine::explore_call_site`, preventing receiver object handles (such as database connections and KV namespaces) from being interpreted as positional argument slot 0.
- **Non-Sink Exploration Gating**: Ensured `explore_call_site` skips call positions when `sink_alert_with_facts` evaluates to `None`, eliminating false-positive backward walks from safe receivers, safe parameterized binding channels, and non-sink methods.
- **Use-Block Guard Dominance Tracking**: Updated `BackwardTaintEngine::explore_from` to evaluate whether a guard branch dominates the block where the tainted variable is consumed (`use_block`), rather than where it was defined (`def_block`), allowing predicate guards (such as `RegExp.test`) to accurately sanitize downstream taint flows.
- **Branch Terminator Preservation in IR Lowering**: Corrected `NodeRole::Branch` lowering to check `matches!(b.terminator, Terminator::None)` before appending `Terminator::Jump(merge_block)`, preserving `Terminator::Return` instructions in early-exit guard blocks and removing invalid control-flow paths into merge blocks.
- **Unary Negation Operation Support**: Extended `GuardMap::build` and `analysis/value.rs` to support `"neg"` and `"not"` unary operator representations alongside `"!"`, properly handling condition polarity inversion for TypeScript and other language lowerings.
- **IR Lowering Pipeline Modularization**: Deconstructed monolithic `lowering.rs` into specialized submodules (`context`, `expr`, `stmt`, `calls`, `binary`, `memory`, `pattern`, `dispatch`), improving readability and maintainability.

#### Bundler
- **Exception Constructor Filtering**: Added `is_exception_name` checks in `frensense-bundler/src/extract/noise.rs`, preventing standard exception and error classes (such as `ValueError`, `SecurityError`, `RuntimeError`, `Error`) from being misclassified as guard validation calls.
- **Fact Extraction Pipeline Modularization**: Deconstructed monolithic `fact_extract.rs` into isolated submodules (`family`, `candidate`, `noise`, `call_analysis`, `propose`, `gate`, `tests`), providing a robust and extensible training extraction pipeline.

#### Language Specs & Facts
- **JavaScript/TypeScript Sink Signatures**: Registered slot-restricted signatures for `prepare` (`&[0]`), `redirect` (`&[0]`), `put` (`&[0, 1]`), `delete` (`&[0]`), `del` (`&[0]`), `set` (`&[0, 1]`), and `append` (`&[0, 1]`) in `JS_SINK_SIGNATURES`.
- **LanguageSpec AST Classification Hooks**: Added `is_cast`, `is_template_string`, `is_destructuring_pattern`, `is_pair_pattern`, `is_ternary_straight_line`, and `unwrap_declarator_node` to `LanguageSpec` to decouple IR lowering from hardcoded grammar node kinds.
- **Predicate Sanitizer Classification**: Added `test` to `JS_SANITIZER_NAMES` and classified it as `SanitizerKind::Full` in `js_classify_sanitizer`; automated guard style recognition for sanitizers matching `test`, `isValid`, or prefixed with `is`.
- **Ambiguous Verb Disambiguation**: Added `set` to ambiguous verb sinks in `facts.rs` to require known client roots (`lodash`, `_`) before alerting, preventing bare `.set(...)` on context objects from being misflagged as prototype pollution.
- **Credential Setter Specificity**: Refined credential sink exclusions to replace bare `"set"` with qualified identifiers (`setPassword`, `set_password`, `setSecret`, `set_secret`).

### Performance

#### CI & Benchmarks
- **Streamlined Vulnerability Benchmarks**: Replaced multi-tag Juice Shop clone with a dedicated, lightweight OWASP Python benchmark runner (`scripts/owasp_benchmark.py`), saving 51 minutes of CI execution time across pipeline runs.

## [0.7.0-preview.3] - 2026-09-28

Preview release adding interprocedural memory safety contracts,
bundle-learned non-taint analyses, value-aware guard validation,
spatial memory safety, and CallVirtual receiver-binding fixes on top of
0.7.0-preview.2.

### Added

#### Engine

- **Corpus-learned non-taint analyses from `.frc` bundles**: all remaining
  non-taint security analyses can now be learned autonomously from positive
  and negative examples in corpus bundles without user-managed JSON or engine
  recompilation:
  - **Argument-literal & selector policy constraints**: `PolicyRequirement::BannedArgLiteral`
    and `PolicyRequirement::RequiredArgLiteral` evaluated using lattice constants.
  - **Weak cryptography rules**: `WeakCryptoFact` enabling bundle-driven detection
    of weak cryptographic primitives and method selectors in `weak_hash.rs`.
  - **Guard bypass allowlists & credential sinks**: `GuardBypassFact` enabling
    bundle-driven allowlist containment callees and credential setter
    sinks/parameters in `guard_bypass.rs`, marked with `learned: true`.
  - **Tool schema policies**: `SchemaPolicyFact` enabling bundle-driven tool
    registration builders, enforcers, and unbounded numeric parameter keywords
    in `schema_policy.rs`.
  - **Memory contracts**: `MemoryContractFact` enabling bundle-driven custom
    allocators and deallocation wrappers in spatial and temporal checkers.
- **Interprocedural allocation and deallocation wrapper summaries (Limitation M1)**:
  bottom-up interprocedural analysis (`checks/memory_summary.rs`) computing
  memory lifecycle contracts (`returns_fresh`, `return_capacity`, `consumes_params`)
  across arbitrary call chains (`outer_free -> inner_free -> free`), preserving
  allocation provenance across factory and deallocator wrappers.
- **Buffer overflow / out-of-bounds checker (Limitation M3)**: spatial
  memory-safety checker (`checks/oob.rs`) tracking pointer allocation capacities
  and indexed dereferences (`LoadElement` / `StoreElement`) against the interval
  value lattice.
- **Use-after-free and double-free checkers**: ported from the legacy
  analysis tree (`checks/uaf.rs`), featuring a forward path-sensitive finite-state
  machine (`Allocated` -> `Freed` -> `UseAfterFree` / `DoubleFree`) over
  Steensgaard points-to equivalence classes with C declarator unwrapping.
- **Abstract-interpretation value lattice**: constants, string/number
  ranges, and join/meet over branches now flow through the analysis,
  powering a co-occurrence policy checker, weak crypto key size checks,
  and sharper guard decisions.
- **Branch sharpening (Limitation B1)**: predicate narrowing on conditional
  branches (`Terminator::Branch`), refining interval bounds and constant equality
  along true and false successor edges.
- **Value-based range guard validation with GuardMap**: guards such as
  `if len(x) > 0` or `if i < arr.len()` are checked against the value
  lattice; a learned `unless_range_check` requirement is satisfied by a
  guard that provably dominates the sink, not merely by textual
  presence of a call.
- **Co-occurrence policy checker**: generalized `PolicyFact` engine evaluating
  `GuardCall`, `RequireCall`, `NotCall`, and `RangeCheck` across `Function` and
  `Module` scopes.
- **Corpus Source facts for bundles**: `.frc` bundles can now teach the
  engine new taint sources (e.g. framework request properties) that merge
  into the fact table at load time; Python subscript expressions also
  lower correctly so tuple/dict-indexed sources participate in flows.

#### Bundler (`frensense-bundler`)

- **Differential non-taint fact extraction**: the corpus learner now derives
  `WeakCrypto`, `GuardBypass`, `SchemaPolicy`, `MemoryContract`, and arg-literal
  policy candidates from positive vs. negative IR deltas.
- **Zero-regression replay gate validation**: every candidate fact is replayed
  against ground-truth positive and negative corpus families; only facts achieving
  clean separation without false-positive regressions are published into `.frc` bundles.
- **Policy fact proposals**: the corpus learner proposes `Policy` facts
  from labelled check-call families (`NotCall` and `RequireCall` with `Module`
  scope).
- **Family metadata in bundles**: a `[frensense]` comment block
  (observation / impact / improvement / cwe / cvss / owasp / severity)
  in the first 30 lines of a positive example is parsed and written into
  the bundle's pattern entries, so corpus documentation travels with the
  learned facts.
- **Multi-language stem-collision guard**: families whose stem exists in
  more than one language (e.g. `foo.py` and `foo.ts`) are split into
  `<stem> (<lang>)` sub-families with a warning listing the affected
  files, instead of silently mixing languages in one replay.
- **Synthetic-name leak fix**: lowering-internal function names
  (`<fn@byte>`, file-position-dependent) are excluded from learned
  `RequireCall` requirements, so bundles no longer encode requirements
  that can only ever fire on the training corpus.

#### Docs

- **Public corpus authoring guide**: `docs/FRENSENSE_CORPUS_GUIDE.md`
  rewritten as the reference for writing corpus families: quick start,
  naming conventions, the metadata block, policy authoring, verification
  workflow, and common mistakes.

### Fixed

- **Receiver-parameter slot binding in `CallVirtual`**: decoupled caller
  `receiver` from positional `args` in `analysis/forward.rs`. For receiver-less
  callees (JS/TS/Go methods), arguments bind directly starting at positional
  slot 0 without false taint offset. For Rust methods with explicit `self_parameter`,
  receiver binds to `parameters[0]` and positional arguments map to `parameters[i+1]`.
- **Spurious Rust taint rules**: cleaned up `frensense-lang/src/providers/rust_lang.rs`
  by removing bare `"var"`, eliminating spurious JS sinks (`setItem`, `Object.assign`,
  `DOMParser`), and scoping database query sinks (`"find_one"`, `"Collection::find"`)
  so standard Rust `Iterator::find` is not misclassified as a database injection sink.
- **C declarator lowering**: recursive unwrapping of `pointer_declarator`,
  `array_declarator`, and `cast_expression` in `lowering.rs`, ensuring pointer
  allocations in C declarations are correctly assigned to variables instead of
  being dropped as bare expression statements.
- **Policy requirement serialization**: fixed `PolicyRequirement` serialization
  to externally tagged format so bundles containing Policy facts load cleanly.

### Changed

- Engine: guard recognition now consults the value lattice (see
  value-based range guards above); previously guard satisfaction was
  purely call/textual.
- Bundler: check-call comment syntax is language-aware (`#` for
  Python-family files, `//` otherwise).


## [0.7.0-preview.2] - 2026-09-27

### Added

- **GitHub Actions annotations**: `frensense . --github` emits one workflow
  command per finding (`::error|warning|notice file=…,line=…,col=…::message`)
  with spec-compliant property escaping. Drop it into a CI step and findings
  render directly on the PR's Files Changed tab, with no SARIF upload step.
- **Watch mode**: `frensense watch [path] [options]` re-scans changed files
  (500 ms poll, zero new dependencies) and prints only NEW findings via a
  fingerprint-set diff between rounds. Fixed findings age out of the baseline
  automatically. Accepts the same options as a one-shot scan
  (`--corpus-bundle`, `--lang`, severity/confidence filters).
- **MCP surface expansion**: `frensense-mcp` now exposes three tools.
  - `frensense_audit` (existing): directory audit, now with
    `FRENSENSE_CORPUS_BUNDLE` env support.
  - `frensense_scan_file` (new): single-file scan for agent edit loops, with
    `corpus_bundle` argument and tool-level `unsupported_file` outcomes.
  - `frensense_diff` (new): scan a unified diff (git diff / patch text, or
    `git diff HEAD` plus untracked files) and report only findings on
    added-line ranges; the result answers "does MY change introduce
    findings?".
  All three accept `.frc` corpus bundles so learned facts participate in MCP
  scans exactly as in CLI scans.
- **Stable finding IDs**: fingerprints are now computed over semantic
  coordinates only (file, rule/sink, enclosing function, source); line and
  column are excluded, so a finding that shifts lines after an unrelated edit
  keeps its identity. Baseline comparison (`--compare-baseline`) therefore
  no longer flags shifted findings as regressions, and MCP payloads carry
  `stable_ids` (`FRN-<12hex>@<file>:<line>`). One migration step: regenerate
  pre-existing baselines once with `--emit-baseline`.
- **LSP server**: `frensense-lsp` publishes diagnostics on
  `textDocument/didOpen`/`didSave` for Python, JavaScript/TypeScript, Rust,
  and Go files. Diagnostics carry 0-based ranges, stable IDs in `code`, and
  the taint observation in `message`. Zero new dependencies (hand-rolled
  `Content-Length` framing); the engine stays the single source of truth:
  the server scans the saved file on disk through the same per-file path as
  watch mode and MCP.

### Changed

- `Advisory::identity()` is now the semantic fingerprint (was a
  `(fingerprint, path, line, col)` tuple). Consumers matching on the old
  tuple should match on `fingerprint` instead.
- Engine: containment/equality guard recognition (`x in bar`, literal-sibling
  equality) cuts guarded dataflow paths; constant propagation plus ternary
  branch feasibility prunes infeasible arms of conditional expressions.

## [0.7.0-preview.1] - 2026-09-26

First public release of the Frensense v0.7.0 dataflow engine.

### Licence

- **GPL-3.0-only**: the engine is free software. All source files carry
  `SPDX-License-Identifier: GPL-3.0-only` headers, all crate manifests declare
  `license = "GPL-3.0-only"`, and the full GPL-3.0 text is included as
  `LICENSE`. Commercial licences for redistribution without GPL obligations are
  available at https://friehub.com/licensing.
- **Open-core**: the analysis engine is open; `.frc` knowledge bundles carry
  the detection knowledge.
- **Contributor licensing**: contributions are accepted under GPL-3.0 with a
  lightweight CLA (see `CONTRIBUTING.md` and `CLA.md`). CLA signing is
  automated by a GitHub Action.

### Added

- **Compiler-mode dataflow engine**: the scanner lowers every file to a
  lightweight IR and builds a full program graph: def-use chains, call graph,
  Steensgaard points-to with two-phase constraint solving, heap modelling, and
  an SVFG (Sparse Value-Flow Graph). Findings come from exact reachability
  queries on this graph, not heuristic scoring.
- **Taint-path reporting**: findings include the concrete source-to-sink path
  through the program graph with file positions, not just a confidence score.
- **Two-phase points-to analysis**: constraint-based alias resolution with a
  second propagation phase for call-site-sensitive flow.
- **Memory SSA backend**: a dedicated SSA construction pass over the memory
  model for precise def-use resolution.
- **Multi-language sink model**: unified sink/source modelling across
  TypeScript, JavaScript/TSX, Python, Go, and Rust with per-language providers
  (Oxc for JS/TS, rust-analyzer HIR for Rust).
- **Session-trust and guard-bypass analysis**: checkers for authentication
  guard bypass and session-trust violations on the SVFG.
- **Knowledge bundles (.frc)**: checksummed, versioned archives of patterns
  and replay-verified source/sink/sanitizer facts. Loaded via
  `--corpus-bundle`, auto-discovery of `frensense-corpus.frc` in the project
  root, or the library API. Facts merge into the engine's fact table at scan
  time.
- **MCP server**: `frensense-mcp` exposes the scanner to AI coding agents via
  the Model Context Protocol.
- **CI hardening**: every third-party GitHub Action pinned to an immutable
  commit SHA, egress auditing on all jobs, least-privilege permissions, and
  SLSA L3 provenance on release binaries.

### Notes

- This is a **preview**: the knowledge-bundle format and CLI surface may still
  change before the stable `0.7.0` release.
- The engine detects command injection, SQL/NoSQL injection, SSRF, path
  traversal, IDOR, weak cryptography, XSS, and misconfiguration out of the
  box; `.frc` bundles extend and sharpen detection.
