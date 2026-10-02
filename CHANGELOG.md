# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Engine
- **CVE-2026-56109 Deallocation on Error Path Detection**: Added analysis in `checks::uaf::uninit` detecting deallocation of uninitialized stack pointers along unchecked error/EOF paths (inequality return checks without dominating `< 0` diversion).
- **CFG Jump Resolution for `goto` and Labels**: Added first-class lowering support in `LoweringContext` (`visit_goto`, `visit_labeled_statement`) wiring basic block jump terminators and control flow edges across forward and backward labels.
- **Out-Parameter Address-Taken Initialization Tracking**: Implemented `is_address_taken_on_all_paths` in `uninit.rs` verifying whether all paths reaching a block execute `Instruction::AddressOf` for a local pointer, correctly recognizing out-parameter initialization.

#### CLI & Bundler
- **Unified `frensense bundle` Subcommand**: Exposed `frensense bundle <corpus_dir> [output.frc]` directly in the primary CLI with rich documentation under `frensense bundle --help`, enabling users to compile positive/negative corpus pairs into `.frc` bundles without internal crate invocations.
- **Modular Bundling Pipeline**: Extracted the bundle compilation, seed facts ingestion, and replay gate verification into `frensense_bundler::run_facts_pipeline` with strictly scoped helper functions (< 40 lines).
- **Corpus-Driven C Memory Contract Learning**: Verified end-to-end learning from upstream C codebases (`alsa-lib`), extracting 11 interprocedural memory contracts (allocators, deallocators, parameter consumers) directly from source deltas and enforcing the Zero False-Positive contract on patched code.

### Changed

#### Engine
- **Modularized UAF Engine**: Decomposed the monolithic `uaf.rs` checker into single-responsibility submodules under `checks::uaf/` (`types.rs`, `discovery.rs`, `must_exec.rs`, `walker.rs`, `uninit.rs`, and `mod.rs`), adhering to strict single-purpose function sizing (< 40 lines).

### Fixed

#### Engine
- **Fallthrough Blindness on `goto` Error Exits**: Resolved an engine blindspot where unmodeled `goto` statements in C AST lowering caused error-diverting guard branches to fall through into subsequent code blocks.
- **Out-Parameter Uninitialized False Positives**: Resolved false positive `UninitializedFree` reports on valid C out-parameter patterns (e.g. `snd_config_hook_load`), ensuring full precision on real-world production codebases.

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
