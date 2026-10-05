# Frensense Engine Purity Refactor - Plan & Findings

**Principle:** `frensense-engine` is a pure analysis library - mechanism only
(provers, lattices, parametrized matchers). All security knowledge (vocabulary,
rules, severities, messages, budgets) is data shipped via `.frc`.
`frensense-lang` is grammar + classification mechanism only. Consumers
(bundler, CLI) own all verdict policy: alerting, tiers, rendering, exit codes.
Corpus-learn what the corpus can teach; hand-author the rest; consumer controls
what ships.

## Part 1 - Findings

### 1.1 Current architecture

```
frensense-lang (grammars + spec trait + ~47% knowledge tables)
      |
frensense-engine (claimed "pure dataflow compiler", lib.rs:5-11)
  harness -> ir/lowering -> SSA -> control -> graph -> analysis -> checks -> scan
  x 3 dev CLI bins, x disk cache, x env/eprintln, ~40 hardcoded knowledge sites
      |
frensense-bundler --.frc--> frensense (root CLI)
```

Dependency order: `lang <- engine <- bundler <- CLI`. Verdicts are produced
only in the engine but interpreted at least 4 times downstream.

### 1.2 Engine issues by category

#### A. Policy in the engine (decisions that belong to consumers)

- `scan.rs:273-277` `vulnerable()` fuses verdict + `alert.is_some()`;
  `scan.rs:287-297` `has_alert()` hardcodes `"info"` tier suppression and
  `checker => alert`. This one line is the bundler's accept/reject gate
  (`gate.rs:64`); the predicate is re-implemented at least 4x
  (`runner.rs:112-122`, `engine/mod.rs:406-411`, `e2e_batch.rs:255`,
  7 test sites).
- `role.rs:94-100` severity ladder (`critical`/`warning`/`info`);
  `role.rs:53-90` exhaustive SinkLabel->role map.
  `LogLeak|CredentialLeak -> Response -> info` (`role.rs:84`) silently
  demotes credential leaks to the suppressed tier.
- `"CRITICAL VULNERABILITY"` hardcoded 5x: `taint/config.rs:271,318,328`;
  `predicates.rs:399`; `svfg.rs:1169,1181,1187`.
- `CheckerFinding` (`checks/mod.rs:57-72`) has **no severity field** -
  `PolicyFact.severity` / `LearnedCheckFact.severity` dropped at
  `policy.rs:119-125`, `checks/mod.rs:292-298`.
- Presentation in engine: `path.rs:197-203` `render_text()`,
  `path.rs:206-225` `sarif_locations()` (contradicting its own doc
  `path.rs:9-12`), ~40 prose `format!` sites in checks.
- `learned: bool` mislabeled: `weak_hash.rs:202,222`,
  `guard_bypass.rs:431`, `int_overflow.rs:211` report facts-sourced rules
  as built-in. `UninitializedFree` reported under `DOUBLE_FREE` id
  (`uaf/types.rs:100-101`).

#### B. Security knowledge as Rust literals (must become data)

- `harness.rs:273` route suffixes `.post`/`.get`/... - duplicates and
  diverges from the dead spec API `route_registration_patterns()`
  (`spec.rs:865`).
- `oob.rs:111,115,124` `malloc`/`calloc`/`realloc`/`valloc`/`alloca` -
  shadows `MemorySummaryRegistry`.
- `schema_policy.rs:41` `describe`/`description`;
  `guard_bypass.rs:374` `Set`/`Map`; `weak_hash.rs:57-64,379-413`
  context/JWT gates; `predicates.rs:540-543` auth vocab (bypasses
  FactTable); `facts/signatures.rs:14,17` `session`/`get`;
  `uaf/uninit.rs:247,302-304` `< 0` idiom only; `leak.rs:795` `"NULL"`;
  `edges.rs:24` + `summaries.rs:178` `self`/`this`.
- 18 `bootstrap_*` tables in `frensense-lang/src/policy.rs` unioned at
  check time (`weak_hash.rs:181`, `int_overflow.rs:158`,
  `guard_bypass.rs:61`) - unremovable fallback, never overridden by any
  provider (`spec.rs:660-778` is pure pass-through).

#### C. Verdict-shaping magic numbers (budget exhaustion => silent false negatives)

`guard_bypass.rs:137,319` (8 hops); `uaf/walker.rs:17,20` (512/256),
`uaf/walker.rs:116` (depth<=1), `:180`, `:309`; `uaf/discovery.rs:17`
(4096); `memory_summary.rs:294` (10); `leak.rs:502` (64*blocks);
`value.rs:373,382` (64); `oob.rs:289` and `steensgaard.rs:101` (+1000);
`mod.rs:242-243` (`i64::MAX` sentinels).

#### D. Structural

- `leak::check` (`leak.rs:463`) and all of `uaf/` (`uaf/mod.rs:40-67`)
  take **no FactTable** - unteachable by design.
- 4 taint engines exist: `TaintEngine` (`config.rs:34`),
  `SvfgTaintEngine` (`svfg.rs:999`, dead), `BackwardTaintEngine`,
  `InterproceduralTaintEngine`.
- Merge-policy inconsistency: union in weak_hash/guard_bypass/schema_policy
  vs replace in `oob.rs:214-219`, `memory_summary.rs:120-125`. Three dedup
  keys: `mod.rs:94`, `uaf/mod.rs:206`, `oob.rs:557`.

#### E. Layering violations (4 upward edges + 1 cycle)

- `ir/lowering/context.rs:5,43` -> `analysis::taint::facts` (FactTable is a
  field of LoweringContext; contradicts `ir/mod.rs:11-12`).
- `graph/store.rs:37-38,115` -> `analysis::forward`;
  `graph/svfg.rs:984,999` embeds a taint engine.
- `facts/table.rs:10`, `kinds.rs:7` -> `checks::memory_summary` (cycle).
- `analysis/forward/predicates.rs:253,394,399` <-> `taint/engine`
  (forward owns `FindingClass` + alert copy).

#### F. Impurity

- `graph/store.rs:71-107` fs+blake3 behind `serialize` which is in default
  features (`Cargo.toml:40,45`); forces `FrensenseError::Io`
  (`lib.rs:52,62-66`); `SvfgStore` has no production caller.
- `debug_flags.rs:36-59` 5 env vars + `eprintln!` reachable from hot path
  (`predicates.rs:79-83`); `serialize.rs:158` `Box::leak`.
- `src/bin/*` - 3 dev CLIs with their own hardcoded source/sink tables
  (`e2e_taint.rs:18-43`) bypassing harness.
- Dead deps: `toml`, `regex`, `rayon`, `tracing`, `petgraph`,
  `tree-sitter-go` (`Cargo.toml:17-37`).

#### G. Data-schema gaps (blocked today)

| Gap | Site | Missing home |
|-----|------|--------------|
| G1 | `schema_policy.rs:41` | `FactTable.schema_describers` |
| G2 | `guard_bypass.rs:374` | `FactTable.collection_ctors` |
| G3 | `oob.rs:111-124` | field exists (`memory_functions` `table.rs:99`) - must be used |
| G4 | `leak.rs:124,138` | `FactTable.stack_allocators` |
| G5 | `signatures.rs:14,17` | `FactTable.session_accessor_methods` |
| G6 | `leak.rs:795` | `spec.known_null_tokens()` |
| G7 | `edges.rs:24`, `summaries.rs:178` | `spec.known_receiver_params()` |
| G8 | `harness.rs:273` | `spec.route_registration_patterns()` (exists, dead) |
| + | `WeakPrimitiveRule`, `KeySizeRule`, insecure-config tuple (`lang/policy.rs:127-252`), `WeakCryptoFact` (`kinds.rs:268-273`) | lack `severity`+`message` (`IntegerOverflowRule` `policy.rs:178-190` is the reference) |

#### H. Format constraints (frc.rs)

- bincode 1.3 positional + `allow_trailing_bytes` + u32 variant tags:
  `#[serde(default)]` does **not** rescue new fields; a new
  `LearnedFactEntry` variant breaks old readers entirely; the version gate
  only rejects *newer* bundles (`frc.rs:73-78`). => one deliberate
  `BUNDLE_VERSION 5` bump with version-branched payload load
  (`frc.rs:66-78`).

#### I. Bundler gate mechanics (knowledge intake)

- Existential-vote rule rejects any candidate with no separating voter
  (`extract/mod.rs:305-313`) - the only hard blocker in the gate;
  cross-family regression (`:291-303`) and
  `apply_candidate -> scan_prepared -> separates` work vote-free.
- Gate can only observe behavior through the alert predicate:
  messages/severities/invisible thresholds pass vacuously. Precedent for
  hand-authored + gated: `IntegerOverflowRule` from `[frensense] wrap-max:`
  metadata (`propose.rs:88-105`).
- Provenance is dropped before serialization
  (`LearnedFact{support,status,families}` dies at `builder.rs:26-27`).

## Part 2 - Decisions (final)

| # | Decision | Resolution |
|---|----------|------------|
| D1 | Default pack home | **Embedded `include_bytes!` default `.frc` inside `frensense-bundler`**, exposed as `default_bundle_bytes()`. Rationale: bundler owns the `.frc` format end-to-end (`format/mod.rs:5-9`) *and* is a dependency of the CLI - one embed gives both consumers identical baselines (replay-gate parity) and keeps engine/lang shipping zero policy. Consumer replaces it via `--bundle`; empty pack = spec-seed only. |
| D2 | Authored input format | **Cancelled - corpus-only (2026-10).** All client-facing authored policy flows through corpus pairs + the in-corpus `[frensense]` metadata block (`family.rs:96-113`, already authors `IntegerOverflowRule`s); no rule file, no TOML/JSON authoring surface ("corpus-based, not rule-based" - `FRENSENSE_CORPUS_GUIDE.md`). `policy_pack` stays in the v5 schema as a reserved, always-empty section; the `Authored` provenance tier stays structural with no producer until a decision reopens it; dead `toml` dep removed from the bundler. |
| D3 | Per-language tables out of lang (Phase 6.2) | **Deferred until Phases 0-5 land, then executed**, riding the D1 vehicle: each provider's knowledge bodies become **per-language sections of the default pack** (keyed `language` field + `"*"` wildcard, mirroring `grammar_roles` at `table.rs:356-378`). Not skipped - "lang not cluttered" is untrue without it. |
| D4 | Tier ladder home | **Now: `frensense-lang/src/severity.rs`** - enum, ordering, default role->tier map; both bundler and CLI already depend on lang; CLI already re-exports `Severity` (`src/lib.rs:29`). **Later (post-D1-schema):** role->tier map becomes bundle-overridable. Engine keeps only the `SinkRole` enum, zero tier strings. |

## Part 3 - Target end state

```
frensense-lang   grammar, LanguageSpec (classify/grammar/queries/imports),
                 NodeRole, registry, Severity + role->tier default map (D4)
                 x no policy.rs, no knowledge string tables,
                   no fact-shaped structs

frensense-engine provers: parse->lower->SSA->SVFG->points-to->dominators->
                 taint fixpoint
                 checks as FACT-DRIVEN evaluators (weak-hash prover,
                 range prover, co-occurrence evaluator, UAF/OOB/leak walkers)
                 input: (files, TaintConfig, FactTable)
                 output: structured verdicts
                 x zero security string literals, zero prose,
                   zero severity tiers, zero fs/env, zero bootstrap_ imports,
                   no Io error variant

frensense-bundler owns .frc format + DEFAULT PACK bytes (D1) + reserved
                 policy_pack section (D2 cancelled: corpus-only) + replay
                 gate with local alert predicate
                 x never renders user findings

frensense (CLI)  owns alert policy, tier mapping, dedup, rendering
                 (text/JSON/SARIF), exit codes, baseline gating - one
                 filtering path (MCP/LSP reuse it)
```

`.frc` v5 payload:

```
BundlePayloadV5 { patterns, learned_facts, policy_pack }
  learned_facts  -> provenance = Learned   (corpus pairs, replay-gated)
  policy_pack    -> provenance = Authored  (reserved: always empty; D2
                                            corpus-only, no rule file)
  default pack   -> provenance = Spec      (embedded in bundler, merged first)
```

## Part 4 - PR plan (ordered; workspace compiles after every PR)

Verification harness run after every PR: `cargo test` (workspace) + e2e_batch
precision/recall vs `baseline_scorecard.json` + bundler round-trip
(`pipeline.rs:97`). No PR may move these numbers unless the PR's intent says
so.

Status below reflects the tree at `76a5226`. The debt-cleanup series C1-C8
(formerly tracked in `ENGINE_AUDIT.md`, kept in git history) landed as
`76deff0` .. `047fb94` on top of Phases 0-3.

### Phase 0 - Safety net + dead weight (no behavior change)

**Status: done** (`d7d5ea7`, `4966358`, `deeec1b`, `d7b80a4`, `4d4696d`).

| PR | Change | Key sites |
|----|--------|-----------|
| 0.1 | **Debt ratchet**: script/test counting violations (engine `bootstrap_` imports, non-test prose `format!`, `"critical"`/`"warning"`/`"info"` in engine, `frensense_lang::policy` refs). CI fails if count *increases*. | baseline = current counts |
| 0.2 | **Delete dead taint engines**: `SvfgTaintEngine`; legacy `TaintEngine` in `taint/config.rs:32-45` (confirm no non-test use). Removes 3 `"CRITICAL VULNERABILITY"` copies. | `svfg.rs:984-1202` |
| 0.3 | **Delete `SvfgStore`** => removes `FrensenseError::Io`, drops `serialize` from default features. | `store.rs`, `lib.rs:52,62-66`, `Cargo.toml:40,45` |
| 0.4 | **Move `src/bin/` out** to a new `frensense-devtools` crate (they duplicate lowering + hardcode source/sink tables; `frensense-bench` is not a Rust crate). | `e2e_taint.rs:18-43` |
| 0.5 | **Remove dead deps** + stale `frensense-engine/Cargo.lock`. | `Cargo.toml:17-37` |

**Accept:** ratchet green; e2e_batch identical; engine diff purely subtractive.

### Phase 1 - Verdict contract: engine stops deciding

**Status: done** (`7418af1`, `c2be15c`, `6c7a123`).

| PR | Change | Key sites |
|----|--------|-----------|
| 1.1 | Add `severity: String` to `CheckerFinding`; copy `fact.severity` at the two drop points. | `checks/mod.rs:57-72`, `policy.rs:119-125`, `mod.rs:292-298` |
| 1.2 | `Provenance { Spec, Authored, Learned }` replaces `learned: bool`; fix mislabels; fix `UninitializedFree -> DOUBLE_FREE` id aliasing (new rule id in lang `rules.rs`). | `weak_hash.rs:202,222`; `guard_bypass.rs:431`; `int_overflow.rs:211`; `uaf/types.rs:100-101` |
| 1.3 | **Alert policy leaves the engine**: deprecate `vulnerable()`/`has_alert()`; bundler-local `fn alerts(&ScanResult) -> bool` in `gate.rs` (must re-declare both clauses: info-tier exclusion + checker-inclusion) with `propose.rs:107-110` rerouted through it; CLI collapses its triple filter (`runner.rs:112-122`, `:150-153`, MCP `scan_file.rs:94-99`) into one reporting-policy function; delete `role.rs default_level()/tag()`, move default role->tier map to **lang `severity.rs` (D4)** - engine emits `SinkRole` only. | `scan.rs:271-297`; `role.rs:94-114` |

**Accept:** `grep '"info"' engine/src` -> 0 outside tests; bundler gate tests
pass with unchanged behavior; CLI output byte-identical.

### Phase 2 - Bundle format v5 (before all knowledge moves)

**Status: done** (`2ebe800`, `3850a6f`, `fb42237`). 2.1: version-branched
load + `policy_pack`. 2.2: `WeakPrimitiveRule`, `KeySizeRule`, the
insecure-config tuple (promoted to `InsecureConfigRule`) and
`WeakCryptoFact` carry `severity` + `message`; `weak_hash` findings copy
the declared severity (`IntegerOverflowRule` reference pattern), the
ratchet's `lang_policy_refs` tightened 6 -> 3. 2.3: `BundlePattern`
gains a `rules` join (finding identities from
`LearnedFactEntry::finding_identities`), v4 patterns load with an empty
join, and the runner overlays matched patterns onto checker and taint
advisories (CVSS severity labels -> CLI tiers; observation precedence:
fact prose > pattern prose > lang template). Accept: v4 bundles load,
old readers reject v5 with the clean version error, round-trip green,
A/B 36/36 identical after every PR.

| PR | Change | Key sites |
|----|--------|-----------|
| 2.1 | `BUNDLE_VERSION = 5`; version-branched payload load (`V4Payload` vs `BundlePayloadV5`); new section `policy_pack: Vec<AuthoredPolicyEntry>` (section = provenance). | `frc.rs:14,66-78`; `types.rs:47-54` |
| 2.2 | Widen rule structs with `severity` + `message`: `WeakPrimitiveRule`, `KeySizeRule`, insecure-config tuple, `WeakCryptoFact` (`IntegerOverflowRule` = reference pattern). | `lang/policy.rs:127-252`; `kinds.rs:268-273` |
| 2.3 | Wire `BundlePattern` (severity/cwe/cvss - written, never read) into the consumer advisory path. | `types.rs:23-39`; `runner.rs:198,241` |

**Accept:** old v4 bundles load; v5 rejected by old code with clean version
error; round-trip green.

### Phase 3 - Presentation leaves the engine

**Status: done** (`9a50920`, `31e4a0e`, `02da5b5`, `f51fb6e`, `b6db2e8`,
`858210d`).

| PR | Change | Key sites |
|----|--------|-----------|
| 3.1 | Delete `render_text()`/`sarif_locations()` -> root `reporter.rs`; `describe()` becomes CLI-owned presentation from structured steps. | `path.rs:77-116,197-225`; `runner.rs:248` |
| 3.2a-e | **Messages become data, per-check** (weak_hash -> guard_bypass -> uaf/oob/leak -> schema/int_overflow): findings emit `rule` + structured params; prose lookup moves to consumer/bundle/lang `RuleAdvisory`. Remove all `"CRITICAL VULNERABILITY"` strings. | ~40 `format!` sites; `predicates.rs:367-399` |

**Accept:** ratchet count of non-test prose `format!` in engine = 0;
e2e_batch identical after each sub-PR.

### Phase 4 - Schema completion: every check fact-driven

**Status: done** (`9757ef7`, `43f7396`, `6f1d3cc`). 4.1-4.3 complete:
spec-seeded FactTable fields, registry/facts consumption, null tokens,
receiver params, and `route_registration_patterns()` wired into the
harness seam. 4.4: leak and oob take `&FactTable`; uaf receives its
vocabulary through `MemorySummaryRegistry::from_facts(facts)` (a direct
facts parameter would be dead code); the three dedup sites collapsed into
`checks::finding_key` at the one dedup point (`check_all`); teachability
tests prove a hand-built bundle can create a UAF finding and create or
suppress a leak finding (the phase's Accept).

| PR | Change | Gaps |
|----|--------|------|
| 4.1 | New FactTable fields + spec seeds: `schema_describers`, `collection_ctors`, `stack_allocators`, `session_accessor_methods`. | G1, G2, G4, G5 |
| 4.2 | `oob.rs` consumes `MemorySummaryRegistry`/`memory_functions` capacity instead of inline allocator match; unifies merge policy (kills replace-vs-union inconsistency at `oob.rs:214-219`). | G3 |
| 4.3 | Spec methods: `known_null_tokens`, `known_receiver_params`, wire the existing dead `route_registration_patterns()` into harness (seam already exists at `harness.rs:260-276`). | G6, G7, G8 |
| 4.4 | **Thread `&FactTable` through `leak::check` and all of `uaf/`**; unify the three dedup keys (`mod.rs:94`, `uaf/mod.rs:206`, `oob.rs:557`) at FactTable level. | D-structural |

**Accept:** teachability test - a hand-built bundle can suppress/alter a leak
and a UAF finding (fails today).

### Phase 5 - Ingestion surface + default pack (heart of the principle)

**Status: partially done.** Check-time `bootstrap_*` unions are gone
(engine refs = 0: `76deff0`, `9757ef7`, `43f7396`); provenance is
per-entry in `FactTable` (`73bbc0f`). 5.1 CLI arg fix done (`76a5226`,
D2 cancelled - corpus-only). Remaining: default pack (5.2),
provenance-ordered merge flip (5.3). Phase 2 gate closed (`fb42237`).

| PR | Change | Key sites |
|----|--------|-----------|
| 5.1 | **CLI arg parsing (D2 corpus-only)**: `frensense-bundler` and `frensense bundle` parse `-c/--corpus` + `-o/--output` (release CI passes `-c corpus/targets -o frensense-corpus.frc`; today they are misread as the corpus/output paths), positional args keep working, strict unknown-flag errors, drop stale `--facts`, remove dead `toml` dep. | `main.rs:13-32`; `src/bin/frensense.rs:84-103` |
| 5.2 | **Default pack (D1)**: generate `frensense-default.frc` from lang's `bootstrap_*` tables; `include_bytes!` in bundler as `default_bundle_bytes()`; seeding order = spec seed -> default pack -> consumer bundle (last-wins). **Remove check-time `bootstrap_*` unions** so checks read `facts.*` only. | `weak_hash.rs:181`, `int_overflow.rs:158`, `guard_bypass.rs:61`, `predicates.rs:540`; `facts/config.rs:16` |
| 5.3 | **Explicit precedence + provenance** in `FactTable::merge` (today `learned_checks`/`policy_facts` are first-wins, `table.rs:206-229` - flip to provenance-ordered: Spec < Authored < Learned-or-consumer). | `table.rs:189-345` |

**Accept:** no bundle -> spec-seed + default pack only; `--bundle`
replaces/extends; empty pack = zero policies.

### Phase 6 - Lang purge

**Status: pending** (`frensense-lang/src/policy.rs` still present).

| PR | Change |
|----|--------|
| 6.1 | Move fact types (`WeakPrimitiveRule`, `IntegerOverflowRule`, `KeySizeRule`, `MemoryFuncSpec`, `BufferBuiltinSpec`) -> `engine::facts::kinds`; **delete `frensense-lang/src/policy.rs`**; delete the 18 never-overridden `known_*` trait methods (`spec.rs:660-778`); bundler import site updates (`candidate.rs:263`). |
| 6.2 | **(D3)** Provider knowledge bodies (~2,570 lines across go/python/rust/c/js) -> per-language sections of the default pack (keyed `language` + `"*"`); lang keeps only trait/grammar/queries/classify/registry. |

**Accept:** lang ~= mechanism only; `grep bootstrap_ workspace` -> 0.

### Phase 7 - Enforcement + hardening

**Status: partially done.** `Box::leak` eliminated (scan borrows `self.irs`;
`serialize.rs` deleted in `c551412`); debug-flag env reads live in consumer
bins (`0f1c186`). Remaining: ratchet -> hard 0, `Limits` budget struct.

- Ratchet -> **hard 0**: CI fails on `bootstrap_` in engine, prose `format!`
  in engine, tier strings in engine, `std::fs`/`std::env` in engine lib,
  `policy.rs` imports anywhere.
- `debug_flags` injected or cfg(test)-only; eliminate `Box::leak`
  (`scan.rs:115`, `serialize.rs:158`) with a real arena; magic budgets ->
  `Limits` struct passed by consumer with defaults in the bundle
  (`guard_bypass.rs:137`, `uaf/walker.rs:17`, `uaf/discovery.rs:17`).

## Part 5 - Definition of done

1. `frensense-engine` src (non-test): zero security string literals, zero
   prose messages, zero tier strings, zero `bootstrap_` refs, zero fs/env,
   no `Io` error variant.
2. `frensense-lang`: no `policy.rs`, no knowledge tables, only
   grammar/classification + `Severity` + rule-id constants.
3. All knowledge reachable only through `FactTable` (Spec seed -> default
   pack -> consumer pack), provenance-ordered and consumer-controllable.
4. One alert predicate per consumer (bundler gate, CLI reporting) - no
   engine policy, no >=4 copies.
5. e2e_batch precision/recall >= `baseline_scorecard.json`; all workspace
   tests green.

## Part 6 - Risks

- **Silent gate drift (1.3):** if the bundler's new `alerts()` drops a
  clause, replay results change invisibly -> mitigation: port the existing
  gate test suite unchanged and diff publish/reject reports before/after
  (`FXREPORT` JSON).
- **Prose migration regressions (3.2):** message-only diffs should not
  affect e2e_batch (it scores verdicts, not text) - verified by keeping
  verdict logic byte-identical per sub-PR.
- **Format bump (Phase 2):** old binaries + new bundles fail closed by
  design; release notes must state `.frc` v5 requires updated CLI.
- **D3 scale:** largest single phase; deliberately last, after purity is
  otherwise proven.
