# Engine Purity Audit (2026-10-05)

Swarm audit of `frensense-engine/src` (non-test code only), performed by four
area readers (checks/, analysis/taint/, analysis/forward/, ir+graph+infra) plus
one cross-cutting grep sweeper. Findings verified against the working tree.
This document is the cleanup tracker for the remaining debt; the refactor plan
it belongs to is `ENGINE_PURITY_REFACTOR.md`.

## Scoping decisions

- `taint/context.rs` (`ContextSensitiveTaintEngine`, ~346 lines, test-only
  consumer) is **kept**: a complete, well-tested k=1 context-sensitivity
  subsystem. Only its impurities are fixed.
- Provenance mislabels are **fixed now** with per-entry provenance in
  `FactTable` (spec seed -> `Spec`, bundle entry -> `Learned`), not deferred.

## What is already clean (verified)

| Axis | State |
|---|---|
| Prose messages in checks | zero: all `message:` sites are `String::new()` or copied from a fact |
| Tier strings `"critical"/"warning"/"info"` | zero in non-test code |
| Security literals (md5, jwt, password, ...) | zero as code; comments only |
| `std::fs` | zero in non-test code |
| `frensense_lang::policy::bootstrap_*` in checks/taint/forward | zero in working tree (purged); only `frensense_lang::memory::bootstrap_*` remains |
| `scan.rs` `Box::leak` | removed; code borrows `self.irs` |
| Io error variants | zero in engine |
| Sink/source/sanitizer/IDOR/credential vocabulary | read from `TaintConfig` / `FactTable` / `LanguageSpec` |

## Remaining impurities

### P1. Prose in `forward/predicates.rs` (Phase 3.2e, not done)

- `predicates.rs:366-402` builds `"CRITICAL VULNERABILITY: ..."` /
  `"IDOR-CLASS: ..."` / `where_` clauses; returns `(FindingClass, String)`.
- Consumers discard the class and keep only the prose string:
  `forward/mod.rs:286` (`alerts: Vec<String>`), `taint/context.rs:234`
  (`ContextualAlert.message`). The backward engine keeps both
  (`engine/walk.rs:250`).
- Fix: structured `SinkAlert { sink, slot, function, class }`; prose lives
  only in consumers (devtools/test rendering).

### P2. `std::env` in `debug_flags.rs`

- `debug_flags.rs:39-43`: five `FRENSdbg_*` `std::env::var_os` reads behind a
  `OnceLock`. Only env access in the crate.
- Consumers: `harness.rs:94`, `forward/predicates.rs:80`,
  `taint/engine/walk.rs:401`, `taint/engine/walk.rs:631`, plus the
  `dbg_trace!` macro (`debug_flags.rs:52-59`, lazy args, stderr).
- No consumer binary currently reads `FRENSdbg_*`. Fix: engine exposes
  `DebugFlags::install(flags)` + `get()` (no env); bins read the env and
  install.

### P3. `Box::leak` in `taint/facts/kinds.rs` (hot path)

- `kinds.rs:372-374` `leak_field` leaks 2-4 strings per
  `TeachableNodeRole::to_node_role()` call, and `table.rs:364` converts on
  **every** `get_grammar_role` lookup, i.e. per lowered AST node
  (`ir/lowering/context.rs:89`). The `table.rs:124-127` comment claiming the
  opposite is false.
- Fix: `frensense_lang::NodeRole` string fields become `Cow<'static, str>`;
  spec providers keep `Cow::Borrowed`, bundle roles become `Cow::Owned`.
  Kills all 12 leak sites. Lowering signatures take `&str`.
- Second leak: `forward/serialize.rs:158` inside `ProgramSvfg::from_parts`,
  which has zero callers workspace-wide. Fix: delete the dead
  `from_parts`/`to_parts` path (C7).

### P4. Memory bootstrap fallbacks (three inconsistent patterns)

- `checks/memory_summary.rs:121-125` and `checks/oob.rs:220-225`: empty
  `facts.memory_functions` / `facts.buffer_builtins` -> silent lang fallback.
- `checks/leak.rs:125,139`: bypasses `FactTable` entirely via
  `frensense_lang::memory::is_stack_allocator` (no FactTable field exists).
- Everything else reads `FactTable` only. Fix: spec seeding is the single
  channel; add `FactTable.stack_allocators` (plan G4); remove fallbacks.

### P5. Hardcoded vocabulary (proper channel: spec / FactTable)

| Site | Vocabulary | Target channel |
|---|---|---|
| `checks/oob.rs:112-127` | `malloc/calloc/realloc/...` classifier ahead of summaries | `MemorySummaryRegistry` / facts |
| `checks/guard_bypass.rs:376` | `"Set" \| "Map"` collection ctors | spec method + FactTable field |
| `checks/schema_policy.rs:42` | `"describe" \| "description"` | spec method + FactTable field |
| `checks/leak.rs:794` | `s == "NULL"` | `spec.known_null_tokens()` (plan G6) |
| `harness.rs:272-276` | Express route verbs `.post/.get/...` | spec method |
| `taint/facts/signatures.rs:17,27` | accessor method `"get"` | FactTable field |
| `forward/edges.rs:24`, `forward/summaries.rs:178` | receiver params `"self" \| "this"` | spec method |
| `forward/predicates.rs:136` | `"InitialHeapState"` IR sentinel | named IR constant |

Also dead: `signatures.rs:11-20` `is_session_accessor` (zero callers, and its
`kind == "session"` condition never matches any producer).

### P6. Provenance mislabels (fix now)

- `guard_bypass.rs:60,238` and `schema_policy.rs:67-88`: `let is_learned =
  is_builtin;` collapses the distinction; every `Provenance::Spec` arm is
  unreachable; `check_allowlist_definitions` can never see a Spec guard.
- `int_overflow.rs:160`: hardcodes `Provenance::Spec` for all rules; bundle
  `LearnedFactEntry::IntegerOverflowRule` entries are mislabeled.
- `Provenance::Authored` is never constructed (expected until bundle v5).
- Fix (per-entry provenance in FactTable):
  - `integer_overflow_rules: Vec<(IntegerOverflowRule, Provenance)>`
    (spec seed -> Spec, bundle apply -> Learned).
  - guard/schema provenance fields become `FxHashMap<String, Provenance>`:
    `containment_callees`, `credential_sinks`, `credential_params`,
    `schema_builders`, `schema_keywords`. Checks read match provenance
    directly; aliasing and dead branches go away.
  - `weak_hash_rules` / `key_size_rules` / `insecure_config_selectors` stay
    plain: bundle cannot populate them today (no `LearnedFactEntry` variant),
    so `Spec` is correct. Revisit with bundle v5 sections.
  - `Provenance` enum moves to the facts module; `checks` re-exports it so
    `frensense_engine::checks::Provenance` keeps working.

## Structural debt (dead code, stale comments, duplication)

### Dead code to delete (C7)

- `lib.rs:46-66`: `FrensenseError`, `Result<T>`, `From<LanguageError>` (zero
  users; live APIs return `Result<_, String>`); drop `thiserror` if unused.
- `ir/control.rs`: control-dependence subsystem
  (`ControlDependence`, `immediate_dominators` unused halves,
  `postdominators`/`immediate_postdominators`, `edge_labels`,
  `control_dependence`); `dominators`/`DomSets` are used and stay.
- `ir/function.rs`: `Terminator::Unreachable` (never constructed),
  `unwind_to` (write-only).
- `graph/heap.rs`: `Default`/`new()` conflict violates the `LocId(0)`
  reserved-global invariant (route `Default` through `new()`); done.
  `var_locs` KEPT: the single `entry()` use is the per-variable LocId
  identity cache for AddressOf (dropping it would split same-var
  allocations into distinct locs and change the points-to lattice).
- `graph/svfg.rs`: `def_nodes`, `nodes_where`, `stats`/`SvfgStats`/`Display`
  (test-only or unused).
- `graph/callgraph.rs`: `callees_of`/`callers_of` (test-only), dead
  `callee_name` clone at `:367`, ignored `external_name` at `:273`,
  `unresolved` written in prod but only read in tests (decide: keep for
  diagnostics or drop).
- `analysis/forward/serialize.rs`: `from_parts`/`to_parts`/`FunctionParts`/
  `ProgramSvfgParts`/`SerKey` (zero callers; contains a `Box::leak`).
- `analysis/forward/summaries.rs`: `param_reaches_sink` (computed for every
  param, read only by one test).
- `analysis/forward/predicates.rs:323` and `graph/two_phase_tests.rs:34`:
  `#[allow(clippy::disallowed_methods)]` with no `clippy.toml` anywhere
  (vestigial; verify before removing).
- `checks/mod.rs:342-343`: `_assert_operand_used` placeholder;
  `checks/weak_hash.rs:139`: stale `#[allow(dead_code)]` (the fn is used).
- `taint/facts/signatures.rs`: `is_session_accessor` (dead),
  `policies_for` (dead).
- `taint/engine/mod.rs:406-411`: `alerts()` (zero callers).
- Kept by decision: `taint/context.rs` `ContextSensitiveTaintEngine`.

### Stale comments to fix (C8)

All resolved (C8 unless noted):

- `taint/facts/table.rs:124-127` (leak claim now false, rewritten by C3).
- `forward/predicates.rs:638` ("union lang bootstrap defaults" - removed;
  the fn reads only `facts.auth_guard_hints`).
- `checks/int_overflow.rs:14-15,149-150` (claimed a lang bootstrap union;
  now describes spec seeding + bundle extension).
- `checks/weak_hash.rs:357-359` (claimed a bootstrap fallback), `:47-48`
  (doc/behavior mismatch: doc now matches the security-context
  heuristic; dead `_args`/`_callee` params dropped), `:66-71`
  (duplicated doc block).
- `graph/callgraph.rs:7` (broken intra-doc link to nonexistent
  `interprocedural` module - now a plain code span).
- `taint/engine/mod.rs:25-28` vs `:387-392` (removed the hardcoded
  "9,988" claim; doc now separates the eager per-function pre-pass from
  the sink-reachable backward walks).
- `taint/engine/context.rs:8-10` (stray doc moved onto
  `ensure_reverse_index`).
- `checks/guard_bypass.rs:294-299` (Program-level doc moved onto
  `check_allowlist_definitions`; `allocation_of` keeps its own).
- `frensense-engine/Cargo.toml:6` (description rewritten to the modules
  the crate actually has).
- Inconsistent `#[cfg(test)]`: `taint/mod.rs` `mod session_trust_tests;`
  now carries the attribute its siblings carry.

### Duplication to consolidate (C8)

- `last_segment` defined 7x across checks -> single
  `checks::last_segment` (dot, then `::` for Rust/C++ paths). The 7th
  copy (`uaf/discovery.rs`) had no callers and was deleted together with
  its `pub use` re-export. Note: guard_bypass/weak_hash previously used
  the dot-only body; they now also strip `::` segments (superset
  semantics; A/B byte-identical on the samples).
- Member-path walkers: the `LoadField` def-search is shared as
  `FunctionIR::loadfield_def` (used by `predicates::member_access_path`
  and both `facts::signatures` receiver walkers). The recursive family
  at `predicates.rs` (`var_member_path`/`operand_member_path`) is kept:
  it deliberately also follows `Assign`/`LoadGlobal` defs, so folding it
  into the LoadField-only walker would change path-matching behavior
  (e2e-gated). Hop bounds stay 16 (predicates path rebuilding) vs 8
  (signatures receiver resolution) for the same reason.
- `"encode"` sanitizer-kind default x2 -> `DEFAULT_SANITIZER_KIND` /
  `ALLOWLIST_SANITIZER_KIND` consts, and the kind dialect is unified to
  one convention across every producer (spec seeding, built-in table,
  bundles): guard-style -> `"allowlist"`, everything else -> `"encode"`
  (spec seeding previously wrote `SanitizerKind` debug names). The
  field is advisory: the engine branches on `guard_style`, never on
  `kind` (dropping the strength labels loses nothing).
- `SinkRole::Other` default x3 -> `.unwrap_or_default()` (the enum
  already derives `Default` with `#[default] Other`).
- `self`/`this` receiver check x2: already consolidated in C5
  (`FactTable::is_receiver_param`); no hardcoded sites remain.
- Cross-edge sort+dedup loop x3 -> `edges::sort_dedup_edges`.
- `signatures.rs` `kind == "session"`: reader deleted with the dead
  session-accessor helpers; producer dialect unified as above.

## Verification protocol (after every cleanup commit)

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets`
3. `cargo test --workspace` (hook runs `--lib --bins`, so run the full thing
   locally)
4. `scripts/purity-ratchet.py` (and `--update` when a count drops, in the
   same commit that dropped it)
5. A/B byte-compare against `/tmp/opencode/frensense-baseline` using the
   `/tmp/opencode/ab/` samples (touch a source file first: shared target dir
   cross-contamination otherwise)
6. `e2e_batch` vs `baseline_scorecard.json` where the corpus exists (cannot
   run locally; required before merge)

## Cleanup checklist

- [x] Commit the bootstrap-purge work (`02ef4a1`, `b1e0b9d`, `76deff0`)
- [x] C1: predicates prose -> `SinkAlert` (Phase 3.2e) (`858210d`)
- [x] C2: debug_flags env -> consumer bins (`0f1c186`)
- [x] C3: `NodeRole` -> `Cow<'static, str>` (kinds.rs leak) (`9e18fb9`)
- [x] C4: memory fallbacks -> spec seeding + `FactTable.stack_allocators` (`9757ef7`)
- [x] C5: hardcoded vocabulary -> spec/FactTable (table above) (`43f7396`)
- [x] C6: per-entry provenance in `FactTable` (`73bbc0f`)
- [x] C7: dead-code sweep (`c551412`)
- [x] C8: stale comments + duplication (`047fb94`)
- [x] Final gate (fmt, clippy, tests, ratchet, A/B): all green on
      `047fb94` (410 tests / 15 suites, clippy 0 warnings, ratchet
      0/33/0/6, A/B 6 samples x 6 modes byte-identical). `e2e_batch` vs
      `baseline_scorecard.json` still required where the corpus exists.
