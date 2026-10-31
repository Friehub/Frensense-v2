<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub. All rights reserved. -->

# AGENTS.md — Contract for AI Coding Agents

This file is for **AI agents** (Claude Code, Codex, Cursor, and similar)
contributing to Frensense. Human contributors: read
[CONTRIBUTING.md](CONTRIBUTING.md) instead.

Read this file fully before writing code. It explains how the engine is
built, where knowledge is allowed to live, and the exact gate your change
must pass.

---

## 1. What Frensense is

A deterministic, dataflow-driven security scanner for TypeScript, JavaScript,
Python, Go, Rust, and C. No YAML rule packs, no regex heuristics: the engine
lowers code to an IR, builds program graphs, and verifies whether untrusted
data can actually reach a dangerous sink.

One binary, three surfaces: `frensense [path]` (CLI/CI), `frensense mcp`
(AI agents), `frensense lsp` (editors). All share one analysis engine and
one stable finding-identity scheme (`FRN-…`).

## 2. Engine architecture (read this before touching analysis code)

The pipeline, in order:

```
parse (tree-sitter, via frensense-lang spec)
  → lower → FunctionIR + Memory SSA        [frensense-engine/src/ir]
  → SVFG + callgraph + heap points-to      [frensense-engine/src/graph]
  → demand-driven backward taint (+ forward engine, summaries)
                                           [frensense-engine/src/analysis]
  → non-dataflow checks                    [frensense-engine/src/checks]
```

Strict layering — each layer depends only on the ones above it:

| layer | crate/path | knows about |
|---|---|---|
| Language specs | `frensense-lang` | grammar mechanism only: "one call per decision" (`spec.classify(node.kind()) → NodeRole`), never hardcoded node-kind strings, **no security vocabulary** |
| IR frontend | `frensense-engine/src/ir` | pure data. Knows nothing about taint or checks |
| Program graphs | `frensense-engine/src/graph` | SVFG, callgraph, Steensgaard points-to |
| Analysis | `frensense-engine/src/analysis` | demand-driven **backward** taint: seed at sinks, walk backward; source reached → Vulnerable, sanitizer → pruned, unresolvable → Unknown |
| Checks | `frensense-engine/src/checks` | **"built-in = how to look; learned = what to conclude"** — builtin checks supply mechanism only; conclusions arrive as `LearnedCheckFact`s via `.frc` bundles |
| Harness | `frensense-engine/src/harness.rs` | the ONE implementation of "source text → analyzed program graph". The scanner AND the bundler's fact extractor both go through it, so facts are extracted from exactly the IR the engine scans |
| Stable API | `frensense-engine/src/scan.rs` | `files + TaintConfig + FactTable → findings`. Everything downstream (CLI, MCP, LSP, bundler replay gate, benchmarks) calls only this |

**The `FactTable` is the teaching interface.** Detection knowledge is data
merged into it at scan time — never engine code.

## 3. The two knowledge lanes (do not conflate them)

There are exactly two places detection knowledge may live. Pick by what
you are changing:

### Lane A — Built-in vocabulary: `frensense-packgen` (maintainer territory)

The **default pack is NOT learned from positive examples.** It is generated
from static Rust vocabulary tables owned by `frensense-packgen`
(`src/data.rs`, `src/vocab/`). The generator emits them deterministically as
`LearnedFactEntry`s into the committed asset
`frensense-bundler/assets/frensense-default.frc` (zero patterns, provenance
`Spec`). The bundler merely embeds that asset via `include_bytes!` and
parses it.

If you must change built-in vocabulary (rare; usually a maintainer task):

1. Edit the tables in `frensense-packgen/src/`.
2. Regenerate the asset: `cargo run -p frensense-packgen -- --out`.
3. Commit both the generator change and the regenerated asset together.
4. CI's `packgen --check` fails if the asset drifts from the generator.

### Lane B — Corpus bundles: twin examples (the contributor/agent path)

**This is the path for virtually all new detection knowledge.** Frensense is
corpus-based, not rule-based:

1. Author a family: `<name>_positive.<ext>` (vulnerable) +
   `<name>_negative.<ext>` (fixed). See
   [docs/FRENSENSE_CORPUS_GUIDE.md](docs/FRENSENSE_CORPUS_GUIDE.md).
2. Compile: `frensense bundle <corpus_dir> <output>.frc`.
3. The bundler lowers both twins through the **same harness the engine
   scans with**, proposes a fact, and runs the **replay gate**: the fact is
   published only if the positive alerts, the negative stays silent, and no
   other family regresses. Facts that cannot prove themselves are discarded.
4. Ship the `.frc` bundle. No engine, lang, or packgen edits.

### Seeding order (last wins)

```
spec seed → default pack → consumer bundle
```

- Consumer bundle facts override default-pack facts on collision.
- Coarse facts never widen precise ones: an "all arguments dangerous" rule
  cannot overwrite a slot-restricted signature learned by a bundle.
- Multiple bundles accumulate additively with dedup on `(rule, call)`.

### Decision table

| You want to... | Lane |
|---|---|
| Teach the engine a new framework sink/source/sanitizer | B (corpus family) |
| Add advisory text, CWE, severity for a pattern | B (`[frensense]` block on the positive) |
| Extend a built-in rule table (weak hashes, key sizes, ...) | A (packgen vocab + regenerate asset) |
| Change how analysis *works* (new lowering, guard handling) | Engine change — see §4 |

## 4. Engine purity rules (hard constraints)

1. **`frensense-engine` contains analysis mechanisms only.** No benchmark
   identifiers, no product names, no dataset-specific knowledge, no prose
   that belongs to a consumer. Learned knowledge lives in `LearnedFactEntry`
   / `.frc` bundles — that is the whole point of the architecture.
2. **The purity ratchet enforces this mechanically.** CI runs
   `python3 .github/scripts/purity-ratchet.py` (see
   [docs/ENGINE_PURITY_REFACTOR.md](docs/ENGINE_PURITY_REFACTOR.md)): it
   counts debt classes (engine `format!` prose, tier strings, policy refs
   outside lang, provider vocab in lang) and **fails if any count grows**.
   If your change must add to a counted class, justify lowering the
   baseline in the same PR — or better, don't add.
3. **Engine changes need a fixture test.** If your change alters findings
   (a new source, sink, sanitizer, guard, or lowering behavior), add a unit
   test with a minimal positive/negative reproduction. PRs that change
   detection behavior without a test are rejected.
4. **No benchmark chasing.** Do not tune rules against the OWASP
   BenchmarkPython corpus or any benchmark. Tests must reproduce
   *real-world* patterns; the benchmark is an independent measurement, not
   a target list.

## 5. The gate (run before every PR)

```bash
./.github/scripts/local-ci.sh
```

This mirrors the required checks in `.github/workflows/ci.yml`; a few local-only
steps also cover security, release compatibility, and feature isolation.

1. `python3 .github/scripts/purity-ratchet.py` — engine purity debt must not grow
2. `cargo fmt --all -- --check` — style
3. `RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" cargo doc -p frensense-engine --all-features --no-deps` — engine docs
4. `cargo machete --with-metadata ...` — unused workspace dependencies
5. `cargo hack check -p frensense-engine --each-feature --locked` — isolated engine features
6. `cargo run -p frensense-packgen -- --check` — default pack asset must not drift
7. `cargo clippy --all-features --all-targets -- -D warnings` — warnings are errors
8. `cargo test --workspace --all-features` — full regression suite
9. `cargo deny check` — advisories, licenses, bans, and sources
10. `python3 .github/scripts/semver-gate.py --base-ref HEAD` — per-crate public-API compatibility for every publishable crate (one binary, four independently versioned crates)

While iterating, run individual steps; the pre-commit hook
(`make setup`) runs the fast subset (fmt, clippy, unit tests) on every
commit. The full suite runs in step 8 — do not skip it before a PR.

## 6. Dogfood the scanner on your own edits

Frensense scans itself. Before finishing any change, gate your own diff:

```bash
cargo build
./target/debug/frensense . --diff-only
```

Or, if you work through the MCP server, call `frensense_diff` with the
workspace as `repo`. Findings on your added lines must be clean — or
explained in the PR description. Stable finding IDs (`FRN-…`) let you track
"did I fix THIS finding" across edit cycles; see
[docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md) for the full
edit → gate → fix → verify workflow.

## 7. Housekeeping

- **The changelog is the only documentation you update for a change** — see
  §7.1 below. Update the changelog of the crate you changed (the root
  `CHANGELOG.md` for `src/`) and, when the root moved, regenerate its mirror at
  `docs-site/changelog.md`; those are the only documentation files to change.
  Do not write new prose docs, and do not edit other `docs/*.md` files to
  describe a change; that directory is background reading for humans, not a
  per-change obligation. Version bumps follow §7.2.
- **SPDX header**: every source file starts with
  `// SPDX-License-Identifier: GPL-3.0-only` (+ the copyright line). Copy
  from any existing file.
- **Commits**: sign with `git commit -s` (DCO). Small, mechanical PRs;
  architectural changes need a human-driven issue first.
- **A human opens the PR** after reading the diff; the author line says who
  (or what) wrote the change.
- **Scripts**: `.github/scripts/local-ci.sh` is the canonical gate; `make setup`
  installs the fast pre-commit hook. Heavy analysis tooling (Miri, mutation
  testing, unsafe audits) was deliberately removed from the contributor
  path — CI's clippy + tests + `cargo deny` cover those classes.

### 7.1 The changelogs — the only docs a change must update

Each crate has its own changelog and its own version. A user-visible change
gets an entry in the changelog of the crate whose behaviour it changes, under
that file's unreleased heading. If your change does not reach a changelog, it
is not done.

| you changed | entry goes in |
|---|---|
| `src/` — CLI, MCP, LSP, reporting, policy, build identity | [`CHANGELOG.md`](CHANGELOG.md) |
| `frensense-engine/` — IR, graphs, taint, checks, harness, `scan` | [`frensense-engine/CHANGELOG.md`](frensense-engine/CHANGELOG.md) |
| `frensense-lang/` — specs, rule cards, CWE/severity tables | [`frensense-lang/CHANGELOG.md`](frensense-lang/CHANGELOG.md) |
| `frensense-bundler/` — `.frc` format, corpus compiler, `lint`, default pack | [`frensense-bundler/CHANGELOG.md`](frensense-bundler/CHANGELOG.md) |
| `frensense-packgen/` — built-in vocabulary behind the default pack | [`frensense-packgen/CHANGELOG.md`](frensense-packgen/CHANGELOG.md) |
| repo tooling — CI, scripts, docs-site, test-data moves | [`CHANGELOG.md`](CHANGELOG.md) under `#### Repository & Release Tooling` |

`frensense-devtools` is an unpublished harness and has no changelog.

- **One entry per crate that changed, written for that crate.** A change that
  spans crates (a new sink plus the CLI flag that exposes it) gets an entry in
  each file that states that crate's half and links to the sibling for the
  rest; it does not paste one crate's internals into another's changelog. Keep
  the deep implementation narrative in the crate that owns the mechanism — the
  measurements, the failing repro, the algorithm — and keep the root entry to
  what a `frensense` *user* observes (flag, report field, exit code).
- **Do not duplicate release history into crate files.** Sections below
  `0.8.0` in the root file are the combined narrative of tagged releases;
  per-crate history starts at `0.8.0` and each crate cuts its own version
  heading from then on.
- **Sections**: Keep a Changelog's `### Added` / `### Changed` / `### Fixed` /
  `### Removed` (plus `### Breaking` and `### Security` when they apply), in
  that order. Group a themed run of entries under a `#### <Theme>` sub-heading.
  Add to the existing section instead of starting a new `##` version — the
  version heading is cut by a human at release time.
- **Write it like the entries around it**: what was broken, *why* it was
  broken, what the fix does, and the measured before/after (wall time, peak
  RSS, finding counts, benchmark scores). "Fixed a bug" is not an entry; a
  reviewer should be able to tell from the changelog alone whether their
  problem is the one you fixed.
- **`frensense-bundler/CHANGELOG.md` is contract-checked.**
  `.github/scripts/format-ratchet.py` fails when `BUNDLE_VERSION` moves without the new
  number appearing in that file, because `.frc` compatibility is what the
  number governs. Ctrl that entry there, not in the root.

[`docs-site/changelog.md`](docs-site/changelog.md) mirrors the **root** file
behind a five-line YAML front matter, and the two must stay byte-identical
below that front matter. Regenerate it whenever the root moves — never
hand-edit it, and never add an entry only there:

```bash
{ printf -- '---\ntitle: Changelog\ndescription: Complete release history and preview releases for Frensense\n---\n\n'; cat CHANGELOG.md; } > docs-site/changelog.md
diff CHANGELOG.md <(tail -n +6 docs-site/changelog.md)   # empty output = in sync
```

When updating agent instructions, keep this rule explicit: the crate changelogs
are the source of truth for their crate, the root file is the source of truth
for `frensense` and its docs-site mirror must stay in sync, and no other
documentation is changed for routine code changes.

### 7.2 Versioning and the bump strategy

Crates version **independently**. The root `version` in `Cargo.toml` is the
`frensense` crate's version, and it is the only thing a release tag names
(`vX.Y.Z`); a release does not force the workspace onto one number. Shipping
`frensense` 0.7.1 on top of `frensense-engine` 0.8.0 is supported and expected —
the dependency requirement, not a shared version, expresses compatibility.

**Bump on evidence, not on lockstep.** `.github/scripts/semver-gate.py` is the single
per-crate gate, used by `.github/scripts/local-ci.sh`, CI's `semver` job and the release
workflow:

```bash
python3 .github/scripts/semver-gate.py --base-ref HEAD      # local: what did I break?
python3 .github/scripts/semver-gate.py --base-ref HEAD^     # CI push
python3 .github/scripts/semver-gate.py --published          # release pre-check
```

It discovers the publishable crates from `cargo metadata` (`publish = false`
crates such as packgen/devtools are excluded), closes the changed set over
workspace dependents (a break in a re-exported engine/lang type reaches
`frensense`), and runs `check-release --release-type patch` per crate. A crate
is **ok** with no break, **absorbed** when its own version moved a breaking
component, and **FAIL** when it broke without bumping — the only failure mode,
so the fix is always the same question: which crate broke, and did that crate
bump itself? A build error is reported as an error, not as a SemVer signal.

- **No major failures** → the crate did not break its public API: ship a patch
  (`0.8.0 -> 0.8.1`) for fixes, or a minor-patch (`0.8.0 -> 0.9.0`) only if you
  choose to treat a new API as a feature boundary.
- **Any major failure** → the public API broke: bump the middle number
  (`0.7.0 -> 0.8.0`). Under Cargo's `0.x` rules that *is* the breaking bump.
- `check-release` with no `--release-type` compares the version you wrote
  against the baseline and **skips all 260 checks when the middle number moved**
  (it reports "major change, 0 checks, 260 skip"). That is why the flag matters:
  the patch mode is what tells you whether a bump was justified.

Measured on the 0.8.0-beta line (baseline: published 0.7.0), patch mode:

| crate | major checks failed | what broke |
|---|---|---|
| `frensense-engine` | 6 | `sink_signature_scoped`/`is_sink_call_scoped` arity, `SinkFinding`/`BackwardStats` now `non_exhaustive`, new enum variants |
| `frensense` | 4 | `reporting` module removed/renamed, `print_results` arity, `Advisory` now `non_exhaustive` |
| `frensense-lang` | 3 | `NodeRole::KeywordArgument` added and later discriminants shifted, `Export` fields |
| `frensense-bundler` | 3 | `Candidate` now `non_exhaustive`, `Candidate::Check.package`, `FamilyMetadata`/`PreparedFamily` fields |

So all four legitimately take a middle-number bump on this line — but that is a
conclusion from the checks, not a rule that they must move together. A CI-only
or script-only change bumps nothing; a fix inside the engine that adds no
public item bumps only `frensense-engine`, and `frensense` may ship its own
patch the same day.

**Dependency requirements.** `frensense` declares path dependencies with a
version range: `{ path = "frensense-engine", version = "0.8.0" }`.
`^0.8.0` means `>=0.8.0, <0.9.0`, so a dependent needs **no manifest edit** when
a dependency releases `0.8.1` (or any `0.8.x`) — only a change to the middle
number reaches the dependents' manifests. Two things still need care:

- **A dependency's 0.x breaking bump** (`0.8.0 -> 0.9.0`) requires editing the
  dependents' requirements. That edit alone does *not* force the dependent's own
  bump: it does only when the changed item is part of the dependent's public
  API. `frensense` re-exports `frensense_engine::FileId` and
  `frensense_lang::{Profile, RuleTier, Severity}` and stores them in `Advisory`,
  so a breaking change to those specific types does force `frensense` to bump;
  a break elsewhere in the engine does not.
- **Pre-release pinning**: Cargo only selects a pre-release dependency when the
  requirement itself allows that pre-release. `version = "1.2.3"` does not
  resolve against a published `1.2.3-rc.1`; while a crate is pre-release, every
  dependent's requirement keeps the same suffix. Drop the suffix from every
  dependent in the commit that cuts the final release (as the 0.8.0 cut did).

**Mechanics.** Versions are set by hand in the manifests; the release workflow
publishes **every publishable crate by name**, in dependency order
(`frensense-lang frensense-engine frensense-bundler frensense`), with
`cargo smart-release --bump keep --bump-dependencies keep`, which publishes
exactly those manifest versions and skips `publish = false` crates.

A release is decided per crate, not by the root version alone:

- `.github/scripts/release-matrix.py` records which publishable crates are missing
  from crates.io at their manifest version. If any are, the run publishes even
  when the root version did not move (a crate-only release has **no new tag**).
- The tag is `v<root version>`, created only when it does not exist, and the
  binary/npm/GitHub-release jobs run only for a new tag. A crate-only release
  publishes to crates.io and leaves the existing tag and assets alone.
- Before publishing, `semver-gate.py --published` asserts every crate's version
  already covers its public-API change; afterwards
  `release-matrix.py --require-published --wait 420` fails the job unless every
  publishable crate at its manifest version is live on crates.io. A skipped
  crate cannot pass silently.

**Bundle compatibility is separate.** A `.frc` is decodable per
`BUNDLE_VERSION` plus `FACT_VOCABULARY_FINGERPRINT` (see `docs/FORMATS.md`),
not per crate version; `.github/scripts/format-ratchet.py` enforces the pair. Do not
infer artifact compatibility from a version number.

### 7.3 One crate at a time

Crates version independently, so they are changed independently. A commit (and
a PR) touches **one crate's tree** plus the changelog entry that records it:
`frensense-lang`, `frensense-engine`, `frensense-bundler`, `frensense-packgen`,
or `src/` for the `frensense` binary. A change that genuinely spans crates is a
*series* in dependency order — language fact, then the engine that consumes it,
then the CLI surface that reports it — with one commit per crate, each green on
its own and each carrying its own version decision. Measured on the 0.8 line
before this rule: 33 of 84 commits (39%) touched more than one crate, which is
why every crate ended up on one version.

- **Scope the subject to the crate**: `fix(engine): …`, `feat(lang): …`,
  `refactor(bundler): …`, `feat(packgen): …`, `feat(cli): …`; `cliff.toml`
  groups the changelog by exactly these scopes. `git commit -s` (DCO) as usual.
- **Do not bump a crate you did not change.** A workspace-wide bump is not a
  convention; `.github/scripts/semver-gate.py` reports per crate what moved.
- **Prefer finishing a crate to starting a second one.** A crate with an
  unshipped changelog entry is not done; land it, cut its release, then move
  on. Cross-crate work in flight is what makes a release hard to reason about.

## 8. Where to go deeper

| doc | contents |
|---|---|
| [frensense-engine/AGENTS.md](frensense-engine/AGENTS.md) | crate-specific library API, modularization, and verification contract |
| [docs/ENGINE_MAINTAINERS_GUIDE.md](docs/ENGINE_MAINTAINERS_GUIDE.md) | engine hotspots, staged file splits, API stability, and Rust tooling recommendations |
| [docs/TEACHABILITY.md](docs/TEACHABILITY.md) | the 13 teachable fact subsystems, twin-example learning model |
| [docs/FRENSENSE_CORPUS_GUIDE.md](docs/FRENSENSE_CORPUS_GUIDE.md) | authoring corpus families, the `[frensense]` metadata block |
| [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md) | baselines, `--github` annotations, agent-fixes/CI-judges workflow |
| [docs/MCP_USAGE.md](docs/MCP_USAGE.md) | MCP tools + a worked end-to-end agent session |
| [docs/LSP_USAGE.md](docs/LSP_USAGE.md) | editor setup and protocol walkthrough |
| [docs/BENCHMARKING.md](docs/BENCHMARKING.md) | benchmark methodology and per-CWE results |
| [docs/ENGINE_PURITY_REFACTOR.md](docs/ENGINE_PURITY_REFACTOR.md) | the purity refactor and what the ratchet counts |
