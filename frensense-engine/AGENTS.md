<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub. All rights reserved. -->

# `frensense-engine` contributor contract

This file supplements the repository-root [`AGENTS.md`](../AGENTS.md), which
remains authoritative for Frensense architecture, knowledge lanes, purity,
changelog handling, and the project-wide quality gate. Read that file first.
This file adds rules for work inside `frensense-engine`; it does not authorize
changes to sibling crates unless the task requires them.

For decomposition, API-stability, and tool recommendations, see
[`docs/ENGINE_MAINTAINERS_GUIDE.md`](../docs/ENGINE_MAINTAINERS_GUIDE.md).

## 1. Treat this as a critical library

The scanner, CLI/MCP/LSP drivers, bundler replay gate, pack generator, and
devtools depend on engine behavior. An engine change can alter findings,
source locations, uncertainty/completeness reporting, runtime, and bundle
compatibility. Preserve behavior deliberately; do not treat an apparently
internal refactor as safe until its consumers and tests are understood.

The intended high-level query boundary is `scan` (`files + TaintConfig +
FactTable -> ScanResult`). The IR, graph, lowering, analysis, and checker
mechanisms are not automatically stable merely because they currently use
`pub`. Before adding a public item or module, explain which external consumer
needs it and whether it belongs to the supported API, an extension API, or an
unstable/internal surface. Do not widen visibility to make a refactor easier.

## 2. Preserve the architecture and knowledge lanes

The allowed pipeline is:

```text
frensense-lang specs -> ir (pure lowered data) -> graph -> analysis -> checks
                                             harness -> scan API
```

- `ir` is data and lowering only. It must not know about taint policy,
  security conclusions, or check-specific vocabulary.
- `graph` builds program structure and points-to/value-flow relations; it
  does not decide security findings.
- `analysis` implements analysis mechanisms. Do not add provider/framework
  names, benchmark identifiers, dataset-specific knowledge, or consumer-facing
  advisory prose here.
- `checks` implement non-dataflow proof mechanisms. Detection conclusions
  and vocabulary belong in `FactTable`/learned facts, following the root
  instructions' “built-in = how to look; learned = what to conclude” rule.
- `harness` remains the single source-text-to-IR/program preparation path.
- `scan` coordinates analysis and is the intended high-level query API.

Do not use engine implementation changes to teach a new framework sink,
source, sanitizer, or advisory. Use the corpus bundle lane unless the root
instructions explicitly identify a packgen vocabulary change.

## 3. Keep modules cohesive and visibility narrow

- Organize new implementation by one responsibility or algorithm, not by
  where there happens to be room. A module should have a clear owner and a
  short description of its contract.
- Prefer a private child module (`mod child;`) and a deliberate parent-level
  `pub use` facade over a new `pub mod`. Use `pub(super)` for sibling
  collaboration and `pub(crate)` only when cross-subsystem crate access is
  required. Use `pub` only for an intentional downstream contract.
- Avoid wildcard public re-exports. They make accidental API growth hard to
  review. Re-export only named items needed at the intended boundary.
- When moving an existing item, preserve its old public path with an explicit
  re-export if compatibility requires it. A source-file move is not permission
  to break downstream imports.
- Aim for production modules below roughly 500 lines. This is a Frensense
  review heuristic, not a Rust language rule: if a file exceeds it, look for
  a cohesive extraction before adding another feature. Do not make arbitrary
  fragments or hide complexity across many tiny files just to meet the number.
- Put focused unit tests with the module they exercise and split oversized
  test files by behavior. Keep test helpers private unless a real sibling
  test module needs them.

Before adding substantial code to an already-large module, consult the
hotspot-specific decomposition map in the maintainer guide. If no clean seam
exists, explain why keeping the implementation together improves clarity.

## 4. Protect analysis and result contracts

- Keep deterministic output: do not expose hash-map iteration order as a
  stable result. Sort at observable boundaries and test repeatability where
  relevant.
- Preserve conservative behavior. When an analysis cannot resolve a case
  or reaches a cap, report uncertainty/incompleteness rather than silently
  treating missing work as a clean result.
- Every safety cap must retain its documented soundness/precision tradeoff
  and report through telemetry; do not introduce silent truncation.
- Keep failure boundaries explicit. Expected input or resource failures
  should be returned or represented in scan accounting. Panics are for
  violated internal invariants, not routine malformed source. If a public
  callback/check panic is isolated, preserve the diagnostic outcome instead
  of silently swallowing it.
- Maintain the distinction among `Vulnerable`, `Sanitized`, `Unknown`, and
  `Clean`; do not collapse unresolved analysis into a clean result.
- For behavior changes, add a small positive and negative regression fixture
  that demonstrates the intended finding difference. For behavior-preserving
  file moves, run the directly affected tests and the required quality gate.

## 5. Public API and documentation contract

For every proposed public item, module, field, trait method, feature, or
serialization behavior:

1. Identify actual downstream uses in the workspace and decide whether the
   item is supported, extension-level, or unstable.
2. Document inputs, output semantics, ordering, mutability/ownership,
   feature requirements, recoverable errors, and panic conditions as relevant.
3. Consider semver impact before adding/removing enum variants or struct
   fields, changing visibility/bounds, or changing a public module path.
4. Treat serde representation, defaults, and feature gates as observable
   contracts if downstream data or consumers rely on them.

Do not add `#[non_exhaustive]`, privatize public fields, or remove a public
module casually: those can themselves be breaking changes once published.
Stage API narrowing with explicit compatibility decisions and workspace
consumer migrations. Avoid claiming an API is “stable” in comments unless the
project has a policy and checks that support that promise.

## 6. Tooling and verification

The root `./.github/scripts/local-ci.sh` is the canonical project gate. For focused
iteration, use the narrowest applicable checks, then run the full gate when
required by the root instructions. Current relevant checks include:

```bash
cargo fmt --all -- --check
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" cargo doc -p frensense-engine --all-features --no-deps
cargo machete --with-metadata frensense-engine frensense-lang frensense-bundler frensense-packgen frensense-devtools
cargo hack check -p frensense-engine --each-feature --locked
cargo semver-checks check-release -p frensense-engine
cargo clippy --all-features --all-targets -- -D warnings
cargo test -p frensense-engine --all-features
cargo deny check
```

CI checks the declared MSRV (`rust-version = "1.95"`), runs workspace-wide
tests and Clippy, cargo-deny, the public API compatibility check, and these
engine-specific docs/dependency/feature checks. Install `cargo-machete`,
`cargo-hack`, and `cargo-semver-checks` with `cargo install <tool> --locked`
when they are not already available. `cargo lint` is an alias, not a
substitute for checking the actual workflow command.

The SemVer check compares against the latest published `frensense-engine`
release; it should gate a patch-compatible release and therefore catches
current compatibility debt if a would-be patch makes a breaking change. An
intentional breaking release requires changing the package version/release
policy deliberately, not suppressing the check. `cargo hack --each-feature`
checks all-features, no-default-features, and each feature alone; it is not a
full combinatorial powerset. Do not introduce a nightly-only tool into the
required stable gate without explicit project approval and a documented reason.
There is currently no `unsafe` block in `frensense-engine`; if unsafe code is
proposed, justify why safe Rust is insufficient and add focused safety
review/testing before accepting it.

## 7. Documentation boundaries

For routine user-visible changes, record the engine half of the change in
[`frensense-engine/CHANGELOG.md`](CHANGELOG.md) — this crate has its own
changelog and its own version, and `frensense`'s root changelog takes only what
a binary user observes (see the root `AGENTS.md` §7.1). A change that moves a
public item also takes the version decision that `cargo semver-checks
check-release -p frensense-engine --release-type patch` implies (root §7.2);
the engine does not move because the binary moved.

Do not create or update unrelated documents for ordinary code work. A task that
explicitly asks for contributor guidance or documentation is an exception: keep
that documentation scoped to the requested engine maintenance purpose, as in
the linked guide.
