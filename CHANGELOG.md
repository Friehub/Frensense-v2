# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
