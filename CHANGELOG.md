# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
