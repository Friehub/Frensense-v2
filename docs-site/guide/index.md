# Frensense v2

Frensense is a **compiler-mode static analysis engine**. Instead of pattern
matching on source text, it lowers every file into a lightweight IR and builds
a full program graph:

- def-use chains and a call graph,
- Steensgaard points-to with two-phase constraint solving,
- heap modelling and a memory SSA backend,
- an SVFG (Sparse Value-Flow Graph).

Findings come from **exact reachability queries** on this graph, and every
report includes the concrete source-to-sink path with file positions, not a
confidence score.

## What it detects out of the box

Command injection, SQL/NoSQL injection, SSRF, path traversal, IDOR, weak
cryptography, XSS, session-trust and guard-bypass violations,
use-after-free / double-free, and out-of-bounds accesses.

`.frc` knowledge bundles extend and sharpen detection, see
[Corpus & bundles](/corpus/).

## Status

v2 is a **preview** (<span class="frensense-version">v0.7.0-preview</span>). The knowledge-bundle format and CLI
surface may still change before the stable release.

> **Coming from v1?** The legacy v1 documentation is preserved at
> [/v1/](/v1/) and its sources live in the
> [Friehub/Frensense](https://github.com/Friehub/Frensense) repository. v2 is
> a ground-up rebuild of the engine; see the [architecture overview](/architecture/)
> for what changed.
