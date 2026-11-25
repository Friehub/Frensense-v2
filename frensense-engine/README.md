# frensense-engine

The analysis core of [Frensense](https://github.com/Friehub/Frensense-v2): it
lowers source files to a typed IR, builds the value-flow and call graphs, and
runs the interprocedural taint walk and the structural policy checks. It is a
library - it finds nothing on its own. The `frensense` binary owns file
discovery, reporting and the CLI; this crate owns what a finding *is*.

> Part of [Frensense](https://github.com/Friehub/Frensense-v2) - a
> deterministic SAST scanner. Docs: <https://frensense.friehub.cloud>.

---

## What it does

| Stage | Where | Notes |
|---|---|---|
| IR lowering | `src/ir/` | Typed values, memory state, `FunctionIR` per function |
| Call graph | `src/graph/` | Pass 3 receiver/method resolution, callback edges, namespace bindings |
| Module resolution | `src/graph/module/` | Imports, re-exports, barrel chains, package identity |
| Value flow (SVFG) | `src/analysis/svfg*`, `src/analysis/forward/` | Def-use plus cross-function heap edges |
| Taint walk | `src/analysis/taint/engine/` | Backward, k=1 call-site contexts, guards, launders |
| Fact tables | `src/analysis/taint/facts/` | Sinks, sanitizers, sources, policies, per-language packs |
| Checks | `src/checks/` | Memory lifecycle, guard bypass, schema policy, weak crypto |

A scan is `scan::prepare(files)` followed by `scan_prepared(&prepared, &config,
&facts)`. `TaintConfig` is the caller's policy (sinks, sources, sanitizers);
`FactTable` is the knowledge base those calls resolve against, seeded from the
language specs and refined by `.frc` bundles.

## What a fact carries

Facts are data, not rules: a sink signature names its dangerous argument slots
and its role, a sanitizer fact names the sink classes it defeats and the
argument slots it validates, and a package category lets a call resolve to the
right package family when the import path alone is ambiguous. Every finding
reports the path it followed, so a verdict can be audited rather than trusted.

## Building

```sh
cargo build -p frensense-engine
cargo test -p frensense-engine
```

The crate is `#![deny(unreachable_pub)]` and keeps a committed public API
snapshot in
[`api/frensense-engine.txt`](https://github.com/Friehub/Frensense-v2/blob/main/api/frensense-engine.txt)
(regenerate with `.github/scripts/public-api.sh`).

## License

GPL-3.0-only. Using it in a proprietary product needs a separate license:
<https://friehub.cloud/licensing>.
