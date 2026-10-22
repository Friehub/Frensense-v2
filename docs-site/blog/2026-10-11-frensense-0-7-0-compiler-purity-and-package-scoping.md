---
written-against-version: 0.7.0
fact-checked: "2026-10-22"
source-revision: d6cfd3f-dirty
title: "Inside Frensense 0.7.0: Package-Aware Dataflow, Compiler Purity, and Replay-Verified Static Analysis"
date: 2026-10-11
description: A deep technical dive into Frensense 0.7.0 - solving cross-framework false positives with package-scoped facts, decoupling AST vocabularies into pure compiler IR, and enforcing replay verification over the bundle's own corpus.
---

> **Provenance.** Written against Frensense 0.7.0; fact-checked on source
> rev `d6cfd3f` (0.8.0-beta). Mechanism references:
> `frensense-engine/src/analysis/taint/facts/entries.rs`,
> `analysis/taint/facts/table.rs`, `walk.rs` (package binding),
> `purity-ratchet` in `scripts/`.

# Inside Frensense 0.7.0: Package-Aware Dataflow, Compiler Purity, and Replay-Verified Static Analysis

Modern software development is defined by dense, multi-framework ecosystems. A single full-stack monorepo regularly combines a Next.js or React frontend, an Express or Hono microservice, an ORM like Prisma or TypeORM, and real-time transports like Socket.io.

For pattern-based analyzers, this polyglot density is where unscoped rules bleed. When the analyzer's pattern fires on a bare method name, a database-injection rule keyed on `.query()` can also fire on a harmless client library that exposes a method with the same shape. Deep tools mitigate this in different ways (CodeQL through typed and sanitized modeling of library APIs, Semgrep through framework-specific rule engineering); Frensense 0.7.0 attacks it structurally with **package-scoped facts**.

The consequence is **Cross-Framework Bleed**: an aggressive rule tailored for a backend ORM fires on harmless UI components, utility helpers, or unrelated client libraries. Security teams are inundated with false positive noise, developers lose trust in the scanner, and legitimate vulnerabilities are lost in the backlog.

With the release of **Frensense 0.7.0**-following an intensive cycle from Preview 1 through Preview 5-we solved this problem at the compiler and dataflow level. 

This release introduces **Bundle Format v6** with package-aware dataflow scoping, a complete **engine purity refactor** that decouples language ASTs from the analysis core, an **abstract-interpretation value lattice**, and an immutable **4-file held-out verification contract**.

Here is an architectural breakdown of what we built and why it matters.

---

## 1. The Cross-Framework Problem & Package-Aware Scoping

To eliminate cross-framework false positives without hardcoding rules into Rust or requiring engine recompilation, we analyzed the structural anatomy of web application vulnerabilities.

### The Asymmetry of Web Vulnerabilities

Web application security exhibits a fundamental structural asymmetry:

1. **Sinks are highly centralized (~30 core primitives)**: Across modern runtimes, dangerous execution sinks invariably terminate in standard platform APIs: Node standard modules (`node:child_process`, `node:fs`, `node:crypto`, `node:vm`, `node:net`), standard Web APIs (`fetch`, `Response`), or database connection drivers (`.query`, `.prepare`, `.raw`).
2. **Sources and framework methods have high cardinality (hundreds of libraries)**: Every web framework, ORM, and queue defines its own request interfaces (`c.req.query()`, `req.body`, `@Param()`) and specialized data-access wrappers (`prisma.$queryRawUnsafe`, `socket.emit`).

When an analyzer evaluates standard sinks, pure language-level rules apply universally across every framework. However, when an analyzer evaluates framework-specific wrapper methods, scoping is essential. Without package awareness, an analysis fact for `prisma.$queryRawUnsafe` risks bleeding into any arbitrary class that exposes an unsafe query method.

### The Standardized Metadata Header

In Frensense 0.7.0, rule authors declare framework provenance directly within the standardized training header:

```typescript
// [frensense]
// observation: Raw SQL injection via unparameterized query execution
// impact: Complete database exfiltration and arbitrary record mutation
// improvement: Parameterize query variables using tagged templates
// cwe: CWE-89
// severity: High
// package: prisma
```

The header serves two purposes:
- **Human & LLM Readability**: The `observation`, `impact`, and `improvement` fields supply human-grade diagnostic descriptions that flow directly into terminal reports and SARIF outputs, eliminating vendor-opaque error codes.
- **Compiler Provenance**: The optional `// package: <pkg>` directive instructs the bundler to attach package metadata to the extracted security facts.

### Bundle Format v6 Serialization

In `frensense-bundler`, Format v6 extends the binary `LearnedFactEntry` schema to store package provenance. The real schema (as shipped in `frensense-engine/src/analysis/taint/facts/entries.rs`):

```rust
pub enum LearnedFactEntry {
    Source {
        pattern: String,
        package: Option<String>, // package-scoped provenance
    },
    Sink {
        call: String,
        package: Option<String>,
        /// Dangerous argument slots; empty = all slots dangerous.
        dangerous_args: BTreeSet<usize>,
        /// Whether non-dangerous slots are safe binding channels.
        binding_args_safe: bool,
    },
    Sanitizer {
        call: String,
        package: Option<String>,
        kind: String,
        guard_style: bool,
    },
    // ... 13 subsystems total, see docs/TEACHABILITY.md
}
```

This binary payload is serialized with zero overhead into `.frc` bundles. When Frensense scans a project, the engine reads the `.frc` bundle and installs these facts dynamically into `FactTable` at runtime.

### Engine-Level Blast-Radius Quarantine

Inside `frensense-engine`, member calls and imported sinks are resolved against module-level symbol tables:

```
Source Code AST Lowering
         │
         ▼
Extract Module Imports & Receiver Roots (e.g. import { PrismaClient } from '@prisma/client')
         │
         ▼
Taint Engine Dataflow Query
         │
   Is Fact Package-Scoped?
      ├── YES ──► Does current module import / bind declared package?
      │             ├── YES ──► Evaluate dataflow path
      │             └── NO  ──► Quarantined (Silent drop, 0 execution overhead)
      │
      └── NO  ──► Universal primitive: Evaluate dataflow path
```

If a file does not import or instantiate the declared framework (such as `@prisma/client` or `prisma`), the rule is not consulted for that file. This blast-radius quarantine keeps backend rules from triggering advisories on frontend codebases such as Next.js or React.

**One caveat, measured honestly:** package binding is keyed per file in multi-file scans. A *single-file* CLI run (`frensense foo.ts`) currently applies that file's package imports as a blanket default for the scan, so package-scoped rules can arm on code paths in that file they would not match in a full-tree run. Track `ROADMAP.md` (single-file package fallback) for the fix; in CI you get the full-tree behavior.

---

## 2. Scientific Generalization: The 4-File Held-Out Replay Contract

A persistent flaw in static analysis rule development is **overfitting**. A developer notices a vulnerability in a PR, authors a pattern rule tailored to that exact code snippet, and releases it. In practice, the rule is fragile: it fails when variables are renamed, or it fires aggressively on clean production code that implements legitimate validation guards.

To prevent overfitting, Frensense 0.7.0 mandates the **4-File Family Contract** for production rules:

```
family_directory/
├── stem_positive.ts          (Canonical vulnerable training fixture)
├── stem_negative.ts          (Canonical safe/remediated training fixture)
├── stem_heldout_positive.ts  (Held-out vulnerable fixture with structural variance)
└── stem_heldout_negative.ts  (Held-out safe fixture with production guard controls)
```

### The Separation Between Training and Evaluation

- **Training Pair (`_positive`, `_negative`)**: The bundler compiler lowers both files to intermediate representation (IR), computes the AST and control-flow delta, and extracts candidate facts (sinks, sources, sanitizers, or policies).
- **Held-Out Pair (`_heldout_positive`, `_heldout_negative`)**: Files carrying the `_heldout_` infix are excluded from fact extraction, so what is learned comes from the training pair alone. After a bundle is built, scanning these files (never seen during extraction) checks whether the learned fact generalizes across realistic engineering variance: renamed symbols, parameter wrapping, async boundaries, and alternate control-flow structures.

### The Replay Gate

Before any `.frc` bundle is emitted, `frensense-bundler` executes a replay verification gate over the training pair. A candidate fact is installed into a fresh engine instance and:

- the positive case must trigger the expected alert,
- the negative case must stay silent,
- no other family in the corpus may regress its existing verdict,

on pain of the candidate being discarded at build time. Held-out files (the `_heldout_` variants above) are deliberately **excluded from learning** while the bundler runs, so they can be scanned afterward as independent evidence of generalization - they are a verification harness (`test_bundles.sh`), not a gate inside the bundler itself. Two independent families voting for the same call upgrades a fact from `provisional` to `confirmed`.

---

## 3. Engine Purity Refactor: Decoupling Language ASTs

In earlier preview releases, like many traditional analyzers, `frensense-engine` contained remnant language-specific vocabulary tables, route regexes, and AST node strings. 

In Frensense 0.7.0, we completed an **Engine Purity Refactor**, enforced mechanically by the CI ratchet (`scripts/purity-ratchet.py`) rather than by convention:

1. **Language knowledge out of the engine core**: the engine operates exclusively over:
   - Abstract compiler Intermediate Representation (IR).
   - Static Single Assignment (SSA) memory variables.
   - Steensgaard points-to equivalence classes.
   - The Sparse Value-Flow Graph (SVFG).
   - Data-driven `FactTable` facts.
   The ratchet counts the remaining debt classes and fails CI if any grows; a small amount of known residual debt exists and is tracked in `ROADMAP.md` rather than hidden (e.g., a handful of hardcoded identifier short-circuits in the checks layer).
2. **Standalone `frensense-packgen` Compiler**: We extracted all language grammatical knowledge into a dedicated compiler crate, `frensense-packgen`. It extracts language provider vocabularies (JavaScript, TypeScript, Python, Go, Rust, C) and emits standalone binary `.frc` packs.
3. **13 Teachable Security Dimensions**: The engine can be taught entirely through `.frc` bundles across 13 distinct security dimensions-including custom taint sources, sinks, sanitizers, propagators, memory allocators, memory deallocators, IDOR verbs, weak crypto algorithms, schema policy builders, and argument literal constraints-with zero engine recompilation.

---

## 4. Advanced Compiler IR & Program Graph Precision

Between 0.6.0 and 0.7.0, the core dataflow and intermediate representation underwent major architectural upgrades to eliminate classical static analysis blind spots.

### Structured CFG Lowering
The IR lowering pipeline was redesigned to provide first-class lowering for `break`, `continue`, `switch`, `goto`, and labeled statements:
- Loop targets maintain an explicit `LoopTarget` stack, wiring loop exits to clean pre-header and body-end terminators.
- `switch` statements lower to explicit condition chains with source-order fall-through bodies and structured merge blocks, preventing orphan exits.
- C `goto` statements and labeled jumps resolve forward and backward control-flow edges, eliminating fall-through blindness on error handling paths.

### Single-Owner Function IRs with Lexical Closure Feeding
Previously, nested functions and arrow closures contributed inlined body copies to enclosing IRs, leading to linear IR memory blow-up and phantom duplicate findings (e.g. `<fn@N>` duplicate advisories). 

In 0.7.0, every function body lowers to exactly **one named IR**, linked through an `enclosing_fn` chain. Free variables inside closures are fed directly along lexical closure edges from defining scopes, resolving deep parameter-plus-closure chains without duplicating AST graphs.

### Dominator-Based Control Dependence Graph (CDG)
In prior analyzers, guard bypass checks could be satisfied if a validator call simply existed anywhere in the function. In 0.7.0, dominator-based CDG analysis (`ir/control.rs`) computes the exact set of predicates controlling each basic block. A guard bypass check requires that the predicate actually controls the sink's block (`feeds_predicate`). Unrelated validation checks in earlier branches no longer erroneously clear downstream taint.

### Abstract-Interpretation Value Lattice
Frensense 0.7.0 incorporates an interval value lattice supporting constant propagation, string sets, and numeric intervals:
- **Branch Sharpening**: When control branches on `Terminator::Branch`, predicate narrowing sharpens interval bounds and constant equality along true and false successor edges.
- **Value-Aware Guard Validation**: Guards like `if len(x) > 0` or `if i < arr.len()` are validated mathematically against the value lattice. A learned range check is satisfied only if the interval condition provably dominates the sink.

### Role-Qualified Sanitizers
A common static analysis vulnerability is the "sanitizer collapse": an HTML sanitizer (such as `escapeHtml`) being treated as a universal sanitizer that clears SQL injection or command injection. 

In 0.7.0, sanitizers can be qualified: a bundle can scope a sanitizer so it stays where the corpus proves it belongs (same package/receiver discipline as sinks). Where a bundle supplies qualification, an HTML-encoding sanitizer does not clear a database-query sink; where no bundle supplies qualification, the sanitizer fact applies within the universe that bundle was verified against. (Roadmap item: per-role slot semantics for sanitizers are not yet enforced everywhere in the walk - `SanitizerFact.sanitizes_args` currently defaults to "all args + result" when unset; see `ROADMAP.md`.)

---

## 5. Systems Safety: Interprocedural Memory Lifecycle Analysis (C)

While web runtimes prioritize taint analysis, systems codebases written in C require deep memory safety tracking. In 0.7.0, Frensense incorporates advanced spatial and temporal checkers:

- **Interprocedural Allocation & Deallocation Summaries**: A bottom-up interprocedural analysis (`checks/memory_summary.rs`) traces memory contracts (`returns_fresh`, `return_capacity`, `consumes_params`) across arbitrary wrapper chains (`outer_free -> inner_free -> free`), preserving allocation provenance across custom factory and deallocator layers.
- **Spatial Memory Safety (Buffer Overflow / OOB)**: A dedicated out-of-bounds checker (`checks/oob.rs`) tracks pointer capacities and indexed element accesses (`LoadElement`, `StoreElement`) against the interval value lattice.
- **Temporal Memory Safety (UAF & Double-Free)**: A path-sensitive finite-state machine over Steensgaard points-to classes detects use-after-free and double-free conditions, as well as deallocation of uninitialized stack pointers along unchecked error paths (CWE-401, CWE-190/680).

---

## 6. Developer Experience & Autonomous Agent Tooling

A security engine is only as effective as its integration into the developer workflow. Frensense 0.7.0 ships with major UX and protocol additions.

### Compiler-Grade Diagnostic Formatter

Terminal output now mirrors modern compiler diagnostics (`rustc` / Clang style):

```
CRITICAL: SQL Injection in 'handleUserSearch'
  --> src/controllers/user.ts:42:15
   |
42 |   const rows = await db.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${userId}`);
   |                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   |
   = Details:      Unsanitized user input flows directly into dynamic SQL query construction.
   = Impact:       Allows arbitrary database readout, tampering, and authentication bypass.
   = Remediation:  Use parameterized queries or Prisma tagged template literals ($queryRaw).
   = Flow Trace:
     1. src/controllers/user.ts:38:12  userId := req.query.id (HTTP Source)
     2. src/controllers/user.ts:40:9   query := `... ${userId}` (Taint Propagator)
     3. src/controllers/user.ts:42:15  db.$queryRawUnsafe(...) (SQL Sink)
```

### Stable Semantic Finding IDs

Traditional scanners identify findings by file and line number (`file.ts:42`). If an unrelated PR inserts five lines at the top of the file, every finding changes identity, breaking triage baselines and generating spurious alert churn.

In 0.7.0, findings carry coordinate-independent semantic fingerprints:

$$\text{ID} = \text{FRN-}\langle 12\text{hex}\rangle@\text{file}:\text{line}$$

The fingerprint is hashed over semantic coordinates: `(file, rule/sink, enclosing_function, source)`. If code shifts lines or functions are reordered, the finding maintains its stable identity. Baseline comparisons (`--compare-baseline`) evaluate true security regressions rather than line shifts.

### Tooling Interfaces: CLI, Watch Mode, LSP, and MCP

Frensense 0.7.0 consolidates multiple delivery workflows into a single self-contained binary:

```
                            ┌────────────────────────┐
                            │ frensense binary (v0.7)│
                            └───────────┬────────────┘
         ┌──────────────────┬───────────┴───────────┬──────────────────┐
         ▼                  ▼                       ▼                  ▼
   One-Shot CLI        Watch Mode              LSP Server          MCP Server
(`frensense .`)    (`frensense watch`)     (`frensense lsp`)   (`frensense mcp`)
- Single-pass flags  - 500ms poll diff       - Real-time IDE     - AI coding agents
- -o output report   - Semantic baseline     - Diagnostics on    - frensense_audit
- SARIF / GitHub     - Instant terminal        save & edit       - frensense_scan_file
  annotations          alerts                                    - frensense_diff
```

- **Unified Single-Pass CLI**: The CLI supports direct report output via `-o, --output <file>` for text, JSON, SARIF, and GitHub Actions annotations (`--github`), with standardized short aliases (`-o`, `-s`, `-l`, `-b`, `-f`).
- **Low-Latency Watch Mode (`frensense watch`)**: A built-in watcher monitors source trees with a 500ms polling loop, calculating finding diffs against an initial baseline. Developers receive instant terminal feedback only when edits introduce new vulnerabilities.
- **Language Server Protocol (`frensense lsp`)**: Provides diagnostics directly to VS Code, Neovim, and any LSP-compatible editor on file save.
- **Model Context Protocol (`frensense mcp`)**: Built natively into the same binary. Rather than blocking on infinite watcher loops, autonomous AI coding agents (in Claude Desktop, Cursor, or Windsurf) utilize targeted tools:
  - `frensense_audit`: Full directory audits with streaming support.
  - `frensense_scan_file`: Instant single-file verification after an agent writes code.
  - `frensense_diff`: Patch-level verification that answers: *"Did my proposed change introduce any security findings?"* without rescanning the entire repository.

---

## 7. Summary & Upgrade Guide

Frensense 0.7.0 marks the transition from heuristic pattern scanning to compiler-grade, dataflow-driven security verification:

| Capability | Legacy / Traditional SAST | Frensense 0.7.0 |
|---|---|---|
| **Multi-Framework Scoping** | Global function name matching; frequent cross-framework bleed | **Format v6 Package Scoping**: Module provenance tracking with blast-radius quarantine |
| **Rule Generalization** | Brittle regexes; frequent overfitting to training samples | **Replay-verified facts**: pos/neg separation enforced at build time, with `_heldout_` variants excluded from learning for afterward generalization checks |
| **Engine Architecture** | Hardcoded language vocabularies and AST node kinds in engine | **Pure Compiler IR**: Zero hardcoded language strings; dynamic 13-dimension learning |
| **Control Flow & Guards** | Textual call checks; blind to branching and loop exits | **Dominator CDG & Value Lattice**: Predicate feed verification and branch narrowing |
| **Developer Ergonomics** | Opaque finding codes; fragile line-based triage baselines | **Compiler Diagnostics & Semantic IDs**: `rustc`-style traces with stable fingerprinting |
| **Ecosystem Surface** | Standalone CLI only | **Native CLI, Watch Mode, LSP, and MCP** in a single binary |

### Upgrading to 0.7.0

Frensense 0.7.0 maintains complete backward compatibility for reading legacy Format v4 and v5 `.frc` bundles. 

To upgrade your environment:

```bash
# Cargo install
cargo install --path .

# Or download pre-built release binaries
curl -fsSL https://frensense.friehub.cloud/install.sh | bash
```

To run a scan with the latest Format v6 bundle:

```bash
frensense . --bundle dist/frensense-typescript.frc
```

For IDE integration, configure your editor's LSP client to execute `frensense lsp`. For AI coding agent environments, register `frensense mcp` in your agent's MCP configuration.
