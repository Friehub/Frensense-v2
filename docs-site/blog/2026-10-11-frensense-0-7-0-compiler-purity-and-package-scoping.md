---
title: "Inside Frensense 0.7.0: Package-Aware Dataflow, Compiler Purity, and Zero-Bleed Static Analysis"
date: 2026-10-11
description: A deep technical dive into Frensense 0.7.0 — solving cross-framework false positives with package-scoped facts, decoupling AST vocabularies into pure compiler IR, and enforcing held-out replay verification.
---

# Inside Frensense 0.7.0: Package-Aware Dataflow, Compiler Purity, and Zero-Bleed Static Analysis

Modern software development is defined by dense, multi-framework ecosystems. A single full-stack monorepo regularly combines a Next.js or React frontend, an Express or Hono microservice, an ORM like Prisma or TypeORM, and real-time transports like Socket.io.

For traditional static application security testing (SAST), this polyglot density is catastrophic. Traditional static analyzers rely heavily on call-site name matching or brittle syntax queries. When an analyzer searches for database injection or command execution, it flags any method invocation named `.query()`, `.send()`, or `.emit()`. 

The consequence is **Cross-Framework Bleed**: an aggressive rule tailored for a backend ORM fires on harmless UI components, utility helpers, or unrelated client libraries. Security teams are inundated with false positive noise, developers lose trust in the scanner, and legitimate vulnerabilities are lost in the backlog.

With the release of **Frensense 0.7.0**—following an intensive cycle from Preview 1 through Preview 5—we solved this problem at the compiler and dataflow level. 

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

In `frensense-bundler`, Format v6 extends the binary `LearnedFactEntry` schema to store package provenance:

```rust
pub enum LearnedFactEntry {
    Sink {
        call: String,
        arg_index: usize,
        cwe: u32,
        severity: Severity,
        package: Option<String>, // Package-scoped provenance
    },
    Source {
        pattern: String,
        package: Option<String>,
    },
    Sanitizer {
        call: String,
        package: Option<String>,
    },
    // ...
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

If a file does not import or instantiate the declared framework (such as `@prisma/client` or `prisma`), the rule is quarantined. This blast-radius quarantine guarantees that backend rules never trigger false positive advisories on frontend codebases (such as Next.js or React), achieving **Zero Cross-Framework Bleed**.

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
- **Held-Out Pair (`_heldout_positive`, `_heldout_negative`)**: The candidate fact is immediately subjected to an automated replay test on held-out files that were *never seen during fact extraction*. The held-out files introduce realistic engineering variance: renamed symbols, parameter wrapping, async boundaries, and alternate control-flow structures.

### The Replay Gate

Before any `.frc` bundle is emitted, `frensense-bundler` executes a strict replay verification gate. A candidate fact is rejected if it fails either of two mathematical criteria:

$$\text{True Positive Rate (TPR)} = 100\% \quad \text{across positive and held-out positive fixtures}$$
$$\text{False Positive Rate (FPR)} = 0.00\% \quad \text{across negative and held-out negative fixtures}$$

If a candidate fact causes a single false alarm on a safe held-out fixture, it is quarantined and discarded at build time. This ensures that every fact distributed to production environments generalizes robustly across real-world codebases.

---

## 3. Engine Purity Refactor: Decoupling Language ASTs

In earlier preview releases, like many traditional analyzers, `frensense-engine` contained remnant language-specific vocabulary tables, route regexes, and AST node strings. 

In Frensense 0.7.0, we completed a total **Engine Purity Refactor**:

1. **Zero Language Knowledge in Engine Core**: All language provider vocabularies, AST node classifications, route decorators, and framework hints were eradicated from `frensense-engine`. The core analysis engine operates exclusively over:
   - Abstract compiler Intermediate Representation (IR).
   - Static Single Assignment (SSA) memory variables.
   - Steensgaard points-to equivalence classes.
   - The Sparse Value-Flow Graph (SVFG).
   - Data-driven `FactTable` facts.
2. **Standalone `frensense-packgen` Compiler**: We extracted all language grammatical knowledge into a dedicated compiler crate, `frensense-packgen`. It extracts language provider vocabularies (JavaScript, TypeScript, Python, Go, Rust, C) and emits standalone binary `.frc` packs.
3. **13 Teachable Security Dimensions**: The engine can be taught entirely through `.frc` bundles across 13 distinct security dimensions—including custom taint sources, sinks, sanitizers, propagators, memory allocators, memory deallocators, IDOR verbs, weak crypto algorithms, schema policy builders, and argument literal constraints—with zero engine recompilation.

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

In 0.7.0, sanitizers are qualified by `SinkRole` and labels (`defeats_role_and_label`). An HTML encoding sanitizer can defeat cross-site scripting sinks, but will never clear a database query or shell execution sink.

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
| **Rule Generalization** | Brittle regexes; frequent overfitting to training samples | **4-File Held-Out Contract**: 100% TPR / 0.00% FPR gate on unseen held-out fixtures |
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
