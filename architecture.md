---
url: https://frensense.friehub.cloud/architecture.md
description: >-
  How Frensense turns source files into findings, from parsing to the program
  graph and the checkers.
---

# Architecture overview

Frensense is a compiler first and a checker second. Every source file is
lowered to a small intermediate representation (IR), and all analysis runs on
the program graph built from that IR, never on source text.

## The pipeline

1. **Parse and lower.** Each language has a provider built on a
   [tree-sitter](https://tree-sitter.github.io/) grammar (TypeScript,
   JavaScript, Python, Go, Rust, C). A provider says which syntax nodes are
   functions, calls, assignments and so on, and the lowering turns them into the
   shared IR. The engine itself does not know any one language.
2. **Build the program graph.** From the IR the engine builds def-use chains
   in SSA form, a call graph, a points-to analysis (Steensgaard), a model of
   heap objects and fields, memory SSA, and a sparse value-flow graph that links
   definitions to uses across functions.
3. **Look up knowledge.** Sources, sinks, sanitizers and policies come from the
   built-in pack and any [bundle](/bundles). They are data, not code.
4. **Run the checkers.** Taint analysis starts from each sink argument and walks
   the value-flow graph backward: what could feed this value? It stops at a
   source (report a finding), at a sanitizer (clean), or at a value the engine
   cannot see into (stay quiet and record it for `frensense --explain`). Other
   checkers handle memory safety, policy and hygiene. A finding is an exact
   source-to-sink path.

Two pieces of reasoning sit on top of that graph:

* **Guards.** Conditions such as an early return after a failed check, or a
  comparison against a literal, can mark a value as validated on the branch
  where the check held.
* **Values.** A small value analysis tracks constants and numeric ranges. The
  memory-safety and policy checks use it, and the taint analysis uses it to
  ignore branches that integer comparisons prove can never run.

To keep large projects fast, the taint analysis first runs without call-site
context and then re-checks only the functions on a candidate path with one
level of call-site context.

## What it does not do yet

Worth knowing when you read a clean scan:

* **Top-level code** that is not inside a function (a script's own body, for
  instance) is not analysed.
* **Types are not resolved.** The engine matches calls by name and by the
  package a value was imported from. It does not yet know that a variable holds
  a particular class, so it cannot follow an interface to its implementation.
* **Value tracking is narrow.** Integer constants are folded, string constants
  are not, and a check against a named collection (`if x not in ALLOWED`) is not
  recognised as a guard.
* **Library calls with no model** pass taint through by default, which can
  produce false positives.

These are the engine's current limits, and each is a candidate for a
[challenge](/challenges).

## Chapters

* [The program graph](/architecture/program-graph)
* [Checkers](/architecture/checkers)
* [Engine blindness](/architecture/blindness)
* [Benchmarks](/architecture/benchmarks)
* [Bundles (.frc)](/bundles)
