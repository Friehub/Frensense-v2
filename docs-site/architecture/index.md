# Architecture overview

Frensense v2 is a **compiler first, checker second**. Every source file is
lowered to a lightweight IR, and all analysis happens on the resulting
program graph, never on source text.

## The pipeline

1. **Lowering**, per-language providers (Oxc for JS/TS, rust-analyzer HIR
   for Rust, tree-sitter-style parsing for Python/Go) reduce each file to the
   engine IR.
2. **Program graph**, def-use chains, call graph, Steensgaard points-to
   with two-phase constraint solving, heap modelling, memory SSA, and an
   SVFG (Sparse Value-Flow Graph) are built from the IR.
3. **Value analysis**, an abstract-interpretation value lattice tracks
   constants and string/number ranges, with branch sharpening: each `if`/
   `match` arm is analysed under the constraints its guard implies.
4. **Checkers**, taint reachability, memory safety, policy, and learned
   checks query the graph. Each finding is an exact source-to-sink path.

## Chapters

- [The program graph](/architecture/program-graph)
- [Checkers](/architecture/checkers)
- [Knowledge bundles (.frc)](/architecture/bundles)
