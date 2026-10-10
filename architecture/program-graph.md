---
url: https://frensense.friehub.cloud/architecture/program-graph.md
---
# The program graph

The program graph is the union of several analyses over one IR:

* **Def-use chains** resolve where every value is produced and consumed.
* **Call graph** drives interprocedural reachability and summaries.
* **Points-to** is Steensgaard-based with two-phase constraint solving; the
  second phase adds call-site-sensitive flow for sharper alias answers.
* **Heap model + memory SSA** model stores and loads so field-sensitive and
  index-sensitive flows (e.g. `$row[$col]`) participate in analysis.
* **SVFG** (Sparse Value-Flow Graph) connects value definitions to their
  uses across procedures, the substrate taint queries walk.

## Branch sharpening

Guards are not just cut-edges. Inside `if x < 10 { ... }` the value lattice
knows `x ∈ [.., 9]`; inside the else-branch it knows the negation. This makes
range guards (`if i < arr.len()`) *provably* dominate sinks instead of being
matched textually.
