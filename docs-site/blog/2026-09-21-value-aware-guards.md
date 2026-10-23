---
written-against-version: 0.7.1-preview.1
fact-checked: "2026-10-24"
source-revision: 8a0ef9d-dirty
title: "Proving guards, not guessing them"
date: 2026-09-21
description: Guard validation used to be textual, a call with the right name near the sink. The value lattice changed that - and has limits we state here.
---

> **Provenance.** Behavioral claims in this post were written against
> Frensense 0.7.x and fact-checked on source rev `d6cfd3f` (0.8.0-beta).
> Mechanism references: `frensense-engine/src/analysis/value.rs`,
> `checks/policy.rs`, `checks/oob.rs`. The live per-CWE benchmark table in
> `docs/BENCHMARKING.md` is the source of truth for any accuracy number.

# Proving guards, not guessing them

Early versions of the engine accepted a guard if a plausible-sounding check
appeared on the path to a sink. That works until it doesn't: `if (i < 10)`
guards `arr[i]`, but only because `10` happens to relate to the array, 
knowledge the text of the call does not carry.

The value lattice fixes the reasoning, not the pattern:

- **Constants and ranges** flow through the analysis.
- **Branch sharpening** narrows values inside each `if`/`match` arm by the
  constraints the predicate implies.
- **The GuardMap** records which guard dominates which block, and
  `if i < arr.len()` *provably* dominates `arr[i]` inside the arm.

The same machinery powers the learned policy checks: a corpus bundle can
require that a call only happen behind a range check, and the engine accepts
a guard only when the lattice proves the bound, false positives on clean
code drop accordingly.

This is the foundation the out-of-bounds checker is built on, and the
relational (octagon) domain is the next step: tracking *relationships*
between variables, not just their individual ranges.

## Limits of the proof, stated plainly

Two honest caveats for the reader who wants to rely on this:

1. **Convergence is best-effort.** The lattice runs a bounded fixpoint
   (`value.rs:403`); when it terminates early on analyzing loops, narrowed
   ranges can be too narrow. The analysis records a `converged` flag when
   this happens - and, as of this revision, prunes based on ranges still
   consult it inconsistently. Treat a lattice-based "proven clean" on a
   deep loop as provisional until that flag is enforced (tracked as a
   roadmap correctness item).
2. **Branch sharpening covers what the predicate implies numerically.**
   `typeof x === 'string'` or truthiness checks narrow the *type*, not
   attacker payload content; they do not clear taint on their own today.

None of these caveats make the guard story weaker than the textual
status quo it replaced - they are here so nobody takes "proven" broader
than the engine actually guarantees.
