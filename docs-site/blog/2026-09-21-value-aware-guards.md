---
title: "Proving guards, not guessing them"
date: 2026-09-21
description: Guard validation used to be textual, a call with the right name near the sink. The value lattice changed that.
---

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
