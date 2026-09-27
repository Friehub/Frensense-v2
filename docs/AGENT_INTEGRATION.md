<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub. All rights reserved. -->

# Agent + CI Integration Guide

Frensense is designed for a split workflow: **AI agents fix code, CI judges
it.** This guide wires the two halves together with the CLI surface
(`--github` for CI annotations, baselines for regression gating) and shows
where the MCP and LSP surfaces plug in. Every mechanism here shares one
finding-identity scheme, so "the same bug" means the same thing on both
sides.

## The model

```
┌──────────┐  frensense-mcp        ┌──────────────┐
│ AI agent │──────────────────────▶│ per-change   │
│          │   frensense_diff      │ gate (fast)  │
└────┬─────┘                       └──────────────┘
     │ edit/commit                          │
     ▼                                      ▼
┌──────────┐  pull request          ┌──────────────┐
│   CI     │───────────────────────▶│ baseline +   │
│          │   frensense --github   │ annotations  │
└──────────┘                        └──────────────┘
```

- **The agent gates its own change** before committing with
  `frensense_diff`: only findings on the change's added lines are
  reported, so pre-existing debt never blocks it.
- **CI enforces the invariant** with baselines and `--strict`: a merged
  change can never *increase* the number of findings, even as the
  codebase churns.
- Both sides speak the same finding identity (stable fingerprints), so
  an agent fix and a CI pass are provably about the same finding.

## 1. CI workflow: annotations + baseline gate

### One-time: capture the baseline

Baselines record the findings that exist *today*; from then on, CI only
fails on findings that are **new**. Findings whose lines shift after
unrelated edits are recognized as the same finding (stable fingerprints
exclude line/column), so the baseline does not rot as the codebase moves.

```bash
cargo install frensense   # or download the release binary

frensense . --emit-baseline .frensense/baseline.json
git add .frensense/baseline.json && git commit -m "chore: frensense baseline"
```

Commit the baseline file: it is the shared contract between the agent
and CI about what debt is accepted.

### The workflow

`.github/workflows/frensense.yml`:

```yaml
name: Frensense

on:
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # Required for actions/checkout on pull_request to read the merge commit
      checks: write
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v4.3.0

      - name: Install frensense
        run: |
          curl -L https://github.com/Friehub/frensense-v2/releases/latest/download/frensense-x86_64-unknown-linux-gnu \
            -o /usr/local/bin/frensense && chmod +x /usr/local/bin/frensense

      - name: Baseline gate (fail on new findings)
        run: |
          frensense . \
            --compare-baseline .frensense/baseline.json \
            --github

      - name: Strict full scan (optional hard gate)
        run: frensense . --github --strict
        continue-on-error: true   # flip to false once TPR debt is burned down
```

### What each flag does

| flag | behavior | exit code |
|---|---|---|
| `--compare-baseline <file>` | fails only on findings whose fingerprint is not in the baseline | `1` on new findings, `0` otherwise |
| `--github` / `--github-annotations` | prints one `::error\|warning\|notice file=…,line=…,col=…,title=…::message` command per finding; GitHub renders these inline on the PR's Files Changed tab | unchanged |
| `--strict` | fails on *any* finding (ignores the baseline) | `1` if any finding exists |

Combine them: `--compare-baseline --github` fails the job on regressions
*and* annotates every finding in the diff view. The baseline gate and the
annotation rendering are independent: annotations appear for all current
findings so reviewers see the accepted debt in context, while the exit
code reflects only the regression verdict.

Recommended policy: **baseline gate as the failing step; strict scan with
`continue-on-error: true` as a visibility step** until the accepted debt
is burned down, then flip it to a hard gate. This gives agents a green
path for fixing existing findings without ever letting the total increase.

### Updating the baseline

When an agent (or human) fixes findings, shrink the baseline in the same
PR:

```bash
frensense . --emit-baseline .frensense/baseline.json
git add .frensense/baseline.json
```

Reviewers should treat a baseline-shrinking diff the same way they treat
a test-count-increasing diff: as a positive. If a PR *grows* the
baseline, that is the agent asking to accept new debt; reject or inspect.

**Migration note:** baselines captured before stable IDs landed
(pre-`FRN-` fingerprints, which hashed the line number) must be
regenerated once, as above. After that one regeneration, comparisons are
shift-stable.

## 2. Agent-side gating (pre-commit)

The MCP server is the agent's primary surface (see
[docs/MCP_USAGE.md](MCP_USAGE.md) for the full walkthrough). The pattern
that keeps PRs green:

1. **Edit.**
2. **Gate the change**: call `frensense_diff` with `repo` set to the
   workspace. It runs `git diff HEAD` (plus untracked files), scans every
   touched file, and reports only findings on added lines.
3. **Fix until `clean: true`.** The result's `stable_ids` name exactly
   which findings the change introduces; after a fix, the ID disappearing
   is proof that specific finding is resolved, regardless of how lines
   moved in between.
4. **Commit.** CI re-runs the same engine over the whole tree; because
   the agent's change introduced nothing new, the baseline gate passes.

For agents working through an editor instead of the MCP, the LSP surface
([docs/LSP_USAGE.md](LSP_USAGE.md)) shows the same findings with the same
IDs as diagnostics on save.

### Without MCP: plain shell

An agent that only has shell access gets identical semantics from the
CLI. New findings relative to the baseline, with GitHub annotation
formatting on stdout:

```bash
frensense . --compare-baseline .frensense/baseline.json --github
echo "exit=$?"   # 0 = no regressions, 1 = new findings
```

Or gate just the changed files (works without a committed baseline):

```bash
frensense . --diff-only --github
```

## 3. Watch mode: local inner loop

While developing with an agent running in a terminal, a second terminal
running the watcher turns it into a live gate:

```bash
frensense watch .
```

- Re-scans changed files every 500 ms and prints **only new findings**
  (fingerprint-set diff between rounds), so the stream goes quiet when a
  fix lands.
- Accepts the same flags as a one-shot scan, e.g.
  `frensense watch . --corpus-bundle frensense-corpus.frc`.
- Ctrl-C to stop; exit code follows the usual convention.

## 4. Finding identity across surfaces

A finding has one fingerprint everywhere. Concretely:

| surface | where the identity appears |
|---|---|
| CLI text | stable ID printed in regression output (`FRN-…`) |
| CLI JSON / MCP advisories | `fingerprint` field on every advisory |
| MCP diff/scan_file results | top-level `stable_ids` array |
| LSP diagnostics | `code` field of each diagnostic |
| baseline file | the `fingerprint` field of each stored advisory |

The fingerprint hashes semantic coordinates only (file, rule/sink,
enclosing function, source), never line numbers. Consequences:

- Inserting/deleting unrelated code **moves** the finding but keeps its
  identity: baselines don't churn, issue links stay valid.
- Renaming the enclosing function, changing the sink, or fixing the call
  **changes** the identity: it is a genuinely different code state.
- `frensense_diff` gates on added *lines*; the baseline gate gates on
  added *fingerprints*. Together they bound both directions: the agent
  can't add new findings (diff gate) and can't quietly break existing
  fixes (baseline gate).

## 5. Reference CI recipes

### Minimal (annotations only, never fails)

```yaml
- run: frensense . --github
```

### Agent-friendly (default)

```yaml
- run: frensense . --compare-baseline .frensense/baseline.json --github
```

Fails on regressions, annotates everything, tolerates line churn.

### Hard gate (debt burned down)

```yaml
- run: frensense . --github --strict
```

Fails on any finding. Use after the accepted debt reaches zero.

### Bundle-aware

```yaml
- run: >
    frensense . --corpus-bundle frensense-corpus.frc
    --compare-baseline .frensense/baseline.json --github
```

Use the same bundle in CI as the agent's MCP server does; learned facts
change what the engine can see, and both sides must agree on reality.

## See also

- [MCP_USAGE.md](MCP_USAGE.md): agent tool surface + end-to-end session
- [LSP_USAGE.md](LSP_USAGE.md): editor surface
- [FRENSENSE_CORPUS_GUIDE.md](FRENSENSE_CORPUS_GUIDE.md): building bundles
- README: install, one-crate-three-binaries
