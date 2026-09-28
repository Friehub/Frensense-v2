# GitHub Actions

## Inline annotations

`frensense . --github` emits one workflow command per finding:

```yaml
- name: Frensense scan
  run: frensense . --github
```

Each finding becomes a spec-compliant
`::error|warning|notice file=…,line=…,col=…::message` command, so findings
render directly on the PR's Files Changed tab, no SARIF upload step.

## Baseline gating

Only fail on *new* findings by committing a baseline and comparing against it:

```bash
frensense . --emit-baseline frensense-baseline.json   # once
frensense . --compare-baseline frensense-baseline.json # in CI
```

Because fingerprints are computed over semantic coordinates only
(file, rule/sink, enclosing function, source), moving code around does not
create false regressions.

## Release integrity

Release binaries ship with SLSA L3 provenance; every third-party GitHub
Action used in the project's own workflows is pinned to an immutable commit
SHA.
