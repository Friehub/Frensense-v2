---
url: https://frensense.friehub.cloud/guide/first-scan.md
---
# Your first scan

Scan a directory and print findings to the terminal:

```bash
frensense ./src
```

## GitHub Actions annotations

In CI, emit one workflow command per finding so results render directly on
the PR's Files Changed tab:

```bash
frensense . --github
```

## Watch mode

Re-scan changed files on every save and print only *new* findings:

```bash
frensense watch ./src
```

Findings are compared through stable semantic fingerprints, a finding that
merely shifts lines after an unrelated edit is not reported again, and fixed
findings age out of the baseline automatically.

## Using a corpus bundle

Teach the engine extra facts at scan time:

```bash
frensense ./src --corpus-bundle ./frensense-corpus.frc
```

If a `frensense-corpus.frc` file exists in the scanned root it is discovered
automatically. See [Corpus & bundles](/corpus/).
