---
url: https://frensense.friehub.cloud/guide/cli.md
description: Every frensense command, flag, output format and exit code.
---

# CLI reference

This page matches `frensense --help` for version 0.8.0. If your installed
version is older or newer, `frensense --help` is the final word.

## Commands

| Command | What it does |
| --- | --- |
| `frensense <path>` | Scan a file or folder and print findings. Use `.` for the current folder. With no arguments it prints the help text. |
| `frensense watch [path]` | Re-scan when files change and print only new findings. |
| `frensense explain [rule-id]` | Explain one rule (CWE, why, fix). With no id, list all rules. |
| `frensense mcp` | Run the MCP server for AI agents. See [AI agents](/guide/mcp). |
| `frensense lsp` | Run the editor server. See [Editors](/guide/lsp). |
| `frensense bundle <corpus> [out.frc]` | Compile labelled examples into a `.frc` bundle. |
| `frensense bundle info <file.frc>` | Show what a bundle contains (`--json` for machine output). |
| `frensense lint <corpus>` | Check corpus examples before they are bundled. |

Everything is in the one binary. There is no separate MCP or LSP package.

### When a folder has the same name as a command

A path that exists wins over a subcommand name, so a repository containing a
`mcp/` or `watch/` folder can still be scanned with the bare word. Each mode has
a spelling that cannot be confused:

| To do this | Use |
| --- | --- |
| Start the MCP server | `frensense --mcp` |
| Watch a path | `frensense watch <path>` (the path makes it unambiguous) |
| Compile a bundle | `frensense bundle <corpus> [out.frc]` |
| Lint a corpus | `frensense lint <corpus>` |
| List all rules | `frensense --list-rules` |
| Explain one rule | `frensense --explain-rule <rule-id>` |

`frensense lsp` is always the server, because editors start it without a
terminal and a silent scan there would be a bug, not an ambiguity.

## Scan options

| Flag | Meaning |
| --- | --- |
| `-b`, `--bundle <file>` | Load a `.frc` [bundle](/bundles) for this scan. `--corpus-bundle` is an older spelling of the same flag. |
| `-l`, `--language <lang>` | Scan one language only: `c`, `go`, `javascript`, `python`, `rust`, `typescript`, `vue`. |
| `-s`, `--severity <level>` | Lowest severity to report: `critical`, `warning` or `info`. Default `warning`, so `info` findings are hidden unless you ask. |
| `-p`, `--profile <name>` | `default`, `recommended` or `strict`. `strict` also reports hygiene rules such as function complexity. |
| `--hygiene` | Report hygiene rules (for example, function complexity) under any profile. |
| `--max-complexity <n>` | Complexity ceiling before a function is reported (default 25). |
| `--diff-only` | Report only findings on lines changed since the last git commit. Changed files are still analysed whole, because a change can make an old line reachable. |

## Output options

| Flag | Meaning |
| --- | --- |
| `-o`, `--output <file>` | Write the report to a file instead of printing it. |
| `-f`, `--format <fmt>` | `text`, `json`, `sarif` or `github`. |
| `--json` | One JSON object with an `advisories` list. Same as `--format json`. |
| `--sarif` | SARIF 2.1.0. Same as `--format sarif`. |
| `--github` | GitHub Actions annotation commands. Same as `--format github`. |
| `--show-flows` | In text output, list each step from source to sink. (JSON and SARIF always include the path.) |
| `--explain` | Also list sink arguments that produced no finding and why (printed to stderr). |
| `--explain-json <file>` | Write those silent sink arguments to a file as JSON. Implies `--explain`. |

### The JSON report

`--json` prints a single JSON object, not one object per line. The fields you
will most often use:

| Field | Meaning |
| --- | --- |
| `advisory_count` | Number of findings. |
| `advisories` | The findings. Each has `rule_id`, `severity`, `title`, `file_path`, `line`, `column`, `fingerprint` and `taint_steps`. |
| `clean` | `true` when there are no findings. |
| `analysis_incomplete` | Reasons the scan may have missed things (unsupported or partly parsed files, safety limits). Check this before you trust a clean result. |
| `schema_version` | Version of this report format. |

## Gating options

| Flag | Meaning |
| --- | --- |
| `--strict` | Exit 1 if there is **any** finding. |
| `--emit-baseline <file>` | Save the current findings as a baseline. |
| `--compare-baseline <file>` | Exit 1 only if there are findings that are not in the baseline. |

::: warning Do not combine `--strict` with `--compare-baseline`
`--strict` fails on any finding, including ones already in the baseline, so the
pair fails every run. Use `--compare-baseline` on its own for a regression gate.
See [CI and agent gating](/guide/github-actions).
:::

## Exit codes

| Code | When |
| --- | --- |
| `0` | The scan finished. Findings do not change this unless you ask for it. |
| `1` | `--strict` and at least one finding; or `--compare-baseline` found a new finding; or an error such as an unreadable bundle file. |
| `2` | The command line was wrong (unknown flag, invalid severity, and so on). |

## Environment

| Variable | Meaning |
| --- | --- |
| `FRENSENSE_CORPUS_BUNDLE` | Default `.frc` bundle for the MCP and LSP servers. The CLI scan uses `-b` instead. |

A file named `frensense-corpus.frc` in the folder being scanned is loaded
automatically when no `-b` is given.

## Explaining a rule

Every finding carries a stable rule id (`taint.sql-injection`,
`check.weak-hash`, ...). `frensense explain <rule-id>` prints what it means:

```console
$ frensense explain taint.path-traversal
taint.path-traversal  Path traversal
  CWE:  CWE-22  https://cwe.mitre.org/data/definitions/22.html
  why:  Attacker-supplied path segments can reach files outside the intended directory.
  fix:  Resolve the path, then check it stays inside the allowed base directory; prefer fixed names.
```

Rules that came from a bundle describe themselves from the bundle's data. Pass
`-b` to explain or list them:

```console
$ frensense explain policy.redirect-challenge -b learned.frc
```

## Version and identity

`frensense --version` prints the version. `frensense --version --json` also
prints the bundle format the binary reads and the size of the built-in
knowledge pack.

## Corpus commands

`frensense lint <corpus>` takes `--strict`, `--json`, `--coverage`,
`--no-gate`, `--classes <file>`, `--advisories <file>`, `--require-heldout`
and `--dup-threshold <0..1>`. It exits 1 when it finds an error. The
[authoring guide](/corpus/authoring) explains what each check means.
