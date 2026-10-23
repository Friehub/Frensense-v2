---
url: https://frensense.friehub.cloud/guide/cli.md
---
# CLI reference

The `frensense` binary is the single entry point for the engine.

## Commands

| Command | Description |
| --- | --- |
| `frensense [path]` | Scan a file or directory and print findings. |
| `frensense watch [path]` | Watch mode: re-scan changed files, print only new findings. |
| `frensense mcp` | Run the MCP server (stdio, newline-delimited JSON-RPC) for AI agents. |
| `frensense lsp` | Run the LSP server (stdio, Content-Length framing) for editors. |
| `frensense bundle [<corpus>] [out.frc]` | Compile twin-example families into a `.frc` knowledge bundle. |
| `frensense bundle info <file.frc>` | Inspect a bundle's metadata and facts. |
| `frensense lint <corpus>` | Check corpus families before they are bundled: layout, metadata, class, provenance, diversity, and teachability. `--strict`, `--json`, `--coverage`, `--no-gate`, `--classes`, `--advisories`, `--require-heldout`. Exit `0` clean, `1` issues, `2` bad configuration. |
| `frensense explain [<rule-id>] [-b <bundle>]` | Describe one rule (id, CWE, why, fix); no id lists every rule. `-b` also describes bundle-learned rules. A directory literally named `explain` is still scannable — flags are the unambiguous form. |

One binary carries all of this; there is no separate MCP or LSP package.

### Paths vs subcommands

A path named like a subcommand wins, so a repo containing `mcp/`, `watch/` or
`bundle/` stays scannable with the bare token. Arguments only the subcommand
understands keep it claimed, and each mode has an unambiguous form:

| Invocation | Result when a same-named path exists |
| --- | --- |
| `frensense mcp` | Scans `./mcp`. `frensense --mcp` starts the server. |
| `frensense watch` | Scans `./watch`. `frensense watch <path>` enters watch mode. |
| `frensense bundle` | Scans `./bundle`. `frensense bundle <corpus> [out.frc]` compiles. |
| `frensense lint` | Scans `./lint`. `frensense lint <corpus>` lints; `frensense lint --help` explains the subcommand's own flags. |
| `frensense explain` | Scans `./explain`. `frensense --list-rules` lists rules. |

Only argv\[1] names a subcommand — `frensense . mcp` scans both paths — and
`lsp` is always the server, since editors run `frensense lsp`
non-interactively where a silent scan would be a break, not an ambiguity.

## Options

| Flag | Description |
| --- | --- |
| `--github` | Emit GitHub Actions workflow commands (`::error`/`::warning`) per finding. |
| `--corpus-bundle <file>` | Load a `.frc` knowledge bundle into the engine for this scan. |
| `--emit-baseline <file>` | Write the current finding fingerprints as a baseline. |
| `--compare-baseline <file>` | Only report findings that are new relative to the baseline. |
| `--language <lang>` | Restrict scanning to one language (`rust`, `typescript`, `javascript`, `python`). |
| severity / confidence filters | Limit output to findings above a threshold. |
| `--show-flows` | Print the source→sink flow with each step's location in text output. |
| `--explain` | List sink arguments that produced no advisory, with the reason. |
| `--diff-only` | Report only findings on lines changed since the last commit. Changed files are still scanned whole (a diff can make an old line reachable), but findings at unchanged lines are pre-existing: they are counted and suppressed, not reported. Track them with `--compare-baseline`. |
| `--mcp` | Run the MCP server unconditionally, even when a path named `mcp` exists. |
| `--list-rules` | List every rule id: built-in, plus the bundle's learned rules when `-b` is given. Unambiguous form of `frensense explain` with no id. |
| `--explain-rule <id>` | Describe one rule. Unambiguous form of `frensense explain <rule-id>`, for when a path named `explain` exists. |

Every finding reports a stable rule id (`taint.sql-injection`, `check.weak-hash`,
`policy.<id>`) and its CWE, so `frensense explain <rule-id>` is the fastest way
to see what a finding means and how to fix it:

```console
$ frensense explain taint.path-traversal
taint.path-traversal  Path traversal
  CWE:  CWE-22  https://cwe.mitre.org/data/definitions/22.html
  why:  Attacker-supplied path segments can reach files outside the intended directory.
  fix:  Resolve the path, then check it stays inside the allowed base directory; prefer fixed names.
```

Built-in rules carry a card; bundle-learned rules carry their data instead —
trigger, requirements, message — so the bundle that taught the rule is its
documentation. Pass `-b` to describe one, or to list them all:

```console
$ frensense explain policy.redirect-challenge -b learned.frc
policy.redirect-challenge  Learned policy (from learned.frc)
  severity: warning
  trigger:  call to `redirect`
  scope:    same function
  requires: guard call `challenge_ok` is present
  why:  open redirects bypass the challenge
```

## Environment variables

| Variable | Description |
| --- | --- |
| `FRENSENSE_CORPUS_BUNDLE` | Default `.frc` bundle for MCP/LSP scans. |
