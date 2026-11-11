<div align="left">
  <h1>Frensense</h1>
  <p><strong>A deterministic security scanner that follows untrusted input through your code and shows every path from source to dangerous call.</strong></p>
  <p>
    <a href="https://crates.io/crates/frensense"><img src="https://img.shields.io/crates/v/frensense.svg" alt="crates.io" /></a>
    <a href="https://www.npmjs.com/package/@friehub/frensense"><img src="https://img.shields.io/npm/v/@friehub/frensense.svg" alt="npm" /></a>
    <a href="https://frensense.friehub.cloud"><img src="https://img.shields.io/badge/docs-frensense.friehub.cloud-blue.svg" alt="Documentation" /></a>
    <a href="https://github.com/Friehub/frensense-v2/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-green.svg" alt="License" /></a>
    <a href="https://github.com/sponsors/0xademola"><img src="https://img.shields.io/badge/sponsor-♥-ea4aaa.svg" alt="Sponsor" /></a>
  </p>
</div>

Frensense is an open-source static application security testing (SAST) tool for
TypeScript, JavaScript, Python, Go, Rust and C (Vue files have early support). It
builds a graph of how values move through your whole project and reports a
finding when data from an untrusted source can reach a dangerous call without
being sanitized. Each finding shows that path with file and line positions.

It is one binary. Scanning, watch mode, an MCP server for AI agents and a
language server for editors are all subcommands of `frensense`. There is no
model and no network call in a scan: the same input always gives the same
output.

> **Status: young, and honest about it.** Frensense reports what it can show
> and stays quiet about what it cannot, so it **misses real vulnerabilities**.
> On the OWASP Benchmark for Python it finds 38% of the vulnerable cases with a
> 7% false-alarm rate, and finds none of the cross-site scripting, weak
> randomness, XML external entity, LDAP injection or trust-boundary cases. Treat
> a clean scan as "nothing found", not "nothing there". Full numbers are in
> [Benchmarks](https://frensense.friehub.cloud/architecture/benchmarks).

## Install

```bash
npm install -g @friehub/frensense     # prebuilt binary, needs Node.js 18+
# or
cargo install frensense               # builds from source, needs Rust 1.95+
```

Release binaries for Linux x64, macOS and Windows are on the
[releases page](https://github.com/Friehub/frensense-v2/releases). Details:
[Install](https://frensense.friehub.cloud/guide/installation).

## Scan

```bash
frensense .                          # scan the current folder
frensense . --show-flows             # include every step from source to sink
frensense . --json                   # machine-readable report
frensense . --sarif -o results.sarif # SARIF 2.1.0 for code-scanning tools
frensense explain taint.sql-injection  # what a rule means and how to fix it
```

A finding looks like this:

```text
[CRITICAL] OS command injection: `request.get` reaches `popen`
  --> app.py:10:12 (in `ping`)

     |
   9 |     host = request.args.get("host")
  10 |     return os.popen("ping -c 1 " + host).read()
     |            ^^^^^^^^
     |
  = rule: taint.command-injection  (CWE-78)
  = why:  Attacker-supplied text reaches a shell or process launcher and can run other commands.
  = fix:  Pass arguments as a list without a shell, and validate the value against an allowlist.
```

A normal scan exits `0` even when it finds something. Add `--strict` to exit
`1` on any finding. [First scan walkthrough](https://frensense.friehub.cloud/guide/first-scan).

## Use it in CI

Record today's findings once, commit the file, and fail pull requests only on
findings that are new:

```bash
frensense . --emit-baseline .frensense/baseline.json
```

```bash
frensense . --compare-baseline .frensense/baseline.json --github
```

The second command exits `1` only on new findings and prints GitHub
annotations for the rest. Do not add `--strict` to it: `--strict` fails on every
finding, including ones already in the baseline. A finding that only moves
lines after an unrelated edit still counts as the same finding. A full workflow
file is in
[CI and agent gating](https://frensense.friehub.cloud/guide/github-actions).

## Use it from an AI agent or an editor

```json
{ "mcpServers": { "frensense": { "command": "frensense", "args": ["mcp"] } } }
```

`frensense mcp` gives an agent three tools (`frensense_audit`,
`frensense_scan_file`, `frensense_diff`) so it can check its own changes with
the same engine CI uses. `frensense lsp` shows findings as diagnostics in any
editor with a generic LSP client. Setup for each:
[AI agents](https://frensense.friehub.cloud/guide/mcp) and
[Editors](https://frensense.friehub.cloud/guide/lsp).

## What it reports

57 built-in rules, listed by `frensense explain`:

- **30 taint rules** for injection (SQL, NoSQL, command, code, template, LDAP,
  XPath), path traversal, SSRF, open redirect, XSS, unsafe deserialization, XXE,
  prototype pollution and regular-expression denial of service.
- **27 checks** for weak hashes and ciphers, cookie flags, insecure transport,
  and memory safety (use after free, double free, out-of-bounds, leaks).

A rule existing does not mean it fires on every framework. The engine only
detects what it knows about, and what it knows about frameworks comes from
bundles.

## Bundles: teaching the engine your framework

A `.frc` bundle adds sources, sinks and sanitizers for libraries the built-in
pack does not know. Load one with `frensense . --bundle my.frc`, or build your
own from pairs of vulnerable and fixed examples. A bundle can add detections and
it can add false alarms, so compare a scan with and without it on your own code
before you rely on it. See
[Bundles](https://frensense.friehub.cloud/bundles).

## Benchmarks

Scored on the OWASP Benchmark for Python (1,230 cases), Frensense 0.8.0, no
bundle, conservative matching (a finding must carry the case's CWE):

| Score (TPR - FPR) | TPR | FPR | TP / FP / FN / TN |
|---|---|---|---|
| 31.0% | 38.1% | 7.1% | 172 / 55 / 280 / 723 |

That is better than the previous record on detections (the false-alarm rate
rose from 2.3% to 7.1%, which is a known priority). We do not publish a
comparison with other tools: the OWASP project's scorecards are for the Java
benchmark and cannot be compared with these. Per-category results and how to
reproduce the run:
[Benchmarks](https://frensense.friehub.cloud/architecture/benchmarks).

## Documentation

| | |
|---|---|
| Start | [Overview](https://frensense.friehub.cloud/guide/) · [Install](https://frensense.friehub.cloud/guide/installation) · [First scan](https://frensense.friehub.cloud/guide/first-scan) · [CLI reference](https://frensense.friehub.cloud/guide/cli) |
| Use | [CI](https://frensense.friehub.cloud/guide/github-actions) · [AI agents](https://frensense.friehub.cloud/guide/mcp) · [Editors](https://frensense.friehub.cloud/guide/lsp) |
| Teach | [Bundles](https://frensense.friehub.cloud/bundles) · [How teaching works](https://frensense.friehub.cloud/guide/teachability) · [Authoring](https://frensense.friehub.cloud/corpus/authoring) |
| Understand | [Architecture](https://frensense.friehub.cloud/architecture/) · [Engine blindness](https://frensense.friehub.cloud/architecture/blindness) |
| Help | [Engine Blindness Challenges](https://frensense.friehub.cloud/challenges) · [Changelog](https://frensense.friehub.cloud/changelog) |

## Contributing

The most useful contribution is a
[blindness challenge](https://frensense.friehub.cloud/challenges): a vulnerable
case the engine cannot see yet, with a pinned repository and a command to
check your fix. Code contributions are welcome under GPL-3.0. Read
[CONTRIBUTING.md](https://github.com/Friehub/frensense-v2/blob/main/CONTRIBUTING.md)
and sign the lightweight
[CLA](https://github.com/Friehub/frensense-v2/blob/main/CLA.md) (one click via
the CLA bot on your first pull request).

## License

GPL-3.0, see [LICENSE](https://github.com/Friehub/frensense-v2/blob/main/LICENSE).
Commercial licensing is available at https://www.friehub.cloud/contact.
