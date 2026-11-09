---
url: https://frensense.friehub.cloud/guide.md
description: What Frensense is, what it scans, and where to go next.
---

# Frensense overview

Frensense is a static application security testing (SAST) scanner. It reads
your source code, follows untrusted input through the program, and reports a
finding only when that input can reach a dangerous call. Every finding shows
the path it took, with file and line positions, so you can check it yourself.

It is one binary. Scanning, watch mode, the AI-agent server (`frensense mcp`)
and the editor server (`frensense lsp`) are all subcommands of `frensense`.

::: warning What to expect
Frensense is young and deliberately conservative about what it reports, which
means it **misses real vulnerabilities**. On the OWASP Benchmark for Python it
currently finds 38% of the vulnerable cases, and it finds none of the cases
for cross-site scripting, weak randomness, XML external entities, LDAP
injection or trust-boundary violations. See
the [benchmark record](/architecture/benchmarks) for the numbers, and treat a
clean scan as "nothing found", not "nothing there".
:::

## Choose your path

| I want to... | Go to |
| --- | --- |
| Scan a project once | [Install](/guide/installation), then [Your first scan](/guide/first-scan) |
| Fail a pull request on new findings | [CI and agent gating](/guide/github-actions) |
| Let an AI coding agent check its own changes | [AI agents (MCP)](/guide/mcp) |
| See findings in my editor | [Editors (LSP)](/guide/lsp) |
| Look up a flag or an exit code | [CLI reference](/guide/cli) |
| Add knowledge about my framework | [Bundles](/bundles), then [How teaching works](/guide/teachability) |
| Help improve the engine | [Engine Blindness Challenges](/challenges) |

## What it scans

| Language | File extensions |
| --- | --- |
| TypeScript | `.ts` `.tsx` `.mts` `.cts` |
| JavaScript | `.js` `.jsx` `.mjs` `.cjs` |
| Python | `.py` `.pyi` `.pyw` |
| Go | `.go` |
| Rust | `.rs` |
| C | `.c` `.h` |
| Vue | `.vue` single-file components (early support) |

C++ is not supported. Files in other languages are skipped.

## What it reports

57 built-in rules, each with a stable id and a CWE number. Run
`frensense explain` to list them, or `frensense explain <rule-id>` for the
explanation and fix advice of one.

* **Taint flows (`taint.*`, 30 rules):** untrusted input reaching a dangerous
  call. These include SQL, NoSQL, command, code, template, LDAP and XPath
  injection, path traversal, SSRF, open redirect, XSS, unsafe deserialization,
  XXE, prototype pollution and regular-expression denial of service.
* **Checks (`check.*`, 27 rules):** problems that do not need a source, such as
  weak hashes and ciphers, missing cookie flags, insecure transport, and the
  memory-safety checks (use after free, double free, out-of-bounds access,
  integer overflow in an allocation size, memory leaks).

A rule existing does not mean it works on every framework. Detection depends
on the engine knowing the framework's sources and sinks, which is what
[bundles](/bundles) add.

## How a finding is produced

1. Each file is parsed and converted to a small intermediate form.
2. The engine builds a graph of how values move between variables, functions
   and objects across the whole project.
3. It asks one question per dangerous call: can a value from an untrusted
   source reach this argument without passing through a sanitizer or a guard?
4. If yes, you get a finding with the path. If the engine cannot tell (for
   example, a value comes from code it cannot see), it stays quiet rather than
   guessing. `frensense --explain` lists those silent spots.

The same input always gives the same output. There is no model, no network
call and no sampling in the scan. See [Architecture](/architecture/) for the
details.

## Status

Frensense is at version v0.8.0. The
documentation for the earlier 1.x line is kept at [/v1/](/v1/). Version 2
is a rebuild of the engine.

## Summary for assistants

Frensense (`frensense` on crates.io, `@friehub/frensense` on npm) is a
GPL-3.0 deterministic dataflow scanner for TypeScript, JavaScript, Python, Go,
Rust, C and Vue files. It reports taint paths from untrusted sources to
dangerous calls. It is not a replacement for a full SAST suite: detection
coverage is limited (see /architecture/benchmarks), so describe results as
"findings" and a clean scan as "nothing found".

Useful for: CI gates (`frensense . --compare-baseline baseline.json`), scanning
an unfamiliar repository, checking an AI agent's own edits through MCP
(`frensense mcp`; tools `frensense_audit`, `frensense_scan_file`,
`frensense_diff`), and editor diagnostics (`frensense lsp`).

Install: `cargo install frensense` or `npm install -g @friehub/frensense`.
One binary, three surfaces; there is no separate MCP or LSP package.
