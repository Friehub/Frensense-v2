<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub -->

# Security policy

Frensense is a security tool, so bugs in it matter. This page says what counts
as a vulnerability in Frensense, how to report one privately, and which versions
get fixes.

## What this policy covers

- The `frensense` crate: library, `frensense` CLI, LSP server and MCP server.
- The other crates that ship it: `frensense-engine`, `frensense-bundler`,
  `frensense-lang`, `frensense-packgen`.
- The `.frc` rule bundles published by Friehub.

Examples of vulnerabilities we want reported: a crash, hang or out-of-memory
caused by scanning attacker-supplied input (a project, a bundle, an LSP or MCP
message); a bug that lets a scanned project execute code, read or write files,
or reach the network through the engine; a bundle that can make the engine run
something other than analysis; a path traversal in bundle or report output paths.

## What this policy does not cover

A **missed** vulnerability, a false positive, or an unsound fact is a detection
bug, not a vulnerability in Frensense. Frensense is deliberately incomplete: it
reports what it can prove and says `unknown` or `partial` where it cannot. Please
open a normal issue with a minimised reproduction (the smallest project, and the
exact command).

Third-party components listed in `THIRD_PARTY_LICENSES.md` are covered by their
own projects' policies; report to them, and tell us if Frensense's use of the
component makes it exploitable here.

## Reporting a vulnerability

**Do not open a public issue for a security bug in Frensense.**

Use GitHub private vulnerability reporting on this repository:
<https://github.com/Friehub/Frensense-v2/security/advisories/new>
(Security → Report a vulnerability). The advisory thread is private between you
and the maintainers until it is published.

Please include:

- the affected version (`frensense --version`, or the crate version),
- what an attacker can do, and what they need to be able to supply,
- a minimal reproduction: the smallest input plus the command, or a link to a
  gist,
- your platform and how Frensense was built, if it matters.

If GitHub private reporting is unavailable to you, email <dev@friehub.cloud> or
use the contact listed on the licensing page at <https://friehub.cloud/licensing>,
and say that the message is a security report.

## What happens next

The maintainers read the advisory, reproduce the problem, and reply on the
thread with an assessment: whether it is a vulnerability in Frensense, how
severe it is, and what the fix will be. If it is not a vulnerability in
Frensense, the reply says why and suggests where the report belongs instead.

Fixes ship in a patch release of the affected crate, with a CVE requested when
the impact warrants it. We practise coordinated disclosure: the advisory stays
private while a fix is prepared, and is published with the release. We are glad
to credit you in the advisory and the changelog. Say how you want to be named,
or ask to stay anonymous.

There is no bug bounty.

## Supported versions

Fixes go to the latest published 0.9.x line of `frensense` on crates.io and
`@friehub/frensense` on npm, and to the matching engine versions. Older
pre-1.0 releases do not get backported fixes; upgrade to the latest patch
release. Check the changelog for the versions a fix landed in.
