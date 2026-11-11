---
title: Bundles (.frc)
description: What a Frensense bundle is, how to download and use one, and how to judge whether it helps on your code.
---

# Bundles (`.frc`)

Frensense ships with a built-in knowledge pack: 1,627 facts about sources,
sinks and sanitizers for the languages it supports. A **bundle** is an extra
pack you load on top, for frameworks and libraries the built-in pack does not
know. If a scan misses a vulnerability because the engine has never heard of
your web framework's request object or database call, a bundle is how you tell
it.

A `.frc` file is a versioned, checksummed archive of two things:

1. **Learned facts**: sources, sinks, sanitizers and policy checks that the
   engine merges into its tables at scan time. A learned sink takes part in the
   same graph analysis as a built-in one, so taint paths and guards apply to it.
2. **Patterns**: vulnerable and fixed examples with their CWE, impact and
   severity, kept so you can see what the bundle was taught from.

A bundle is data, not code. It cannot run anything. It can change what the
engine reports, in both directions (see "Check that a bundle helps").

## Use a bundle

```bash
frensense ./src --bundle my.frc        # -b is the short form
```

Other ways the engine finds one, in the order it looks:

| How | Applies to |
| --- | --- |
| `-b` / `--bundle <file>` on the command line | CLI scans |
| `frensense-corpus.frc` in the scanned folder | CLI scans (found automatically) |
| `FRENSENSE_CORPUS_BUNDLE` environment variable | the MCP and LSP servers only |
| `corpus_bundle` argument on an MCP tool call | MCP |

`FRENSENSE_CORPUS_BUNDLE` does not affect a plain `frensense .` scan. Use `-b`
or the auto-discovered file there.

To see what a bundle contains:

```bash
frensense bundle info my.frc          # add --json for machine output
```

## Community bundles

Free starter bundles are published for the main stacks. Each has a datasheet
that lists the classes it covers and the examples it was checked against.

| Bundle | For |
| --- | --- |
| [`frensense-typescript.frc`](https://bundles.friehub.cloud/community/latest/frensense-typescript.frc) | TypeScript and JavaScript (Node.js, Express, Next.js) |
| [`frensense-python.frc`](https://bundles.friehub.cloud/community/latest/frensense-python.frc) | Python (Flask, Django, scripts) |
| [`frensense-go.frc`](https://bundles.friehub.cloud/community/latest/frensense-go.frc) | Go (HTTP handlers, templates, SQL drivers) |
| [`frensense-c.frc`](https://bundles.friehub.cloud/community/latest/frensense-c.frc) | C (memory safety: use after free, leaks, buffer bounds) |
| [`frensense-master.frc`](https://bundles.friehub.cloud/community/latest/frensense-master.frc) | All of the above in one file |

Alongside them:
[`CWE_DATASHEET.md`](https://bundles.friehub.cloud/community/latest/CWE_DATASHEET.md),
[`SHA256SUMS`](https://bundles.friehub.cloud/community/latest/SHA256SUMS) and
its signature
[`SHA256SUMS.sig`](https://bundles.friehub.cloud/community/latest/SHA256SUMS.sig).
Check a download before you use it:

```bash
curl -fsSLO https://bundles.friehub.cloud/community/latest/frensense-python.frc
curl -fsSLO https://bundles.friehub.cloud/community/latest/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Commercial bundles with broader framework coverage are offered separately.
[Get in touch](https://www.friehub.cloud/contact) for details.

## Check that a bundle helps

More knowledge is not automatically better. A bundle that teaches the engine a
very common function name as a sink can flood a large codebase with false
alarms, and slow the scan down. Before you rely on one in CI, run it against
your own code both ways:

```bash
frensense ./src --json > bare.json
frensense ./src --json -b my.frc > with-bundle.json
```

Compare `advisory_count` in the two files. Then read a sample of the findings
that only the bundle produced and ask whether each one is a real problem. If
most are not, do not use that bundle on this code, and report it so it can be
fixed. A bundle's own datasheet describes the examples it was verified on, not
how it behaves on your project.

## Make your own

You teach the engine with pairs of labelled examples: one vulnerable, one
fixed. The bundler replays each pair through the engine, learns the facts that
separate them, and keeps a fact only if it survives checks against every other
pair. A fact backed by one family is marked `provisional`; two or more make it
`confirmed`.

```bash
frensense lint mycorpus --strict     # check the examples first
frensense bundle mycorpus my.frc     # compile
frensense bundle info my.frc         # read what was actually published
```

Start with [How teaching works](/guide/teachability), then the
[authoring guide](/corpus/authoring).
