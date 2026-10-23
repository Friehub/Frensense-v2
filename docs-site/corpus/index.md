# Corpus & .frc bundles

The corpus is a set of **labelled example families**. Each family contains at
least one *positive* (vulnerable) example and one *negative* (fixed) example.
The bundler replays each family through the engine, diffs the two variants,
learns facts that distinguish them, then verifies those facts against every
other family before publishing them into a `.frc` bundle.

```
mycorpus/
├── bug_classes.json                  # class registry the lint checks against
└── ts/inj.sql/ts_sqli/
    ├── ts_sqli_positive.ts           # [frensense] metadata block at the top
    ├── ts_sqli_negative.ts           # fixed version, starts with "SAFE:"
    ├── ts_sqli_heldout_positive.ts   # blind pair: never read by the bundler
    └── ts_sqli_heldout_negative.ts
```

The `<family>_positive.<ext>` / `<family>_negative.<ext>` infix is what makes a
family; a directory with `positive.ts` and `negative.ts` groups **zero**
families. Supported extensions: `ts`, `tsx`, `js`, `jsx`, `py`, `go`, `rs`,
`c`, `cpp`, `h`, `hpp`.

## Lint, build, inspect

```bash
# 1. Pre-flight: metadata, layout, provenance, diversity, teachability.
frensense lint mycorpus --strict

# 2. Compile the families into a bundle.
frensense bundle mycorpus my.frc

# 3. Read what was actually published.
frensense bundle info my.frc
```

`frensense lint` never scans target code unless you ask it to, and it refuses
the mistakes the replay gate cannot see: a mislabelled class, copied families,
placeholder advisory prose, and a pair that would teach nothing (`PU004`).
`frensense bundle` is the current spelling of the old `frensense-bundler`
invocation that took a corpus and an output path.

## Use the bundle

Place the output at the root of the scanned project as
`frensense-corpus.frc` (auto-discovered), pass it with
`-b` / `--bundle` / `--corpus-bundle`, or set `FRENSENSE_CORPUS_BUNDLE` for
MCP and LSP.

## Next

- [Authoring guide](/corpus/authoring) - the full contract: required metadata,
  the nine fact shapes a family can teach, held-out pairs, the lint codes,
  verified command output, and a migration checklist for families written
  against the old guide.
