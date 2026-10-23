# Knowledge bundles (.frc)

`.frc` files are checksummed, versioned archives carrying two things:

1. **Patterns**, vulnerability examples with metadata (observation, impact,
   CWE, CVSS, OWASP, severity).
2. **Learned facts**, replay-verified Source / Sink / Sanitizer / Policy /
   Check facts the engine merges into its fact table at scan time.

## Loading order

At scan time the engine loads spec tables, then seed facts, then merges the
bundle. A bundle is discovered from (in order):

- the `--corpus-bundle` / `--bundle` CLI flag,
- the `FRENSENSE_CORPUS_BUNDLE` environment variable (MCP / LSP),
- auto-discovery of `frensense-corpus.frc` in the scanned root.

## Why facts, not rules

Facts are lower-level than "regex rules": a learned sink participates in the
same graph analysis as a builtin one, so taint paths, guard recognition, and
value reasoning all apply to it. The bundler only publishes a fact after it
replays against labelled positive *and* negative examples; one voting family
publishes it as `provisional`, two or more as `confirmed`. Run
`frensense bundle info my.frc` to see what a bundle actually carries, and
`frensense lint mycorpus` to check the families before they are compiled - see the
[authoring guide](/corpus/authoring).
