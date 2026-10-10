---
url: https://frensense.friehub.cloud/corpus.md
---
# Corpus & .frc bundles

The corpus is a set of **labelled example families**. Each family contains
at least one *positive* (vulnerable) example and one *negative* (fixed)
example. The bundler replays each family through the engine, diffs the two
variants, and learns facts that distinguish them, then verifies those facts
against every other family before publishing them into a `.frc` bundle.

```
corpus/
├── ts_sqli_01/
│   ├── positive.ts     # vulnerable
│   └── negative.ts     # fixed  (starts with "SAFE:")
├── py_cmd_03/
│   ├── positive.py     # [frensense] metadata block at the top
│   └── negative.py
└── ...
```

## Building a bundle

```bash
frensense-bundler ./corpus ./frensense-corpus.frc
```

Place the output at the root of the scanned project as
`frensense-corpus.frc` (auto-discovered), pass it with `--corpus-bundle`, or
set `FRENSENSE_CORPUS_BUNDLE` for MCP/LSP.

## Next

* [Authoring guide](/corpus/authoring), naming, metadata blocks, policy
  families, verification workflow, and common mistakes.
