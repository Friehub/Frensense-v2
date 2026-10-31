# Changelog
All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`frensense-packgen` is not published to a registry (`publish = false`). It is
the maintainer-side generator for the built-in vocabulary: the tables in
`src/vocab/` are emitted deterministically as `LearnedFactEntry` facts into
`frensense-bundler/assets/frensense-default.frc`, which the bundler embeds with
`include_bytes!`. Its changes reach users through that asset, so this file
records what moved in the default pack and why. `cargo run -p frensense-packgen
-- --check` fails CI if the asset drifts from the generator; the entries below
are the reasons the asset moved.

There is no semver contract here (nothing is published, and
`cargo semver-checks` excludes it). The version tracks the workspace line.

## [0.8.0] - 2026-10-30

### Changed
- **Cross-language sink contamination removed from the vocabulary tables**: the
  Python, Go, C, and Rust tables carried large copy-pasted blocks of foreign
  APIs (JS DOM sinks like `innerHTML`/`dangerouslySetInnerHTML`, Express
  `res.send`, Node `spawnSync`/`readFile`, prototype-pollution
  `Object.assign`/`_.set`, Cloudflare Workers and Prisma bindings, camelCase
  MongoDB driver verbs, Flask `render_template` in Go/C/Rust, Rust
  `bincode`/`serde_json` in Python/Go/C). Because the engine registers each
  dotted entry's last segment as a bare sink, every one of these was a
  false-positive generator for the host language - e.g. a Go `Object.assign`
  entry made every Go `.assign(` call a prototype-pollution sink, and Go/C's
  `_.set` made every `.set(` call one. All foreign entries are removed; each
  table now contains only APIs that exist in its own language. Default pack
  93,036 -> 82,697 bytes. OWASP score unchanged (25.9%). The engine half of the
  fix (install-time language scoping) is in `frensense-engine`, without which
  removing the entries alone was not sufficient.
- **Duplicate propagator keys removed per language**: `join`/`Join` was declared
  twice in Python, Go and JS (a string/array method and a path builder sharing
  one bare call key), and JS declared `toString` twice. Order decided which one
  won, which silently dropped the string/array-`join` receiver->return flow.
  The duplicates are gone and a regression test asserts no duplicate propagator
  keys per language, so the `last-wins` engine install has nothing to arbitrate.
- **C buffer vocabulary covers appends, copies and formatted writes**: the
  buffer contract named only `strcpy`, a source-less `strncpy` and a source-less
  `snprintf`, so `strcat(buf, argv[1]); system(buf)` stayed silent while the
  same `strcpy` flow alerted. It now carries `stpcpy`, `strlcpy`, `strcat`,
  `strncat`, `strlcat`, `sprintf` and `snprintf` with their source arguments
  (`strncat`/`strlcpy`/`strlcat` sourced from argument 1, bounded by argument 2;
  `sprintf`/`snprintf` sourced from the first variadic argument, the one the
  format consumes). Pack asset 92,422 -> 92,701 bytes.
- **The last two name-based engine guesses are now tables here**:
  `HintKind::PreparedStatementPrefix` and `HintKind::WeakHashDisclaimer` carry
  the "a call named `prepare*` returns a bound statement handle" and "a literal
  `false` argument disclaims security use of a weak digest" vocabularies. An
  empty set recognises nothing, so a config that teaches nothing never
  suppresses a flow. OWASP BenchmarkPython and the 92-finding real-repo
  baseline are unchanged by the move.
- **Default pack regenerated under the v7 envelope** so the embedded asset
  records its fact-vocabulary fingerprint. Any vocabulary edit here changes
  `FACT_VOCABULARY_FINGERPRINT`, which `scripts/format-ratchet.py` requires to
  come with a `BUNDLE_VERSION` bump and a note in
  `frensense-bundler/CHANGELOG.md`.

### Added
- **`package:` metadata parsing**: a corpus family's `// package: <framework>`
  header is parsed here and forwarded to the emitted facts, so the generated
  tables and bundle-compiled facts carry the same provenance field.
