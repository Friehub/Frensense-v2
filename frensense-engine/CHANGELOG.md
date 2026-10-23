# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0-beta] - Unreleased

### Breaking
- **`SinkFinding` and `BackwardStats` are now `#[non_exhaustive]`**, and
  `SinkFinding` gains a `cut_reasons` field (surfaced by `--explain`). Adding a
  field to these previously all-public constructible types is a breaking change
  under Cargo's `0.x` rules; the `0.8.0` line absorbs it and `non_exhaustive`
  keeps future field additions minor-compatible.

### Added
- **`--explain` support**: surfaces *where the engine stayed silent*. Every
  explored sink argument that did not become an advisory records the reason the
  backward taint walk was cut (`guard`, `value-const`, `sanitizer`,
  `unresolvable`), so a false negative is no longer a black box.
- **Advisory CWE classification**: findings carry their canonical CWE through
  the reporting pipeline.
- **Language-scoped provider facts**: `FunctionIR` carries the language it was
  lowered from, and sink signatures / source vocabulary are keyed by
  `(language, call)` (`FactTable::lang_sink_signatures` / `lang_sources`), so a
  mixed-language scan no longer arms every file with every language's provider
  vocabulary (measured: 78 -> 26 advisories on a mixed TS/Rust/Python/Go repo,
  0 flows lost per language). The shared table keeps only genuinely
  language-agnostic knowledge.
- **Flow steps carry real locations**: the taint origin records its source
  span (declaration fallback for entry parameters), so SARIF's first
  `codeFlow` step is a region instead of `location: null`, and the origin is
  no longer printed twice.

### Fixed
- **Borrowed parameter types no longer match framework extractors**: the
  type-named source matcher strips the `&` when normalizing a parameter type,
  so `fn load(root: &Path)` no longer matched axum's `Path` extractor and
  reported every file-reading helper as attacker-controlled. The borrow marker
  is kept (`&Path` is `std::path::Path`); by-value extractors (`Path<T>`) still
  fire. New fixtures: `type_source_tests`.
- **Propagator install is consistently last-wins**: duplicate `join`/`Join`
  propagator entries (a string/array method and a path-builder sharing one bare
  call key) resolved by order-dependent accident, silently dropping the
  string/array-`join` receiver->return flow. The receiver-block flag is now a
  two-way map and both arg slots and the receiver flag install last-wins.
- **Branch-arm-assigned variables survive the merge**: variables assigned only
  inside a `match`/`switch` arm were dropped from the environment at the branch
  merge, losing taint for values crossing an arm boundary.
