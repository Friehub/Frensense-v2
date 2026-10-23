# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0-beta] - Unreleased

### Breaking
- **`BUNDLE_VERSION` 6 -> 7: bundles now record the fact-vocabulary
  fingerprint and the engine that built them.** A `.frc` stores fact entries by
  variant position (bincode is positional), so it is only decodable by an
  engine speaking the same vocabulary. Version 7 makes that explicit in the
  header instead of surfacing a mismatch as an opaque serde decode error:
  - `BundleHeader::vocabulary` — the writing engine's
    `FACT_VOCABULARY_FINGERPRINT`. Checked **strictly** on load; a mismatch is
    refused with both values named and a rebuild instruction.
  - `BundleHeader::requires_engine` — an optional coarse engine range
    (`EngineRequirement`) for corpus authors who want a policy bound.
  - `BundleHeader::built_by_engine` — diagnostics only.

  Compatibility is **one-directional**: v6-and-earlier bundles still load
  (they carry no fingerprint, so there is nothing to compare, and are marked
  `is_legacy()`), but a v7 bundle built for a newer vocabulary is refused by an
  older binary at the version gate before any payload decode. Rebuild a corpus
  bundle with a matching engine when this happens.
- **`Candidate` is now `#[non_exhaustive]`**, and its `Check` variant gains a
  `package` field. Adding a field to a public enum variant is a breaking change
  under Cargo's `0.x` rules; the `0.8.0` line absorbs it and `non_exhaustive`
  keeps future variant-field additions minor-compatible.

### Changed
- **Regenerated embedded default-pack asset** (`assets/frensense-default.frc`):
  stripped cross-language sink contamination from the Python/Go/C/Rust vocab
  tables (foreign JS/Node/Express/Prisma/Cloudflare APIs that were false-positive
  factories for the host language) and de-duplicated the propagator tables.
  Re-emitted under the v7 envelope so it records its fact-vocabulary
  fingerprint; a `v7` asset is readable by `BUNDLE_VERSION >= 7` engines only.
  See `docs/FORMATS.md` for the artifact version table and bump rules.
