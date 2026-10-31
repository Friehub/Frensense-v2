# Changelog
All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate versions and ships independently of the `frensense` binary, which
pins a compatible range. It owns the `.frc` envelope, the corpus compiler and
its replay gate, the corpus `lint` checks, and the embedded default-pack asset.
`scripts/format-ratchet.py` requires a `BUNDLE_VERSION` bump to be acknowledged
in *this* file, so a format change - not the root changelog - is what records
artifact compatibility.

## [0.8.0] - 2026-10-30

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
  `package` field (with `unbounded_product` on `IntegerOverflowRule`).
  `FamilyMetadata` and `PreparedFamily` likewise gain fields
  (`require_arg_keys`, `unbounded_product`, `guards`, `cwe`). Adding a field to
  a public enum variant is a breaking change under Cargo's `0.x` rules; the
  `0.8.0` line absorbs it and `non_exhaustive` keeps future variant-field
  additions minor-compatible. `cargo semver-checks check-release
  --release-type patch` against the published `0.7.0` reports 3 major checks
  failing for these.

### Added
- **`frensense-bundler lint` / `frensense lint <corpus>`**: a corpus pre-flight
  that exits `0` when the corpus is acceptable, `1` when any error (or any
  warning under `--strict`) is found, and `2` on a usage error. The `frensense`
  binary exposes the same entry point so curators need one executable.
- **What `lint` checks**: file layout and naming (missing or orphaned twins,
  incomplete held-out pairs, cross-language stem collisions), the `[frensense]`
  metadata block (required keys, unknown-key suggestions, duplicate keys,
  placeholder prose, severity/CWE/cvss syntax), the class registry
  (`bug_classes.json`: unknown class ids get a nearest-match hint, and every CWE
  must belong to the declared class), provenance (`source:` form, CVE/GHSA/RUSTSEC
  ids must exist in the offline advisory index and agree with the CWE),
  cross-family diversity (near-duplicate call sets, structural clones, families
  that teach identical or subset facts), and the family's declared `purpose:`
  against what the bare engine actually does with the pair.
- **`PU004`: a family that would teach nothing now says so, with the reason**.
  A pair can satisfy every layout, metadata and purpose check and still
  contribute no fact: the declared premise holds (knowledge with a silent
  positive, precision with a noisy negative), yet the only facts it proposes do
  not separate its own twins, so the replay gate publishes nothing and the
  bundle scans both files exactly as the bare engine did. Lint now trials each
  proposed fact against the family the way the gate's vote does and reports the
  closest candidate with the engine verdict that sank it - e.g. `none of its 2
  proposed fact(s) separates the pair; closest is sink:rawQuery
  (positive_alerts=true, negative_alerts=true): the positive alerts but so does
  the negative`. It also names the opposite case (the fact changes no verdict)
  and the no-candidate case (the twins differ in no learnable source, sink,
  sanitizer, guard or check call). Anchors are exempt, and the warning only
  fires where the declared purpose's premise is actually true, so a family never
  gets both PU001/PU003 and PU004 for the same mistake.
- **Lint flags**: `--classes <file>`, `--advisories <file>`, `--strict`,
  `--require-heldout`, `--no-gate` (skip the scan-based purpose and
  teachability checks), `--dup-threshold <0..1>`, `--json`, `--coverage`
  (class x language coverage counting only error-free families).
- **Package-scoped learned facts** (carried over from the 0.7.0 line): a
  candidate fact may declare `package: <framework>` in its corpus metadata and
  is then bound to files that import or declare that package, with the bundler
  quarantining candidates whose voting family never imports it.
- **`frensense bundle info --json`**: reports the bundle's magic, format
  version, writer engine, vocabulary fingerprint, optional engine requirement,
  learned-fact counts by kind, pattern count, payload size and BLAKE3 checksum.

### Changed
- **Regenerated embedded default-pack asset** (`assets/frensense-default.frc`):
  stripped cross-language sink contamination from the Python/Go/C/Rust vocab
  tables (foreign JS/Node/Express/Prisma/Cloudflare APIs that were false-positive
  factories for the host language) and de-duplicated the propagator tables.
  Re-emitted under the v7 envelope so it records its fact-vocabulary
  fingerprint; a `v7` asset is readable by `BUNDLE_VERSION >= 7` engines only.
  Default pack 93,036 -> 82,697 bytes after the purge, then 92,422 -> 92,701
  bytes once the C buffer vocabulary grew. See `docs/FORMATS.md` for the
  artifact version table and bump rules.
