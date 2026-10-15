# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0-beta] - Unreleased

### Breaking
- **`Candidate` is now `#[non_exhaustive]`**, and its `Check` variant gains a
  `package` field. Adding a field to a public enum variant is a breaking change
  under Cargo's `0.x` rules; the `0.8.0` line absorbs it and `non_exhaustive`
  keeps future variant-field additions minor-compatible.

### Changed
- **Regenerated embedded default-pack asset** (`assets/frensense-default.frc`):
  stripped cross-language sink contamination from the Python/Go/C/Rust vocab
  tables (foreign JS/Node/Express/Prisma/Cloudflare APIs that were false-positive
  factories for the host language) and de-duplicated the propagator tables.
  Asset 93,036 -> 82,697 bytes. The bundle format itself is unchanged
  (`BUNDLE_VERSION` 6); existing user-supplied `.frc` corpora remain compatible.
