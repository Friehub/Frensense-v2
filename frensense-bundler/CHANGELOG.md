# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1-beta] - 2026-10-13

### Changed
- **Regenerated embedded default-pack asset** (`assets/frensense-default.frc`):
  stripped cross-language sink contamination from the Python/Go/C/Rust vocab
  tables (foreign JS/Node/Express/Prisma/Cloudflare APIs that were false-positive
  factories for the host language) and de-duplicated the propagator tables.
  Asset 93,036 -> 82,697 bytes. The bundle format itself is unchanged
  (`BUNDLE_VERSION` 6); existing user-supplied `.frc` corpora remain compatible.
