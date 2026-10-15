# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1-beta] - 2026-10-13

### Added
- **`--explain` support**: surfaces *where the engine stayed silent*. Every
  explored sink argument that did not become an advisory records the reason the
  backward taint walk was cut (`guard`, `value-const`, `sanitizer`,
  `unresolvable`), so a false negative is no longer a black box.
- **Advisory CWE classification**: findings carry their canonical CWE through
  the reporting pipeline.

### Fixed
- **Propagator install is consistently last-wins**: duplicate `join`/`Join`
  propagator entries (a string/array method and a path-builder sharing one bare
  call key) resolved by order-dependent accident, silently dropping the
  string/array-`join` receiver->return flow. The receiver-block flag is now a
  two-way map and both arg slots and the receiver flag install last-wins.
- **Branch-arm-assigned variables survive the merge**: variables assigned only
  inside a `match`/`switch` arm were dropped from the environment at the branch
  merge, losing taint for values crossing an arm boundary.
