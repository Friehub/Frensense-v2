# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1-beta] - 2026-10-13

### Added
- **Advisory CWE classification**: built-in advisories now carry their canonical
  CWE so findings resolve to a stable CWE identifier instead of a generic label.

### Fixed
- **CWE-94 tagging for Code Execution**: `eval`, `exec`, and `compile` sinks now
  carry CWE-94 (Code Injection); the mapping previously matched a dead arm.
- **CWE-601 tagging for Open Redirect**: `redirect`-labelled Resource-role sinks
  now carry CWE-601 (URL Redirection to Untrusted Site).
