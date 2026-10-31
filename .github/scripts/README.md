# Repository & CI Maintenance Scripts (`.github/scripts/`)

This directory contains deterministic repository gates, quality ratchets, release utilities, and Git hooks.

These scripts enforce internal engine purity, format compatibility, and SemVer stability before code is merged or published.

---

## The Canonical Gate: `local-ci.sh`

`local-ci.sh` mirrors `.github/workflows/ci.yml` locally. Contributors should run this before opening a pull request:

```bash
./.github/scripts/local-ci.sh
```

---

## Individual Utilities & How to Run Them

### 1. Engine Purity Ratchet (`purity-ratchet.py`)
Enforces the Engine Purity contract: legacy bootstrap calls, raw prose formatters, and hardcoded tier strings must not leak into `frensense-engine`.
* **CI Mode (Check against baseline)**:
  ```bash
  python3 .github/scripts/purity-ratchet.py
  ```
* **Update Baseline**:
  ```bash
  python3 .github/scripts/purity-ratchet.py --update
  ```
* **Verbose Inspection**:
  ```bash
  python3 .github/scripts/purity-ratchet.py --verbose
  ```

### 2. Artifact Format Ratchet (`format-ratchet.py`)
Guarantees that any change to the fact vocabulary fingerprint (`FACT_VOCABULARY_FINGERPRINT`) in `frensense-engine` is accompanied by a `.frc` `BUNDLE_VERSION` bump in `frensense-bundler` and a changelog entry.
* **CI Mode**:
  ```bash
  python3 .github/scripts/format-ratchet.py
  ```
* **Update Baseline**:
  ```bash
  python3 .github/scripts/format-ratchet.py --update
  ```

### 3. Per-Crate SemVer Compatibility Gate (`semver-gate.py`)
Checks each publishable workspace crate (`frensense`, `frensense-engine`, `frensense-lang`, `frensense-bundler`) against a git ref using `cargo-semver-checks`. Ensures breaking API changes require an explicit version bump.
* **Local PR Gate (against HEAD or target branch)**:
  ```bash
  python3 .github/scripts/semver-gate.py --base-ref HEAD
  python3 .github/scripts/semver-gate.py --base-ref origin/main
  ```
* **Dry Run (inspect plan without compilation)**:
  ```bash
  python3 .github/scripts/semver-gate.py --dry-run --base-ref HEAD
  ```
* **Release Gate**:
  ```bash
  python3 .github/scripts/semver-gate.py --published
  ```

### 4. Corpus Lint Gate (`corpus-lint.sh`)
Runs `frensense lint` over corpus families to ensure that any authored corpus is clean and teachable before ingestion.
* **Run against default corpus**:
  ```bash
  ./.github/scripts/corpus-lint.sh
  ```
* **Run against custom corpus directory**:
  ```bash
  ./.github/scripts/corpus-lint.sh path/to/corpus/targets
  ```

### 5. Documentation Blog Provenance (`blog_provenance.py`)
Validates that every article in `docs-site/blog/` declares its verified engine version, fact-check date, and git SHA.
* **Check (warning mode)**:
  ```bash
  python3 .github/scripts/blog_provenance.py check
  ```
* **Strict Mode (fails on stale posts, used in CI/deploy)**:
  ```bash
  python3 .github/scripts/blog_provenance.py check --strict
  ```
* **Stamp current version into blog post frontmatter**:
  ```bash
  python3 .github/scripts/blog_provenance.py stamp docs-site/blog/<post>.md
  ```

### 6. Workspace Release Matrix (`release-matrix.py`)
Coordinates independent releases of workspace crates to crates.io and generates matrix outputs for GitHub Actions.
* **Human-readable status table**:
  ```bash
  python3 .github/scripts/release-matrix.py
  ```
* **Machine-readable JSON**:
  ```bash
  python3 .github/scripts/release-matrix.py --json
  ```
* **Verify published status with polling**:
  ```bash
  python3 .github/scripts/release-matrix.py --require-published --wait 300
  ```

### 7. SBOM Generator (`generate-sbom.sh`)
Generates CycloneDX `bom.json` containing workspace dependencies.
* **Run**:
  ```bash
  ./.github/scripts/generate-sbom.sh
  ```

### 8. Git Pre-Commit Hooks (`setup-hooks.sh` & `pre-commit`)
Installs fast local git hooks into `.git/hooks/pre-commit` to catch formatting, clippy lints, and fast unit tests before commit.
* **Install**:
  ```bash
  ./.github/scripts/setup-hooks.sh
  ```

### 9. Knowledge Curation Assistant (`exa-search/`)
Exa search tool for knowledge curation and research.
* **Run**:
  ```bash
  node .github/scripts/exa-search/search.mjs "query"
  ```
