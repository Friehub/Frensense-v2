#!/bin/bash
set -e

# Frensense Local CI - THE canonical quality gate.
#
# This script mirrors the required checks in `.github/workflows/ci.yml`,
# including the engine-specific API and feature checks. If this passes
# locally, the CI quality checks will pass (modulo platform differences).
#
# Run it before opening every PR. Individual commands are listed below if
# you need to run a subset while iterating.

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 0. Artifact-format ratchet: a moved fact-vocabulary fingerprint must come
#    with a BUNDLE_VERSION bump and a changelog note. Runs first because it is
#    source-only (no build) and catches the contract violation cheapest.
echo -e "\n${BLUE}[0/12] Artifact-format ratchet (fingerprint must move with bundle version)...${NC}"
python3 scripts/format-ratchet.py
echo -e "${GREEN}OK Artifact-format contract holds${NC}"

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}      Frensense Local CI (mirror of ci.yml)        ${NC}"
echo -e "${BLUE}==================================================${NC}"

# 1. Purity debt ratchet (ci.yml `qa` job, runs FIRST)
echo -e "\n${BLUE}[1/12] Engine purity ratchet (debt must not grow)...${NC}"
python3 scripts/purity-ratchet.py
echo -e "${GREEN}OK Purity debt within baseline${NC}"

# 1b. Blog provenance gate (ci.yml `qa` job): version-pinned claims, fresh audits
echo -e "\n${BLUE}[2/12] Blog provenance gate (--strict)...${NC}"
python3 scripts/blog_provenance.py check --strict
echo -e "${GREEN}OK Blog claims version-pinned and fresh${NC}"

# 3. Style (ci.yml `qa` job)
echo -e "\n${BLUE}[3/12] Enforcing style (rustfmt)...${NC}"
cargo fmt --all -- --check
echo -e "${GREEN}OK Formatting is correct${NC}"

echo -e "\n${BLUE}[4/12] Engine rustdoc (broken/private intra-doc links are errors)...${NC}"
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links -D rustdoc::private_intra_doc_links" cargo doc -p frensense-engine --all-features --no-deps
echo -e "${GREEN}OK Engine rustdoc passed${NC}"

echo -e "\n${BLUE}[5/12] Unused dependency check (cargo-machete)...${NC}"
cargo machete --with-metadata frensense-engine frensense-lang frensense-bundler frensense-packgen frensense-devtools
echo -e "${GREEN}OK No unused dependencies found${NC}"

echo -e "\n${BLUE}[6/12] Isolated engine feature checks (cargo-hack)...${NC}"
cargo hack check -p frensense-engine --each-feature --locked
echo -e "${GREEN}OK Engine feature matrix passed${NC}"

# 4. Default pack drift check (ci.yml `qa` job)
echo -e "\n${BLUE}[7/12] Default pack drift check (packgen --check)...${NC}"
cargo run -p frensense-packgen -- --check
echo -e "${GREEN}OK Default pack asset is up to date${NC}"

# 4b. Corpus lint (ci.yml `qa` job): a family that fails lint would teach the
#     engine the wrong thing, so it is refused before the replay gate sees it.
#     Skips only when the checkout carries no corpus at all; a half-configured
#     corpus (families without bug_classes.json) fails here.
echo -e "\n${BLUE}[8/12] Corpus lint (families must be teachable)...${NC}"
./scripts/corpus-lint.sh
echo -e "${GREEN}OK Corpus lint gate passed${NC}"

# Lint (ci.yml `qa` job)
echo -e "\n${BLUE}[9/12] Linting (clippy, warnings are errors)...${NC}"
cargo clippy --all-features --all-targets -- -D warnings
echo -e "${GREEN}OK Clippy passed${NC}"

# 6. Full regression suite (ci.yml `test-rust` job)
echo -e "\n${BLUE}[10/12] Running full regression suite...${NC}"
cargo test --workspace --all-features
echo -e "${GREEN}OK All tests passed${NC}"

echo -e "\n${BLUE}[11/12] Supply-chain audit (cargo-deny)...${NC}"
cargo deny check
echo -e "${GREEN}OK cargo-deny passed${NC}"

echo -e "\n${BLUE}[12/12] Engine public API compatibility (cargo-semver-checks)...${NC}"
cargo semver-checks check-release -p frensense-engine --baseline-rev HEAD --release-type patch
echo -e "${GREEN}OK Engine public API compatible with HEAD baseline${NC}"

echo -e "\n${GREEN}==================================================${NC}"
echo -e "${GREEN}   ALL LOCAL GATE CHECKS PASSED                     ${NC}"
echo -e "${GREEN}==================================================${NC}"
