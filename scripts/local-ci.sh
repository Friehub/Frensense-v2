#!/bin/bash
set -e

# Frensense Local CI - THE canonical quality gate.
#
# This script is a 1:1 mirror of the checks `.github/workflows/ci.yml` runs
# in its `qa` and `test-rust` jobs, in the same order. If this passes
# locally, the CI quality checks will pass (modulo platform differences).
#
# Run it before opening every PR. Individual commands are listed below if
# you need to run a subset while iterating.

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}      Frensense Local CI (mirror of ci.yml)        ${NC}"
echo -e "${BLUE}==================================================${NC}"

# 1. Purity debt ratchet (ci.yml `qa` job, runs FIRST)
echo -e "\n${BLUE}[1/5] Engine purity ratchet (debt must not grow)...${NC}"
python3 scripts/purity-ratchet.py
echo -e "${GREEN}OK Purity debt within baseline${NC}"

# 2. Style (ci.yml `qa` job)
echo -e "\n${BLUE}[2/5] Enforcing style (rustfmt)...${NC}"
cargo fmt --all -- --check
echo -e "${GREEN}OK Formatting is correct${NC}"

# 3. Default pack drift check (ci.yml `qa` job)
echo -e "\n${BLUE}[3/5] Default pack drift check (packgen --check)...${NC}"
cargo run -p frensense-packgen -- --check
echo -e "${GREEN}OK Default pack asset is up to date${NC}"

# 4. Lint (ci.yml `qa` job)
echo -e "\n${BLUE}[4/5] Linting (clippy, warnings are errors)...${NC}"
cargo clippy --all-features --all-targets -- -D warnings
echo -e "${GREEN}OK Clippy passed${NC}"

# 5. Full regression suite (ci.yml `test-rust` job)
echo -e "\n${BLUE}[5/5] Running full regression suite...${NC}"
cargo test --workspace --all-features
echo -e "${GREEN}OK All tests passed${NC}"

echo -e "\n${GREEN}==================================================${NC}"
echo -e "${GREEN}   ALL CHECKS PASSED: identical to CI's quality    ${NC}"
echo -e "${GREEN}==================================================${NC}"
