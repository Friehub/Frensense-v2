#!/bin/bash
# Frensense corpus lint gate.
#
# Runs `frensense lint` (the shipped CLI; `frensense-bundler lint` is the same
# entry point) over a corpus so a family that would teach the engine the wrong
# thing is refused BEFORE the replay gate ever sees it. The
# lint's own exit code is the verdict: 0 clean, 1 issues found, 2 unusable
# configuration (missing registry, unreadable file) - all non-zero fail here.
#
# Usage: .github/scripts/corpus-lint.sh [corpus_dir] [extra lint args...]
#        corpus_dir defaults to corpus/targets (the bundler's own default).
#
# Skip policy: a checkout with no corpus at all (neither the corpus directory
# nor a bug_classes.json anywhere next to it) is not an error - this repo ships
# the engine, not every consumer's corpus. A HALF-configured corpus (registry
# without families, or families without a registry) is a real misconfiguration
# and fails, so the gate can never go quiet on a corpus that is actually there.

set -uo pipefail

CORPUS="${1:-corpus/targets}"
shift || true

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

# The registry may sit inside the corpus or one directory above it; mirror the
# lint's own lookup rather than inventing a second convention.
PARENT=$(dirname "$CORPUS")
HAS_FAMILIES=0
[ -d "$CORPUS" ] && HAS_FAMILIES=1
HAS_REGISTRY=0
if [ -f "$CORPUS/bug_classes.json" ] || [ -f "$PARENT/bug_classes.json" ]; then
    HAS_REGISTRY=1
fi

if [ "$HAS_FAMILIES" -eq 0 ] && [ "$HAS_REGISTRY" -eq 0 ]; then
    echo -e "${YELLOW}SKIP corpus lint: no corpus at $CORPUS (nothing to check)${NC}"
    exit 0
fi
if [ "$HAS_FAMILIES" -eq 0 ]; then
    echo -e "${RED}FAIL corpus lint: no families at $CORPUS but a registry is present${NC}"
    echo "       A registry without families means the corpus moved or was never"
    echo "       checked out. Point the gate at the real directory:"
    echo "       ./.github/scripts/corpus-lint.sh <corpus_dir>"
    exit 1
fi
if [ "$HAS_REGISTRY" -eq 0 ]; then
    echo -e "${RED}FAIL corpus lint: families found in $CORPUS but no bug_classes.json${NC}"
    echo "       The lint needs the class registry: put it at $CORPUS/bug_classes.json"
    echo "       or $PARENT/bug_classes.json, or pass --classes <file>."
    exit 1
fi

echo -e "${BLUE}Linting corpus $CORPUS...${NC}"
cargo run -q --bin frensense -- lint "$CORPUS" "$@"
STATUS=$?
if [ "$STATUS" -eq 0 ]; then
    echo -e "${GREEN}OK Corpus lint passed${NC}"
    exit 0
fi
echo -e "${RED}FAIL corpus lint: families would teach the engine the wrong thing${NC}"
echo "       Fix the reported families, or run the lint directly to iterate:"
echo "       cargo run --bin frensense -- lint $CORPUS"
exit "$STATUS"
