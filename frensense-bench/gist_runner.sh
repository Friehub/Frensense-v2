#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
#
# ==============================================================================
# Frensense Autonomous Benchmark Reproducer (Gist Runner)
# ==============================================================================
# Reproduces the published 26.6% Score / 1.5% FPR result against the
# official OWASP Benchmark for Python (v0.1, 1,230 test cases).
#
# One-liner execution:
#   curl -sSL https://raw.githubusercontent.com/Friehub/frensense-v2/main/scripts/gist_runner.sh | bash
#
# Requirements:
#   - git
#   - python3
#   - cargo (or npx @friehub/frensense)
# ==============================================================================

set -euo pipefail

WORK_DIR="$(mktemp -d /tmp/frensense-bench-XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "=== [1/3] Setting up Frensense engine ==="
if command -v frensense >/dev/null 2>&1; then
    FRENSENSE_BIN="$(command -v frensense)"
    echo "Using system frensense: ${FRENSENSE_BIN}"
else
    echo "Cloning and building latest Frensense release..."
    git clone --depth 1 https://github.com/Friehub/frensense-v2.git "${WORK_DIR}/frensense"
    (cd "${WORK_DIR}/frensense" && cargo build --release --bin frensense)
    FRENSENSE_BIN="${WORK_DIR}/frensense/target/release/frensense"
fi

echo "=== [2/3] Fetching OWASP Benchmark dataset ==="
OWASP_DIR="/tmp/BenchmarkPython"
if [[ ! -f "${OWASP_DIR}/expectedresults-0.1.csv" ]]; then
    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython.git "${OWASP_DIR}"
fi

echo "=== [3/3] Running benchmark evaluation (1,230 cases) ==="
python3 - <<PYEOF
import sys
sys.path.insert(0, "${WORK_DIR}/frensense/scripts")
import owasp_benchmark
owasp_benchmark.main()
PYEOF \
  --bin "${FRENSENSE_BIN}" \
  --owasp-csv "${OWASP_DIR}/expectedresults-0.1.csv" \
  --owasp-testcode "${OWASP_DIR}/testcode" \
  --workers 8 \
  --md-out "${PWD}/benchmark_report.md" \
  --json-out "${PWD}/benchmark_scorecard.json"

echo ""
echo "=============================================================="
echo " Verification Complete!"
echo " Markdown report saved to: ${PWD}/benchmark_report.md"
echo " JSON scorecard saved to:  ${PWD}/benchmark_scorecard.json"
echo "=============================================================="
