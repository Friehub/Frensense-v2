#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
#
# Frensense Autonomous Benchmark Reproduction Runner
# Scores Frensense against the OWASP Benchmark for Python (v0.1, 1,230 cases)
#
# Usage:
#   ./scripts/reproduce_benchmark.sh
#   ./scripts/reproduce_benchmark.sh --workers 8
#   ./scripts/reproduce_benchmark.sh --publish-gist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Ensure python3 is available
if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 is required to run the benchmark evaluation." >&2
    exit 1
fi

# Locate or build frensense binary
BINARY=""
if [[ -n "${FRENSENSE_BIN:-}" && -x "${FRENSENSE_BIN}" ]]; then
    BINARY="${FRENSENSE_BIN}"
elif [[ -x "${REPO_ROOT}/target/release/frensense" ]]; then
    BINARY="${REPO_ROOT}/target/release/frensense"
elif [[ -x "${REPO_ROOT}/target/debug/frensense" ]]; then
    BINARY="${REPO_ROOT}/target/debug/frensense"
elif command -v frensense >/dev/null 2>&1; then
    BINARY="$(command -v frensense)"
fi

if [[ -z "${BINARY}" ]]; then
    echo "[INFO] No pre-built frensense binary found. Building release binary with Cargo..."
    if command -v cargo >/dev/null 2>&1; then
        (cd "${REPO_ROOT}" && cargo build --release --bin frensense)
        BINARY="${REPO_ROOT}/target/release/frensense"
    else
        echo "[ERROR] 'cargo' is not installed and no frensense binary was found." >&2
        echo "        Install Rust via https://rustup.rs or install frensense globally." >&2
        exit 1
    fi
fi

# Ensure OWASP Benchmark data is available
OWASP_DIR="/tmp/BenchmarkPython"
if [[ ! -f "${OWASP_DIR}/expectedresults-0.1.csv" ]]; then
    echo "[INFO] Cloning OWASP BenchmarkPython suite to ${OWASP_DIR}..."
    git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython.git "${OWASP_DIR}"
fi

OUTPUT_JSON="${REPO_ROOT}/benchmark_scorecard.json"
OUTPUT_MD="${REPO_ROOT}/benchmark_report.md"

echo "=============================================================="
echo " Starting Frensense Independent Benchmark Evaluation"
echo " Binary:  ${BINARY}"
echo " Suite:   OWASP Benchmark for Python (1,230 ground-truth cases)"
echo " Output:  ${OUTPUT_MD}"
echo "=============================================================="

python3 "${SCRIPT_DIR}/owasp_benchmark.py" \
    --bin "${BINARY}" \
    --owasp-csv "${OWASP_DIR}/expectedresults-0.1.csv" \
    --owasp-testcode "${OWASP_DIR}/testcode" \
    --json-out "${OUTPUT_JSON}" \
    --md-out "${OUTPUT_MD}" \
    "$@"

echo ""
echo "=============================================================="
echo " Benchmark run complete."
echo " Machine-readable scorecard: ${OUTPUT_JSON}"
echo " Markdown summary report:    ${OUTPUT_MD}"
echo "=============================================================="
