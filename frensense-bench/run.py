#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

"""
Unified Frensense Capability Benchmark Harness.

Runs reproducible benchmarks against:
1. OWASP Benchmark for Python (1,230 standardized test cases)
2. Curated CVE Verification Benchmark (Real-world paired upstream CVEs)

Usage:
  python3 frensense-bench/run.py --suite owasp
  python3 frensense-bench/run.py --suite cve
  python3 frensense-bench/run.py --suite all
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_cve():
    print("=" * 64)
    print(" Running Frensense Curated CVE Verification Suite")
    print("=" * 64)
    cve_script = ROOT / "frensense-bench" / "cve_benchmark.py"
    res = subprocess.run([sys.executable, str(cve_script)], cwd=ROOT)
    return res.returncode == 0


def run_owasp(workers=8, publish_gist=False):
    print("=" * 64)
    print(" Running Frensense OWASP Benchmark Suite (1,230 cases)")
    print("=" * 64)
    owasp_script = ROOT / "scripts" / "reproduce_benchmark.sh"
    cmd = [str(owasp_script), "--workers", str(workers)]
    if publish_gist:
        cmd.append("--publish-gist")
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def main():
    parser = argparse.ArgumentParser(description="Frensense Unified Benchmark Runner")
    parser.add_argument(
        "--suite",
        choices=["owasp", "cve", "all"],
        default="all",
        help="Benchmark suite to execute (default: all)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Worker threads for parallel scan (default: 8)",
    )
    parser.add_argument(
        "--publish-gist",
        action="store_true",
        help="Upload results to a GitHub Gist if GITHUB_TOKEN is set",
    )
    args = parser.parse_args()

    success = True
    if args.suite in ("cve", "all"):
        if not run_cve():
            success = False

    if args.suite in ("owasp", "all"):
        if not run_owasp(workers=args.workers, publish_gist=args.publish_gist):
            success = False

    if not success:
        print("\n[ERROR] Benchmark run completed with one or more failures.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[SUCCESS] All benchmark suites completed successfully.")


if __name__ == "__main__":
    main()
