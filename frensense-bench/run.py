#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

"""
Unified Frensense Capability Benchmark Harness (`frensense-bench`).

Runs reproducible benchmarks and evaluation suites:
  --suite cve          Curated paired real-world CVEs (Zero False-Positive contract)
  --suite owasp        OWASP Benchmark for Python (1,230 standardized cases)
  --suite blindness    Engine Blindness & Capability Benchmark (unknown sinks, bounds, RSS)
  --suite real-repos   Scans pinned OSS projects (Django, Next.js, Redis, etc.)
  --suite correctness  Static correctness assertions on positive/negative samples
  --suite scale        Synthetic file scaling benchmark
  --suite juice-shop   OWASP Juice Shop challenge-line benchmark
  --suite mutation     OWASP mutation ladder triage
  --suite rules        Rule card variants check
  --suite all          Runs standard core benchmarks (CVE + OWASP)

Usage:
  python3 frensense-bench/run.py --suite cve
  python3 frensense-bench/run.py --suite owasp --workers 8
  python3 frensense-bench/run.py --suite blindness --prepare --run
  python3 frensense-bench/run.py --suite real-repos --prepare
  python3 frensense-bench/run.py --suite real-repos --run
  python3 frensense-bench/run.py --suite all
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUITES_DIR = ROOT / "frensense-bench" / "suites"


def find_or_build_binary() -> Path:
    candidates = [
        ROOT / "target" / "release" / "frensense",
        ROOT / "target" / "debug" / "frensense",
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    print("[INFO] Building frensense release binary with Cargo...")
    subprocess.run(["cargo", "build", "--release", "--bin", "frensense"], cwd=ROOT, check=True)
    return ROOT / "target" / "release" / "frensense"


def run_cve(extra_args=None) -> bool:
    print("=" * 64)
    print(" Running Frensense Curated CVE Verification Suite")
    print("=" * 64)
    cve_script = SUITES_DIR / "cve.py"
    cmd = [sys.executable, str(cve_script)] + (extra_args or [])
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def run_owasp(workers=8, publish_gist=False, extra_args=None) -> bool:
    print("=" * 64)
    print(" Running Frensense OWASP Benchmark Suite (1,230 cases)")
    print("=" * 64)
    owasp_dir = Path("/tmp/BenchmarkPython")
    if not (owasp_dir / "expectedresults-0.1.csv").exists():
        print(f"[INFO] Cloning OWASP BenchmarkPython suite to {owasp_dir}...")
        subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/OWASP-Benchmark/BenchmarkPython.git", str(owasp_dir)],
            check=True,
        )

    binary = find_or_build_binary()
    output_json = ROOT / "benchmark_scorecard.json"
    output_md = ROOT / "benchmark_report.md"

    owasp_script = SUITES_DIR / "owasp.py"
    cmd = [
        sys.executable,
        str(owasp_script),
        "--bin", str(binary),
        "--owasp-csv", str(owasp_dir / "expectedresults-0.1.csv"),
        "--owasp-testcode", str(owasp_dir / "testcode"),
        "--workers", str(workers),
        "--json-out", str(output_json),
        "--md-out", str(output_md),
    ]
    if publish_gist:
        cmd.append("--publish-gist")
    if extra_args:
        cmd.extend(extra_args)

    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def run_real_repos(extra_args=None) -> bool:
    print("=" * 64)
    print(" Running Real Repositories Benchmark")
    print("=" * 64)
    script = SUITES_DIR / "real_repos.py"
    cmd = [sys.executable, str(script)] + (extra_args or [])
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def run_correctness(extra_args=None) -> bool:
    print("=" * 64)
    print(" Running Correctness Benchmark")
    print("=" * 64)
    script = SUITES_DIR / "correctness.py"
    cmd = [sys.executable, str(script)] + (extra_args or [])
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def run_juice_shop(extra_args=None) -> bool:
    print("=" * 64)
    print(" Running OWASP Juice Shop Benchmark")
    print("=" * 64)
    script = SUITES_DIR / "juice_shop.py"
    cmd = [sys.executable, str(script)] + (extra_args or [])
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def run_scale(extra_args=None) -> bool:
    print("=" * 64)
    print(" Running Scale Benchmark")
    print("=" * 64)
    script = SUITES_DIR / "scale.py"
    cmd = [sys.executable, str(script)] + (extra_args or [])
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def run_mutation(extra_args=None) -> bool:
    print("=" * 64)
    print(" Running Mutation Ladder")
    print("=" * 64)
    script = SUITES_DIR / "mutation_ladder.py"
    cmd = [sys.executable, str(script)] + (extra_args or [])
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def run_rules(extra_args=None) -> bool:
    print("=" * 64)
    print(" Running Rules Suite")
    print("=" * 64)
    script = SUITES_DIR / "rules.py"
    cmd = [sys.executable, str(script)] + (extra_args or [])
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def run_blindness(extra_args=None) -> bool:
    print("=" * 64)
    print(" Running Engine Blindness & Capability Benchmark")
    print("=" * 64)
    script = SUITES_DIR / "blindness.py"
    cmd = [sys.executable, str(script)] + (extra_args or [])
    res = subprocess.run(cmd, cwd=ROOT)
    return res.returncode == 0


def main():
    parser = argparse.ArgumentParser(
        description="Frensense Unified Benchmark Runner (frensense-bench)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--suite",
        choices=["owasp", "cve", "real-repos", "blindness", "correctness", "juice-shop", "scale", "mutation", "rules", "all"],
        default="all",
        help="Benchmark suite to execute (default: all [cve + owasp])",
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

    args, extra = parser.parse_known_args()

    success = True
    if args.suite in ("cve", "all"):
        if not run_cve(extra):
            success = False

    if args.suite in ("owasp", "all"):
        if not run_owasp(workers=args.workers, publish_gist=args.publish_gist, extra_args=extra):
            success = False

    if args.suite == "real-repos":
        if not run_real_repos(extra):
            success = False

    if args.suite == "blindness":
        if not run_blindness(extra):
            success = False

    if args.suite == "correctness":
        if not run_correctness(extra):
            success = False

    if args.suite == "juice-shop":
        if not run_juice_shop(extra):
            success = False

    if args.suite == "scale":
        if not run_scale(extra):
            success = False

    if args.suite == "mutation":
        if not run_mutation(extra):
            success = False

    if args.suite == "rules":
        if not run_rules(extra):
            success = False

    if not success:
        print("\n[ERROR] Benchmark run completed with one or more failures.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[SUCCESS] Benchmark suite(s) completed successfully.")


if __name__ == "__main__":
    main()
