#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""OWASP BenchmarkPython runner for Frensense.

Scores the engine against the OWASP Benchmark for Python (v0.1): 1,230
test cases authored by the OWASP project with an authoritative
expected-results CSV. Third-party ground truth, zero overlap with any
Frensense knowledge bundle. Use it as a diagnostic: the per-CWE misses
are the engine's work queue.

Scoring follows the OWASP Benchmark accuracy metric:

  vulnerable case + finding  -> TP     safe case + no finding  -> TN
  vulnerable case + no find  -> FN     safe case + finding     -> FP

  score = TPR - FPR

What counts as "a finding" is set by --match:

  conservative (default)  A vulnerable case is a TP only if a finding is
                          attributed to the case's CWE. A safe case is a FP
                          if a finding is attributed to its CWE OR a finding
                          could not be attributed to any CWE. Gives a lower
                          bound on TPR and an upper bound on FPR.
  cwe                     Strict: findings with no resolvable CWE are
                          ignored on both sides.
  any                     Legacy: any finding in the file counts, whatever
                          its class. Overstates TPR; shown as an upper bound.

A finding's CWE comes from a "CWE-n" tag (built-in and bundle-backed
findings carry one since 0.7.1-beta) or from --tag-cwe-map / the small
built-in map for legacy binaries whose findings predate engine tagging.

A scan that crashes, times out, exits with a code other than 0 or 1, or
prints invalid JSON is class ERR: reported separately, excluded from the
rates, and fails the run (exit 3) unless --allow-errors is given.

Exit codes: 0 ok, 1 setup error, 3 scan errors, 4 regression vs
--baseline (only with --fail-on-regression).

Usage:

  # 1. get the benchmark (one-time)
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython /tmp/BenchmarkPython

  # 2. build the engine (one-time)
  cargo build --release

  # 3. run
  python3 scripts/owasp_benchmark.py \\
    --owasp-csv /tmp/BenchmarkPython/expectedresults-0.1.csv \\
    --owasp-testcode /tmp/BenchmarkPython/testcode \\
    --json-out owasp_scorecard.json

  # 4. track progress: compare against a committed baseline in CI
  python3 scripts/owasp_benchmark.py --baseline owasp_baseline.json --fail-on-regression

Results are printed as a summary table and, with --json-out, written as
a machine-readable scorecard with per-CWE breakdowns and per-case
verdicts.
"""

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_BIN = Path(__file__).resolve().parent.parent / "target" / "release" / "frensense"

# Tags whose CWE is unambiguous. Sink-role tags such as "execution" or
# "resource" span several CWEs and are deliberately absent; extend with
# --tag-cwe-map (JSON object: {"tag": "CWE-n"}).
DEFAULT_TAG_CWE = {
    "weak_hash": "CWE-328",
    "xss": "CWE-79",
}

# Tags present on every advisory of a kind; no information for attribution.
GENERIC_TAGS = {"checker", "taint", "policy"}

CWE_RE = re.compile(r"^CWE-0*(\d+)$", re.IGNORECASE)

CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-94": "Code Injection",
    "CWE-328": "Weak Cryptographic Hash",
    "CWE-330": "Insufficient Randomness",
    "CWE-501": "Trust Boundary Violation",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-614": "Sensitive Cookie Insecure Transport",
    "CWE-643": "XPath Injection",
}

# --- WI-74: per-rule scoring + merge gate ---------------------------------

# Baseline merged-fact format: {"rule_id": {"TP": n, "FP": n, "FN": n, "TN": n}}
BASELINE_FACTS_RE = re.compile(r"^BLF:\s*(.+)$")


def load_baseline_facts(path: str | Path) -> dict[str, dict[str, int]]:
    """Load the committed per-rule baseline from a BLF file."""
    facts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = BASELINE_FACTS_RE.match(line)
            if not m:
                raise ValueError(f"bad baseline line: {line!r}")
            parts = m.group(1).split(":", 1)
            if len(parts) != 2:
                raise ValueError(f"baseline line has no count separator: {line!r}")
            rule, tag = parts
            facts[rule.strip()][tag.strip()] = int(count.strip())
    return facts


def count_per_rule_tag(cases: dict[str, dict], results: list[dict]) -> dict[str, dict[str, int]]:
    """WI-74: per-rule scorer.

    The engine findings carry tags (OWASP categories such as `traversal`,
    `xss`, `weak_hash`, `cookie_secure_missing`, and the CWE tags). For
    every distinct tag a case file contains, classify the case with the
    OWASP accuracy metric and accumulate TP/FP/FN/TN.

    Returns {tag: {"TP": n, "FP": n, "FN": n, "TN": n}}.
    """
    tally: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in results:
        meta = cases[r["id"]]
        for tags in r.get("tag_sets", []):
            for t in tags:
                if t in GENERIC_TAGS:
                    continue
                vul = meta["vul"]
                cwe = meta["cwe"]
                attributed_hit = any(cwe in s for s in tags)
                if attributed_hit:
                    cls = "TP" if vul else "FP"
                else:
                    cls = "FN" if vul else "TN"
                tally[t][cls] += 1
    return dict(tally)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Score Frensense against the OWASP Benchmark for Python.")
    ap.add_argument("--bin", default=None, help="frensense binary path (auto-detected if omitted)")
    ap.add_argument("--workers", type=int, default=8, help="concurrent scan threads (default: 8)")
    ap.add_argument("--json-out", default=None, help="write machine-readable scorecard JSON here")
    ap.add_argument("--md-out", default=None, help="write markdown summary report here")
    ap.add_argument("--publish-gist", action="store_true", help="upload report to a public GitHub Gist via GITHUB_TOKEN")
    ap.add_argument("--owasp-csv", default=None,
                    help="OWASP BenchmarkPython expectedresults CSV (auto-detected if omitted)")
    ap.add_argument("--owasp-testcode", default=None,
                    help="testcode dir with the .py cases (default: CSV dir / testcode)")
    ap.add_argument("--bundle", default=None,
                    help=".frc corpus bundle passed to every scan via --corpus-bundle")
    ap.add_argument("--match", choices=("conservative", "cwe", "any"), default="conservative",
                    help="how findings are matched to a case's CWE (default: conservative)")
    ap.add_argument("--tag-cwe-map", default=None,
                    help="JSON object mapping advisory tags to CWE ids, e.g. {\"crypto\": \"CWE-328\"}")
    ap.add_argument("--baseline", default=None,
                    help="previous scorecard JSON (from --json-out) to diff against")
    ap.add_argument("--fail-on-regression", action="store_true",
                    help="exit 4 if FPR rises or any per-rule/per-CWE TPR drops vs --baseline")
    ap.add_argument("--tpr-tolerance", type=float, default=0.0,
                    help="allowed per-rule/per-CWE TPR drop before it counts as a regression (0.01 = 1 pp)")
    ap.add_argument("--fpr-tolerance", type=float, default=0.0,
                    help="allowed overall FPR rise before it counts as a regression")
    ap.add_argument("--allow-errors", action="store_true",
                    help="do not fail the run when some scans errored")
    args = ap.parse_args()

    binary = resolve_binary(args.bin)
    if not binary or not binary.exists():
        print("[ERROR] frensense binary not found.", file=sys.stderr)
        print("        Build it with: cargo build --release", file=sys.stderr)
        print("        Or specify with: --bin /path/to/frensense", file=sys.stderr)
        sys.exit(1)

    bundle = Path(args.bundle) if args.bundle else None
    if bundle is not None and not bundle.exists():
        print(f"[ERROR] bundle not found at {bundle}", file=sys.stderr)
        sys.exit(1)

    try:
        tag_cwe = load_tag_cwe_map(args.tag_cwe_map)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"[ERROR] cannot load --tag-cwe-map: {e}", file=sys.stderr)
        sys.exit(1)

    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"[ERROR] cannot read --baseline: {e}", file=sys.stderr)
            sys.exit(1)
        base_mode = baseline.get("meta", {}).get("match", "any")  # pre-patch scorecards were any-finding
        if base_mode != args.match:
            print(f"[ERROR] baseline was scored with --match {base_mode}, this run uses "
                  f"--match {args.match}; regenerate the baseline with the same mode.", file=sys.stderr)
            sys.exit(1)

    # Auto-resolve OWASP CSV
    csv_candidates = [
        Path(args.owasp_csv) if args.owasp_csv else None,
        Path("/tmp/BenchmarkPython/expectedresults-0.1.csv"),
        Path.home() / ".cache" / "BenchmarkPython" / "expectedresults-0.1.csv",
    ]
    csv_path = next((c for c in csv_candidates if c and c.exists()), None)
    if not csv_path:
        print("[INFO] OWASP BenchmarkPython not found locally. Auto-cloning to /tmp/BenchmarkPython...", file=sys.stderr)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "https://github.com/OWASP-Benchmark/BenchmarkPython.git", "/tmp/BenchmarkPython"],
                check=True,
            )
            csv_path = Path("/tmp/BenchmarkPython/expectedresults-0.1.csv")
        except Exception as e:
            print(f"[ERROR] Failed to auto-clone BenchmarkPython: {e}", file=sys.stderr)
            print("        Please clone manually: git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython.git /tmp/BenchmarkPython", file=sys.stderr)
            sys.exit(1)

    testcode = Path(args.owasp_testcode or csv_path.parent / "testcode")
    cases_list = load_cases(csv_path, testcode)
    if not cases_list:
        print(f"[ERROR] no OWASP cases resolved from {csv_path}", file=sys.stderr)
        sys.exit(1)
    cases = {c["file"].stem: c for c in cases_list}

    bundle_desc, scan_env = describe_bundle(bundle, testcode)

    # Query binary version and commit
    try:
        ver_proc = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=True)
        binary_version = ver_proc.stdout.strip()
    except Exception:
        binary_version = "frensense 0.7.0"

    try:
        commit_proc = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True)
        repo_commit = commit_proc.stdout.strip()
    except Exception:
        repo_commit = "unknown"

    print(f"[INFO] Using binary: {binary} ({binary_version})")
    print(f"[INFO] {len(cases_list)} OWASP ground-truth cases from {csv_path}")
    print(f"[INFO] Scanning with {args.workers} workers...")
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda c: scan_case(binary, c, bundle, scan_env), cases_list))
    elapsed = time.time() - t0

    errors = [r for r in results if "error" in r]
    if errors:
        print(f"[WARN] {len(errors)} scan errors (excluded from rates); first: "
              f"{errors[0]['id']}: {errors[0]['error']}", file=sys.stderr)

    scorecard = score(results, cases, args.match, tag_cwe)
    diff = compare_to_baseline(scorecard, baseline, args.tpr_tolerance, args.fpr_tolerance) if baseline else None
    print_scorecard(scorecard, elapsed, diff)

    scorecard_json_str = json.dumps(scorecard, indent=1)
    if args.json_out:
        Path(args.json_out).write_text(scorecard_json_str)
        print(f"\n[INFO] full scorecard JSON -> {args.json_out}")

    ctx = {"bundle": bundle_desc, "workers": args.workers}
    md_report = generate_markdown_report(scorecard, elapsed, binary_version, repo_commit, ctx, diff)
    if args.md_out:
        Path(args.md_out).write_text(md_report)
        print(f"[INFO] markdown report -> {args.md_out}")

    if args.publish_gist:
        print("\n[INFO] Publishing benchmark reproduction to GitHub Gist...")
        files = {
            "benchmark_report.md": md_report,
            "benchmark_scorecard.json": scorecard_json_str,
        }
        gist_url = publish_github_gist("Frensense 0.7.0 Benchmark Reproduction Scorecard", files, public=True)
        if gist_url:
            print(f"[SUCCESS] Benchmark Gist published: {gist_url}")
            step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
            if step_summary:
                try:
                    with open(step_summary, "a") as f:
                        f.write(f"\n\n### Published Benchmark Gist\n- [{gist_url}]({gist_url})\n")
                except Exception:
                    pass
        else:
            print("[INFO] You can manually paste 'benchmark_report.md' into https://gist.github.com")

    if errors and not args.allow_errors:
        print(f"[ERROR] {len(errors)} scans failed; scorecard is incomplete "
              "(rerun with --allow-errors to accept).", file=sys.stderr)
        sys.exit(3)
    if diff is not None and diff["regressions"] and args.fail_on_regression:
        sys.exit(4)
