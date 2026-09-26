#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""OWASP BenchmarkPython runner for Frensense.

Scores the engine against the OWASP Benchmark for Python (v0.1): 1,230
test cases authored by the OWASP project with an authoritative
expected-results CSV. Third-party ground truth, zero overlap with any
Frensense knowledge bundle. This is the engine's independent,
competitor-comparable number.

Scoring follows the OWASP Benchmark accuracy metric:

  vulnerable case + finding  -> TP     safe case + no finding  -> TN
  vulnerable case + no find  -> FN     safe case + finding     -> FP

  score = TPR - FPR

Usage:

  # 1. get the benchmark (one-time)
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython /tmp/BenchmarkPython

  # 2. build the engine (one-time)
  cargo build --release

  # 3. run
  python3 scripts/owasp_benchmark.py \
    --owasp-csv /tmp/BenchmarkPython/expectedresults-0.1.csv \
    --owasp-testcode /tmp/BenchmarkPython/testcode \
    --json-out owasp_scorecard.json

Results are printed as a summary table and, with --json-out, written as
a machine-readable scorecard with per-CWE breakdowns and per-case
verdicts.
"""

import argparse
import concurrent.futures
import csv
import json
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

DEFAULT_BIN = Path(__file__).resolve().parent.parent / "target" / "release" / "frensense"


def load_cases(csv_path: Path, testcode: Path) -> list[dict]:
    """Load ground truth: expectedresults CSV (name, category,
    real_vulnerability, cwe) plus the testcode directory of .py cases."""
    cases = []
    with open(csv_path) as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            name = row[0]
            vul = row[2].strip().lower() == "true"
            cwe = row[3]
            f = testcode / f"{name}.py"
            if f.exists():
                cases.append({"file": f, "vul": vul, "cwe": f"CWE-{cwe}"})
    return cases


def scan_case(binary: Path, case: dict, bundle: Path | None = None) -> dict:
    """Scan one case file in isolation (own process: no cross-case state)."""
    try:
        cmd = [str(binary), str(case["file"])]
        if bundle is not None:
            cmd += ["--corpus-bundle", str(bundle)]
        cmd += ["--json"]
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120,
        )
        data = json.loads(proc.stdout) if proc.stdout.strip() else {"advisories": []}
        advisories = data if isinstance(data, list) else data.get("advisories", [])
        return {"id": case["file"].stem, "findings": len(advisories)}
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return {"id": case["file"].stem, "findings": 0, "error": str(e)}


def score(results: list[dict], cases: dict[str, dict]) -> dict:
    per_case = []
    for r in results:
        meta = cases[r["id"]]
        has_finding = r["findings"] > 0
        if meta["vul"] and has_finding:
            cls = "TP"
        elif meta["vul"]:
            cls = "FN"
        elif has_finding:
            cls = "FP"
        else:
            cls = "TN"
        per_case.append({
            "id": r["id"],
            "cwe": meta["cwe"],
            "lang": "py",
            "expected": "vulnerable" if meta["vul"] else "safe",
            "findings": r["findings"],
            "class": cls,
            **({"error": r["error"]} if "error" in r else {}),
        })

    by_cwe = defaultdict(lambda: defaultdict(int))
    total = defaultdict(lambda: defaultdict(int))
    for c in per_case:
        for bucket, key in ((by_cwe, c["cwe"]), (total, "all")):
            bucket[key][c["class"]] += 1

    def rates(d):
        out = {}
        for k, v in d.items():
            tp, fp = v.get("TP", 0), v.get("FP", 0)
            fn, tn = v.get("FN", 0), v.get("TN", 0)
            tpr = tp / (tp + fn) if tp + fn else 0.0
            fpr = fp / (fp + tn) if fp + tn else 0.0
            out[k] = {
                **{c: v.get(c, 0) for c in ("TP", "FP", "FN", "TN")},
                "tpr": round(tpr, 3),
                "fpr": round(fpr, 3),
                "score": round(tpr - fpr, 3),
            }
        return out

    return {
        "total": rates(total)["all"],
        "by_cwe": dict(sorted(rates(by_cwe).items())),
        "cases": per_case,
    }


def print_scorecard(s: dict, elapsed: float) -> None:
    t = s["total"]
    n = t["TP"] + t["FP"] + t["FN"] + t["TN"]
    print(f"\n{'=' * 62}")
    print(f"FRENSENSE on OWASP BenchmarkPython  ({n} cases, {elapsed:.0f}s)")
    print(f"{'=' * 62}")
    print(f"TPR {t['tpr']*100:5.1f}%   FPR {t['fpr']*100:5.1f}%   SCORE (TPR-FPR) {t['score']*100:5.1f}%")
    print(f"   TP {t['TP']:4d}   FP {t['FP']:4d}   FN {t['FN']:4d}   TN {t['TN']:4d}")
    rows = [(cwe, v) for cwe, v in s["by_cwe"].items() if v["TP"] + v["FN"] >= 5]
    rows.sort(key=lambda kv: kv[1]["score"])
    print(f"\nPer CWE (lowest score first, min 5 vulnerable cases):")
    print(f"{'CWE':<12}{'TPR':>7}{'FPR':>7}{'score':>8}{'cases':>7}")
    for cwe, v in rows[:15]:
        n_cwe = v["TP"] + v["FP"] + v["FN"] + v["TN"]
        print(f"{cwe:<12}{v['tpr']*100:6.1f}%{v['fpr']*100:6.1f}%{v['score']*100:7.1f}%{n_cwe:7d}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Score Frensense against the OWASP Benchmark for Python.")
    ap.add_argument("--bin", default=str(DEFAULT_BIN), help="frensense binary")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json-out", default=None, help="write machine-readable scorecard here")
    ap.add_argument("--owasp-csv", required=True,
                    help="OWASP BenchmarkPython expectedresults CSV")
    ap.add_argument("--owasp-testcode", default=None,
                    help="testcode dir with the .py cases (default: CSV dir / testcode)")
    ap.add_argument("--bundle", default=None,
                    help=".frc corpus bundle passed to every scan via --corpus-bundle")
    args = ap.parse_args()

    binary = Path(args.bin)
    bundle = Path(args.bundle) if args.bundle else None
    if not binary.exists():
        print(f"[ERROR] frensense binary not found at {binary}", file=sys.stderr)
        print("        build it with: cargo build --release", file=sys.stderr)
        sys.exit(1)
    if bundle is not None and not bundle.exists():
        print(f"[ERROR] bundle not found at {bundle}", file=sys.stderr)
        sys.exit(1)

    csv_path = Path(args.owasp_csv)
    testcode = Path(args.owasp_testcode or csv_path.parent / "testcode")
    cases_list = load_cases(csv_path, testcode)
    if not cases_list:
        print("[ERROR] no OWASP cases resolved: check --owasp-csv/--owasp-testcode",
              file=sys.stderr)
        sys.exit(1)
    cases = {c["file"].stem: c for c in cases_list}

    print(f"[INFO] {len(cases_list)} OWASP ground-truth cases, "
          f"scanning with {args.workers} workers...")
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda c: scan_case(binary, c, bundle), cases_list))
    elapsed = time.time() - t0

    errors = sum(1 for r in results if "error" in r)
    if errors:
        print(f"[WARN] {errors} scan errors", file=sys.stderr)

    scorecard = score(results, cases)
    print_scorecard(scorecard, elapsed)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(scorecard, indent=1))
        print(f"\n[INFO] full scorecard -> {args.json_out}")


if __name__ == "__main__":
    main()
