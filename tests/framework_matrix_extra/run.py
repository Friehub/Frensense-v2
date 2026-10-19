#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Runner for the extra framework fixtures in this directory.

Each fixture file has an expectation in manifest.json:

    FIRE    the engine must report at least one finding
    SILENT  the engine must report none

Every case that fails today is listed in known_gaps.json with the layer that
owns the fix (ENGINE, KNOWLEDGE, LANG, or DECISION for policy questions). The
runner exits 4 when a case fails that is not listed (a regression) and, with
--strict, when a listed gap now passes (remove it from the list).

    python3 tests/framework_matrix_extra/run.py --bin target/release/frensense
    python3 tests/framework_matrix_extra/run.py --bin new --compare-bin old

Each case records the wall time of its scan, so `--compare-bin` reports both
verdicts and timings for the two binaries on the same fixtures. Timings are
end-to-end CLI scans (startup, pack seeding, lowering, analysis, report), one
scan per case; they are a latency comparison, not a throughput benchmark.

These cases complement scripts/framework_matrix.py: they cover joins, guards,
misuse checks (non-flow), browser sinks and tool-specific argv handling.
"""

import argparse
import json
import statistics
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent


def count(binary, path):
    try:
        p = subprocess.run([str(binary), str(path), "--json"], capture_output=True, text=True, timeout=60)
        return json.loads(p.stdout)["advisory_count"]
    except Exception:  # noqa: BLE001
        return None


def timed_count(binary, path):
    """Return (verdict count, end-to-end wall milliseconds)."""
    start = time.perf_counter()
    n = count(binary, path)
    return n, (time.perf_counter() - start) * 1000.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--compare-bin", help="older binary; cases that passed there and fail now are reported as REGRESSED")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument(
        "--suite-runs",
        type=int,
        default=3,
        help="time a directory as one scan, N times per binary (0 disables)",
    )
    ap.add_argument(
        "--suite-path",
        type=Path,
        default=HERE,
        help="directory for the suite timing (default: the fixture directory); both binaries must see the same files",
    )
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    cases = json.loads((HERE / "manifest.json").read_text())["cases"]
    gaps = json.loads((HERE / "known_gaps.json").read_text())["gaps"]

    def ok(expect, n):
        return n is not None and (n > 0) == (expect == "FIRE")

    def run(c):
        p = HERE / c["file"]
        n, ms = timed_count(args.bin, p)
        o, old_ms = timed_count(args.compare_bin, p) if args.compare_bin else (None, None)
        return {
            **c,
            "count": n,
            "pass": ok(c["expect"], n),
            "ms": round(ms, 1),
            "old_pass": ok(c["expect"], o) if args.compare_bin else None,
            "old_ms": round(old_ms, 1) if old_ms is not None else None,
        }

    with ThreadPoolExecutor(args.workers) as ex:
        res = list(ex.map(run, cases))

    errors = [r for r in res if r["count"] is None]
    regress = [r for r in res if not r["pass"] and r["id"] not in gaps and r["count"] is not None]
    stale = [r for r in res if r["pass"] and r["id"] in gaps]
    regressed_vs_old = [r for r in res if r["old_pass"] and not r["pass"]]
    layer = Counter(gaps[r["id"]]["layer"] for r in res if not r["pass"] and r["id"] in gaps)

    print(f"extra framework matrix: {sum(r['pass'] for r in res)}/{len(res)} pass; open gaps by layer: {dict(layer)}")
    timings = [r["ms"] for r in res if r["count"] is not None]
    if timings:
        ordered = sorted(timings)
        p95 = ordered[max(0, int(round(0.95 * (len(ordered) - 1))))]
        print(
            f"perf new: {len(timings)} cases total={sum(timings) / 1000:.2f}s "
            f"median={statistics.median(timings):.1f}ms p95={p95:.1f}ms max={max(timings):.1f}ms"
        )
    if args.suite_runs > 0:
        # One scan over the whole fixture directory: no per-process startup
        # in the ratio, so this is the corpus-level comparison.
        new_suite = [timed_count(args.bin, args.suite_path)[1] for _ in range(args.suite_runs)]
        line = f"perf suite ({args.suite_path}: 1 scan): new median={statistics.median(new_suite):.0f}ms"
        if args.compare_bin:
            old_suite = [
                timed_count(args.compare_bin, args.suite_path)[1]
                for _ in range(args.suite_runs)
            ]
            delta = statistics.median(new_suite) - statistics.median(old_suite)
            line += (
                f" old median={statistics.median(old_suite):.0f}ms"
                f" delta={delta:+.0f}ms ({delta / statistics.median(old_suite) * 100:+.1f}%)"
            )
        print(line)
    if args.compare_bin:
        pairs = [(r["old_ms"], r["ms"]) for r in res if r["ms"] is not None and r["old_ms"] is not None]
        if pairs:
            old_ms = [p[0] for p in pairs]
            new_ms = [p[1] for p in pairs]
            delta = statistics.median(new_ms) - statistics.median(old_ms)
            faster = sum(1 for o, n in pairs if n < o)
            print(
                f"perf old: {len(pairs)} cases total={sum(old_ms) / 1000:.2f}s "
                f"median={statistics.median(old_ms):.1f}ms"
            )
            print(
                f"perf new vs old: median delta={delta:+.1f}ms "
                f"({delta / statistics.median(old_ms) * 100:+.1f}%), faster in {faster}/{len(pairs)} cases"
            )
    for r in regress:
        print(f"REGRESSION  {r['id']}: expected {r['expect']}, got {r['count']} findings")
    for r in regressed_vs_old:
        print(f"REGRESSED   {r['id']}: passed on --compare-bin, fails now")
    for r in stale:
        print(f"STALE GAP   {r['id']}: now passes; remove it from known_gaps.json")
    for r in errors:
        print(f"ERROR       {r['id']}: scan failed")
    if args.json_out:
        args.json_out.write_text(json.dumps(res, indent=2) + "\n")
    if errors:
        return 3
    if regress or regressed_vs_old or (args.strict and stale):
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
