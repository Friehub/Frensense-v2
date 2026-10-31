#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""OWASP Juice Shop gate for Frensense.

Methodology (docs/JUICESHOP_BASELINE.md):

- Ground truth: Juice Shop's own ``// vuln-code-snippet vuln-line
  <challengeName>`` markers - machine-readable, line-exact, shipped by
  the upstream project. No hand-maintained labels.
- Scan target: ``routes/``, ``lib/``, ``models/`` passed to one scan so
  the cross-file callgraph links them as one program.
- Scoring: challenge-granular. A challenge is caught when >=1 finding
  lands on (or within +/-1 line of) one of its vuln-lines. Findings on
  lines no challenge claims are false positives.

Usage:
  git clone --depth 1 https://github.com/juice-shop/juice-shop /tmp/juice-shop
  cargo build --release
  python3 scripts/benchmark_juice_shop.py --root /tmp/juice-shop
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_BIN = Path(__file__).resolve().parent.parent.parent / "target" / "release" / "frensense"
DEFAULT_ROOT = Path("/tmp/juice-shop")
SCAN_DIRS = ("routes", "lib", "models")
# The directive plus the challenge-name token(s) that follow it. Names are
# camelCase starting lowercase; the regex stops at any non-name token so
# lines that merely mention the directive (lib/codingChallenges.ts) yield
# nothing.
MARKER_RE = re.compile(
    r"vuln-code-snippet\s+vuln-line\s+((?:[a-z][A-Za-z0-9]*\s*)+)"
)
TOLERANCE = 1


def collect_markers(root: Path, dirs: tuple[str, ...]) -> dict[str, list[tuple[str, int]]]:
    """challenge -> [(relative file path, line number), ...]"""
    markers: dict[str, list[tuple[str, int]]] = {}
    for d in dirs:
        for f in sorted((root / d).rglob("*.ts")):
            for lineno, line in enumerate(f.read_text().splitlines(), 1):
                if "vuln-code-snippet vuln-line" not in line:
                    continue
                m = MARKER_RE.search(line)
                if not m:
                    continue
                rel = str(f.relative_to(root))
                for name in m.group(1).split():
                    markers.setdefault(name, []).append((rel, lineno))
    return markers


def scan(binary: Path, root: Path, dirs: tuple[str, ...]) -> tuple[list[dict], float]:
    cmd = [str(binary), *(str(root / d) for d in dirs), "--json"]
    t0 = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, cwd=root)
    elapsed = time.time() - t0
    if proc.returncode not in (0, 1):  # 1 = findings under --strict; tolerate anyway
        raise SystemExit(f"scan failed ({proc.returncode}): {proc.stderr[-2000:]}")
    data = json.loads(proc.stdout) if proc.stdout.strip() else {}
    advisories = data if isinstance(data, list) else data.get("advisories", [])
    return advisories, elapsed


def score(advisories: list[dict], markers: dict[str, list[tuple[str, int]]],
          root: Path) -> dict:
    def rel(p: str) -> str:
        try:
            return str(Path(p).resolve().relative_to(root))
        except ValueError:
            return p

    # claimed[(file, line)] = set of challenges that claim that line
    claimed: dict[tuple[str, int], set[str]] = {}
    for name, locs in markers.items():
        for f, ln in locs:
            claimed.setdefault((f, ln), set()).add(name)

    caught: dict[str, bool] = {name: False for name in markers}
    fps: list[dict] = []
    for a in advisories:
        f, ln = rel(a["file_path"]), a["line"]
        hit = any(
            cf == f and abs(cl - ln) <= TOLERANCE
            for (cf, cl) in claimed
        )
        if hit:
            for name, locs in markers.items():
                if any(cf == f and abs(cl - ln) <= TOLERANCE for cf, cl in locs):
                    caught[name] = True
        else:
            fps.append({"file": f, "line": ln,
                        "rule": a.get("rule") or ",".join(a.get("tags", [])),
                        "severity": a.get("severity")})

    tp = sum(caught.values())
    fn = len(caught) - tp
    return {"total_challenges": len(caught), "tp": tp, "fn": fn, "fp": len(fps),
            "caught": sorted(n for n, c in caught.items() if c),
            "missed": sorted(n for n, c in caught.items() if not c),
            "false_positives": fps, "findings": len(advisories)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Score Frensense on OWASP Juice Shop.")
    ap.add_argument("--bin", default=str(DEFAULT_BIN))
    ap.add_argument("--root", default=str(DEFAULT_ROOT))
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    binary, root = Path(args.bin), Path(args.root)
    if not binary.exists():
        sys.exit(f"[ERROR] frensense binary not found at {binary} (cargo build --release)")
    if not root.is_dir():
        sys.exit(f"[ERROR] juice-shop checkout not found at {root}")

    markers = collect_markers(root, SCAN_DIRS)
    if not markers:
        sys.exit("[ERROR] no vuln-line markers found - wrong checkout?")
    print(f"[INFO] {len(markers)} challenges with vuln-lines in "
          f"{'/'.join(SCAN_DIRS)}")

    advisories, elapsed = scan(binary, root, SCAN_DIRS)
    s = score(advisories, markers, root)
    s["scan_seconds"] = round(elapsed, 1)

    recall = s["tp"] / s["total_challenges"]
    precision = s["tp"] / (s["tp"] + s["fp"]) if s["tp"] + s["fp"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    print(f"\n{'=' * 62}")
    print(f"FRENSENSE on OWASP Juice Shop  ({s['findings']} findings, "
          f"{elapsed:.1f}s)")
    print(f"{'=' * 62}")
    print(f"caught {s['tp']}/{s['total_challenges']} challenges "
          f"(recall {recall*100:.0f}%)   FP {s['fp']}   "
          f"precision {precision*100:.1f}%   F1 {f1:.2f}")
    if s["missed"]:
        print(f"missed: {', '.join(s['missed'])}")
    print("\nFalse positives:")
    for fp in s["false_positives"]:
        print(f"  {fp['file']}:{fp['line']}  [{fp['severity']}] {fp['rule']}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(s, indent=1))
        print(f"\n[INFO] full scorecard -> {args.json_out}")


if __name__ == "__main__":
    main()
