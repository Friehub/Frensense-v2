#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""Rule-card runner.

Wire-up for WI-75: assert that each `tests/rules/<rule-id>/` family
separates the way its rule card says it should.

Two outputs per variant:
  positive -> expected findings (rule id must fire)
  negative -> zero findings

Usage:

  scripts/rules/run.py cookie_secure_missing
  scripts/rules/run.py --list
"""

import argparse
import json
import sys
from pathlib import Path

RULE_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "rules"


def rule_variants(rule_id: str) -> list[dict]:
    """Read one rule card and return its variants as (role, filename)."""
    card = RULE_DIR / rule_id / "rule_card.md"
    if not card.exists():
        print(f"[error] rule card not found: {card}", file=sys.stderr)
        sys.exit(1)

    variants: list[dict] = []
    current: dict | None = None
    pending: list[str] = []

    for raw in card.read_text().splitlines():
        line = raw.split("#")[0].strip()
        if line.startswith("###"):
            if current is not None and current["file"]:
                variants.append(current)
            current = {"role": line.removeprefix("### ").strip(), "file": ""}
            pending = []
        elif current is not None and (line.startswith("#") or not line):
            continue
        elif current is not None and line.startswith("```"):
            if pending and not current["file"]:
                current["file"] = pending[0]
            pending = []
        elif current is not None and not current["file"] and raw.strip():
            pending.append(raw)
        elif current is not None and current["file"] and not line.startswith("#") and not line.startswith("###"):
            pass

    if current is not None and current["file"]:
        variants.append(current)
    return variants


def find_variant(rule_id: str, role: str) -> str | None:
    for v in rule_variants(rule_id):
        if v["role"] == role:
            return v["file"]
    return None


def scan_file(binary: Path, path: Path, bundle: str | None) -> int:
    cmd = [str(binary), str(path)]
    if bundle:
        cmd += ["--corpus-bundle", bundle]
    cmd += ["--json"]
    proc = __import__("subprocess").run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"exit {proc.returncode}: {proc.stderr[-200:]}")
    data = json.loads(proc.stdout) if proc.stdout.strip() else []
    advisories = data if isinstance(data, list) else data.get("advisories", [])
    return len(advisories) if isinstance(advisories, list) else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="rule card runner")
    ap.add_argument("rule_id", help="rule id, e.g. cookie_secure_missing")
    ap.add_argument("--bin", default=None, help="frensense binary path")
    ap.add_argument("--bundle", default=None, help="optional .frc bundle used in scans")
    args = ap.parse_args()

    binary = Path(args.bin or "frensense")
    failures: list[str] = []
    checked = 0

    for variant in rule_variants(args.rule_id):
        path = (RULE_DIR / args.rule_id / variant["file"]).resolve()
        if not path.exists():
            failures.append(f"{args.rule_id}: {variant['role']} missing file {path}")
            continue
        expected = 1 if variant["role"].startswith("positive") else 0
        got = scan_file(binary, path, args.bundle)
        checked += 1
        status = "ok" if got == expected else "MISMATCH"
        if got != expected:
            failures.append(
                f"{args.rule_id}: {variant['role']} -> {got} findings, "
                f"expected {expected}"
            )
        print(f"  [{status}] {args.rule_id} {variant['role']:<10} {got} findings (expected {expected})")

    print(f"\n{args.rule_id}: {checked} variants checked")
    if failures:
        print("FAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("all variants separate as advertised")
    return 0


if __name__ == "__main__":
    sys.exit(main())
