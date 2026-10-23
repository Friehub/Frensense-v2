#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""A/B two Frensense binaries over real repositories and diff their findings.

The OWASP Benchmark answers "did recall or precision move on labelled
cases?" (`scripts/owasp_benchmark.py --baseline ... --fail-on-regression`).
It cannot answer the other half: a real repository is unlabelled, so the
only regression signal is *which findings changed*. This script produces
that diff.

Usage:
  scripts/fp_ab.py --base /tmp/frensense-before --head /tmp/frensense-after \
      --repo ~/src/juice-shop --repo ~/src/NodeGoat --md-out /tmp/ab.md

Finding identity is `(rule_id, file_path, line)` - deliberately *not* the
title, which embeds the source description. A finding whose source
attribution improved (`req.params.id` -> `req.body.password` on the same
line and rule) is reported as ATTRIBUTION, not as one removal plus one
addition.

Exit codes:
  0  no new findings
  3  findings appeared that the base binary did not report (review them:
     they are either new true positives or a regression)
  2  a scan failed (engine error, timeout, unparsable JSON)
  1  usage error

Removals are never an automatic failure here: a removed finding can be a
false positive (the goal) or a lost true positive (a regression). The
report lists every removal so it can be reviewed, which is what the real
repo audit does by hand.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

MIN_SEVERITIES = ("info", "warning", "critical")


def scan(binary: Path, repo: Path, severity: str, timeout: int) -> list[dict[str, Any]]:
    """Run one binary over one repository and return its advisories."""
    cmd = [str(binary), str(repo), "--json", "--severity", severity]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        raise RuntimeError(f"{binary.name} on {repo.name}: {e}") from e
    # 0 = clean run, 1 = findings under --strict / baseline regression. Any
    # other status is a failed scan, not an empty result.
    if proc.returncode not in (0, 1):
        detail = proc.stderr.strip()[-400:]
        raise RuntimeError(f"{binary.name} on {repo.name}: exit {proc.returncode}: {detail}")
    if not proc.stdout.strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{binary.name} on {repo.name}: unparsable JSON: {e}") from e
    advisories = data if isinstance(data, list) else data.get("advisories", [])
    if not isinstance(advisories, list):
        raise RuntimeError(f"{binary.name} on {repo.name}: unexpected JSON shape")
    return advisories


def identity(a: dict[str, Any]) -> tuple[str, str, int]:
    return (str(a.get("rule_id", "?")), str(a.get("file_path", "?")), int(a.get("line", 0)))


def by_identity(advisories: list[dict[str, Any]]) -> dict[tuple[str, str, int], dict[str, Any]]:
    """Keep the first advisory per identity (duplicates on one line collapse)."""
    out: dict[tuple[str, str, int], dict[str, Any]] = {}
    for a in advisories:
        out.setdefault(identity(a), a)
    return out


def compare(base: list[dict[str, Any]], head: list[dict[str, Any]]) -> dict[str, Any]:
    b, h = by_identity(base), by_identity(head)
    added = sorted(h.keys() - b.keys())
    removed = sorted(b.keys() - h.keys())
    # Same rule and line, different observation/title: the flow through the
    # line was re-attributed, not lost and not duplicated.
    attributed = sorted(
        k for k in b.keys() & h.keys() if b[k].get("observation") != h[k].get("observation")
    )
    return {
        "base_count": len(base),
        "head_count": len(head),
        "added": [(k, h[k]) for k in added],
        "removed": [(k, b[k]) for k in removed],
        "attributed": [(k, b[k], h[k]) for k in attributed],
    }


def rule_counter(advisories: list[dict[str, Any]]) -> Counter[str]:
    return Counter(str(a.get("rule_id", "?")) for a in advisories)


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# Frensense A/B finding diff", ""]
    lines.append(f"base: `{report['base_binary']}`  head: `{report['head_binary']}`")
    lines.append(f"severity floor: `{report['severity']}`")
    lines.append("")
    (tb, th) = (report["totals"]["base"], report["totals"]["head"])
    verdict = "NEW FINDINGS" if report["totals"]["added"] else "no new findings"
    lines.append(f"**Total**: {tb} -> {th} ({verdict})")
    lines.append("")
    lines.append("| repo | base | head | removed | added | re-attributed |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for r in report["repos"]:
        lines.append(
            f"| {r['name']} | {r['result']['base_count']} | {r['result']['head_count']} "
            f"| {len(r['result']['removed'])} | {len(r['result']['added'])} "
            f"| {len(r['result']['attributed'])} |"
        )
    for r in report["repos"]:
        res = r["result"]
        if not (res["added"] or res["removed"] or res["attributed"]):
            continue
        lines += ["", f"## {r['name']}", ""]
        if res["added"]:
            lines.append("### Added (review: new true positive or a regression)")
            for (rule, path, line), a in res["added"]:
                lines.append(f"- `{rule}` {path}:{line} - {a.get('title', '')}")
            lines.append("")
        if res["attributed"]:
            lines.append("### Re-attributed (same rule and line, different source)")
            for (rule, path, line), old, new in res["attributed"]:
                lines.append(
                    f"- `{rule}` {path}:{line}: {old.get('observation', '')} -> {new.get('observation', '')}"
                )
            lines.append("")
        if res["removed"]:
            lines.append("### Removed (review: false positive fixed, or a lost flow)")
            for (rule, path, line), a in res["removed"]:
                lines.append(f"- `{rule}` {path}:{line} - {a.get('title', '')}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", required=True, type=Path, help="baseline frensense binary")
    ap.add_argument("--head", required=True, type=Path, help="candidate frensense binary")
    ap.add_argument(
        "--repo", action="append", required=True, type=Path, help="repository to scan (repeatable)"
    )
    ap.add_argument(
        "--severity", choices=MIN_SEVERITIES, default="warning", help="minimum severity (default: warning)"
    )
    ap.add_argument("--timeout", type=int, default=900, help="per-scan timeout in seconds")
    ap.add_argument("--json-out", type=Path, default=None, help="write the machine-readable diff here")
    ap.add_argument("--md-out", type=Path, default=None, help="write a markdown report here")
    args = ap.parse_args()

    for binary in (args.base, args.head):
        if not binary.exists():
            print(f"[ERROR] binary not found: {binary}", file=sys.stderr)
            return 1

    report: dict[str, Any] = {
        "base_binary": str(args.base),
        "head_binary": str(args.head),
        "severity": args.severity,
        "repos": [],
        "totals": {"base": 0, "head": 0, "added": 0, "removed": 0, "attributed": 0},
    }

    failed = False
    for repo in args.repo:
        if not repo.is_dir():
            print(f"[ERROR] repository not found: {repo}", file=sys.stderr)
            return 1
        try:
            base = scan(args.base, repo, args.severity, args.timeout)
            head = scan(args.head, repo, args.severity, args.timeout)
        except RuntimeError as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            failed = True
            continue
        result = compare(base, head)
        result["base_rules"] = dict(rule_counter(base))
        result["head_rules"] = dict(rule_counter(head))
        report["repos"].append({"name": repo.name, "path": str(repo), "result": result})
        totals = report["totals"]
        totals["base"] += result["base_count"]
        totals["head"] += result["head_count"]
        totals["added"] += len(result["added"])
        totals["removed"] += len(result["removed"])
        totals["attributed"] += len(result["attributed"])
        print(
            f"{repo.name}: {result['base_count']} -> {result['head_count']} "
            f"(-{len(result['removed'])}, +{len(result['added'])}, "
            f"~{len(result['attributed'])})"
        )

    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2) + "\n")
        print(f"[INFO] diff JSON -> {args.json_out}")
    if args.md_out:
        args.md_out.write_text(render_markdown(report))
        print(f"[INFO] markdown report -> {args.md_out}")

    if failed:
        return 2
    return 3 if report["totals"]["added"] else 0


if __name__ == "__main__":
    sys.exit(main())
