#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Clippy debt ratchet.

Lints at `deny` in the root Cargo.toml fail the build outright. Lints at
`warn` are known debt: this script counts their diagnostics per
(crate, lint) and fails when any count EXCEEDS the committed baseline, or
when a (crate, lint) pair appears that the baseline does not have. Counts may
drop; rerun with --update in the PR that removed the debt to tighten it.

Diagnostics are deduplicated by (lint, file, line, column) because
`--all-targets` compiles a crate's library and its test harness separately and
reports the same site twice.

Usage:
  .github/scripts/clippy-ratchet.py            run clippy, compare to baseline (CI mode)
  .github/scripts/clippy-ratchet.py --update   rewrite the baseline with current counts
  .github/scripts/clippy-ratchet.py --show     list every counted site
"""

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

BASELINE = Path(__file__).resolve().parent / "clippy-baseline.json"
CMD = [
    "cargo", "clippy", "--workspace", "--all-features", "--all-targets",
    "--message-format=json",
]


def collect():
    proc = subprocess.run(CMD, stdout=subprocess.PIPE, text=True)
    sites = set()
    errors = 0
    for line in proc.stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if msg.get("reason") != "compiler-message":
            continue
        m = msg["message"]
        level, code = m.get("level"), (m.get("code") or {}).get("code")
        if level == "error":
            errors += 1
            continue
        if level != "warning" or not code or not code.startswith("clippy::"):
            continue
        pkg = msg["package_id"]
        # "path+file:///x/frensense-engine#0.8.2" (or "...#name@ver" when the dir differs)
        tail = pkg.split("#")
        name = tail[1].split("@")[0] if "@" in tail[1] else tail[0].rsplit("/", 1)[-1]
        span = next((s for s in m["spans"] if s.get("is_primary")), None)
        if span is None:
            continue
        sites.add((name, code, span["file_name"], span["line_start"], span["column_start"]))
    return proc.returncode, errors, sites


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--show", action="store_true")
    args = ap.parse_args()

    rc, errors, sites = collect()
    if errors:
        print(f"clippy reported {errors} error-level diagnostics (deny lints or compile errors); fix those first.")
        return 1
    counts = Counter(f"{pkg}::{code}" for pkg, code, *_ in sites)
    if args.show:
        for s in sorted(sites):
            print("%s %s %s:%s:%s" % (s[0], s[1], s[2], s[3], s[4]))
    current = dict(sorted(counts.items()))
    if args.update:
        BASELINE.write_text(json.dumps(current, indent=2) + "\n")
        print(f"baseline updated: {sum(current.values())} sites in {len(current)} (crate, lint) pairs")
        return 0
    base = json.loads(BASELINE.read_text())
    bad = {k: (base.get(k, 0), v) for k, v in current.items() if v > base.get(k, 0)}
    dropped = {k: (base[k], current.get(k, 0)) for k in base if current.get(k, 0) < base[k]}
    for k, (b, v) in sorted(bad.items()):
        print(f"FAIL {k}: {v} (baseline {b}). New violations; fix them or justify a lint-level change.")
    for k, (b, v) in sorted(dropped.items()):
        print(f"note {k}: {v} (baseline {b}). Debt shrank; run with --update to lock it in.")
    if bad:
        return 1
    print(f"clippy ratchet OK: {sum(current.values())} sites, none above baseline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
