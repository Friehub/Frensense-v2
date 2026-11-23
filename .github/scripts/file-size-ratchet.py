#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub
"""File-length ratchet: a Rust source file may not be longer than LIMIT lines.

clippy cannot lint module length (`too_many_lines` is per function), so this
script does. Files that were already over the limit when it was introduced are
recorded in `file-size-baseline.json` with their line count at that time:

  * a file over LIMIT that is not in the baseline fails (new bloat);
  * a baselined file that grew fails (existing bloat may only shrink);
  * a baselined file that shrank is reported; run with --update to lock it in,
    and a baselined file that dropped to LIMIT or below leaves the baseline.

The fix for a failure is to split the module by responsibility, not to raise a
number. Usage:

    python3 .github/scripts/file-size-ratchet.py           # check
    python3 .github/scripts/file-size-ratchet.py --update  # lock in shrinkage
    python3 .github/scripts/file-size-ratchet.py --init    # (re)write the baseline from scratch
"""
import json
import pathlib
import sys

LIMIT = 500
ROOT = pathlib.Path(__file__).resolve().parents[2]
BASELINE = pathlib.Path(__file__).with_name("file-size-baseline.json")
SOURCE_DIRS = ["src", "frensense-engine/src", "frensense-lang/src",
               "frensense-bundler/src", "frensense-packgen/src",
               "frensense-devtools/src"]


def measure() -> dict[str, int]:
    sizes: dict[str, int] = {}
    for d in SOURCE_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.rs")):
            with path.open(encoding="utf-8", errors="replace") as f:
                n = sum(1 for _ in f)
            if n > LIMIT:
                sizes[path.relative_to(ROOT).as_posix()] = n
    return sizes


def main() -> int:
    update = "--update" in sys.argv[1:]
    current = measure()
    if "--init" in sys.argv[1:]:
        BASELINE.write_text(json.dumps(dict(sorted(current.items())), indent=2) + "\n")
        print(f"baseline written: {len(current)} file(s) over {LIMIT} lines")
        return 0
    baseline: dict[str, int] = (
        json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    )
    failures, shrunk = [], []
    for path, n in sorted(current.items()):
        old = baseline.get(path)
        if old is None:
            failures.append(f"NEW   {path}: {n} lines (limit {LIMIT}). Split it by responsibility.")
        elif n > old:
            failures.append(f"GREW  {path}: {n} lines (baseline {old}). Move code out instead of adding.")
        elif n < old:
            shrunk.append(f"{path}: {old} -> {n}")
    gone = [p for p in baseline if p not in current]

    if update:
        if failures:
            print("Refusing to update while files are new or grew:\n  " + "\n  ".join(failures))
            return 1
        BASELINE.write_text(json.dumps(dict(sorted(current.items())), indent=2) + "\n")
        print(f"baseline updated: {len(current)} file(s) over {LIMIT} lines")
        return 0

    if failures:
        print(f"File-size ratchet FAILED (limit {LIMIT} lines per file):")
        print("  " + "\n  ".join(failures))
        return 1
    for line in shrunk:
        print(f"shrank  {line}")
    if shrunk or gone:
        print("Run with --update to lock in the improvement.")
    print(f"file-size ratchet ok: {len(current)} file(s) over {LIMIT} lines (baseline {len(baseline)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
