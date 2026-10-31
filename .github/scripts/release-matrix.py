#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Per-crate release matrix for the publishable crates of the workspace.

Frensense is one binary but four registry crates, each with its own version.
A release therefore has to answer "which crates does this run publish?", not
"what is the root version?". This script answers it from the manifests and the
registry, so the release workflow can:

  * decide whether anything still needs publishing, even when the root version
    did not move (a crate-only release has no new `vX.Y.Z` tag);
  * name every crate it is going to publish, so none is skipped silently;
  * assert afterwards that each manifest version actually exists on crates.io.

Usage
-----
    python3 scripts/release-matrix.py                  # human table
    python3 scripts/release-matrix.py --json
    python3 scripts/release-matrix.py --github-output "$GITHUB_OUTPUT"
    python3 scripts/release-matrix.py --require-published --wait 300

Exit status is 1 only under `--require-published` when a crate is still missing
(or its status could not be determined), so the post-publish step cannot pass
while a crate was skipped.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES_IO = "https://crates.io/api/v1/crates"
USER_AGENT = "frensense-release-matrix (https://github.com/Friehub/Frensense-v2)"

PUBLISHED = "published"
PENDING = "pending"
UNKNOWN = "unknown"


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)


def cargo_metadata() -> dict:
    proc = run(["cargo", "metadata", "--no-deps", "--format-version", "1"])
    if proc.returncode != 0:
        raise SystemExit(f"cargo metadata failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def publishable_packages() -> list[dict]:
    """Workspace packages that go to a registry (`publish = false` excluded)."""
    meta = cargo_metadata()
    pkgs = []
    for pkg in meta["packages"]:
        publish = pkg.get("publish")
        if publish == [] or publish == ["false"]:
            continue
        pkgs.append({"name": pkg["name"], "version": pkg["version"]})
    return sorted(pkgs, key=lambda p: p["name"])


def registry_status(name: str, version: str) -> str:
    """Whether `<name>@<version>` exists on crates.io."""
    url = f"{CRATES_IO}/{name}/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return PUBLISHED if resp.status == 200 else UNKNOWN
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return PENDING
        return UNKNOWN
    except (urllib.error.URLError, TimeoutError, OSError):
        return UNKNOWN


def build_matrix() -> list[dict]:
    matrix = []
    for pkg in publishable_packages():
        matrix.append(
            {
                "crate": pkg["name"],
                "version": pkg["version"],
                "status": registry_status(pkg["name"], pkg["version"]),
            }
        )
    return matrix


def unresolved(matrix: list[dict]) -> list[dict]:
    """Rows that are not confirmed published (pending or undetermined)."""
    return [row for row in matrix if row["status"] != PUBLISHED]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report, and optionally assert, per-crate publication state."
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--github-output",
        metavar="FILE",
        help="append step outputs (pending, pending_count, all_published, "
        "crate_versions) to a GitHub Actions output file",
    )
    parser.add_argument(
        "--require-published",
        action="store_true",
        help="exit 1 unless every publishable crate at its manifest version is on "
        "crates.io (the post-publish assertion)",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=0,
        metavar="SECONDS",
        help="with --require-published, poll the registry up to this long "
        "(crates.io indexing is asynchronous)",
    )
    args = parser.parse_args()

    deadline = time.monotonic() + max(args.wait, 0)
    matrix = build_matrix()
    while args.require_published and args.wait and unresolved(matrix):
        if time.monotonic() >= deadline:
            break
        time.sleep(15)
        matrix = build_matrix()

    pending = [row for row in matrix if row["status"] == PENDING]
    unknown = [row for row in matrix if row["status"] == UNKNOWN]
    all_published = not pending and not unknown

    if args.json:
        print(
            json.dumps(
                {
                    "crates": matrix,
                    "pending": [f"{r['crate']}@{r['version']}" for r in pending],
                    "unknown": [f"{r['crate']}@{r['version']}" for r in unknown],
                    "all_published": all_published,
                },
                indent=2,
            )
        )
    else:
        print(f"{'crate':<22} {'version':<14} status")
        for row in matrix:
            print(f"{row['crate']:<22} {row['version']:<14} {row['status']}")
        if pending:
            listed = ", ".join(f"{r['crate']}@{r['version']}" for r in pending)
            print(f"\nto publish: {listed}")
        elif all_published:
            print("\nevery publishable crate at its manifest version is on crates.io")

    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as out:
            out.write(f"all_published={'true' if all_published else 'false'}\n")
            out.write(f"pending_count={len(pending)}\n")
            out.write(
                "pending=" + " ".join(f"{r['crate']}@{r['version']}" for r in pending) + "\n"
            )
            out.write(
                "crate_versions="
                + " ".join(f"{r['crate']}={r['version']}" for r in matrix)
                + "\n"
            )

    if args.require_published and not all_published:
        missing = pending + unknown
        print(
            "\nrelease-matrix: FAILED - these publishable crates are not on "
            "crates.io at their manifest version:",
            file=sys.stderr,
        )
        for row in missing:
            print(
                f"  {row['crate']} {row['version']} ({row['status']})", file=sys.stderr
            )
        print(
            "A release must publish every crate whose version moved. Check the "
            "publish log for a skipped or failed crate.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
