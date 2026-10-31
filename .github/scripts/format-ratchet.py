#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""Artifact-format ratchet (ROADMAP Phase 6.3).

A `.frc` bundle stores `LearnedFactEntry` / `HintKind` values by *variant
position* (bincode is positional). So a bundle is only decodable by an engine
whose fact vocabulary matches the one it was built against. Two version
numbers encode that contract, and this script keeps them honest:

  FACT_VOCABULARY_FINGERPRINT   FNV-1a over the ordered serialized fact
                                vocabulary (frensense-engine). Moves whenever
                                a variant is added, removed, reordered or
                                renamed.
  BUNDLE_VERSION                the `.frc` envelope version (frensense-bundler).
                                Must move whenever the fingerprint moves, so
                                an older binary refuses a newer bundle by a
                                clean version gate instead of an opaque serde
                                decode error.

The invariants, checked against a committed baseline (scripts/format-baseline.json):

  vocabulary_moved   the fingerprint changed since the baseline was recorded.
                     Fails unless the bundle version ALSO changed in the same
                     diff, and the changelog acknowledges it.
  bundle_version     informational echo of the current envelope version.

This is a *source* check: it reads the committed constants, so it needs no
build. It is the prose-and-numbers half of the ratchet; the byte-level half
lives in frensense-engine (tests::vocabulary_fingerprint_is_committed) and the
golden v6 bundle test in frensense-bundler.

Usage:
  scripts/format-ratchet.py            check against baseline (CI mode)
  scripts/format-ratchet.py --update   rewrite baseline with current values
  scripts/format-ratchet.py --verbose  show the parsed constants and changelog
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "format-baseline.json"

VOCAB_FILE = (
    ROOT
    / "frensense-engine"
    / "src"
    / "analysis"
    / "taint"
    / "facts"
    / "vocabulary.rs"
)
FRC_FILE = ROOT / "frensense-bundler" / "src" / "format" / "frc.rs"
BUNDLER_CHANGELOG = ROOT / "frensense-bundler" / "CHANGELOG.md"

# `pub const FACT_VOCABULARY_FINGERPRINT: u64 = 0x4994_27a8_ed94_e470;`
VOCAB_RE = re.compile(
    r"FACT_VOCABULARY_FINGERPRINT[^=]*=\s*(0x[0-9a-fA-F_]+|\d+)"
)
# `pub const BUNDLE_VERSION: u32 = 7;`
BUNDLE_RE = re.compile(r"BUNDLE_VERSION[^=]*=\s*(\d+)")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_constants() -> tuple[str, int]:
    """Return (fingerprint as normalized hex string, bundle version)."""
    vocab_src = read_text(VOCAB_FILE)
    m = VOCAB_RE.search(vocab_src)
    if not m:
        raise SystemExit(f"ERROR: FACT_VOCABULARY_FINGERPRINT not found in {VOCAB_FILE}")
    fingerprint = hex(int(m.group(1).replace("_", ""), 0))

    frc_src = read_text(FRC_FILE)
    m = BUNDLE_RE.search(frc_src)
    if not m:
        raise SystemExit(f"ERROR: BUNDLE_VERSION not found in {FRC_FILE}")
    return fingerprint, int(m.group(1))


def changelog_mentions(value: str) -> bool:
    """Whether the bundler changelog textually acknowledges `value`."""
    return value in read_text(BUNDLER_CHANGELOG)


def git_diff_has_change(path: Path) -> bool:
    """Whether `path` differs from HEAD in the working tree or last commit."""
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        rel = path
    for args in (
        ["git", "diff", "--quiet", "HEAD", "--", str(rel)],
        ["git", "diff", "--quiet", "--", str(rel)],
    ):
        try:
            if subprocess.run(
                args, cwd=ROOT, capture_output=True, check=False
            ).returncode != 0:
                return True
        except OSError:
            # No git available; fall back to the baseline comparison alone.
            return False
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Artifact-format ratchet (fingerprint must move with bundle version)."
    )
    parser.add_argument("--update", action="store_true", help="rewrite baseline")
    parser.add_argument("--verbose", action="store_true", help="show parsed values")
    args = parser.parse_args()

    fingerprint, bundle_version = parse_constants()
    current = {
        "fact_vocabulary_fingerprint": fingerprint,
        "bundle_version": bundle_version,
    }

    if args.update:
        BASELINE.write_text(
            json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"baseline updated: {BASELINE.relative_to(ROOT)}")
        for k in sorted(current):
            print(f"  {k}: {current[k]}")
        return 0

    if not BASELINE.is_file():
        print(f"ERROR: missing baseline {BASELINE}", file=sys.stderr)
        return 1
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    if args.verbose:
        print(f"  fingerprint:        {fingerprint}")
        print(f"  bundle version:     {bundle_version}")
        print(f"  changelog mentions bundle version: {changelog_mentions(str(bundle_version))}")

    failed = False

    # Invariant 1: a moved fingerprint implies a moved bundle version.
    base_fp = baseline.get("fact_vocabulary_fingerprint")
    base_bv = baseline.get("bundle_version")
    if base_fp is not None and fingerprint != base_fp:
        if bundle_version == base_bv:
            print(
                f"FAIL vocabulary_moved: fingerprint {base_fp} -> {fingerprint} "
                f"but BUNDLE_VERSION is still {bundle_version}. A bundle built "
                f"with the new vocabulary is unreadable by the binary that "
                f"still speaks {base_fp}. Bump BUNDLE_VERSION in "
                f"frensense-bundler/src/format/frc.rs."
            )
            failed = True
        else:
            print(
                f"ok   vocabulary_moved: fingerprint {base_fp} -> {fingerprint} "
                f"with BUNDLE_VERSION {base_bv} -> {bundle_version}"
            )
            # Invariant 2: the changelog must acknowledge the new version.
            if not changelog_mentions(str(bundle_version)):
                print(
                    f"FAIL changelog_stale: BUNDLE_VERSION {bundle_version} does "
                    f"not appear in frensense-bundler/CHANGELOG.md. Record the "
                    f"bump (and the compatibility consequence) in the same PR."
                )
                failed = True
            elif args.verbose:
                print("  changelog acknowledges the new bundle version")
    elif base_fp is not None:
        print(f"ok   vocabulary: unchanged ({fingerprint})")
    else:
        print(f"ok   vocabulary: first run ({fingerprint})")

    # Informational: bundle version never regresses silently.
    if base_bv is not None and bundle_version != base_bv and fingerprint == base_fp:
        print(
            f"note bundle_version {base_bv} -> {bundle_version} without a "
            f"vocabulary change (layout-only bump) - confirm it is intended."
        )

    if failed:
        print(
            "\nArtifact-format contract violated. When the fact vocabulary "
            "changes: bump BUNDLE_VERSION, update FACT_VOCABULARY_FINGERPRINT, "
            "regenerate the default pack, and note it in the bundler "
            "changelog (see docs/FORMATS.md).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
