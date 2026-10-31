#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Blog provenance automation.

Every post in docs-site/blog/ must declare which engine version its
behavioral claims were verified against, when they were last fact-checked,
and the source revision they were checked at. This script:

  stamp  - writes those fields into frontmatter for one or all posts
           (--against-version and --revision can be overridden)
  check  - validates every post carries the fields and warns (or, with
           --strict, fails) when a post is stale relative to the
           workspace version

Run `make blog-check` (also invoked by `make docs` and the docs-site
prebuild script) so a stale/unequipped post can never ship silently.
"""

from __future__ import annotations

import argparse
import datetime
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
BLOG_DIR = ROOT / "docs-site" / "blog"
CARGO_TOML = ROOT / "Cargo.toml"

REQUIRED = ("written-against-version", "fact-checked", "source-revision")


def workspace_version() -> str:
    data = tomllib.loads(CARGO_TOML.read_text())
    pkg = data.get("package", {})
    ver = pkg.get("version") or data.get("workspace", {}).get("package", {}).get("version")
    if not ver:
        raise SystemExit(f"error: no package.version in {CARGO_TOML}")
    return ver


def current_revision() -> str:
    try:
        head = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        head = "unknown"
    # A dirty tree can invalidate "verified at this SHA"; mark it.
    try:
        dirty = subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if dirty:
            head += "-dirty"
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return head


def parse_frontmatter(text: str) -> tuple[str, dict | None, int]:
    """Return (body, fm_dict_or_None, fm_end_offset)."""
    m = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    if not m:
        return text, None, 0
    fm_text = m.group(1)
    fm: dict = {}
    for line in fm_text.splitlines():
        kv = line.split(":", 1)
        if len(kv) == 2 and not line.startswith((" ", "\"", "'")):
            val = kv[1].strip().strip('"')
            fm[kv[0].strip()] = val
    return text, fm, m.end()


def write_frontmatter(path: pathlib.Path, version: str | None, revision: str) -> None:
    """Insert the provenance keys into (not replace) a post's frontmatter."""
    text = path.read_text()
    m = re.match(r"^(---\n)(.*?)(\n---\n)", text, re.DOTALL)
    if not m:
        print(f"warning: {path.name} has no frontmatter/history; skipping")
        return
    today = datetime.date.today().isoformat()
    block = m.group(2)
    # Closed field: stamping never silently bumps written-against-version.
    # An explicit --against-version, however, always wins (used when a
    # retro-stamp corrects the pinned version).
    existing = re.search(r"^written-against-version:\s*(\S+)", text, re.M)
    version_field = version if version else (existing.group(1) if existing else workspace_version())
    # Drop any previously stamped provenance lines so they move to the top,
    # preserving title/date/description/head and everything else.
    provenance_lines: list[str] = []
    kept: list[str] = []
    for line in block.splitlines():
        skips = False
        for key in REQUIRED:
            if line.startswith(f"{key}:"):
                skips = True
                break
        if skips:
            provenance_lines.append(line)
        else:
            kept.append(line)
    stamp = (
        f"written-against-version: {version_field}\n"
        f'fact-checked: "{today}"\n'
        f"source-revision: {revision}\n"
    )
    new_text = f"---\n{stamp}" + "\n".join(kept) + "\n---\n" + text[m.end():]
    path.write_text(new_text)
    print(f"stamped {path.name}: against {version_field}, checked {today}, rev {revision}")


def posts() -> list[pathlib.Path]:
    return sorted(p for p in BLOG_DIR.glob("*.md") if p.name != "index.md")


def check(strict: bool) -> int:
    version = workspace_version()
    # Staleness is measured against the last time the workspace version was
    # set (Cargo.toml), not merely the version string itself: a post whose
    # fact-check predates the version bump has not seen that version's
    # behavior and is stale.
    try:
        ver_changed = subprocess.run(
            ["git", "log", "-1", "--format=%cs", "--", "Cargo.toml"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip() or datetime.date.today().isoformat()
    except (subprocess.CalledProcessError, FileNotFoundError):
        ver_changed = datetime.date.today().isoformat()
    failures = 0
    for p in posts():
        _, fm, _ = parse_frontmatter(p.read_text())
        if fm is None:
            print(f"FAIL {p.name}: no frontmatter")
            failures += 1
            continue
        missing = [f for f in REQUIRED if f not in fm]
        if missing:
            print(f"FAIL {p.name}: missing {', '.join(missing)}")
            failures += 1
            continue
        stale = fm["fact-checked"] < ver_changed
        msg = (f"{p.name}: against {fm['written-against-version']}, "
               f"fact-checked {fm['fact-checked']} at {fm['source-revision']}; "
               f"workspace {version} set on {ver_changed}")
        # A post may legitimately pin an older version; it is stale only
        # if its fact-check predates the current version's own set date.
        if stale:
            print(f"{'FAIL' if strict else 'WARN'} STALE {msg}. Re-audit before merge.")
            failures += 1 if strict else 0
        else:
            print(f"OK   {msg}")
    if failures:
        print(f"blog provenance: {failures} problem(s)")
    else:
        print("blog provenance: all posts equipped")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("cmd", choices=["stamp", "check"])
    ap.add_argument("--file", help="stamp a single post instead of all")
    ap.add_argument("--against-version", help="override workspace version (stamp)")
    ap.add_argument("--strict", action="store_true",
                    help="check: stale posts are errors, not warnings")
    args = ap.parse_args()
    if args.cmd == "stamp":
        version = args.against_version  # None when unset; existing field wins then
        revision = current_revision()
        targets = [BLOG_DIR / args.file] if args.file else posts()
        for t in targets:
            if not t.exists():
                print(f"error: {t} not found")
                return 2
            write_frontmatter(t, version, revision)
        return 0
    return check(args.strict)


if __name__ == "__main__":
    sys.exit(main())
