#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

"""Generate the release banner from the version and the what's-new page.

The docs site renders one release bar from `docs-site/public/announcements.json`.
Keeping that file in step with the workspace version by hand is how the site
ends up advertising a release that already shipped: the banner says 0.9.0 while
the crate is 0.9.1.

This script owns the release entry:

  - version      <- `[package].version` in the workspace `Cargo.toml`
  - title        <- `Frensense v<version> is out`
  - message      <- the one-line bold summary of that version's section in
                    `docs-site/whats-new.md` (prose, no changelog jargon)
  - link         <- `/whats-new`, where the reader lands

A version with no section on the what's-new page is an error: the bar must
never announce a release the site cannot explain. Hand-written entries whose
id does not start with `release-v` are preserved.

Usage:
    python3 docs-site/scripts/sync_announcements.py           # write
    python3 docs-site/scripts/sync_announcements.py --check   # fail if stale
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CARGO = ROOT / "Cargo.toml"
WHATSNEW = ROOT / "docs-site" / "whats-new.md"
FEED = ROOT / "docs-site" / "public" / "announcements.json"

RELEASE_ID = re.compile(r"^release-v")
SECTION = re.compile(r"^## (\S+) - (.+)$", re.MULTILINE)
SUMMARY = re.compile(r"^\*\*(.+?)\*\*", re.MULTILINE)
LINK_OBJECT = re.compile(
    r'"link": \{\s*"text": ("(?:[^"\\]|\\.)*"),\s*"href": ("(?:[^"\\]|\\.)*")\s*\}'
)


def workspace_version() -> str:
    with CARGO.open("rb") as handle:
        return tomllib.load(handle)["package"]["version"]


def whats_new_summary(version: str) -> tuple[str, str]:
    """The section title and bold summary line for `version`."""
    text = WHATSNEW.read_text(encoding="utf-8")
    headings = list(SECTION.finditer(text))
    for index, heading in enumerate(headings):
        if heading.group(1) != version:
            continue
        body_end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[heading.end() : body_end]
        summary = SUMMARY.search(body)
        if not summary:
            raise SystemExit(
                f"whats-new.md: section {version} has no bold summary line; "
                "the banner needs one user-facing sentence"
            )
        return heading.group(2).strip(), summary.group(1).strip()
    raise SystemExit(
        f"whats-new.md: no '## {version} - <title>' section; "
        "write the user-facing release note before announcing it"
    )


def read_entries() -> list[dict[str, object]]:
    if not FEED.is_file():
        return []
    data = json.loads(FEED.read_text(encoding="utf-8"))
    entries = data.get("announcements", [])
    if not isinstance(entries, list):
        raise SystemExit(f"{FEED.name}: 'announcements' must be a list")
    return entries


def render(version: str, summary: str, others: list[dict[str, object]]) -> str:
    release: dict[str, object] = {
        "id": f"release-v{version}",
        "display": "bar",
        "tone": "brand",
        "title": f"Frensense v{version} is out",
        "message": summary,
        "link": {"text": "See what's new", "href": "/whats-new"},
    }
    text = json.dumps(
        {"announcements": [release, *others]}, indent=2, ensure_ascii=False
    )
    # Keep the link on one line, the shape the file has always had.
    text = LINK_OBJECT.sub(r'"link": { "text": \1, "href": \2 }', text)
    return text + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the banner is current instead of writing it",
    )
    args = parser.parse_args()

    version = workspace_version()
    title, summary = whats_new_summary(version)
    others = [e for e in read_entries() if not RELEASE_ID.match(str(e.get("id", "")))]
    wanted = render(version, summary, others)
    current = FEED.read_text(encoding="utf-8") if FEED.is_file() else ""

    if args.check:
        if current != wanted:
            print(
                f"FAIL announcements.json is stale for {version} ({title}).\n"
                "     Run: python3 docs-site/scripts/sync_announcements.py",
                file=sys.stderr,
            )
            return 1
        print(f"ok   announcements.json announces {version}")
        return 0

    if current == wanted:
        print(f"ok   announcements.json already announces {version}")
        return 0
    FEED.write_text(wanted, encoding="utf-8")
    print(f"wrote {FEED.relative_to(ROOT)}: announces v{version} ({title})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
