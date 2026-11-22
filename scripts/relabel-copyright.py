#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub
"""Rewrite the copyright holder in every tracked file once Friehub is incorporated.

    python3 scripts/relabel-copyright.py "Friehub Technologies Limited"

Replaces only a line that ENDS with the old holder, so running it twice with the
same name changes nothing. Run it in the same commit that updates NOTICE, the
CLA and the privacy page. Check `git diff --stat` before committing.
"""
import re
import subprocess
import sys

OLD = "Friehub"
if len(sys.argv) != 2 or not sys.argv[1].strip():
    sys.exit(__doc__)
new = sys.argv[1].strip()
pat = re.compile(r"(Copyright \(c\) \d{4}-\d{4}) " + re.escape(OLD) + r"$", re.M)

# `git grep` exits 1 when nothing matches, which is the normal second-run case.
files = subprocess.run(
    ["git", "grep", "-I", "-l", "-E", r"Copyright \(c\) [0-9]{4}-[0-9]{4} " + OLD],
    capture_output=True,
    text=True,
).stdout.split()
changed = 0
for f in files:
    text = open(f, encoding="utf-8").read()
    out = pat.sub(lambda m: f"{m.group(1)} {new}", text)
    if out != text:
        open(f, "w", encoding="utf-8").write(out)
        changed += 1
print(f"relabelled {changed} file(s) to: {new}")
