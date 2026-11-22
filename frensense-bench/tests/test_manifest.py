#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from suites import manifest


def _write(path: Path, text: str) -> Path:
    path.write_text(textwrap.dedent(text))
    return path


GOOD = """
    [[repo]]
    name = "a"
    url = "https://example.com/a.git"
    commit = "%s"
    lang = "c"
    targets = ["src"]
"""
SHA = "0123456789abcdef0123456789abcdef01234567"


class ManifestTest(unittest.TestCase):
    def test_the_shipped_manifest_is_valid(self):
        repos = manifest.repos()
        self.assertGreaterEqual(len(repos), 10)
        for r in repos:
            self.assertRegex(r["commit"], r"^[0-9a-f]{40}$", r["name"])

    def test_a_repo_is_added_by_editing_the_manifest_only(self):
        with tempfile.TemporaryDirectory() as d:
            f = _write(Path(d) / "r.toml", GOOD % SHA)
            self.assertEqual([r["name"] for r in manifest.repos(f)], ["a"])
            f.write_text(f.read_text() + (GOOD % SHA).replace('"a"', '"b"'))
            self.assertEqual([r["name"] for r in manifest.repos(f)], ["a", "b"])

    def test_bad_pins_stop_the_run(self):
        for bad, why in (
            (GOOD % "abc1234", "40-character"),
            ((GOOD % SHA).replace('lang = "c"', 'lang = "cobol"'), "lang"),
            ((GOOD % SHA).replace('["src"]', '["../etc"]'), "inside"),
            ((GOOD % SHA).replace('["src"]', "[]"), "targets"),
            ((GOOD % SHA) + (GOOD % SHA), "duplicate"),
            ("not toml [[", "TOML"),
        ):
            with self.subTest(why=why), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(manifest.ManifestError) as ctx:
                    manifest.load(_write(Path(d) / "r.toml", bad))
                self.assertIn(why, str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
