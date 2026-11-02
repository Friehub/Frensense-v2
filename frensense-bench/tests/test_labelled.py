#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from suites import manifest
from suites.blindness import PINNED_REPOS, load_labelled, load_pinned
from suites.blindness_challenges import group_challenges
from suites.blindness_labelled import (
    added_lines, anchored_labels, calls_in, changed_regions, drop_caught,
    make_challenges, match, pick_line, run_scan,
)
from suites.real_repos import REPOS


class LabelledTest(unittest.TestCase):
    ADV = [{"file_path": "a.py", "line": 7, "rule_id": "taint.xss", "observation": "x"}]

    def test_file_level_label_is_detected_by_any_advisory_in_the_file(self):
        # OWASP Python labels whole files: `show_line` is display only. A label whose line
        # had to match the advisory scored 35 of 452 vulnerable cases instead of 172.
        lab = {"file": "a.py", "line": 0, "show_line": 40, "vulnerable": True, "cwe": "79", "case": "xss:T1"}
        got = match([lab], self.ADV)
        self.assertEqual((len(got["detected"]), len(got["missed"])), (1, 0))

    def test_line_label_needs_an_advisory_within_tolerance(self):
        lab = {"file": "a.py", "line": 20, "vulnerable": True, "cwe": "79", "case": "c"}
        self.assertEqual(len(match([lab], self.ADV, tol=1)["missed"]), 1)
        self.assertEqual(len(match([dict(lab, line=8)], self.ADV, tol=1)["detected"]), 1)

    def test_safe_label_with_a_finding_is_a_false_alarm(self):
        lab = {"file": "a.py", "line": 0, "vulnerable": False, "cwe": "79", "case": "xss:T2"}
        got = match([lab], self.ADV)
        self.assertEqual((len(got["false_alarms"]), len(got["missed"])), (1, 0))
        self.assertEqual(match([dict(lab, file="b.py")], self.ADV)["false_alarms"], [])

    def test_fix_hunks_are_the_vulnerable_region(self):
        self.assertEqual(changed_regions("a\nb\nc\nd\n", "a\nB\nc\nd\ne\n"), [(2, 2)])

    def test_a_guard_only_fix_labels_the_statement_it_protects(self):
        # The fix removes nothing; it adds a check above `open(path)`. That statement is the sink.
        pre, post = "a = 1\nopen(path)\nreturn\n", "a = 1\nif bad(path): raise\nopen(path)\nreturn\n"
        self.assertEqual(changed_regions(pre, post), [(2, 3)])
        self.assertEqual(added_lines(pre, post), ["if bad(path): raise"])

    def test_a_failed_scan_is_an_error_not_an_empty_result(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "frensense"
            fake.write_text("#!/bin/sh\nexit 2\n")
            fake.chmod(0o755)
            with self.assertRaises(RuntimeError):
                run_scan(fake, Path(d), ["x"], Path(d) / "e.json")

    def test_card_points_at_the_changed_line_that_makes_a_call(self):
        lines = ["# comment", "x = {", '    "/a": "a.html",', "}", "open(path)"]
        self.assertEqual(pick_line(lines, 1, 5), 5)
        self.assertEqual(pick_line(["# only", "a = 1"], 1, 2), 2)  # no call anywhere: first real line

    def test_calls_ignore_plumbing(self):
        self.assertEqual(calls_in(["p = request.args.get('x')", "os.system(cmd)", "str(x)"]), ["os.system"])

    def _missed(self, text, cwe="78", **lab):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "a.py").write_text(text)
            base = {"file": "a.py", "line": 1, "vulnerable": True, "cwe": cwe, "case": "c", "advisory": None}
            res = {"detected": [], "false_alarms": [], "missed": [dict(base, **lab)]}
            return make_challenges("r", "python", res, [], {}, root=root)[0]

    def test_missed_is_sorted_by_why_it_was_missed(self):
        self.assertEqual(self._missed("subprocess.run(cmd)\n")["track"], "Missed: unrecognised call")
        self.assertEqual(self._missed("x = a + b\n")["track"], "Missed: no call here")
        self.assertEqual(self._missed("random.random()\n", cwe="330")["track"], "Missed pattern check")

    def test_a_silent_explored_sink_is_its_own_track(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("f(x)\n")
            lab = {"file": "a.py", "line": 1, "vulnerable": True, "cwe": "78", "case": "c", "advisory": None}
            rec = {"file": "a.py", "line": 1, "sink": "f", "reason": "stuck", "cut_sites": []}
            res = {"detected": [], "false_alarms": [], "missed": [lab]}
            got = make_challenges("r", "python", res, [rec], {}, root=Path(d))[0]
            self.assertEqual(got["track"], "Missed: silent sink")

    def test_a_case_caught_in_one_hunk_is_not_missed_in_another(self):
        res = {"detected": [{"case": "CVE-1:a.py"}], "false_alarms": [],
               "missed": [{"case": "CVE-1:a.py"}, {"case": "CVE-2:b.py"}]}
        self.assertEqual([m["case"] for m in drop_caught(res)["missed"]], ["CVE-2:b.py"])

    def test_a_drifted_anchor_fails_loudly(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "f.js").write_text("nothing here\n")
            spec = root / "l.json"
            spec.write_text(json.dumps({"labels": [{"file": "f.js", "anchor": "eval(x)", "cwe": "95", "case": "c"}]}))
            with self.assertRaises(ValueError):
                anchored_labels(root, spec)



class LabelledGroupingTest(unittest.TestCase):
    def test_labelled_cases_group_by_category_not_by_stop_site(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text("subprocess.run(cmd)\nsubprocess.run(cmd2)\n")
            labs = [
                {"file": "a.py", "line": i, "vulnerable": True, "cwe": "78", "case": f"c{i}", "advisory": None}
                for i in (1, 2)
            ]
            res = {"detected": [], "false_alarms": [], "missed": labs}
            items = make_challenges("r", "python", res, [], {}, root=Path(d))
            groups = group_challenges(items)
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["impact"], 2)
            self.assertEqual(groups[0]["kind"], "missed")


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
    def test_the_shipped_manifest_is_valid_and_feeds_both_suites(self):
        self.assertTrue(PINNED_REPOS)
        self.assertTrue(REPOS)
        names = {r.name for r in PINNED_REPOS} | {r.name for r in REPOS} | {l.name for l in load_labelled()}
        self.assertGreaterEqual(len(names), 10)
        for r in PINNED_REPOS + REPOS:
            self.assertRegex(r.commit, r"^[0-9a-f]{40}$", r.name)

    def test_a_repo_is_added_by_editing_the_manifest_only(self):
        with tempfile.TemporaryDirectory() as d:
            f = _write(Path(d) / "r.toml", GOOD % SHA)
            self.assertEqual([r.name for r in load_pinned(f)], ["a"])
            f.write_text(f.read_text() + (GOOD % SHA).replace('"a"', '"b"'))
            self.assertEqual([r.name for r in load_pinned(f)], ["a", "b"])

    def test_suites_filter(self):
        text = (GOOD % SHA).replace('targets = ["src"]', 'targets = ["src"]\n    suites = ["real"]')
        with tempfile.TemporaryDirectory() as d:
            f = _write(Path(d) / "r.toml", text)
            self.assertEqual(manifest.repos_for("real", f)[0]["name"], "a")
            self.assertEqual(manifest.repos_for("blindness", f), [])

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
