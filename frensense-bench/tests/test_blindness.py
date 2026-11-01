#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

import contextlib
import csv
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from suites.blindness_challenges import (
    build_challenges,
    carry_forward,
    challenge_id,
    diff_against,
    restrict_previous,
    write_outputs,
)
from suites.blindness import (
    PINNED_REPOS,
    PinnedRepo,
    _resolve_targets,
    generate_markdown_card,
    main,
    parse_synthetic_spec,
    scan_repo,
    scan_synthetic,
    update_csv_sheet,
    update_history_json,
)
from suites.real_repos import Repo, main as real_repos_main
from suites.real_repos import scan as real_repos_scan
from suites.scanproc import run_scan


SITE = {"kind": "external-call", "function": "f", "detail": "os.path.join", "file": "a.py", "line": 3}
REC = {"file": "/c/r/a.py", "line": 10, "function": "f", "sink": "open", "arg_slot": 0,
       "verdict": "unknown", "reason": "x", "cut_sites": [SITE]}


class ChallengeTest(unittest.TestCase):
    def test_id_survives_line_shifts_but_not_a_different_stop_site(self):
        a = challenge_id("r", "a.py", "f", "open", 0, [SITE])
        shifted = dict(SITE, line=99)
        self.assertEqual(a, challenge_id("r", "a.py", "f", "open", 0, [shifted]))
        self.assertNotEqual(a, challenge_id("r", "a.py", "f", "open", 0, [dict(SITE, detail="other")]))

    def test_only_unknown_product_code_becomes_a_challenge(self):
        root = Path("/c/r")
        got = build_challenges("r", "python", root, [
            REC,
            dict(REC, verdict="clean"),
            dict(REC, file="/c/r/tests/t.py"),
            dict(REC, function="test_it"),
        ])
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["track"], "Library call")
        self.assertTrue(got[0]["id"].startswith("BL-"))

    def test_unscanned_or_failed_repos_cannot_be_solved(self):
        prev = [{"id": "BL-1", "repo": "flask"}, {"id": "BL-2", "repo": "cve-X", "group_repo": "recent-cves"}]
        kept = restrict_previous(prev, {"recent-cves"})
        self.assertEqual([c["id"] for c in kept], ["BL-2"])
        self.assertEqual(diff_against(kept, [])["solved"], ["BL-2"])  # scanned and gone: solved
        self.assertIsNone(restrict_previous(None, {"flask"}))

    def test_fixed_challenges_drop_off(self):
        self.assertEqual(diff_against([{"id": "BL-1"}, {"id": "BL-2"}], [{"id": "BL-2"}]),
                         {"solved": ["BL-1"], "new": []})
        self.assertEqual(diff_against(None, [{"id": "BL-2"}])["new"], [])


class TimeoutTest(unittest.TestCase):
    def test_zero_and_none_remove_the_limit(self):
        from suites.blindness import parse_timeout

        for v in ("0", "none", "OFF", "unlimited"):
            self.assertIsNone(parse_timeout(v))
        self.assertEqual(parse_timeout("7200"), 7200)
        with self.assertRaises(ValueError):
            parse_timeout("soon")
        with self.assertRaises(ValueError):
            parse_timeout("-5")

    def test_precedence_cli_then_repo_then_default(self):
        from suites.blindness import DEFAULT_TIMEOUT_S, effective_timeout

        self.assertEqual(effective_timeout(None, None), DEFAULT_TIMEOUT_S)
        self.assertEqual(effective_timeout(None, 5400), 5400)
        self.assertEqual(effective_timeout("60", 5400), 60)
        self.assertIsNone(effective_timeout("0", 5400))
        self.assertEqual(effective_timeout("", None), DEFAULT_TIMEOUT_S)


class PinnedRepoTest(unittest.TestCase):
    def test_pins_are_full_commit_shas(self):
        # `git fetch --depth 1 origin <abbrev>` is refused by servers, which
        # made the whole CI job fail at --prepare.
        for repo in PINNED_REPOS:
            self.assertRegex(repo.commit, r"^[0-9a-f]{40}$", repo.name)


class BlindnessSuiteTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_markdown_card_rendering(self):
        commit_info = {
            "commit": "abcdef1234567890abcdef1234567890abcdef12",
            "short_sha": "abcdef1",
            "branch": "main",
            "author": "Alice Dev <alice@example.com>",
            "date": "2026-10-31T12:00:00Z",
            "message": "test: engine optimization",
        }
        overall = {
            "blindness_rate": 10.5,
            "total_sinks": 200,
            "unknown_sinks": 21,
            "truncation_caps": 5,
            "caps_breakdown": {"call_context_depth": 3, "forward_hops": 2},
            "peak_rss_mb": 150.0,
            "wall_s": 5.2,
        }
        rows = [
            {
                "name": "flask",
                "lang": "python",
                "files_scanned": 40,
                "files_partial": 0,
                "total_sinks": 100,
                "unknown_sinks": 5,
                "blindness_rate": 5.0,
                "truncation_caps": 1,
                "peak_rss_mb": 60.0,
                "wall_s": 2.1,
            }
        ]

        card = generate_markdown_card(commit_info, overall, rows)
        self.assertIn("# Frensense Engine Blindness & Capability Card", card)
        self.assertIn("`abcdef1`", card)
        self.assertIn("10.5%", card)
        self.assertIn("flask", card)
        self.assertIn("call_context_depth", card)

    def test_history_and_csv_sheet_updating(self):
        record = {
            "commit": "1111222233334444555566667777888899990000",
            "short_sha": "1111222",
            "branch": "main",
            "author": "Bob <bob@example.com>",
            "date": "2026-10-31T10:00:00Z",
            "message": "feat: points-to speedup",
            "overall": {
                "blindness_rate": 8.0,
                "total_sinks": 100,
                "unknown_sinks": 8,
                "clean_sinks": 80,
                "sanitized_sinks": 10,
                "vulnerable_sinks": 2,
                "truncation_caps": 3,
                "peak_rss_mb": 120.5,
                "wall_s": 4.0,
                "files_scanned": 50,
                "files_partial": 1,
            },
            "by_repo": {"test_repo": {}},
        }

        history_file = self.tmp / "history.json"
        csv_file = self.tmp / "sheet.csv"

        update_history_json(history_file, record)
        self.assertTrue(history_file.exists())
        data = json.loads(history_file.read_text())
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["short_sha"], "1111222")

        # Update existing record
        record["message"] = "feat: points-to speedup (updated)"
        update_history_json(history_file, record)
        data = json.loads(history_file.read_text())
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["message"], "feat: points-to speedup (updated)")

        # Test CSV export
        update_csv_sheet(csv_file, record)
        self.assertTrue(csv_file.exists())
        with open(csv_file, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["short_sha"], "1111222")
            self.assertEqual(rows[0]["global_blindness_rate"], "8.0")


class SelectionTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_missing_target_is_an_error_not_a_whole_repo_scan(self):
        # Widening to the repo root would silently change both the blindness
        # rate and the memory profile while still publishing the pin's SHA.
        with self.assertRaises(FileNotFoundError):
            _resolve_targets(self.tmp, ("src",))

    def test_synthetic_spec_accepts_name_equals_dir(self):
        d = self.tmp / "cases"
        d.mkdir()
        self.assertEqual(parse_synthetic_spec(f"owasp={d}"), ("owasp", d.resolve()))
        self.assertEqual(parse_synthetic_spec(str(d)), ("cases", d.resolve()))
        with self.assertRaises(ValueError):
            parse_synthetic_spec(str(self.tmp / "missing"))

    def test_unknown_only_name_is_a_usage_error_not_an_empty_run(self):
        out = self.tmp / "out"
        argv = sys.argv
        sys.argv = ["blindness.py", "--run", "--only", "flaskk", "--out-dir", str(out)]
        try:
            with contextlib.redirect_stderr(io.StringIO()):  # argparse prints usage
                with self.assertRaises(SystemExit) as raised:
                    main()
        finally:
            sys.argv = argv
        self.assertEqual(raised.exception.code, 2)
        # The old behaviour exited 0 and published a 0-sink row (0% blindness).
        self.assertFalse((out / "blindness_report.json").exists())


class CarryForwardTest(unittest.TestCase):
    def test_partial_run_carries_other_repos_without_solving_them(self):
        prev = [{"id": "BL-1", "repo": "flask"}, {"id": "BL-2", "repo": "axum"}]
        carried = carry_forward(prev, {"flask"})
        self.assertEqual([c["id"] for c in carried], ["BL-2"])
        self.assertTrue(carried[0]["carried"])
        # Only the scanned repo can be "solved"; the carried one is untouched.
        self.assertEqual(diff_against(restrict_previous(prev, {"flask"}), [])["solved"], ["BL-1"])

    def test_track_does_not_depend_on_engine_site_order(self):
        other = {"kind": "param-no-caller", "function": "g", "detail": "self", "file": "a.py", "line": 2}
        first = build_challenges("r", "python", Path("/c/r"), [dict(REC, cut_sites=[SITE, other])])[0]
        second = build_challenges("r", "python", Path("/c/r"), [dict(REC, cut_sites=[other, SITE])])[0]
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["track"], second["track"])
        self.assertEqual(first["difficulty"], second["difficulty"])


FAKE_BIN = """#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv[1:]
mode = os.environ.get("FAKE_MODE", "ok")
if mode == "sleep":
    time.sleep(30)
if mode == "crash":
    sys.exit(7)
target = args[0]
if "--explain-json" in args:
    ex = args[args.index("--explain-json") + 1]
    json.dump({"schema": 1, "records": [{
        "file": target, "line": 1, "function": "f", "sink": "open", "arg_slot": 0,
        "verdict": "unknown", "reason": "x",
        "cut_sites": [{"kind": "external-call", "function": "f", "detail": "len",
                       "file": target, "line": 1}],
    }]}, open(ex, "w"))
print(json.dumps({
    "producer": {"version": "0.0.0", "engine_version": "0.0.0"},
    "advisories": [],
    "analysis": {"status": "complete",
                 "verdicts": {"clean": 0, "sanitized": 0, "vulnerable": 0, "unknown": 1},
                 "coverage": {"files_scanned": 1, "files_partial": 0, "files_failed": 0, "functions": 1},
                 "truncations": [], "timings": [{"phase": "taint", "ms": 7}]},
}))
"""


class ScanContractTest(unittest.TestCase):
    """The scan wrapper: memory sampling, timeouts and failure marking."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)
        self.binary = self.tmp / "frensense"
        self.binary.write_text(FAKE_BIN)
        self.binary.chmod(0o755)
        self.cache = self.tmp / "cache"
        self.repo_dir = self.cache / "fake"
        self.repo_dir.mkdir(parents=True)
        (self.repo_dir / "a.py").write_text("x = open(p)\n")
        self.repo = PinnedRepo(name="fake", url="", commit="0" * 40, lang="python", targets=(".",))

    def tearDown(self):
        os.environ.pop("FAKE_MODE", None)
        self.temp_dir.cleanup()

    def test_scan_repo_records_peak_rss_and_phases(self):
        if not Path("/usr/bin/time").exists():
            self.skipTest("/usr/bin/time is required for RSS sampling")
        meta = scan_repo(self.repo, self.cache, self.binary, 30)
        self.assertFalse(meta.get("failed"))
        self.assertEqual(meta["unknown_sinks"], 1)
        self.assertGreater(meta["peak_rss_mb"] or 0, 0)
        self.assertEqual(meta["timings"]["taint"], 7)
        self.assertEqual(meta["producer"]["engine_version"], "0.0.0")

    def test_timeout_fails_the_scan_instead_of_returning_empty_results(self):
        os.environ["FAKE_MODE"] = "sleep"
        started = time.monotonic()
        meta = scan_repo(self.repo, self.cache, self.binary, 1)
        elapsed = time.monotonic() - started
        self.assertIn("timed out", meta["failed"])
        self.assertLess(elapsed, 20, "the process group should be killed at the timeout")

    def test_nonzero_exit_is_a_failure_not_a_clean_scan(self):
        os.environ["FAKE_MODE"] = "crash"
        meta = scan_repo(self.repo, self.cache, self.binary, 30)
        self.assertEqual(meta["failed"], "exit code 7")

    def test_checkout_at_another_commit_is_refused(self):
        import subprocess

        subprocess.run(["git", "init", "-q"], cwd=self.repo_dir, check=True)
        subprocess.run(
            ["git", "-c", "user.email=a@b", "-c", "user.name=a", "commit", "--allow-empty", "-qm", "x"],
            cwd=self.repo_dir,
            check=True,
        )
        started = time.monotonic()
        meta = scan_repo(self.repo, self.cache, self.binary, 30)
        self.assertIn("pin is 0000000", meta["failed"])
        self.assertLess(time.monotonic() - started, 5, "the scan must not run at the wrong commit")


class SyntheticSuiteTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)
        self.binary = self.tmp / "frensense"
        self.binary.write_text(FAKE_BIN)
        self.binary.chmod(0o755)
        self.root = self.tmp / "cases"
        self.root.mkdir()
        for i in range(3):
            (self.root / f"case{i}.py").write_text("x = open(p)\n")

    def tearDown(self):
        os.environ.pop("FAKE_MODE", None)
        self.temp_dir.cleanup()

    def test_each_case_is_scanned_in_its_own_process_and_becomes_a_card(self):
        meta = scan_synthetic("owasp", self.root, self.binary, 30, 2, self.tmp / "cache")
        self.assertTrue(meta["synthetic"])
        self.assertEqual(meta["cases"], 3)
        self.assertEqual(meta["total_sinks"], 3)
        self.assertEqual(meta["unknown_sinks"], 3)
        self.assertEqual(meta["blindness_rate"], 100.0)
        self.assertFalse(meta.get("failed"))
        records = json.loads((self.tmp / "cache" / "owasp.explain.json").read_text())["records"]
        self.assertEqual(len(records), 3)
        self.assertEqual(len(build_challenges("owasp", "python", self.root, records)), 3)

    def test_a_failing_case_fails_the_suite(self):
        os.environ["FAKE_MODE"] = "crash"
        meta = scan_synthetic("owasp", self.root, self.binary, 30, 2, self.tmp / "cache")
        self.assertIn("3 of 3 cases failed", meta["failed"])


class ProfileRenderingTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    @staticmethod
    def _card(repo: str) -> dict:
        root = Path("/c") / repo
        rec = dict(REC, file=str(root / "a.py"))
        return build_challenges(repo, "python", root, [rec])[0]

    def test_html_profile_band_reports_memory_and_phases(self):
        out = self.tmp / "out"
        profile = {
            "identity": {"version": "0.8.0", "engine_version": "0.8.0"},
            "rows": [{
                "name": "redis", "lang": "c", "files_scanned": 200, "functions": 900,
                "total_sinks": 10, "unknown_sinks": 2, "truncation_caps": 1,
                "peak_rss_mb": 2500.0, "wall_s": 61.0,
            }, {
                "name": "broken", "lang": "c", "files_scanned": 0, "functions": 0,
                "total_sinks": 0, "unknown_sinks": 0, "truncation_caps": 0,
                "peak_rss_mb": None, "wall_s": 0.0, "failed": "timed out after 1800s",
            }],
            "overall": {
                "files_scanned": 200, "total_sinks": 10, "peak_rss_mb": 2500.0,
                "phases": {"taint": 1234}, "max_rss_mb": None, "over_budget": [],
            },
        }
        write_outputs(out, [self._card("redis")], "abc1234", None, {}, [], profile)
        page = (out / "challenges.html").read_text()
        for needle in ("Capability &amp; memory profile", "2500 MB", "Memory ceiling", "redis", "1.23s", "failed"):
            self.assertIn(needle, page)

    def test_partial_output_keeps_carried_cards_and_counts_them(self):
        out = self.tmp / "out"
        carried = [{**self._card("axum"), "carried": True}]
        write_outputs(out, [self._card("flask")], "abc1234", None, {}, carried)
        doc = json.loads((out / "challenges.json").read_text())
        self.assertEqual(doc["schema"], 3)
        self.assertEqual((doc["scanned"], doc["carried"], doc["count"]), (1, 1, 2))
        self.assertEqual(len(doc["challenges"]), 2)


class ScanProcTest(unittest.TestCase):
    """The shared scan runner: exit status, timeout kill, memory sample."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_stale_rss_file_is_not_attributed_to_the_next_scan(self):
        # /usr/bin/time -o is only written on success; an earlier run's 2 GB
        # sample must not be published as this run's peak.
        rss = self.tmp / "scan.rss"
        rss.write_text("2048000")
        result = run_scan([sys.executable, "-c", "print('{}')"], 10, rss)
        self.assertEqual(result["exit"], 0)
        self.assertIsNone(result["peak_rss_mb"])
        self.assertFalse(rss.exists())

    def test_timeout_returns_a_marked_result_and_the_exit_status(self):
        result = run_scan([sys.executable, "-c", "import time; time.sleep(30)"], 1, None)
        self.assertTrue(result["timeout"])
        self.assertLess(result["wall_s"], 20)


class RealReposScanTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.temp_dir.name)
        self.binary = self.tmp / "frensense"
        self.binary.write_text(FAKE_BIN)
        self.binary.chmod(0o755)
        self.cache = self.tmp / "cache"
        (self.cache / "fake").mkdir(parents=True)
        (self.cache / "fake" / "a.py").write_text("x = open(p)\n")

    def tearDown(self):
        os.environ.pop("FAKE_MODE", None)
        self.temp_dir.cleanup()

    def test_scan_records_exit_wall_and_peak_rss(self):
        repo = Repo(name="fake", url="", commit="0" * 40, lang="python", targets=(".",))
        meta = real_repos_scan(repo, self.cache, self.binary, 30)
        self.assertEqual(meta["exit"], 0)
        self.assertIsNone(meta.get("timeout"))
        self.assertEqual(meta["advisories"], 0)
        self.assertGreaterEqual(meta["wall_s"], 0.0)
        if Path("/usr/bin/time").exists():
            self.assertGreater(meta["peak_rss_mb"] or 0, 0)


class RealReposSelectionTest(unittest.TestCase):
    def test_unknown_only_name_is_a_usage_error_not_a_silent_empty_run(self):
        argv = sys.argv
        sys.argv = ["real_repos.py", "--run", "--only", "rediss"]
        try:
            with contextlib.redirect_stderr(io.StringIO()):  # argparse prints usage
                with self.assertRaises(SystemExit) as raised:
                    real_repos_main()
        finally:
            sys.argv = argv
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
