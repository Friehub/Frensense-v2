#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import contrib
from suites.blindness_labelled import match, scorecard

A, B, C = "BG-aaaaaaaaaa", "BG-bbbbbbbbbb", "BG-cccccccccc"


def grp(gid, repo, sinks, difficulty="easy", lang="python"):
    return {"id": gid, "repo": repo, "lang": lang, "kind": "external-call", "detail": "x", "track": "Library call",
            "difficulty": difficulty, "title": f"t {gid}", "impact": len(sinks), "sinks": sinks}


def doc(groups, scores=None):
    chal = [{"id": s, "repo": g["repo"]} for g in groups for s in g["sinks"]]
    return {"groups": groups, "challenges": chal, "scores": scores or []}


def pr(n, body, author="bob", merged="2026-11-01T10:00:00Z"):
    return {"number": n, "body": body, "author": author, "merged_at": merged, "url": f"u/{n}", "title": f"pr {n}", "sha": "s"}


class ClaimsTest(unittest.TestCase):
    def test_only_solves_lines_are_claims(self):
        body = f"Related to BG-dddddddddd in prose.\n\nSolves: {A}, {B}\n- Solves {C}\nsolves: {A}\n"
        self.assertEqual(contrib.parse_claims(body), [A, B, C])
        self.assertEqual(contrib.parse_claims("no claims here"), [])
        self.assertEqual(contrib.parse_claims(None), [])

    def test_unknown_and_excess_claims_are_separated(self):
        base = doc([grp(A, "r", ["BL-1"])])
        known, unknown, extra = contrib.resolve_claims([A, B] + [f"BG-{i:010x}" for i in range(20, 30)], base)
        self.assertEqual([g["id"] for g in known], [A])
        self.assertEqual(unknown[0], B)
        self.assertEqual(len(extra), 2)


class VerifyTest(unittest.TestCase):
    def setUp(self):
        self.base = doc([grp(A, "r", ["BL-1", "BL-2"]), grp(B, "r", ["BL-3"]), grp(C, "other", ["BL-9"])])

    def test_solved_partial_and_regression(self):
        cur = doc([grp(A, "r", ["BL-2"]), grp(B, "r", ["BL-3"]), grp(C, "other", ["BL-9"])])
        res = contrib.evaluate(self.base, cur, [A], ["r"])
        self.assertTrue(res["ok"])
        self.assertEqual((res["claims"][0]["status"], res["claims"][0]["solved"]), ("partial", 1))

        done = doc([grp(B, "r", ["BL-3"]), grp(C, "other", ["BL-9"])])
        self.assertEqual(contrib.evaluate(self.base, done, [A], ["r"])["claims"][0]["status"], "solved")

        worse = doc([grp(A, "r", ["BL-2"]), grp(B, "r", ["BL-3", "BL-new", "BL-new2"]), grp(C, "other", ["BL-9"])])
        res = contrib.evaluate(self.base, worse, [A], ["r"])
        self.assertFalse(res["ok"])
        self.assertIn("more open challenges", res["regressions"][0])

    def test_no_progress_unknown_id_and_no_claim_fail(self):
        same = doc(self.base["groups"])
        self.assertFalse(contrib.evaluate(self.base, same, [A], ["r"])["ok"])
        self.assertFalse(contrib.evaluate(self.base, same, ["BG-ffffffffff"], ["r"])["ok"])
        self.assertFalse(contrib.evaluate(self.base, same, [], [])["ok"])

    def test_a_repo_that_was_not_scanned_cannot_verify(self):
        cur = doc([grp(A, "r", ["BL-1", "BL-2"]), grp(B, "r", ["BL-3"])])  # C's repo vanished from the scan
        res = contrib.evaluate(self.base, cur, [C], ["r"])
        self.assertTrue(res["claims"][0]["outside_scan"])

    def test_scorecard_regressions(self):
        sc = lambda tp, fp: [{"name": "owasp-python", "tp": tp, "fp": fp}]
        base = dict(self.base, scores=sc(10, 2))
        better = dict(doc([grp(A, "r", []), grp(B, "r", ["BL-3"])], sc(11, 2)))
        self.assertTrue(contrib.evaluate(base, better, [A], ["r", "owasp-python"])["ok"])
        lost = dict(doc([grp(A, "r", []), grp(B, "r", ["BL-3"])], sc(9, 2)))
        self.assertFalse(contrib.evaluate(base, lost, [A], ["r", "owasp-python"])["ok"])
        noisy = dict(doc([grp(A, "r", []), grp(B, "r", ["BL-3"])], sc(10, 3)))
        self.assertFalse(contrib.evaluate(base, noisy, [A], ["r", "owasp-python"])["ok"])

    def test_comment_has_marker_and_reads_cleanly(self):
        cur = doc([grp(B, "r", ["BL-3"]), grp(C, "other", ["BL-9"])])
        text = contrib.render_comment(contrib.evaluate(self.base, cur, [A], ["r"]))
        self.assertIn(contrib.MARKER, text)
        self.assertIn("solved", text)
        self.assertIn("after merge", text)


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.cfg = contrib.load_badges()
        self.base = doc([grp(A, "r", ["BL-1", "BL-2", "BL-3", "BL-4"], "medium"), grp(B, "r", ["BL-5"], "hard", "rust")])

    def test_credit_needs_the_sinks_gone_on_main(self):
        cur = doc([grp(A, "r", ["BL-3", "BL-4"], "medium"), grp(B, "r", ["BL-5"], "hard", "rust")])
        led, new = contrib.award({"entries": []}, [pr(7, f"Solves: {A}")], self.base, cur, "now", self.cfg)
        self.assertEqual(len(new), 1)
        e = new[0]
        self.assertEqual((e["sinks_solved"], e["cleared"], e["author"]), (2, False, "bob"))
        self.assertEqual(e["points"], 4 * (1 + 1))  # medium, 2 sinks: 1 + log2(2)
        # a claim for a challenge that did not change earns nothing
        _, none = contrib.award({"entries": []}, [pr(8, f"Solves: {B}")], self.base, cur, "now", self.cfg)
        self.assertEqual(none, [])

    def test_clearing_pays_a_bonus_and_is_idempotent(self):
        cur = doc([grp(B, "r", ["BL-5"], "hard", "rust")])
        led, new = contrib.award({"entries": []}, [pr(7, f"Solves: {A}")], self.base, cur, "now", self.cfg)
        self.assertTrue(new[0]["cleared"])
        self.assertEqual(new[0]["points"], 4 * (1 + 2) + 4)  # 4 sinks: 1 + log2(4); plus the clearing bonus
        led2, again = contrib.award(led, [pr(7, f"Solves: {A}")], self.base, cur, "later", self.cfg)
        self.assertEqual(again, [])
        self.assertEqual(len(led2["entries"]), 1)

    def test_a_sink_is_credited_once_in_merge_order(self):
        cur = doc([grp(B, "r", ["BL-5"], "hard", "rust")])
        prs = [pr(9, f"Solves: {A}", "late", "2026-11-02T00:00:00Z"), pr(8, f"Solves: {A}", "early", "2026-11-01T00:00:00Z")]
        led, new = contrib.award({"entries": []}, prs, self.base, cur, "now", self.cfg)
        self.assertEqual([e["author"] for e in new], ["early"])

    def test_bots_and_authorless_prs_get_nothing(self):
        cur = doc([grp(B, "r", ["BL-5"], "hard", "rust")])
        _, new = contrib.award({"entries": []}, [pr(1, f"Solves: {A}", "dependabot[bot]"), pr(2, f"Solves: {A}", "")], self.base, cur, "now", self.cfg)
        self.assertEqual(new, [])

    def test_badges_are_replayed_with_dates_and_core_contributor_needs_both(self):
        entries = []
        for i in range(5):
            entries.append({"id": f"{i}:x", "pr": i, "author": "bob", "merged_at": f"2026-11-0{i + 1}T00:00:00Z",
                            "points": 4, "sinks_solved": 2, "cleared": False, "difficulty": "medium", "lang": "python"})
        got = contrib.contributors(entries, self.cfg)[0]
        names = {b["id"] for b in got["badges"]}
        self.assertIn("first-light", names)
        self.assertIn("sharp-eye", names)            # 10 sinks on the fifth entry
        self.assertNotIn("core-contributor", names)  # 5 PRs but only 20 points
        entries[-1]["points"] = 40
        got = contrib.contributors(entries, self.cfg)[0]
        core = [b for b in got["badges"] if b["id"] == "core-contributor"]
        self.assertEqual(core[0]["earned_at"], "2026-11-05T00:00:00Z")

    def test_next_badge_reports_what_is_missing(self):
        entries = [{"id": "1:x", "pr": 1, "author": "amy", "merged_at": "2026-11-01T00:00:00Z", "points": 2,
                    "sinks_solved": 1, "cleared": False, "difficulty": "easy", "lang": "c"}]
        got = contrib.contributors(entries, self.cfg)[0]
        self.assertTrue(got["next"]["missing"])

    def test_badge_config_is_valid(self):
        cfg = contrib.load_badges()
        ids = [b["id"] for b in cfg["badges"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("core-contributor", ids)


class ScorecardTest(unittest.TestCase):
    def test_confusion_counts_and_owasp_style_score(self):
        labels = [
            {"file": "a.py", "line": 0, "vulnerable": True, "cwe": "78", "case": "1"},
            {"file": "b.py", "line": 0, "vulnerable": True, "cwe": "78", "case": "2"},
            {"file": "c.py", "line": 0, "vulnerable": False, "cwe": "78", "case": "3"},
            {"file": "d.py", "line": 0, "vulnerable": False, "cwe": "78", "case": "4"},
        ]
        advisories = [{"file_path": "a.py", "line": 1}, {"file_path": "c.py", "line": 1}]
        sc = scorecard("s", "python", match(labels, advisories))
        self.assertEqual((sc["tp"], sc["fn"], sc["fp"], sc["tn"]), (1, 1, 1, 1))
        self.assertEqual((sc["recall"], sc["fpr"], sc["score"]), (0.5, 0.5, 0.0))
        self.assertEqual(sc["categories"][0]["fn"], 1)


class CliTest(unittest.TestCase):
    def test_claims_verify_ledger_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            base = doc([grp(A, "r", ["BL-1", "BL-2"])])
            cur = doc([])
            (d / "base.json").write_text(json.dumps(base))
            (d / "cur.json").write_text(json.dumps(cur))
            (d / "body.md").write_text(f"Fixes a thing.\n\nSolves: {A}\n")
            self.assertEqual(contrib.main(["claims", "--body-file", str(d / "body.md"), "--baseline", str(d / "base.json"), "--out", str(d / "claims.json")]), 0)
            self.assertEqual(json.loads((d / "claims.json").read_text())["repos"], ["r"])
            code = contrib.main(["verify", "--baseline", str(d / "base.json"), "--current", str(d / "cur.json"),
                                 "--claims", str(d / "claims.json"), "--out", str(d / "res.json"), "--comment", str(d / "c.md")])
            self.assertEqual(code, 0)
            (d / "prs.json").write_text(json.dumps([pr(5, f"Solves: {A}")]))
            self.assertEqual(contrib.main(["ledger", "--prs", str(d / "prs.json"), "--baseline", str(d / "base.json"),
                                           "--current", str(d / "cur.json"), "--out", str(d / "ledger.json")]), 0)
            led = json.loads((d / "ledger.json").read_text())
            self.assertEqual(led["contributors"][0]["login"], "bob")


if __name__ == "__main__":
    unittest.main()
