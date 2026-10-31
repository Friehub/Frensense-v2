#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Tests for scripts/owasp_benchmark.py using a fake engine (no cargo build,
no network). Run: python3 -m unittest scripts/test_owasp_scorer.py -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCORER = Path(__file__).resolve().parent.parent / "suites" / "owasp.py"

FAKE_ENGINE = r'''#!/usr/bin/env python3
import json, os, sys
if "--version" in sys.argv:
    print("frensense 0.0.0-fake"); sys.exit(0)
name = os.path.basename(next(a for a in sys.argv[1:] if a.endswith(".py")))[:-3]
B = {
    "A_vul":  (0, [["taint", "resource"]]),                # CWE-22 vuln, unattributed finding
    "B_vul":  (0, [["checker", "weak_hash", "policy"]]),   # CWE-328 vuln, built-in tag map
    "C_safe": (0, [["taint", "resource"]]),                # CWE-22 safe, unattributed finding
    "D_safe": (0, []),                                     # CWE-22 safe, clean
    "E_vul":  (2, []),                                     # CWE-89 vuln, engine error exit
    "F_vul":  (0, [["taint", "xss"]]),                     # CWE-79 vuln, role tag xss
    "G_safe": (0, [["taint", "CWE-22"]]),                  # CWE-79 safe, finding for another CWE
    "H_vul":  (1, [["taint", "CWE-22"]]),                  # CSV id 022, explicit tag, exit 1
}
code, adv = B.get(name, (0, []))
if os.environ.get("FAKE_REGRESS") == "1" and name == "B_vul":
    adv = []
print(json.dumps([{"title": "t", "tags": t} for t in adv]))
sys.exit(code)
'''

CSV = """# name, category, real_vulnerability, cwe
A_vul,pathtraver,true,22
B_vul,hash,true,328
C_safe,pathtraver,false,22
D_safe,pathtraver,false,22
E_vul,sqli,true,89
F_vul,xss,true,79
G_safe,xss,false,79
H_vul,pathtraver,true,022
"""


class ScorerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        (root / "testcode").mkdir()
        for line in CSV.splitlines()[1:]:
            (root / "testcode" / f"{line.split(',')[0]}.py").write_text("# fixture\n")
        (root / "expectedresults-0.1.csv").write_text(CSV)
        engine = root / "fake_frensense.py"
        engine.write_text(FAKE_ENGINE)
        engine.chmod(0o755)
        cls.root, cls.engine = root, engine

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def run_scorer(self, *extra, env=None):
        out = self.root / "scorecard.json"
        out.unlink(missing_ok=True)
        e = {**os.environ, **(env or {})}
        e.pop("FRENSENSE_CORPUS_BUNDLE", None)
        proc = subprocess.run(
            [sys.executable, str(SCORER), "--bin", str(self.engine),
             "--owasp-csv", str(self.root / "expectedresults-0.1.csv"),
             "--owasp-testcode", str(self.root / "testcode"),
             "--workers", "2", "--json-out", str(out), *extra],
            capture_output=True, text=True, env=e, cwd=self.root,
        )
        card = json.loads(out.read_text()) if out.exists() else None
        return proc, card

    def test_conservative_is_lower_bound_on_tpr_upper_bound_on_fpr(self):
        proc, card = self.run_scorer("--allow-errors")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        t = card["total"]
        self.assertEqual((t["TP"], t["FN"], t["FP"], t["TN"], t["ERR"]), (3, 1, 1, 2, 1))
        legacy = card["legacy_any"]["total"]
        self.assertEqual((legacy["TP"], legacy["FP"]), (4, 2))

    def test_cwe_mode_ignores_unattributed_on_both_sides(self):
        _, card = self.run_scorer("--match", "cwe", "--allow-errors")
        t = card["total"]
        self.assertEqual((t["TP"], t["FN"], t["FP"], t["TN"]), (3, 1, 0, 3))

    def test_any_mode_reproduces_legacy_scoring(self):
        _, card = self.run_scorer("--match", "any", "--allow-errors")
        t = card["total"]
        self.assertEqual((t["TP"], t["FN"], t["FP"], t["TN"]), (4, 0, 2, 1))

    def test_wrong_cwe_finding_is_not_a_true_positive(self):
        _, card = self.run_scorer("--allow-errors")
        g = next(c for c in card["cases"] if c["id"] == "G_safe")
        self.assertEqual((g["class"], g["class_any"]), ("TN", "FP"))

    def test_scan_error_is_err_not_clean_and_fails_the_run(self):
        proc, card = self.run_scorer()
        self.assertEqual(proc.returncode, 3)
        e = next(c for c in card["cases"] if c["id"] == "E_vul")
        self.assertEqual(e["class"], "ERR")
        self.assertEqual(card["by_cwe"]["CWE-89"]["FN"], 0)

    def test_exit_code_1_with_findings_is_not_an_error(self):
        _, card = self.run_scorer("--allow-errors")
        h = next(c for c in card["cases"] if c["id"] == "H_vul")
        self.assertEqual(h["class"], "TP")
        self.assertEqual(h["cwe"], "CWE-22")  # '022' normalised

    def test_baseline_regression_gate(self):
        base = self.root / "base.json"
        _, card = self.run_scorer("--allow-errors")
        base.write_text(json.dumps(card))
        proc, _ = self.run_scorer("--allow-errors", "--baseline", str(base),
                                  "--fail-on-regression", env={"FAKE_REGRESS": "1"})
        self.assertEqual(proc.returncode, 4)
        self.assertIn("CWE-328 TPR fell", proc.stdout)
        proc, _ = self.run_scorer("--allow-errors", "--baseline", str(base),
                                  "--fail-on-regression")
        self.assertEqual(proc.returncode, 0)

    def test_baseline_with_different_match_mode_is_rejected(self):
        base = self.root / "base_mode.json"
        _, card = self.run_scorer("--allow-errors")
        base.write_text(json.dumps(card))
        proc, _ = self.run_scorer("--allow-errors", "--match", "any", "--baseline", str(base))
        self.assertEqual(proc.returncode, 1)

    def test_report_does_not_claim_bare_when_a_bundle_is_auto_discoverable(self):
        md = self.root / "report.md"
        ambient = self.root / "frensense-corpus.frc"
        ambient.write_text("x")
        try:
            self.run_scorer("--allow-errors", "--md-out", str(md))
        finally:
            ambient.unlink()
        text = md.read_text()
        self.assertIn("run may not be bare", text)
        self.assertNotIn("zero bundle modifications", text)


if __name__ == "__main__":
    unittest.main()
