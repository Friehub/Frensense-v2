#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from suites.blindness import (
    generate_markdown_card,
    update_history_json,
    update_csv_sheet,
)


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


if __name__ == "__main__":
    unittest.main()
