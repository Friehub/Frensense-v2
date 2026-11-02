#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

"""Tests for `docs-site/scripts/check_announcements.py`."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from check_announcements import check

CHECK_SCRIPT = Path(__file__).resolve().parent / "check_announcements.py"
ROOT = Path(__file__).resolve().parent.parent.parent

BASE_ANN = {
    "id": "release-v0.8.0",
    "message": "Frensense v0.8.0 is out.",
    "display": "bar",
}


class CheckAnnouncementsTest(unittest.TestCase):
    """Unit tests for the per-announcement JSON validator `check()`."""

    def test_valid_bar_announcement_passes(self):
        self.assertEqual(check(dict(BASE_ANN)), [])

    def test_invalid_display(self):
        base = {"id": "a", "message": "m"}
        errors = check(dict(base, display="modal"))
        self.assertEqual(errors, ["display must be one of ['bar', 'popup']"])

    def test_popup_with_image(self):
        a = {"id": "a", "message": "m", "display": "popup",
             "image": {"src": "/x.svg", "alt": "d"}}
        self.assertEqual(check(a), [])

    def test_popup_image_root_scoped_paths_only(self):
        base = {"id": "a", "message": "m", "display": "popup"}
        self.assertEqual(
            check(dict(base, image={"src": "https://cdn.example/x.svg", "alt": "d"})), [])
        for src in ("//evil/x", "http://insecure/x", 42):
            a = dict(base, image={"src": src, "alt": "d"})
            self.assertEqual(check(a), ["image needs alt text and a src starting with / or https://"])

    def test_image_needs_alt(self):
        base = {"id": "a", "message": "m", "display": "popup"}
        a = dict(base, image={"src": "/x.svg"})
        self.assertEqual(check(a), ["image needs alt text and a src starting with / or https://"])

    def test_image_only_shown_by_popup(self):
        base = {"id": "a", "message": "m"}
        a = dict(base, display="bar", image={"src": "/x.svg", "alt": "d"})
        self.assertEqual(check(a), ["image is only shown by display 'popup'"])

    def test_bad_image_use_is_reported_twice(self):
        base = {"id": "a", "message": "m"}
        a = dict(base, display="bar", image={"src": "/x.svg"})
        self.assertEqual(
            check(a),
            ["image needs alt text and a src starting with / or https://",
             "image is only shown by display 'popup'"])

    def test_link_needs_text_and_safe_href(self):
        base = {"id": "a", "message": "m"}
        self.assertEqual(check(dict(base, link={"text": "t", "href": "/changelog"})), [])
        self.assertEqual(check(dict(base, link={"text": "t", "href": "https://frensense.com/x"})), [])
        for href in ("//evil/x", "http://insecure/x"):
            a = dict(base, link={"text": "t", "href": href})
            self.assertEqual(check(a), ["link needs text and an href starting with / or https://"])

    def test_link_needs_text(self):
        a = {"id": "a", "message": "m", "link": {"text": "", "href": "/x"}}
        self.assertEqual(check(a), ["link needs text and an href starting with / or https://"])


class CheckerMainTest(unittest.TestCase):
    """End-to-end checks of check_announcements.main() against temp files."""

    ANN = dict(BASE_ANN)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _client_json(self, items):
        path = self.root / "announcements.json"
        path.write_text(json.dumps({"announcements": items}), encoding="utf-8")
        return path

    def _client_js(self, items=None, export=False):
        path = self.root / "announce.js"
        if export:
            body = ", ".join(
                "{" + ", ".join(
                    f"{k}: '{item[k]}'" for k in ("id", "display", "message", "title")
                    if k in item) + "}"
                for item in items)
            path.write_text("export const announcements = [" + body + "]\n", encoding="utf-8")
        else:
            # The shipped embed is an IIFE that fetches the JSON at runtime;
            # the checker treats it as inert.
            path.write_text(
                "'use strict';\n"
                "(function () { fetch('/announcements.json').then(function (r) { return r.json() }) })();\n",
                encoding="utf-8",
            )
        return path

    def _internal_ts(self, items=None):
        path = self.root / "announcements.ts"
        if items is None:
            # The repo's real TS module is inert: it declares the type and
            # helpers, never a defineAnnouncements([...]) feed.
            path.write_text(
                "export type Announcement = { id: string; message: string }\n",
                encoding="utf-8",
            )
        else:
            body = ", ".join(
                "{" + ", ".join(
                    f"{k}: '{item[k]}'" for k in ("id", "display", "message", "title")
                    if k in item) + "}"
                for item in items)
            path.write_text(
                "declare function defineAnnouncements(xs: Announcement[]): Announcement[]\n"
                "export const announcements = defineAnnouncements([" + body + "])\n",
                encoding="utf-8",
            )
        return path

    def run_main(self, ts, js, json_items):
        env = dict(os.environ)
        env["ANNOUNCEMENTS_TS"] = str(self._internal_ts(ts))
        env["ANNOUNCEMENTS_JS"] = str(self._client_js(items=js, export=True) if js else self._client_js())
        env["ANNOUNCEMENTS_JSON"] = str(self._client_json(json_items))
        env["PYTHONWARNINGS"] = "ignore"
        return subprocess.run(
            [sys.executable, str(CHECK_SCRIPT)],
            capture_output=True, text=True, env=env, timeout=60,
        )

    def test_inert_ts_and_js_pass(self):
        # The shipped layout: a JSON feed with an inert TS module and an IIFE
        # embed. Nothing to cross-compare, but the JSON entries must validate.
        proc = self.run_main(None, None, [dict(self.ANN)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("OK:", proc.stdout)

    def test_invalid_json_entry_fails(self):
        bad = {"id": "x", "message": "m", "display": "modal"}
        proc = self.run_main(None, None, [bad])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("display must be one of", proc.stderr)

    def test_mismatched_managed_key_fails(self):
        # When TS and JS carry feed data, the checker compares the managed
        # keys (title, level, ...) against the JSON.
        differing = {"id": self.ANN["id"], "title": "Different",
                     "display": "bar", "message": self.ANN["message"]}
        proc = self.run_main([differing], [differing], [dict(self.ANN)])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("mismatch", proc.stderr)

    def test_ts_without_js_fails(self):
        proc = self.run_main([dict(self.ANN)], None, [dict(self.ANN)])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("id mismatch", proc.stderr)

    def test_duplicate_id_in_json_fails(self):
        dup = dict(self.ANN)
        path = self._client_json([dup, dup])
        env = dict(os.environ)
        env["ANNOUNCEMENTS_TS"] = str(self._internal_ts())
        env["ANNOUNCEMENTS_JS"] = str(self._client_js())
        env["ANNOUNCEMENTS_JSON"] = str(path)
        proc = subprocess.run(
            [sys.executable, str(CHECK_SCRIPT)],
            capture_output=True, text=True, env=env, timeout=60,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("duplicate", proc.stderr)

    def test_only_json_feed_passes_with_consistent_sources(self):
        # TS and JS carrying one matching entry with no managed-key conflict.
        item = dict(self.ANN)
        proc = self.run_main([item], [item], [item])
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
