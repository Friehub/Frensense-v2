#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Tests for the build-time docs translator.

Run directly (`python3 docs-site/scripts/test_translate_docs.py`) or through
`unittest`. No network: every test that needs a translator uses `identity`, so
the suite checks the pipeline's own guarantees - what is masked, what survives
translation, where links point - and never a model's output.

The strongest test here is `test_identity_round_trip_is_lossless`: it runs the
whole pipeline over the real corpus and asserts that an identity translation
reproduces the English source byte for byte, apart from the two changes the
pipeline is supposed to make (localized links, pinned heading ids). If any
line of any page is mis-classified - a table cell split wrong, a fence ended
early, a heading anchor misplaced - that test fails with the exact diff.
"""

import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import translate_docs as td

DOCS_ROOT = Path(__file__).resolve().parent.parent

# A page set small enough to state by hand: one file page, one directory index.
KNOWN = {"guide/cli.md", "corpus/index.md"}
PREFIX = "/zh"


def recorder():
    """A translate-one that records what it was asked and returns it unchanged."""
    seen: list[str] = []

    def record(text: str) -> str:
        seen.append(text)
        return text

    record.seen = seen  # type: ignore[attr-defined]
    return record


class MaskingTests(unittest.TestCase):
    def test_every_protected_span_round_trips(self):
        line = (
            "Run `frensense --json` then see [the docs](/guide/cli#options) and "
            '<span class="x">CWE-89</span> at https://example.com/a?b=c '
            "{#custom-id}"
        )
        unit = td.mask(line)
        restored = td.unmask(unit.text, unit.tokens)
        self.assertEqual(restored, line)
        # Every untranslatable *span* is gone from the payload. Prose inside an
        # HTML element is not a span: `<span>some prose</span>` masks the tags
        # and leaves the words, which is the point of translating it at all.
        for protected in (
            "frensense --json",
            "<span",
            "</span>",
            "https://example.com",
            "](/guide/cli#options)",
            "{#custom-id}",
        ):
            self.assertNotIn(protected, unit.text)

    def test_tokens_are_numbered_and_ordered(self):
        unit = td.mask("`a` and `b` and `c`")
        self.assertEqual(unit.text, "FZ0FZ and FZ1FZ and FZ2FZ")
        self.assertEqual(unit.tokens, ["`a`", "`b`", "`c`"])

    def test_a_dropped_token_fails_the_build(self):
        with self.assertRaises(td.TranslationError):
            td.unmask("FZ0FZ only", ["`a`", "`b`"])

    def test_an_invented_token_fails_the_build(self):
        with self.assertRaises(td.TranslationError):
            td.unmask("FZ0FZ and FZ1FZ", ["`a`"])

    def test_code_only_lines_are_not_worth_a_request(self):
        # `worth_translating` sees the masked payload, which is what would be
        # sent: a line that is nothing but code has no letters left.
        self.assertFalse(td.worth_translating(td.mask("`--json`").text))
        self.assertFalse(td.worth_translating(td.mask("| `a` | `b` |").text))
        self.assertTrue(td.worth_translating(td.mask("Scan a directory.").text))


class FenceTests(unittest.TestCase):
    def test_fenced_code_is_never_sent(self):
        body = "\n".join(
            [
                "Scan the tree:",
                "",
                "```bash",
                "rm -rf / # MUST-NOT-BE-TRANSLATED",
                "```",
                "",
                "~~~python",
                "print('also untranslated')",
                "~~~",
                "After the fence.",
            ]
        )
        record = recorder()
        out = td.translate_body(body, record, PREFIX, KNOWN)
        joined = "\n".join(record.seen)  # type: ignore[attr-defined]
        self.assertNotIn("MUST-NOT-BE-TRANSLATED", joined)
        self.assertNotIn("print(", joined)
        self.assertIn("Scan the tree:", joined)
        # The fences themselves survive verbatim.
        self.assertIn("```bash\nrm -rf / # MUST-NOT-BE-TRANSLATED\n```", out)
        self.assertIn("~~~python\nprint('also untranslated')\n~~~", out)

    def test_a_fence_with_a_longer_marker_is_not_closed_early(self):
        body = "````md\n```\ninner\n```\n````"
        record = recorder()
        out = td.translate_body(body, record, PREFIX, KNOWN)
        self.assertEqual(out, body)
        self.assertEqual(record.seen, [])  # type: ignore[attr-defined]


class LinkTests(unittest.TestCase):
    def test_links_to_translated_pages_are_localized(self):
        out = td.localize_links("[CLI](/guide/cli)", PREFIX, KNOWN)
        self.assertEqual(out, "[CLI](/zh/guide/cli)")

    def test_links_to_untranslated_pages_stay_english(self):
        for target in ("/challenges", "/blog/2026-10-09-post", "/v1/"):
            line = f"[x]({target})"
            self.assertEqual(td.localize_links(line, PREFIX, KNOWN), line)

    def test_a_directory_index_keeps_its_trailing_slash(self):
        # `/corpus/` and `/corpus` resolve differently; a rewrite must not
        # silently turn one into the other.
        self.assertEqual(
            td.localize_links("[c](/corpus/)", PREFIX, KNOWN), "[c](/zh/corpus/)"
        )

    def test_fragments_and_queries_survive(self):
        self.assertEqual(
            td.localize_links("[o](/guide/cli#options)", PREFIX, KNOWN),
            "[o](/zh/guide/cli#options)",
        )
        self.assertEqual(
            td.localize_links("[o](/guide/cli?x=1)", PREFIX, KNOWN),
            "[o](/zh/guide/cli?x=1)",
        )

    def test_the_site_root_maps_to_the_locale_root(self):
        self.assertEqual(td.localize_links("[h](/)", PREFIX, KNOWN), "[h](/zh/)")

    def test_absolute_urls_are_left_alone(self):
        line = "[x](https://example.com/guide/cli)"
        self.assertEqual(td.localize_links(line, PREFIX, KNOWN), line)

    def test_an_image_is_not_mistaken_for_a_page_link(self):
        line = "![cover](/covers/blog.png)"
        self.assertEqual(td.localize_links(line, PREFIX, KNOWN), line)


class FrontmatterTests(unittest.TestCase):
    def test_values_are_translated_and_keys_are_not(self):
        block = "\n".join(
            [
                "---",
                "title: Getting started",
                'description: "A short guide to the first scan"',
                "outline: deep",
                "sidebar: false",
                "---",
                "",
            ]
        )
        out = td.translate_frontmatter(block, lambda text: f"<{text}>")
        self.assertIn("title: <Getting started>", out)
        self.assertIn('description: "<A short guide to the first scan>"', out)
        self.assertIn("outline: deep", out)  # structural key, untouched
        self.assertIn("sidebar: false", out)
        self.assertTrue(out.startswith("---\n"))

    def test_paths_and_urls_are_not_translated(self):
        block = "---\nlink: /guide/cli\nhero: https://example.com/x\n---\n"
        out = td.translate_frontmatter(block, lambda text: f"<{text}>")
        self.assertEqual(out, block)


class TableTests(unittest.TestCase):
    def test_pipes_survive_and_cells_are_translated(self):
        line = "| `frensense [path]` | Scan a directory and print findings. |"
        out = td.translate_table_row(line, lambda text: text.upper(), PREFIX, KNOWN)
        self.assertEqual(out.count("|"), 3)
        self.assertIn("SCAN A DIRECTORY AND PRINT FINDINGS.", out)
        self.assertIn("`frensense [path]`", out)  # masked, so untouched

    def test_a_pipe_inside_code_does_not_split_the_row(self):
        line = "| `a || b` | Shell or in a pipe. |"
        # The code pipe must be masked before the split, or the row is cut in
        # half and the translator is handed a dangling backtick.
        masked = td.mask(line).text
        self.assertEqual(len(re.split(r"(?<!\\)\|", masked)), 4)
        out = td.translate_table_row(line, lambda text: text, PREFIX, KNOWN)
        self.assertEqual(out, line)


class SlugTests(unittest.TestCase):
    def test_headings_get_the_english_id(self):
        out = td.translate_body("## Options\n", lambda text: "选项", PREFIX, KNOWN)
        self.assertEqual(out, "## 选项 {#options}\n")

    def test_inline_code_keeps_its_underscores(self):
        self.assertEqual(td.slugify("`frensense_audit`"), "frensense-audit")
        self.assertEqual(td.slugify("`LearnedFactEntry::Sink`"), "learnedfactentry-sink")

    def test_a_leading_digit_is_escaped(self):
        self.assertEqual(td.slugify("1. Dangerous Sinks"), "_1-dangerous-sinks")

    def test_link_labels_count_and_targets_do_not(self):
        self.assertEqual(td.slugify("See [the guide](/guide/cli)"), "see-the-guide")

    def test_duplicate_headings_get_the_same_suffix_vitepress_would_use(self):
        body = "## Example\n\n## Example\n\n## Example\n"
        out = td.translate_body(body, lambda text: text, PREFIX, KNOWN)
        self.assertEqual(
            out,
            "## Example {#example}\n\n## Example {#example-1}\n\n## Example {#example-2}\n",
        )

    def test_an_explicit_id_is_preserved(self):
        out = td.translate_body("## Options {#custom}\n", lambda text: text, PREFIX, KNOWN)
        self.assertEqual(out, "## Options {#custom}\n")

    def test_no_anchors_mode_leaves_headings_bare(self):
        out = td.translate_body("## Options\n", lambda text: text, PREFIX, KNOWN, anchors=False)
        self.assertEqual(out, "## Options\n")


class CacheTests(unittest.TestCase):
    def test_a_second_run_asks_the_provider_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = td.Cache(Path(tmp) / "zh.json")
            calls: list[str] = []

            class Counting(td.Provider):
                cacheable = True

                def translate(self, text, locale):
                    calls.append(text)
                    return text.upper()

            translator = td.Translator(Counting(), cache, "zh", 1)
            translator.prefetch(["Scan the tree."])
            self.assertEqual(translator("Scan the tree."), "SCAN THE TREE.")
            self.assertEqual(len(calls), 1)
            cache.save()

            # A fresh process with the same cache must not re-request the unit.
            reloaded = td.Cache(Path(tmp) / "zh.json")
            again = td.Translator(Counting(), reloaded, "zh", 1)
            again.prefetch(["Scan the tree."])
            self.assertEqual(again("Scan the tree."), "SCAN THE TREE.")
            self.assertEqual(len(calls), 1)

    def test_identity_results_are_never_cached(self):
        # An identity run must not poison the cache with English text.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "zh.json"
            cache = td.Cache(path)
            translator = td.Translator(td.Provider(), cache, "zh", 1)
            translator.prefetch(["Scan the tree."])
            translator.close()
            self.assertFalse(path.exists())

    def test_the_cache_is_keyed_by_content_not_position(self):
        first, second = td.Cache(Path("/nonexistent/a.json")), td.Cache(Path("/nonexistent/b.json"))
        first.put("Scan the tree.", "扫描目录树。")
        second.put("Scan the tree.", "扫描目录树。")
        self.assertEqual(first.entries, second.entries)


class CorpusTests(unittest.TestCase):
    """Whole-pipeline checks against the real pages."""

    def setUp(self):
        self.pages = td.collect_pages(DOCS_ROOT)
        self.known = {str(page.relative_to(DOCS_ROOT)) for page in self.pages}

    def test_the_corpus_is_not_empty(self):
        self.assertGreater(len(self.pages), 10)
        names = {str(page.relative_to(DOCS_ROOT)) for page in self.pages}
        self.assertIn("index.md", names)
        self.assertIn("guide/cli.md", names)
        # Excluded on purpose: blog prose, the regenerated changelog, the
        # data-driven challenge board.
        self.assertNotIn("changelog.md", names)
        self.assertNotIn("challenges.md", names)
        self.assertFalse(any(name.startswith("blog/") for name in names))

    def test_identity_round_trip_is_lossless(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp) / "zh"
            state = td.main(
                [
                    "--locale", "zh",
                    "--provider", "identity",
                    "--docs-root", str(DOCS_ROOT),
                    "--out", str(out_root),
                    "--cache", str(Path(tmp) / "cache.json"),
                ]
            )
            self.assertEqual(state, 0)

            compared = 0
            for page in self.pages:
                rel = page.relative_to(DOCS_ROOT)
                produced = (out_root / rel).read_text(encoding="utf-8")
                produced = produced.replace(f"]({PREFIX}/", "](/")
                produced = re.sub(r" \{#[^}]*\}$", "", produced, flags=re.M)
                self.assertEqual(
                    produced,
                    page.read_text(encoding="utf-8"),
                    f"{rel} is not an exact identity translation",
                )
                compared += 1
            self.assertEqual(compared, len(self.pages))

    def test_every_pinned_anchor_matches_the_id_vitepress_generated(self):
        """Guards against a VitePress upgrade silently breaking every anchor."""
        dist = DOCS_ROOT / ".vitepress" / "dist"
        if not dist.is_dir():
            self.skipTest("docs-site/.vitepress/dist not built")

        for page in self.pages:
            rel = page.relative_to(DOCS_ROOT)
            html = dist / rel.with_suffix(".html")
            if not html.is_file():
                continue
            expected = re.findall(r'<h[1-6] id="([^"]+)"', html.read_text(encoding="utf-8"))
            produced = td.translate_body(
                td.split_frontmatter(page.read_text(encoding="utf-8"))[1],
                lambda text: text,
                PREFIX,
                self.known,
            )
            pinned = re.findall(r" \{#([^}]*)\}$", produced, flags=re.M)
            self.assertEqual(pinned, expected, f"{rel} anchors diverge from VitePress")

    def test_translated_pages_never_link_to_an_untranslated_locale_page(self):
        """A `/zh/...` link must point at a page the locale tree actually has."""
        for page in self.pages:
            rel = page.relative_to(DOCS_ROOT)
            produced = td.translate_body(
                td.split_frontmatter(page.read_text(encoding="utf-8"))[1],
                lambda text: text,
                PREFIX,
                self.known,
            )
            for target in re.findall(r"\]\((/zh/[^)#\s]*)\)", produced):
                stem = target[len(PREFIX) + 1 :].rstrip("/")
                candidates = {"index.md"} if not stem else {f"{stem}.md", f"{stem}/index.md"}
                self.assertTrue(
                    candidates & self.known,
                    f"{rel} links to {target}, which has no translated page",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
