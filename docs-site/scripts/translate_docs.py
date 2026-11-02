#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Translate the VitePress docs into a locale tree, at build time.

English markdown is the only source of truth. This script walks the pages worth
translating, sends their prose to a machine-translation endpoint, and writes a
parallel tree (`docs-site/<locale>/...`) that VitePress serves as real,
indexable pages per language.

Two invariants shape the design:

* **Code is never sent for translation.** Fenced blocks, inline code, HTML
  tags, Vue components, URLs and heading ids are masked into `FZ<n>FZ` tokens
  before a request leaves the process, and the token count is verified on the
  way back. A translator that eats a token fails the build instead of shipping
  a mangled page.
* **Nothing is translated twice.** Results are cached by the SHA-256 of the
  masked English text, so a rebuild only pays for paragraphs that changed. The
  cache is the reviewable artifact: a diff shows `English -> Chinese` pairs,
  and correcting a bad translation means editing the cache.

Usage:
    translate_docs.py --locale zh --endpoint http://127.0.0.1:5000
    translate_docs.py --locale zh --check          # drift report, no writes

Providers:
    libretranslate     POST {endpoint}/translate      (self-hosted, no vendor egress)
    translate-service  POST {endpoint}/translate.json (zvo translate.service)
    identity           returns input unchanged; used by the test suite
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

DOCS_ROOT = Path(__file__).resolve().parent.parent

# Pages translated into every locale. Deliberately excluded: blog/ (dated, high
# churn), changelog (regenerated every release), challenges (prose lives in
# board.json). Every link to an excluded page keeps pointing at English.
TRANSLATED_DIRS = ("guide", "architecture", "corpus")
TRANSLATED_FILES = ("index.md", "bundles.md")

# Frontmatter keys holding structure or machine data, never prose.
STRUCTURAL_KEYS = frozenset(
    {
        "layout",
        "date",
        "link",
        "href",
        "image",
        "icon",
        "src",
        "order",
        "weight",
        "aside",
        "outline",
        "sidebar",
        "editlink",
        "lastupdated",
        "head",
    }
)

# VitePress locale key -> (BCP-47 tag, provider language id, translate.service id).
LOCALES = {
    "zh": ("zh-Hans", "zh", "chinese_simplified"),
    "ja": ("ja", "ja", "japanese"),
    "de": ("de", "de", "deutsch"),
    "es": ("es", "es", "spanish"),
    "fr": ("fr", "fr", "french"),
    "pt": ("pt-BR", "pt", "portuguese"),
    "it": ("it", "it", "italian"),
    "ru": ("ru", "ru", "russian"),
    "ko": ("ko", "ko", "korean"),
}

TOKEN = re.compile(r"FZ(\d+)FZ", re.IGNORECASE)
FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})")
HEADING = re.compile(r"^(#{1,6})(\s+)(.*?)(\s*)$")
LIST_ITEM = re.compile(r"^(\s*(?:[-*+]|\d+[.)])\s+)(.*)$")
BLOCKQUOTE = re.compile(r"^(\s*>+\s?)(.*)$")
CONTAINER = re.compile(r"^(:{3,})\s*([A-Za-z-]*)\s*(.*)$")
TABLE_ROW = re.compile(r"^\s*\|")
TABLE_SEPARATOR = re.compile(r"^\s*\|?[\s:|-]+\|?\s*$")
FRONTMATTER_KEY = re.compile(r"^(\s*(?:-\s+)?)([A-Za-z_][\w-]*)(:\s*)(.*?)(\s*)$")
EXPLICIT_ID = re.compile(r"\s*\{#[^}]*\}\s*$")

# VitePress' heading-id alphabet, copied from `vitepress/dist/node`: combining
# marks and control characters are deleted, and this class of punctuation
# collapses to a single dash.
COMBINING = re.compile(r"[\u0300-\u036F]")
CONTROL = re.compile(r"[\u0000-\u001f]")
SPECIAL = re.compile(
    r"[\s~`!@#$%^&*()\-_+=\[\]{}|\\;:\"'\u201c\u201d\u2018\u2019<>,.?/]+"
)
# Placeholder for inline code while punctuation is normalised.
SLOT = re.compile(r"\x00(\d+)\x00")

# Inline constructs whose contents must not reach the translator.
MASKED = (
    re.compile(r"(`+)(?:(?!\1).)*?\1"),          # inline code
    re.compile(r"<!--.*?-->"),                    # html comment
    re.compile(r"</?[A-Za-z][^>]*>"),             # html / Vue component
    re.compile(r"\]\([^)\s]*(?:\s+\"[^\"]*\")?\)"),  # the target half of a link
    re.compile(r"https?://[^\s)\]]+"),            # bare url
    re.compile(r"\{[#:][^}]*\}"),                 # heading id / inline attrs
)


class TranslationError(RuntimeError):
    """The endpoint returned something we will not ship."""


@dataclass
class Unit:
    """A string split into translatable text and masked, untouchable spans."""

    text: str
    tokens: list[str] = field(default_factory=list)


def mask(text: str) -> Unit:
    """Replace every untranslatable span with an ordered `FZ<n>FZ` token."""
    unit = Unit(text=text)

    def stash(match: re.Match[str]) -> str:
        unit.tokens.append(match.group(0))
        return f"FZ{len(unit.tokens) - 1}FZ"

    masked = text
    for pattern in MASKED:
        masked = pattern.sub(stash, masked)
    unit.text = masked
    return unit


def unmask(masked: str, tokens: list[str]) -> str:
    """Put the original spans back, refusing to guess when one is missing."""
    seen: set[int] = set()

    def restore(match: re.Match[str]) -> str:
        index = int(match.group(1))
        if index >= len(tokens):
            raise TranslationError(f"translator invented token FZ{index}FZ")
        seen.add(index)
        return tokens[index]

    restored = TOKEN.sub(restore, masked)
    missing = set(range(len(tokens))) - seen
    if missing:
        raise TranslationError(f"translator dropped token(s) {sorted(missing)}")
    return restored


def worth_translating(masked: str) -> bool:
    """Is there prose left once the code, urls and ids are removed?"""
    plain = TOKEN.sub(" ", masked)
    letters = sum(1 for char in plain if char.isalpha())
    return letters >= 4 and letters / max(len(plain), 1) > 0.3


def inline_text(markdown: str) -> str:
    """The text VitePress' `getTokensText` sees: `text` + `code_inline` only.

    That means an image contributes nothing (its alt text lives on an `image`
    token), a link contributes its label but not its target, and emphasis
    markers are delimiter tokens rather than text. Reproducing the split
    matters: `` `frensense_audit` `` keeps its underscore, while `a_b` written
    as prose loses it to the punctuation pass.
    """
    code: list[str] = []

    def keep(match: re.Match[str]) -> str:
        code.append(match.group(2))
        return f"\x00{len(code) - 1}\x00"

    text = re.sub(r"(`+)(.+?)\1", keep, markdown)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\[[^\]]*\]", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = (
        text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    return SLOT.sub(lambda slot: code[int(slot.group(1))], text)


def slugify(heading: str) -> str:
    """The id VitePress generates for a heading, byte for byte.

    Translated headings are pinned to the *English* id (`## 快速开始
    {#getting-started}`), so `#getting-started` links keep resolving after a
    page is translated. That only works if this is exactly
    `vitepress/dist/node`'s `slugify`; the test suite compares this function
    against the ids in the built English HTML, so a VitePress upgrade that
    changes the algorithm fails a test instead of silently breaking anchors.
    """
    text = unicodedata.normalize("NFKD", inline_text(heading))
    text = COMBINING.sub("", text)
    text = CONTROL.sub("", text)
    text = SPECIAL.sub("-", text)
    text = re.sub(r"-{2,}", "-", text)
    text = re.sub(r"^-+|-+$", "", text)
    text = re.sub(r"^(\d)", r"_\1", text)
    return text.lower()


def split_frontmatter(text: str) -> tuple[str, str]:
    if not text.startswith("---\n"):
        return "", text
    end = text.find("\n---\n", 4)
    if end == -1:
        return "", text
    return text[: end + 5], text[end + 5 :]


def translate_frontmatter(block: str, translate_one) -> str:
    """Translate prose *values* only; keys, paths, dates and links stay put."""

    def rewrite(match: re.Match[str]) -> str:
        prefix, key, colon, value, trailing = match.groups()
        if key.lower() in STRUCTURAL_KEYS or not value:
            return match.group(0)
        quote = value[0] if value[0] in "\"'" else ""
        body = value.strip(quote)
        if body.startswith(("/", "http", "#")) or not worth_translating(body):
            return match.group(0)
        return f"{prefix}{key}{colon}{quote}{translate_one(body)}{quote}{trailing}"

    return "\n".join(
        FRONTMATTER_KEY.sub(rewrite, line) if line.strip() else line
        for line in block.split("\n")
    )


def localize_links(text: str, prefix: str, known: set[str]) -> str:
    """Point root-absolute links at the translated tree.

    `/guide/cli` in an English page becomes `/zh/guide/cli` in the Chinese one;
    a link to a page we do not translate (`/challenges`, `/blog/...`) is left
    alone so it cannot become a 404.
    """

    def rewrite(match: re.Match[str]) -> str:
        target = match.group(1)
        if not target.startswith("/") or target.startswith("//"):
            return match.group(0)
        path = target.split("#", 1)[0].split("?", 1)[0]
        if path in ("", "/"):
            return f"]({prefix}/)"
        stem = path.strip("/")
        # Keep the author's trailing slash: `/corpus/` is a directory index and
        # `/corpus` is a file, and VitePress resolves them differently.
        slash = "/" if path.endswith("/") else ""
        if f"{stem}.md" in known:
            return f"]({prefix}/{stem}{target[len(path):]})"
        if f"{stem}/index.md" in known:
            return f"]({prefix}/{stem}/{target[len(path):]})"
        return match.group(0)

    return re.sub(r"\]\((/[^)\s]*)\)", rewrite, text)


def translate_prose(text: str, translate_one, prefix: str, known: set[str]) -> str:
    """The one path a prose payload takes: localize links, mask, translate."""
    unit = mask(localize_links(text, prefix, known))
    return unmask(translate_one(unit.text), unit.tokens)


def translate_table_row(line: str, translate_one, prefix: str, known: set[str]) -> str:
    """Translate each cell of a `| a | b |` row, never the pipes.

    Masking happens *before* the split: a table cell can legitimately contain
    inline code with a pipe in it (`` `a || b` ``), and splitting first would
    cut that code in half and hand the translator a dangling backtick.
    """
    unit = mask(localize_links(line, prefix, known))
    cells = re.split(r"(?<!\\)\|", unit.text)
    translated = "|".join(
        translate_one(cell) if worth_translating(cell) else cell for cell in cells
    )
    return unmask(translated, unit.tokens)


def unique_slug(slug: str, ids: dict[str, bool]) -> str:
    """The `markdown-it-anchor` dedupe: `slug`, then `slug-1`, `slug-2`, ..."""
    if slug in ids:
        index = 1
        while f"{slug}-{index}" in ids:
            index += 1
        slug = f"{slug}-{index}"
    ids[slug] = True
    return slug


def translate_body(
    body: str,
    translate_one,
    prefix: str,
    known: set[str],
    anchors: bool = True,
) -> str:
    """Walk markdown line by line, translating only the prose payloads."""
    out: list[str] = []
    fence: str | None = None
    # Heading ids already emitted on this page, so a duplicate English heading
    # gets the same `-1` suffix VitePress would have given it.
    ids: dict[str, bool] = {}

    for line in body.split("\n"):
        if fence is not None:
            out.append(line)
            if line.strip().startswith(fence):
                fence = None
            continue

        opener = FENCE.match(line)
        if opener:
            fence = opener.group(2)
            out.append(line)
            continue

        if not line.strip() or TABLE_SEPARATOR.match(line):
            out.append(line)
            continue

        heading = HEADING.match(line)
        if heading:
            hashes, space, text, _ = heading.groups()
            explicit = ""
            if (suffix := EXPLICIT_ID.search(text)) is not None:
                explicit, text = suffix.group(0), text[: suffix.start()]
                if (named := re.match(r"\s*\{#([^}]*)\}\s*$", explicit)) is not None:
                    ids[named.group(1)] = True
            translated = translate_prose(text, translate_one, prefix, known)
            anchor = explicit
            if not anchor and anchors:
                slug = slugify(text)
                if slug:
                    anchor = f" {{#{unique_slug(slug, ids)}}}"
            out.append(f"{hashes}{space}{translated}{anchor}")
            continue

        if TABLE_ROW.match(line):
            out.append(translate_table_row(line, translate_one, prefix, known))
            continue

        matched = False
        for pattern in (LIST_ITEM, BLOCKQUOTE):
            item = pattern.match(line)
            if item:
                lead, payload = item.groups()
                out.append(lead + translate_prose(payload, translate_one, prefix, known))
                matched = True
                break
        if matched:
            continue

        container = CONTAINER.match(line)
        if container:
            marks, kind, title = container.groups()
            if not title.strip():
                out.append(line)
            else:
                translated = translate_prose(title, translate_one, prefix, known)
                out.append(f"{marks} {kind} {translated}")
            continue

        out.append(translate_prose(line, translate_one, prefix, known))

    return "\n".join(out)


def collect_pages(root: Path) -> list[Path]:
    pages = [root / name for name in TRANSLATED_FILES if (root / name).is_file()]
    for directory in TRANSLATED_DIRS:
        pages.extend(sorted((root / directory).rglob("*.md")))
    return sorted(pages)


class Cache:
    """SHA-256 of the masked English -> translated text, per locale."""

    def __init__(self, path: Path):
        self.path = path
        self.entries: dict[str, str] = {}
        if path.is_file():
            self.entries = json.loads(path.read_text(encoding="utf-8")).get("entries", {})
        self.added = 0

    @staticmethod
    def key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get(self, text: str) -> str | None:
        return self.entries.get(self.key(text))

    def put(self, text: str, translated: str) -> None:
        self.entries[self.key(text)] = translated
        self.added += 1

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "entries": dict(sorted(self.entries.items()))}
        self.path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


class Provider:
    """A translation endpoint. One string in, one string out."""

    name = "identity"
    cacheable = False

    def translate(self, text: str, locale: str) -> str:
        return text

    def close(self) -> None:
        return None


class HttpProvider(Provider):
    name = "http"
    cacheable = True

    def __init__(self, endpoint: str, api_key: str, workers: int):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.workers = workers

    def _post(self, request: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:400]
            raise TranslationError(f"{self.name}: HTTP {error.code}: {detail}") from error
        except urllib.error.URLError as error:
            raise TranslationError(
                f"{self.name}: cannot reach {request.full_url}: {error}"
            ) from error


class LibreTranslate(HttpProvider):
    name = "libretranslate"

    def translate(self, text: str, locale: str) -> str:
        payload = {"q": text, "source": "en", "target": LOCALES[locale][1], "format": "text"}
        if self.api_key:
            payload["api_key"] = self.api_key
        request = urllib.request.Request(
            f"{self.endpoint}/translate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._post(request).get("translatedText", "")


class TranslateService(HttpProvider):
    """zvo translate.service: form-encoded, `text` is a JSON array."""

    name = "translate-service"

    def translate(self, text: str, locale: str) -> str:
        body = urllib.parse.urlencode(
            {"to": LOCALES[locale][2], "text": json.dumps([text])}
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.endpoint}/translate.json",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        texts = self._post(request).get("text") or []
        return texts[0] if texts else ""


def make_provider(args) -> Provider:
    if args.provider == "identity":
        return Provider()
    if not args.endpoint:
        raise SystemExit(f"--provider {args.provider} needs --endpoint")
    if args.provider == "libretranslate":
        return LibreTranslate(args.endpoint, args.api_key, args.workers)
    return TranslateService(args.endpoint, args.api_key, args.workers)


class Translator:
    """Cache in front of the provider; one request per distinct unit."""

    def __init__(self, provider: Provider, cache: Cache, locale: str, workers: int):
        self.provider = provider
        self.cache = cache
        self.locale = locale
        self.workers = workers
        self.ready: dict[str, str] = {}
        self.pool: ThreadPoolExecutor | None = None

    def prefetch(self, units: list[str]) -> None:
        """Translate every distinct unit that is not cached yet, in parallel."""
        wanted = sorted(
            {unit for unit in units if worth_translating(unit) and self.cache.get(unit) is None}
        )
        if not wanted:
            return
        self.pool = ThreadPoolExecutor(max_workers=self.workers)
        futures = {unit: self.pool.submit(self._fetch, unit) for unit in wanted}
        for unit, future in futures.items():
            self.ready[unit] = future.result()

    def _fetch(self, text: str) -> str:
        translated = self.provider.translate(text, self.locale)
        if not translated.strip():
            raise TranslationError(f"empty translation for {text[:60]!r}")
        if self.provider.cacheable:
            self.cache.put(text, translated)
        return translated

    def __call__(self, text: str) -> str:
        if not text.strip():
            return text
        cached = self.cache.get(text)
        if cached is not None:
            return cached
        if text in self.ready:
            return self.ready[text]
        return self._fetch(text)

    def close(self) -> None:
        if self.pool is not None:
            self.pool.shutdown(wait=True)


def dry_run(pages, root, prefix, known) -> list[str]:
    """Collect exactly the units the real pass will ask for.

    Both passes call the same two functions, so the recorded list cannot drift
    from what translation later requests - which is what makes `prefetch` a
    parallelization detail rather than a second source of truth.
    """
    recorded: list[str] = []

    def record(text: str) -> str:
        recorded.append(text)
        return text

    for page in pages:
        front, body = split_frontmatter(page.read_text(encoding="utf-8"))
        if front:
            translate_frontmatter(front, record)
        translate_body(body, record, prefix, known)
    return recorded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--locale", required=True, choices=sorted(LOCALES))
    parser.add_argument(
        "--provider",
        default="libretranslate",
        choices=("libretranslate", "translate-service", "identity"),
    )
    parser.add_argument("--endpoint", default="")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--docs-root", type=Path, default=DOCS_ROOT)
    parser.add_argument("--out", type=Path, default=None, help="default: <docs-root>/<locale>")
    parser.add_argument("--cache", type=Path, default=None, help="default: <docs-root>/i18n/<locale>.json")
    parser.add_argument("--check", action="store_true", help="report drift and exit 1")
    parser.add_argument("--no-anchors", action="store_true", help="do not pin heading ids")
    args = parser.parse_args(argv)

    root: Path = args.docs_root
    prefix = f"/{args.locale}"
    out_root = args.out or root / args.locale
    cache_path = args.cache or root / "i18n" / f"{args.locale}.json"

    pages = collect_pages(root)
    known = {str(page.relative_to(root)) for page in pages}
    cache = Cache(cache_path)

    units = dry_run(pages, root, prefix, known)
    if args.check:
        missing = [unit for unit in dict.fromkeys(units) if cache.get(unit) is None]
        total = len(set(units))
        print(f"{args.locale}: {len(missing)} of {total} units need translation")
        for unit in missing[:10]:
            print(f"  {unit[:100]}")
        return 1 if missing else 0

    provider = make_provider(args)
    translator = Translator(provider, cache, args.locale, args.workers)
    translator.prefetch(units)

    written = 0
    for page in pages:
        front, body = split_frontmatter(page.read_text(encoding="utf-8"))
        localized_front = translate_frontmatter(front, translator) if front else ""
        localized_body = translate_body(
            body, translator, prefix, known, anchors=not args.no_anchors
        )
        target = out_root / page.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(localized_front + localized_body, encoding="utf-8")
        written += 1

    translator.close()
    provider.close()
    if provider.cacheable:
        cache.save()
    print(
        f"{args.locale}: wrote {written} pages to {out_root} "
        f"({cache.added} new units, {len(cache.entries)} cached)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
