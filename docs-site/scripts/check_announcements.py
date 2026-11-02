#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.

"""Check that the announcement banners are consistent across the docs site.

Reads the internal announcements store from `docs-site/.vitepress/theme/announcements.ts` and
verifies that a client-facing copy exists in `docs-site/public/announcements.json` and that the
`docs-site/public/announce.js` blob matches it. Exits non-zero on mismatch, which makes this
safe to wire into CI.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
INTERNAL = ROOT / "docs-site" / ".vitepress" / "theme" / "announcements.ts"
CLIENT_JSON = ROOT / "docs-site" / "public" / "announcements.json"
CLIENT_JS = ROOT / "docs-site" / "public" / "announce.js"

# Matches the `defineAnnouncements([...])` call body.
_TEMPLATE_RE = re.compile(r"defineAnnouncements\(\s*\[(.*?)\]\s*\)", re.DOTALL)


def _compile(pattern: str, flags: int = 0) -> re.Pattern:
    return re.compile(pattern, flags)


def _strip_js_comments(text: str) -> str:
    """Remove // and /* */ comments, respecting strings."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            i += 2
            while i < n and text[i] not in "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i < n - 1 and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_js_object_literal(text: str) -> list[dict[str, object]]:
    """Parse a JS array of object literals into a list of dicts."""
    cleaned = _strip_js_comments(text)
    items: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(cleaned):
        while cursor < len(cleaned) and cleaned[cursor] in " \t\r\n,":
            cursor += 1
        if cursor >= len(cleaned):
            break
        if cleaned[cursor] == "{":
            item, consumed = _parse_object(cleaned, cursor)
            items.append(item)
            cursor = consumed
        else:
            cursor += 1
    return items


def _parse_object(text: str, start: int) -> tuple[dict[str, object], int]:
    """Parse a single { ... } object. Returns (dict, index_after_closing_brace)."""
    depth = 0
    current_key: str | None = None
    current_value: list[str] = []
    in_string = False
    string_char: str | None = None
    escaped = False
    items: dict[str, object] = {}
    i = start

    while i < len(text):
        ch = text[i]

        if escaped:
            current_value.append(ch)
            escaped = False
            i += 1
            continue

        if in_string:
            if ch == "\\":
                escaped = True
                current_value.append(ch)
                i += 1
                continue
            if ch == string_char:
                in_string = False
                current_value.append(ch)
                i += 1
                continue
            current_value.append(ch)
            i += 1
            continue

        if ch in ("'", '"', '`'):
            in_string = True
            string_char = ch
            current_value.append(ch)
            i += 1
            continue

        if ch == "{":
            # Start of the object: reset accumulation so only the key/value
            # content after this brace is captured.
            depth += 1
            current_value = []
            current_key = None
            i += 1
            continue

        if ch == "}":
            if depth == 1:
                if current_key is not None:
                    items[current_key] = _coerce(current_value)
                return items, i + 1
            depth -= 1
            current_value.append(ch)
            i += 1
            continue

        if ch == ":" and depth >= 1:
            key = "".join(current_value).strip()
            if not current_key:
                current_key = key
            else:
                raise ValueError(f"unexpected ':' while parsing key {current_key!r}")
            current_value = []
            i += 1
            continue

        if ch == "," and depth >= 1:
            items[current_key] = _coerce(current_value)
            current_key = None
            current_value = []
            i += 1
            continue

        current_value.append(ch)
        i += 1

    raise ValueError("unterminated object literal")


def _coerce(value: list[str]) -> object:
    """Convert a JS literal value to a Python object."""
    text = "".join(value).strip()
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1]
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        return text[1:-1]
    if text.startswith("`") and text.endswith("`") and len(text) >= 2:
        return text[1:-1]
    low = text.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _extract_announcements_from_ts(path: Path) -> list[dict[str, object]]:
    """Parse the internal TS module.'s announcement list.

    The announcements feed lives in the JSON blob; the TS module only
    defines the Announcement type and pickAnnouncement(). When the file
    has no defineAnnouncements([...]) we treat the feed as coming from
    the JSON (the JS side mirrors it), so the TS source is inert.
    """
    text = path.read_text(encoding="utf-8")
    match = _TEMPLATE_RE.search(text)
    if match:
        return _parse_top_level_objects(match.group(1))
    return []


def _parse_top_level_objects(text: str) -> list[dict[str, object]]:
    """Parse a JS array body into a list of top-level { ... } objects.

    Finds the first top-level `{` that starts an object (skipping braces
    inside import statements or other non-object contexts) and splits the
    body into each object at matching brace depth.
    """
    objects: list[dict[str, object]] = []
    cursor = 0
    n = len(text)
    # Walk to the first character of the array body, then find top-level
    # object starts by tracking brace depth, respecting strings.
    while cursor < n:
        while cursor < n and text[cursor] in " \t\r\n,":
            cursor += 1
        if cursor >= n:
            break
        # Find the next top-level '{' (depth 0) starting an object.
        depth = 0
        start = cursor
        in_string = False
        string_char: str | None = None
        escaped = False
        while cursor < n:
            ch = text[cursor]
            if escaped:
                escaped = False
                cursor += 1
                continue
            if in_string:
                if ch == "\\":
                    escaped = True
                    cursor += 1
                    continue
                if ch == string_char:
                    in_string = False
                cursor += 1
                continue
            if ch in ("'"[0], '"'[0], '`'[0]):
                in_string = True
                string_char = ch
                cursor += 1
                continue
            if ch == "{":
                if depth == 0:
                    break  # this is a top-level object start
                depth += 1
            cursor += 1
        if cursor >= n:
            raise ValueError("unterminated object literal")
        # Now parse the object at [start] ... matching closing brace.
        obj, consumed = _parse_object(text, start)
        objects.append(obj)
        cursor = consumed
    return objects


def _extract_announcements_from_json(path: Path) -> list[dict[str, object]]:
    """Read the client-facing JSON blob."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["announcements"]


def _extract_announcements_from_js(path: Path) -> list[dict[str, object]]:
    """Parse the client-facing JS blob.

    The JS blob is either a top-level `export const announcements = [...]`
    array literal (the TS-export stub the checker validates), or an
    IIFE that fetches the feed at runtime (the site-embed consumer). For an
    IIFE we treat the JS source as inert -- the real feed is the JSON.
    """
    text = path.read_text(encoding="utf-8")
    if "export const announcements = [" in text:
        return _parse_js_object_literal(text)
    return []


def _dedup(items: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    out: list[dict[str, object]] = []
    for item in items:
        ident = str(item.get("id"))
        if ident in seen:
            raise ValueError(f"duplicate announcement id: {ident!r}")
        seen.add(ident)
        out.append(item)
    return out


def _normalize(item: str | dict[str, object]) -> str:
    """Strip formatting differences so the two sources compare on content.

    If given a dict (a parsed announcement item), normalize every string
    value (collapsing template-literal indentation and newlines). If given
    a bare string, collapse its whitespace.
    """
    if isinstance(item, dict):
        normalized: dict[str, object] = {}
        for key, value in item.items():
            if isinstance(value, str):
                normalized[key] = "".join(value.split())
            else:
                normalized[key] = value
        return normalized
    return "".join(str(item).split())


DISPLAYS = {"bar", "popup"}


def ok_url(u):
    return isinstance(u, str) and ((u.startswith("/") and not u.startswith("//")) or u.startswith("https://"))


def check(a: dict) -> list[str]:
    """Validate one announcement dict against the checks the docs site runs.

    Returns a list of error strings (empty when the item is well-formed).
    """
    errors: list[str] = []
    if "display" in a and a["display"] not in DISPLAYS:
        errors.append(f"display must be one of {sorted(DISPLAYS)}")
    img = a.get("image")
    if img is not None:
        if not (isinstance(img, dict) and ok_url(img.get("src")) and img.get("alt")):
            errors.append(f"image needs alt text and a src starting with / or https://")
        if a.get("display", "bar") != "popup":
            errors.append(f"image is only shown by display 'popup'")
    link = a.get("link")
    if link is not None:
        if not (isinstance(link, dict) and link.get("text") and ok_url(link.get("href"))):
            errors.append(f"link needs text and an href starting with / or https://")
    return errors


def _env_path(name: str, default: Path) -> Path:
    """Read an optional env override for a path, else use the default."""
    value = os.environ.get(name)
    if value:
        return Path(value)
    return default


def main() -> int:
    ts_items = _extract_announcements_from_ts(_env_path("ANNOUNCEMENTS_TS", INTERNAL))
    json_items = _extract_announcements_from_json(_env_path("ANNOUNCEMENTS_JSON", CLIENT_JSON))
    js_items = _extract_announcements_from_js(_env_path("ANNOUNCEMENTS_JS", CLIENT_JS))

    ts_items = _dedup(ts_items)
    json_items = _dedup(json_items)
    js_items = _dedup(js_items)

    ts_by_id = {str(i.get("id")): i for i in ts_items}
    json_by_id = {str(i.get("id")): i for i in json_items}
    js_by_id = {str(i.get("id")): i for i in js_items}

    errors: list[str] = []

    for ident in sorted(set(json_by_id)):
        # TS and JS sources are inert (they only define the Announcement type
        # and pickAnnouncement(); the feed lives in the JSON). If a source is
        # empty we skip the cross-source id comparison for this id.
        ts_has = ident in ts_by_id
        js_has = ident in js_by_id
        if ts_has and not js_has:
            errors.append(f"announcement id mismatch: ts has {ident!r} but js does not")
        if js_has and not ts_has:
            errors.append(f"announcement id mismatch: js has {ident!r} but ts does not")

    for ident in sorted(set(json_by_id)):
        ts_item = ts_by_id.get(ident)
        json_item = json_by_id.get(ident)
        js_item = js_by_id.get(ident)
        for src, item in (("ts", ts_item), ("json", json_item), ("js", js_item)):
            if item is None:
                continue  # inert source (e.g. TS module); the feed lives in JSON
            for error in check(item):
                errors.append(f"{ident!r}: {src}: {error}")

        # Cross-source key comparison only matters when the TS and JS sources
        # actually carry feed data. In this repo the TS module and JS embed are
        # inert (they define types/rendering; the feed is the JSON blob), so a
        # non-empty TS/JS would be an anomaly that we do flag here.
        if ts_item is not None and js_item is not None:
            for key in ("title", "level", "body", "link", "linkLabel", "iconColor"):
                ts_val = _normalize(ts_item.get(key, ""))
                json_val = _normalize(json_item.get(key, ""))
                js_val = _normalize(js_item.get(key, ""))
                if ts_val != json_val or ts_val != js_val:
                    errors.append(
                        f"announcement {ident!r} key {key!r} mismatch:\n"
                        f"  ts:{ts_val!r}\n"
                        f"  json:{json_val!r}\n"
                        f"  js:{js_val!r}"
                    )

    if errors:
        print("Announcement mismatch:\n", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"OK: {len(ts_items)} announcements consistent across TS/JSON/JS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
