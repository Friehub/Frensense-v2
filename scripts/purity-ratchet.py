#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""Engine purity debt ratchet (ENGINE_PURITY_REFACTOR.md, Phase 0.1).

Counts the debt classes the refactor targets and fails when any count
EXCEEDS its committed baseline. Counts may drop; when they do, rerun with
--update to tighten the baseline in the same PR that removed the debt.

Counters (non-test code only - test expectations legitimately reference
strings and tables until the assertions themselves are rewritten):

  engine_bootstrap_refs   bootstrap_* table references in frensense-engine
  engine_prose_format     format! sites in frensense-engine (prose until
                          Phase 3 moves messages to the consumer)
  engine_tier_strings     "critical"/"warning"/"info" tier strings in
                          frensense-engine (policy - Phase 1.3 moves the
                          ladder to frensense-lang)
  lang_policy_refs        frensense_lang::policy paths anywhere outside
                          frensense-lang (knowledge-as-Rust-literals -
                          Phase 5.2/6.1 moves them into the .frc pack)    lang_provider_refs      provider/structural (security-vocabulary) trait
                           method names in frensense-lang (Phases 6.3d/6.4/
                           6.5/6.6 deleted them; the vocabulary lives in
                           frensense-packgen)

Usage:
  scripts/purity-ratchet.py            check against baseline (CI mode)
  scripts/purity-ratchet.py --update   rewrite baseline with current counts
  scripts/purity-ratchet.py --verbose  list every matching line
"""

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "purity-baseline.json"

COUNTERS = [
    (
        "engine_bootstrap_refs",
        [ROOT / "frensense-engine" / "src"],
        re.compile(r"\bbootstrap_\w+"),
    ),
    (
        "engine_prose_format",
        [ROOT / "frensense-engine" / "src"],
        re.compile(r"\bformat!\s*\("),
    ),
    (
        "engine_tier_strings",
        [ROOT / "frensense-engine" / "src"],
        re.compile(r'"(?:critical|warning|info)"'),
    ),
    (
        "lang_policy_refs",
        [
            ROOT / "frensense-engine" / "src",
            ROOT / "frensense-bundler" / "src",
            ROOT / "src",
        ],
        re.compile(r"\bfrensense_lang::policy\b"),
    ),
    (
        "lang_provider_refs",
        [ROOT / "frensense-lang" / "src"],
        re.compile(
            r"\b(?:known_sink_names|known_sink_signatures|known_idor_sinks"
            r"|known_session_roots|known_source_patterns|request_param_names"
            r"|known_sanitizer_names|classify_sanitizer|propagator_rules"
            r"|is_predicate_guard|route_registration_patterns"
            r"|known_guard_denylist|known_stack_allocators"
            r"|known_collection_constructors|known_schema_describe_methods"
            r"|known_null_tokens|known_session_accessors|known_receiver_params"
            r"|known_ambiguous_verbs)\b"
        ),
    ),
]

CFG_TEST = re.compile(r"#\[cfg\(([^)]*)\)\]")
TEST_WORD = re.compile(r"\btest\b")
MOD_FILE = re.compile(r"\bmod\s+(\w+)\s*;")
MOD_INLINE = re.compile(r"\bmod\s+(\w+)\s*\{")


def strip_comment(line: str) -> str:
    """Drop // comments that are outside of string literals."""
    out = []
    in_str = False
    escape = False
    i = 0
    while i < len(line):
        c = line[i]
        if in_str:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_str = False
            out.append(c)
        else:
            if c == '"':
                in_str = True
                out.append(c)
            elif c == "/" and line[i + 1 : i + 2] == "/":
                break
            else:
                out.append(c)
        i += 1
    return "".join(out)


def brace_delta(line: str) -> int:
    """Net braces of a line, ignoring string contents."""
    without_strings = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
    return without_strings.count("{") - without_strings.count("}")


def is_test_cfg(line: str) -> bool:
    m = CFG_TEST.match(line.strip())
    return bool(m and TEST_WORD.search(m.group(1)))


def next_item(lines: list[str], attr_idx: int) -> tuple[int, str]:
    """(index, text) of the item a cfg attribute at attr_idx gates: the
    remainder of the attribute line after ']', or the next non-attribute
    line."""
    line = lines[attr_idx]
    bracket = line.find("]")
    rest = line[bracket + 1 :] if bracket >= 0 else ""
    if rest.strip():
        return attr_idx, rest
    i = attr_idx + 1
    while i < len(lines):
        s = lines[i].strip()
        if not s or s.startswith("//") or s.startswith("#["):
            i += 1
            continue
        return i, lines[i]
    return len(lines), ""


def resolve_mod_file(base: Path, name: str):
    for candidate in (base / f"{name}.rs", base / name / "mod.rs"):
        if candidate.is_file():
            return candidate
    return None


def collect_excluded(files: list[Path]) -> set[Path]:
    """Files reachable through a #[cfg(test)] mod x; declaration, plus
    everything those test-only module trees declare."""
    excluded: set[Path] = set()
    queue: list[Path] = []
    for f in files:
        lines = f.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if not is_test_cfg(line):
                continue
            _, item = next_item(lines, i)
            m = MOD_FILE.search(item)
            if m:
                target = resolve_mod_file(f.parent, m.group(1))
                if target:
                    queue.append(target)
    while queue:
        f = queue.pop()
        if f in excluded:
            continue
        excluded.add(f)
        for m in MOD_FILE.finditer(f.read_text(encoding="utf-8")):
            target = resolve_mod_file(f.parent, m.group(1))
            if target and target not in excluded:
                queue.append(target)
    return excluded


def kept_lines(path: Path, lines: list[str]):
    """Yield (lineno, text) for lines outside #[cfg(test)] regions."""
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if not is_test_cfg(line):
            yield i + 1, line
            i += 1
            continue
        item_idx, item = next_item(lines, i)
        i = item_idx + 1
        if MOD_FILE.search(item):
            continue  # file target collected by collect_excluded
        if MOD_INLINE.search(item) or "{" in item:
            depth = brace_delta(item)
            while i < n and depth > 0:
                depth += brace_delta(lines[i])
                i += 1
            continue
        if item.rstrip().endswith(";"):
            continue
        # Gated item whose body opens on a later line (fn/impl/...).
        while i < n and "{" not in lines[i]:
            i += 1
        depth = 0
        while i < n:
            depth += brace_delta(lines[i])
            i += 1
            if depth <= 0:
                break


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Engine purity debt ratchet (fails when debt grows)."
    )
    parser.add_argument("--update", action="store_true", help="rewrite baseline")
    parser.add_argument("--verbose", action="store_true", help="list matches")
    args = parser.parse_args()

    scanned_roots = sorted({r for _, roots, _ in COUNTERS for r in roots})
    files: list[Path] = []
    for root in scanned_roots:
        files.extend(root.rglob("*.rs"))
    files = sorted(set(files))
    excluded = collect_excluded(files)

    counts: dict[str, int] = {}
    matches: dict[str, list[str]] = {}
    for name, roots, pattern in COUNTERS:
        total = 0
        detail = []
        for f in files:
            if f in excluded or not any(str(f).startswith(str(r)) for r in roots):
                continue
            for lineno, raw in kept_lines(f, f.read_text(encoding="utf-8").splitlines()):
                line = strip_comment(raw)
                found = len(pattern.findall(line))
                if found:
                    total += found
                    detail.append(f"{f.relative_to(ROOT)}:{lineno}: {line.strip()}")
        counts[name] = total
        matches[name] = detail

    if args.update:
        BASELINE.write_text(
            json.dumps(counts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"baseline updated: {BASELINE.relative_to(ROOT)}")
        for k in sorted(counts):
            print(f"  {k}: {counts[k]}")
        return 0

    if not BASELINE.is_file():
        print(f"ERROR: missing baseline {BASELINE}", file=sys.stderr)
        return 1
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))

    failed = False
    for k in sorted(set(counts) | set(baseline)):
        cur, base = counts.get(k, 0), baseline.get(k, 0)
        if cur > base:
            print(f"FAIL {k}: {cur} > baseline {base} (debt increased)")
            failed = True
        elif cur < base:
            print(f"down {k}: {cur} < baseline {base} - run --update to tighten")
        else:
            print(f"ok   {k}: {cur}")

    if args.verbose:
        for k, detail in matches.items():
            for d in detail:
                print(f"  [{k}] {d}")

    if failed:
        print(
            "\nPurity debt increased. Move knowledge to the .frc pack / "
            "consumer policy (see docs/ENGINE_PURITY_REFACTOR.md), or "
            "justify lowering the baseline in the same PR.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
