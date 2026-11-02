#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Real-repository benchmark: run the scanner over pinned open-source projects.

Motivation: the corpus benchmarks measure what the engine was taught. This
harness measures what it does to code nobody wrote for it - how long it takes,
whether it survives, and how many of its findings survive review.

Each entry pins a repository and a commit, so a run is reproducible. Scanning
happens through the release CLI, exactly as a user would run it; the JSON
report is kept next to the timing so findings can be triaged afterwards.

Usage:
    python3 frensense-bench/real_repos.py --prepare
    python3 frensense-bench/real_repos.py --run
    python3 frensense-bench/real_repos.py --run --only django,redis

Results land in ``target/real-repos/<name>.json`` (raw advisory list),
``<name>.meta.json`` (wall time, peak RSS, exit status) and a printed table.
A run that exceeds ``--timeout`` is recorded as TIMEOUT, not as a zero-finding
run: "finished with nothing to say" and "never finished" are different results.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Optional, Tuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest  # noqa: E402
from blindness import PinnedRepo, clone_repo  # noqa: E402
from scanproc import run_scan, time_wrapped  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_BIN = ROOT / "target" / "release" / "frensense"
DEFAULT_CACHE = ROOT / "target" / "real-repos"
SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".c", ".h", ".rs", ".go",
}
SKIP_DIRS = {
    "node_modules", "target", "dist", "build", "vendor", "out", ".next",
    ".nuxt", ".cache", "coverage", ".git",
}


def load_repos(manifest_file: Optional[Path] = None) -> Tuple[PinnedRepo, ...]:
    """The repos for this suite, from repos.toml (entries whose `suites` include "real")."""
    return tuple(
        PinnedRepo(
            name=e["name"], url=e["url"], commit=e["commit"], lang=e["lang"],
            targets=tuple(e["targets"]), note=e.get("note", ""), timeout=e.get("timeout"),
        )
        for e in manifest.repos_for("real", manifest_file)
    )


# Pinned commits live in repos.toml. Updating a pin is a deliberate act: it moves the baseline.
Repo = PinnedRepo
REPOS: Tuple[PinnedRepo, ...] = load_repos()


def clone(repo: PinnedRepo, cache: Path) -> Path:
    # One implementation for both suites: full-SHA pin, verified cache hit, fails loudly on a
    # missing target (the old copy here moved directories around to hide ENOENT).
    return clone_repo(repo, cache)


def count_files(root: Path, targets: tuple[str, ...]) -> int:
    """Approximate the scanner's input: supported suffixes outside vendored dirs.

    The engine additionally drops test files and minified bundles, so this is
    an upper bound on what it parses, not an exact match.
    """
    total = 0
    for target in targets:
        base = root / target
        if base.is_file():
            total += 1
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            total += sum(1 for f in filenames if Path(f).suffix in SUFFIXES)
    return total


def scan(repo: PinnedRepo, cache: Path, binary: Path, timeout: int) -> dict:
    root = cache / repo.name
    meta = {"name": repo.name, "lang": repo.lang, "commit": repo.commit, "note": repo.note}
    meta["files"] = count_files(root, repo.targets)
    target_paths = [str(root / t) for t in repo.targets]
    rss_file = cache / f"{repo.name}.rss"

    run = run_scan(time_wrapped(binary, target_paths, rss_file, ["--json"]), timeout, rss_file)
    meta["exit"] = run["exit"]
    meta["stderr_tail"] = run["stderr_tail"]
    meta["wall_s"] = run["wall_s"]
    meta["peak_rss_mb"] = run["peak_rss_mb"]
    if run["timeout"]:
        meta["timeout"] = True
        meta["exit"] = None
    raw = run["stdout"]
    try:
        report = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        meta["bad_json"] = True
        report = {}
    advisories = report.get("advisories", [])
    by_rule: dict[str, int] = {}
    for adv in advisories:
        by_rule[adv["rule_id"]] = by_rule.get(adv["rule_id"], 0) + 1
    meta["advisories"] = len(advisories)
    meta["by_rule"] = dict(sorted(by_rule.items(), key=lambda kv: -kv[1]))
    (cache / f"{repo.name}.json").write_text(json.dumps(report, indent=2))
    (cache / f"{repo.name}.meta.json").write_text(json.dumps(meta, indent=2))
    return meta


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prepare", action="store_true", help="clone the pinned repositories")
    ap.add_argument("--run", action="store_true", help="scan them")
    ap.add_argument("--only", default="", help="comma-separated repository names")
    ap.add_argument("--manifest", type=Path, default=None, help="repo manifest (default: frensense-bench/repos.toml)")
    ap.add_argument("--binary", type=Path, default=DEFAULT_BIN)
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--timeout", type=int, default=600, help="per-repository cap, seconds")
    ap.add_argument("--max-rss-mb", type=float, default=None, help="fail (exit 4) when any scan peaks above this many MB")
    args = ap.parse_args()
    if not (args.prepare or args.run):
        ap.error("pass --prepare and/or --run")

    # Same rule as the blindness suite: a name that matches nothing is a typo,
    # not an empty run. `--only redis` silently scanning zero repositories and
    # exiting 0 reads exactly like a clean result.
    try:
        repos = load_repos(args.manifest)
    except manifest.ManifestError as exc:
        ap.error(str(exc))
    known = {r.name for r in repos}
    wanted = [n.strip() for n in args.only.split(",") if n.strip()]
    unknown_names = [n for n in wanted if n not in known]
    if unknown_names:
        ap.error(f"unknown repository name(s): {', '.join(unknown_names)}; known: {', '.join(sorted(known))}")
    if args.max_rss_mb is not None and args.max_rss_mb <= 0:
        ap.error("--max-rss-mb must be a positive number of megabytes")

    selected = [r for r in repos if not wanted or r.name in wanted]
    if not selected:
        ap.error("nothing to scan: name a repository with --only")
    if args.prepare:
        for repo in selected:
            clone(repo, args.cache)
            print(f"prepared {repo.name}")
    if args.run:
        if not args.binary.exists():
            print(f"missing binary: {args.binary} (cargo build --release)", file=sys.stderr)
            return 2
        rows = []
        for repo in selected:
            meta = scan(repo, args.cache, args.binary, args.timeout)
            rows.append(meta)
            status = "TIMEOUT" if meta.get("timeout") else f"exit {meta['exit']}"
            rss = f"{meta['peak_rss_mb']}MB" if meta.get("peak_rss_mb") is not None else "?"
            print(
                f"{repo.name:12} {repo.lang:11} {meta['files']:>5} files "
                f"{meta['wall_s']:>7.1f}s  {meta['advisories']:>4} findings  {rss:>9}  {status}"
            )
        print()
        print("| repo | lang | files | wall | peak RSS | findings | status |")
        print("|---|---|---|---|---|---|---|")
        for row in rows:
            status = "TIMEOUT" if row.get("timeout") else f"exit {row['exit']}"
            top = ", ".join(f"{k} x{v}" for k, v in list(row["by_rule"].items())[:3]) or "-"
            rss = f"{row['peak_rss_mb']}MB" if row.get("peak_rss_mb") is not None else "?"
            print(
                f"| {row['name']} | {row['lang']} | {row['files']} | "
                f"{row['wall_s']}s | {rss} | {row['advisories']} ({top}) | {status} |"
            )
        if args.max_rss_mb is not None:
            over = [r for r in rows if (r.get("peak_rss_mb") or 0) > args.max_rss_mb]
            for row in over:
                print(
                    f"[RSS] {row['name']}: {row['peak_rss_mb']} MB exceeds --max-rss-mb {args.max_rss_mb}",
                    file=sys.stderr,
                )
            if over:
                return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
