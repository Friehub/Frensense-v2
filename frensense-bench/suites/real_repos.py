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
import time
from dataclasses import dataclass
from pathlib import Path

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


@dataclass(frozen=True)
class Repo:
    name: str
    url: str
    commit: str
    lang: str
    #: Paths passed to the scanner, relative to the clone. Several paths are
    #: scanned in one invocation so the cross-file callgraph links them.
    targets: tuple[str, ...] = (".",)
    note: str = ""


# Pinned commits. Updating a pin is a deliberate act: it moves the baseline.
REPOS: tuple[Repo, ...] = (
    Repo(
        name="flask",
        url="https://github.com/pallets/flask.git",
        commit="49943b5",
        lang="python",
        targets=("src",),
        note="framework, ~7k LOC",
    ),
    Repo(
        name="django",
        url="https://github.com/django/django.git",
        commit="a05e16a",
        lang="python",
        targets=("django",),
        note="framework, ~130k LOC, 2937 files",
    ),
    Repo(
        name="express",
        url="https://github.com/expressjs/express.git",
        commit="1c6f1b0",
        lang="javascript",
        targets=("lib",),
        note="framework core only; examples/ are deliberately insecure demos",
    ),
    Repo(
        name="nextjs",
        url="https://github.com/vercel/next.js.git",
        commit="fac5fc8",
        lang="typescript",
        targets=("packages/next/src",),
        note="framework, ~5k files",
    ),
    Repo(
        name="libpng",
        url="https://github.com/pnggroup/libpng.git",
        commit="a70313d",
        lang="c",
        targets=(".",),
        note="~102 C files",
    ),
    Repo(
        name="tokio",
        url="https://github.com/tokio-rs/tokio.git",
        commit="b499257",
        lang="rust",
        targets=("benches", "examples", "src"),
        note="async runtime; reactor, timers, and I/O primitives",
    ),
    Repo(
        name="axum",
        url="https://github.com/tokio-rs/axum.git",
        commit="bebe175",
        lang="rust",
        targets=(".",),
        note="async web framework",
    ),
    Repo(
        name="redis",
        url="https://github.com/redis/redis.git",
        commit="6a5fee6",
        lang="c",
        targets=("src",),
        note="~200 C files",
    ),
    Repo(
        name="juice-shop",
        url="https://github.com/juice-shop/juice-shop.git",
        commit="717f5ef",
        lang="typescript",
        targets=("routes", "lib", "models"),
        note="deliberately vulnerable app; ground truth via vuln-line markers",
    ),
)


def clone(repo: Repo, cache: Path) -> Path:
    dest = cache / repo.name
    if dest.exists():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", repo.url, str(dest)], check=True
    )    # A pin is a commit, not a branch name: fetch just that object. Tags and
    # branch names resolve from the full clone; a short SHA is resolved by git
    # from the fetched branch refs. A shallow `--depth 1` fetch still leaves
    # the full tree of the pinned commit, so the scanner only needs to pass
    # existing relative paths.
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "--quiet", "origin", repo.commit],
        check=False,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "--quiet", repo.commit],
        check=True,
    )
    # A shallow checkout keeps every directory the pin's tree contains, but the
    # audited CLI can only pass *existing* paths. Mirror each pin's target
    # locally so a repo with relocated targets (django -> django/, redis -> src)
    # scans without ENOENT on stale checkout paths. The target is interpreted
    # relative to the repo root; if it no longer exists at that path, look for
    # an equivalent directory name anywhere in the checked-out tree and move it
    # into place (a fuller pin fetch settles the relocation).
    for t in repo.targets:
        _ensure_target(dest, t)
    return dest


def _ensure_target(repo_root: Path, target: str) -> Path:
    """Make sure the scanner's target subpath exists after a shallow clone.

    If the pin's tree no longer has `target` at the checked-out path (targets
    can be relocated between pin updates), search the full tree for a matching
    directory and move it into place under `repo_root`. Returns the path the
    scanner should receive. Raises FileNotFoundError if nothing is found at all.
    """
    base = repo_root / target
    if base.is_dir():
        return base
    if target == ".":
        return repo_root
    # Search for a directory with the same name anywhere in the tree.
    name = target.rstrip("/").split("/")[-1]
    for candidate in repo_root.rglob(name):
        if candidate.is_dir() and candidate.parent != repo_root:
            try:
                candidate.rename(repo_root / target)
                return repo_root / target
            except OSError:
                return base
    raise FileNotFoundError(
        f"{repo_root.name}: target '{target}' not found on pin {repo_root}" \
        f" after full-sha checkout. Check the pin's target layout."
    )


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


def scan(repo: Repo, cache: Path, binary: Path, timeout: int) -> dict:
    root = cache / repo.name
    meta = {"name": repo.name, "lang": repo.lang, "commit": repo.commit, "note": repo.note}
    meta["files"] = count_files(root, repo.targets)
    target_paths = [str(root / t) for t in repo.targets]
    argv = [str(binary), *target_paths, "--json"]
    rss_file = cache / f"{repo.name}.rss"
    if Path("/usr/bin/time").exists():
        argv = ["/usr/bin/time", "-f", "%M", "-o", str(rss_file), *argv]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        meta["exit"] = proc.returncode
        meta["stderr_tail"] = proc.stderr.strip().splitlines()[-3:]
        raw = proc.stdout
    except subprocess.TimeoutExpired as exc:
        meta["exit"] = None
        meta["timeout"] = True
        meta["stderr_tail"] = (exc.stderr or b"").decode("utf-8", "replace").strip().splitlines()[-3:]
        raw = (exc.stdout or b"").decode("utf-8", "replace")
    meta["wall_s"] = round(time.monotonic() - started, 2)
    if rss_file.exists():
        try:
            meta["peak_rss_mb"] = round(int(rss_file.read_text().strip()) / 1024, 1)
        except ValueError:
            pass
        rss_file.unlink()
    try:
        report = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        meta["exit"], meta["bad_json"] = meta.get("exit"), True
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
    ap.add_argument("--binary", type=Path, default=DEFAULT_BIN)
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    ap.add_argument("--timeout", type=int, default=600, help="per-repository cap, seconds")
    args = ap.parse_args()
    if not (args.prepare or args.run):
        ap.error("pass --prepare and/or --run")

    selected = [r for r in REPOS if not args.only or r.name in args.only.split(",")]
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
            print(
                f"{repo.name:12} {repo.lang:11} {meta['files']:>5} files "
                f"{meta['wall_s']:>7.1f}s  {meta['advisories']:>4} findings  {status}"
            )
        print()
        print("| repo | lang | files | wall | peak RSS | findings | status |")
        print("|---|---|---|---|---|---|---|")
        for row in rows:
            status = "TIMEOUT" if row.get("timeout") else f"exit {row['exit']}"
            top = ", ".join(f"{k} x{v}" for k, v in list(row["by_rule"].items())[:3]) or "-"
            rss = f"{row['peak_rss_mb']}MB" if "peak_rss_mb" in row else "?"
            print(
                f"| {row['name']} | {row['lang']} | {row['files']} | "
                f"{row['wall_s']}s | {rss} | {row['advisories']} ({top}) | {status} |"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
