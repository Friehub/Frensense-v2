#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""A repository pinned to one commit: fetch it once, verify the checkout, reuse it.

The rules here are not specific to a suite: a cache hit is verified rather than
trusted, a stale checkout is never measured, and a pin must be a full SHA.
Keeping them in one module means the real-repository benchmark does not depend
on a benchmark suite for them.
"""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


@dataclass(frozen=True)
class PinnedRepo:
    name: str
    url: str
    commit: str
    lang: str
    targets: Tuple[str, ...] = (".",)
    note: str = ""
    timeout: Optional[int] = None  # seconds; a slow repo can raise its own limit (None: the default)


def _head_sha(repo_dir: Path) -> str:
    """The commit a cached checkout is actually on ("" when it is not a git tree)."""
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def clone_repo(repo: PinnedRepo, cache: Path) -> Path:
    """Fetch exactly the pinned commit (full 40-char SHA required: servers do
    not resolve abbreviated SHAs in `git fetch`).

    A cache hit is verified, not trusted: a checkout left by an older pin, a
    failed fetch or a manual `git checkout` would otherwise be measured and
    published under a commit SHA it is not actually at.
    """
    dest = cache / repo.name
    if dest.exists():
        head = _head_sha(dest)
        if head == repo.commit:
            for target in repo.targets:
                _ensure_target(dest, target, repo.targets)
            return dest
        # Stale, partial or not a git tree: never measure it, start over.
        shutil.rmtree(dest, ignore_errors=True)
    if len(repo.commit) != 40:
        raise ValueError(f"{repo.name}: pin a full 40-character commit SHA, got {repo.commit!r}")
    dest.mkdir(parents=True, exist_ok=True)
    try:
        for cmd in (
            ["git", "init", "--quiet"],
            ["git", "remote", "add", "origin", repo.url],
            ["git", "fetch", "--depth", "1", "--quiet", "origin", repo.commit],
            ["git", "checkout", "--quiet", "FETCH_HEAD"],
        ):
            subprocess.run(cmd, cwd=dest, check=True)
        head = _head_sha(dest)
        if head != repo.commit:
            raise RuntimeError(f"{repo.name}: checkout is at {head or 'unknown'}, pin is {repo.commit}")
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)  # never leave a half-cloned cache that later runs trust
        raise
    # A shallow fetch still leaves every target directory available under the
    # checkout root. Build the local mirror the scanner expects so --run can
    # hand the same target paths it recorded during --prepare, regardless of
    # which subdirectories the pin kept.
    for target in repo.targets:
        _ensure_target(dest, target, repo.targets)
    return dest


def _ensure_target(repo_root: Path, target: str, all_targets: Tuple[str, ...]) -> Path:
    """Make sure the scanner's target subpath exists after a shallow clone.

    `git clone --depth 1` keeps every checked-out directory, so `src`, `lib`,
    `tests` etc. are all present. We still mirror each target under the repo
    root so the engine receives a clean, existing tree to walk (a new repo may
    have had its targets relocated between pins).
    """
    base = repo_root / target
    if base.is_dir():
        return base
    if target == ".":
        return repo_root
    raise FileNotFoundError(f"{repo_root.name}: scanned target '{target}' missing from pinned checkout. "
                            f"Repo is at {repo_root}; available subdirs: {[p.name for p in repo_root.iterdir() if p.is_dir()]}")
