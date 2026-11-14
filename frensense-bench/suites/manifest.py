#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Read `frensense-bench/repos.toml`: the one place the real-repository benchmark lists its pins.

The suite asks for the entries and gets plain dicts back, so a new repo is a
TOML edit, not a code change. Validation is strict on purpose: a typo in a pin
must stop the run, not quietly scan something else.
"""

import os
import re
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "repos.toml"
MANIFEST_ENV = "FRENSENSE_BENCH_REPOS"

LANGS = ("python", "javascript", "typescript", "c", "rust", "go")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class ManifestError(ValueError):
    pass


def manifest_path(explicit: Optional[Path] = None) -> Path:
    if explicit:
        return Path(explicit)
    return Path(os.environ[MANIFEST_ENV]) if os.environ.get(MANIFEST_ENV) else DEFAULT_MANIFEST


def _check(entry: Dict[str, Any], seen: set, path: Path) -> Dict[str, Any]:
    name = entry.get("name")
    where = f"{path.name}: [[repo]] {name!r}"
    for key in ("name", "url", "commit", "lang", "targets"):
        if key not in entry:
            raise ManifestError(f"{where}: missing `{key}`")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name):
        raise ManifestError(f"{where}: name must be lowercase letters, digits, '.', '_' or '-'")
    if name in seen:
        raise ManifestError(f"{where}: duplicate name")
    seen.add(name)
    if not _SHA.fullmatch(entry["commit"]):
        raise ManifestError(f"{where}: commit must be a full 40-character lowercase SHA, got {entry['commit']!r}")
    if entry["lang"] not in LANGS:
        raise ManifestError(f"{where}: lang must be one of {', '.join(LANGS)}")
    targets = entry["targets"]
    if not (isinstance(targets, list) and targets and all(isinstance(t, str) and t for t in targets)):
        raise ManifestError(f"{where}: targets must be a non-empty list of paths")
    if any(t.startswith("/") or ".." in Path(t).parts for t in targets):
        raise ManifestError(f"{where}: targets must stay inside the repository")
    timeout = entry.get("timeout")
    if timeout is not None and not (isinstance(timeout, int) and timeout >= 0):
        raise ManifestError(f"{where}: timeout must be whole seconds (0 = no limit)")
    return entry


def load(path: Optional[Path] = None) -> Dict[str, List[Dict[str, Any]]]:
    p = manifest_path(path)
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"cannot read repo manifest {p}: {exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{p}: invalid TOML: {exc}") from None
    seen: set = set()
    repos = [_check(dict(e), seen, p) for e in raw.get("repo", [])]
    if not repos:
        raise ManifestError(f"{p}: no [[repo]] entries")
    for e in repos:
        e.setdefault("note", "")
    return {"repo": repos}


def repos(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    return load(path)["repo"]
