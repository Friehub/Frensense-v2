#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Per-crate SemVer gate for the publishable crates of the workspace.

Frensense ships one binary but four registry crates. Each of them has its own
version and its own public API, so a single "is the workspace semver-clean"
answer is meaningless: a change can break `frensense-engine` while leaving
`frensense-lang` untouched, and a break must be absorbed by *that crate's*
version, not by moving the whole workspace.

This script asks `cargo-semver-checks` per publishable crate and decides, for
each one:

  ok         no breaking public-API change since the baseline
  absorbed   breaking changes, but the crate's own version already moved a
             breaking component (0.A.0 -> 0.B.0, or X.0.0 -> Y.0.0)
  FAIL       breaking changes with an unchanged version: bump the crate or
             revert the break
  ERROR      the crate could not be built/parsed; this is not a SemVer signal

Why `--release-type patch` matters: with no release type, `check-release`
compares the version you wrote against the baseline and **skips every check**
when the middle number moved ("major change, 0 checks, 260 skip"). During a
bump line that turns the workspace gate into a no-op. Patch mode forces the
checks, so the result tells you whether the bump was justified.

Usage
-----
    # PR / local gate: block breaks introduced since a commit without a bump
    python3 .github/scripts/semver-gate.py                       # base = HEAD (local)
    python3 .github/scripts/semver-gate.py --base-ref origin/main
    python3 .github/scripts/semver-gate.py --base-ref HEAD^

    # Release gate: the version about to be published must cover what changed
    python3 .github/scripts/semver-gate.py --published

    # Inspect the plan without spending build time
    python3 .github/scripts/semver-gate.py --dry-run --base-ref HEAD^
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

# Paths that belong to the root package (`frensense`), whose manifest sits at
# the workspace root and therefore cannot be matched by a directory prefix.
ROOT_PACKAGE_PATHS = ("src/", "tests/", "benches/", "examples/")
ROOT_PACKAGE_FILES = ("Cargo.toml", "build.rs")

OK = "ok"
ABSORBED = "absorbed"
FAIL = "fail"
ERROR = "error"

VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"', re.MULTILINE)
# cargo-semver-checks embeds the registry cache path in failure output, e.g.:
#   .cargo/registry/src/.../frensense-engine-0.7.0/src/...
# Parse that to recover the actual published version being compared against.
PUBLISHED_VERSION_RE = re.compile(
    r"/(?:frensense(?:-[a-z]+)?)-(\d+\.\d+\.\d+[^/\s]*)/src/"
)



def run(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd, cwd=ROOT, capture_output=True, text=True, check=check
    )


def published_baseline_version(output: str) -> str | None:
    """Extract the published version from cargo-semver-checks failure output.

    The tool embeds the registry cache path in failure messages, e.g.:
      ~/.cargo/registry/src/.../frensense-engine-0.7.0/src/registry.rs
    Parse the first match to recover the version that was compared against.
    """
    m = PUBLISHED_VERSION_RE.search(output)
    return m.group(1) if m else None



def cargo_metadata() -> dict:
    proc = run(["cargo", "metadata", "--no-deps", "--format-version", "1"])
    if proc.returncode != 0:
        raise SystemExit(f"cargo metadata failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


def publishable_packages(meta: dict) -> list[dict]:
    """Workspace packages that go to a registry, publish = false excluded."""
    pkgs = []
    for pkg in meta["packages"]:
        publish = pkg.get("publish")
        # `null` means unrestricted, `[]` means publish = false.
        if publish == [] or publish == ["false"]:
            continue
        pkgs.append(pkg)
    return sorted(pkgs, key=lambda p: p["name"])


def manifest_rel(pkg: dict) -> str:
    return Path(pkg["manifest_path"]).resolve().relative_to(ROOT).as_posix()


def version_at(pkg: dict, ref: str | None) -> str | None:
    """The crate's own version at `ref` (None when the ref lacks the crate)."""
    rel = manifest_rel(pkg)
    if ref is None:
        text = (ROOT / rel).read_text(encoding="utf-8")
    else:
        proc = run(["git", "show", f"{ref}:{rel}"])
        if proc.returncode != 0:
            return None
        text = proc.stdout
    m = VERSION_RE.search(text)
    return m.group(1) if m else None


def parse_version(v: str) -> tuple[int, int, int, str]:
    core, _, pre = v.partition("-")
    core = core.split("+")[0]
    parts = core.split(".")
    nums = [int(p) for p in parts[:3]] + [0] * (3 - len(parts[:3]))
    return nums[0], nums[1], nums[2], pre


def is_breaking_bump(old: str, new: str) -> bool:
    """Whether `new` already absorbs a breaking change relative to `old`.

    Under Cargo's `0.x` rules the middle number is the breaking component;
    from `1.0.0` on it is the major number.
    """
    o_major, o_minor, _, _ = parse_version(old)
    n_major, n_minor, _, _ = parse_version(new)
    if n_major > o_major:
        return True
    return o_major == 0 and n_major == 0 and n_minor > o_minor


def changed_paths(base_ref: str | None) -> list[str]:
    """Every path changed against the baseline, including untracked files."""
    paths: list[str] = []
    if base_ref is None:
        return paths
    diff = run(["git", "diff", "--name-only", base_ref])
    if diff.returncode == 0:
        paths.extend(p for p in diff.stdout.splitlines() if p.strip())
    untracked = run(["git", "ls-files", "--others", "--exclude-standard"])
    if untracked.returncode == 0:
        paths.extend(p for p in untracked.stdout.splitlines() if p.strip())
    return paths


def package_owned_paths(pkg: dict, meta: dict) -> tuple[str, ...]:
    workspace_root = Path(meta["workspace_root"]).resolve()
    pkg_dir = Path(pkg["manifest_path"]).resolve().parent
    if pkg_dir == workspace_root:
        return ROOT_PACKAGE_PATHS + ROOT_PACKAGE_FILES
    rel = pkg_dir.relative_to(workspace_root).as_posix()
    return (f"{rel}/",)


def touched_packages(pkgs: list[dict], paths: list[str], meta: dict) -> set[str]:
    """Packages whose sources changed, closed over their workspace dependents."""
    direct: set[str] = set()
    for pkg in pkgs:
        owned = package_owned_paths(pkg, meta)
        for path in paths:
            if any(path.startswith(prefix) for prefix in owned):
                direct.add(pkg["name"])
                break

    # A path-dependency change can break a dependent through re-exported types
    # (`frensense` re-exports engine/lang types in its own public API), so a
    # changed crate pulls its workspace dependents into the check too.
    changed = set(direct)
    grew = True
    while grew:
        grew = False
        for pkg in pkgs:
            if pkg["name"] in changed:
                continue
            for dep in pkg.get("dependencies", []):
                if dep.get("path") and dep["name"] in changed:
                    changed.add(pkg["name"])
                    grew = True
                    break
    return changed


BUILD_FAILURE_MARKERS = (
    "failed to build",
    "could not document",
    "could not compile",
    "error: failed to",
)


def looks_like_build_failure(output: str) -> bool:
    return any(marker in output for marker in BUILD_FAILURE_MARKERS)


def check_crate(pkg: dict, base_ref: str | None, published: bool) -> dict:
    cmd = ["cargo", "semver-checks", "check-release", "-p", pkg["name"]]
    if not published:
        cmd += ["--baseline-rev", base_ref, "--release-type", "patch"]
    proc = run(cmd)
    output = (proc.stdout or "") + (proc.stderr or "")
    return {
        "name": pkg["name"],
        "version": pkg["version"],
        "returncode": proc.returncode,
        "output": output,
        "build_failure": looks_like_build_failure(output),
    }


def summarize_failures(output: str, limit: int = 4) -> list[str]:
    """One line per failing lint, for the console summary."""
    lines = []
    for raw in output.splitlines():
        line = raw.rstrip()
        if line.startswith("--- failure "):
            lines.append(line[len("--- failure ") :].split(":")[0].strip())
    seen, unique = set(), []
    for item in lines:
        if item and item not in seen:
            seen.add(item)
            unique.append(item)
    return unique[:limit]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Per-crate SemVer gate over the publishable workspace crates."
    )
    parser.add_argument(
        "--base-ref",
        default="HEAD",
        help="git ref to compare against (default: HEAD; use HEAD^ in CI push, "
        "origin/<base> on pull requests, or HEAD for uncommitted local work)",
    )
    parser.add_argument(
        "--published",
        action="store_true",
        help="compare against the latest published crate versions instead of a "
        "git ref (release gate: the version must cover what changed)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="CRATE",
        help="restrict the gate to one crate (repeatable)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="check every publishable crate, not only those the diff touched",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable result")
    parser.add_argument(
        "--dry-run", action="store_true", help="print the plan without checking"
    )
    args = parser.parse_args()

    meta = cargo_metadata()
    pkgs = publishable_packages(meta)
    if args.only:
        pkgs = [p for p in pkgs if p["name"] in set(args.only)]
        if not pkgs:
            raise SystemExit(f"no publishable crate matched {args.only}")

    base_ref = None if args.published else args.base_ref

    if base_ref is not None:
        verify = run(["git", "rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}"])
        if verify.returncode != 0:
            print(
                f"semver-gate: WARNING base ref '{base_ref}' is not resolvable in "
                "this checkout (shallow clone or root commit); nothing to compare "
                "against, so the gate is skipped.",
                file=sys.stderr,
            )
            return 0

    if args.published:
        selected = pkgs
        changed: set[str] = {p["name"] for p in pkgs}
    else:
        paths = changed_paths(base_ref)
        changed = touched_packages(pkgs, paths, meta)
        if args.all:
            changed = {p["name"] for p in pkgs}
        selected = [p for p in pkgs if p["name"] in changed]

    mode = "published baseline" if args.published else f"git ref {base_ref}"
    if not selected:
        print(f"semver-gate: no publishable crate changed against {base_ref}")
        if args.json:
            print(json.dumps({"mode": mode, "results": []}, indent=2))
        return 0

    if args.dry_run:
        print(f"semver-gate: mode={mode}")
        for pkg in selected:
            base_version = version_at(pkg, base_ref)
            print(
                f"  would check {pkg['name']} {base_version or '(new)'} -> "
                f"{pkg['version']}"
            )
        return 0

    results: list[dict] = []
    failed = False
    for pkg in selected:
        base_version = version_at(pkg, base_ref) if not args.published else None
        row = check_crate(pkg, base_ref, args.published)
        row["base_version"] = base_version

        if row["returncode"] == 0:
            row["verdict"] = OK
            row["detail"] = "no breaking public-API change"
        elif row["build_failure"]:
            row["verdict"] = ERROR
            row["detail"] = "crate failed to build or document; not a SemVer signal"
        elif args.published:
            # Against the published baseline, failures are absorbed if the
            # current version already represents a breaking bump over whatever
            # is on the registry.  Extract the published version from the
            # cargo-semver-checks output (it embeds the registry cache path).
            pub_ver = published_baseline_version(row["output"])
            row["base_version"] = pub_ver
            if pub_ver and is_breaking_bump(pub_ver, row["version"]):
                row["verdict"] = ABSORBED
                row["detail"] = (
                    f"breaking change absorbed by published {pub_ver} "
                    f"-> {row['version']}"
                )
            else:
                row["verdict"] = FAIL
                row["detail"] = (
                    f"version {row['version']} does not cover the public-API "
                    f"change vs published {pub_ver or 'unknown'}; bump "
                    f"{row['name']} before publishing"
                )
        elif base_version and is_breaking_bump(base_version, row["version"]):
            row["verdict"] = ABSORBED
            row["detail"] = f"breaking change absorbed by {base_version} -> {row['version']}"
        else:
            row["verdict"] = FAIL
            row["detail"] = (
                f"breaking public-API change in {row['name']} with version still "
                f"{row['version']}; bump the middle number (0.X.0) or revert it"
            )

        if row["verdict"] in (FAIL, ERROR):
            failed = True
        results.append(row)

        icon = {
            OK: "ok  ",
            ABSORBED: "ok  ",
            FAIL: "FAIL",
            ERROR: "ERR ",
        }[row["verdict"]]
        print(
            f"{icon} {row['name']:<20} {row['version']:<12} {row['verdict']:<9} "
            f"{row['detail']}"
        )
        if row["verdict"] in (FAIL, ERROR):
            for lint in summarize_failures(row["output"]):
                print(f"       - {lint}")

    if args.json:
        print(
            json.dumps(
                {
                    "mode": mode,
                    "results": [
                        {
                            "crate": r["name"],
                            "version": r["version"],
                            "base_version": r["base_version"],
                            "verdict": r["verdict"],
                            "detail": r["detail"],
                            "lints": summarize_failures(r["output"], limit=20),
                        }
                        for r in results
                    ],
                },
                indent=2,
            )
        )

    if failed:
        print(
            "\nsemver-gate: FAILED. Each publishable crate versions independently: "
            "a break in one crate is absorbed by that crate's own bump, not by "
            "moving the workspace. See AGENTS.md §7.2.",
            file=sys.stderr,
        )
        return 1
    print("\nsemver-gate: every changed publishable crate is SemVer-clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
