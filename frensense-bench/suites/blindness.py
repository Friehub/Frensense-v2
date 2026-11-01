#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Engine Blindness & Capability Benchmark: track dataflow limits and RSS across commits.

Motivation:
OWASP evaluates synthetic True/False Positive rates. This benchmark evaluates
the engine's analytical boundary on real-world open-source software:
1. Blindness Rate: percentage of sink arguments where backward taint traversal
   ended with 'unknown' (hit an unmodeled edge, opaque callee, or missing stub).
2. Truncation Caps: tally of safety valves fired (call_context_depth, forward_hops,
   callgraph_hops, value_iterations, points_to_passes).
3. Resource Profile: Peak RSS (MB), wall-clock phase breakdown, and the per-repo
   memory ceiling, so a scan that grows from 300 MB to 2.5 GB is visible on the
   page a contributor reads, not just in CI logs.
4. Historical Tracking: generates CSV sheets and JSON history logs across git commits.
5. Challenge cards: `challenges.html` / `challenges.json`, one card per engine
   blind spot grouped by the thing the walk could not see through.

Usage:
    python3 frensense-bench/suites/blindness.py --prepare
    python3 frensense-bench/suites/blindness.py --run
    python3 frensense-bench/suites/blindness.py --run --only flask,express
    python3 frensense-bench/suites/blindness.py --run --synthetic owasp=/path/to/testcode

Timeouts (per scan, so a repo is never cut short silently):
    default 1800s; override with --timeout SECONDS, the FRENSENSE_BLINDNESS_TIMEOUT environment
    variable, or a per-repo `timeout=` on its pin. `0` / `none` removes the limit.
    --case-timeout (default 120s) bounds one file of a synthetic suite such as OWASP.
    A scan that times out or crashes fails the run (exit 3); it is never counted as clean.
    The whole process group is killed, so a timed-out scan cannot keep burning RAM.

Memory budget:
    --max-rss-mb N turns the per-repo peak RSS into a hard gate: any scan above N
    MB is reported and the run exits 4. Without it the ceiling is only recorded.

Exit codes: 0 ok, 2 usage/selection error, 3 a scan failed or timed out,
4 a scan exceeded --max-rss-mb.
"""

import argparse
import csv
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from blindness_challenges import (  # noqa: E402
    build_challenges,
    carry_forward,
    restrict_previous,
    write_outputs,
)
from scanproc import run_scan, time_wrapped  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BIN = ROOT / "target" / "release" / "frensense"
DEFAULT_DEBUG_BIN = ROOT / "target" / "debug" / "frensense"
DEFAULT_CACHE = ROOT / "target" / "blindness-repos"
DEFAULT_OUT_DIR = ROOT / "target" / "blindness"

SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".c", ".h", ".rs", ".go",
}
SKIP_DIRS = {
    "node_modules", "target", "dist", "build", "vendor", "out", ".next",
    ".nuxt", ".cache", "coverage", ".git", "tests", "test", "fixtures",
}


@dataclass(frozen=True)
class PinnedRepo:
    name: str
    url: str
    commit: str
    lang: str
    targets: Tuple[str, ...] = (".",)
    note: str = ""
    timeout: Optional[int] = None  # seconds; a slow repo can raise its own limit (None: the default)


# Pinned commits representing diverse language ecosystems and programming patterns
PINNED_REPOS: Tuple[PinnedRepo, ...] = (
    PinnedRepo(
        name="flask",
        url="https://github.com/pallets/flask.git",
        commit="d086db856be187255b8ec61ef409357393020f32",
        lang="python",
        targets=("src",),
        note="Python microframework; dynamic WSGI request routing",
    ),
    PinnedRepo(
        name="express",
        url="https://github.com/expressjs/express.git",
        commit="1c6f1b0fe4000977b9a7b4f34097e4d527dd9824",
        lang="javascript",
        targets=("lib",),
        note="Node.js middleware framework; asynchronous callback chains",
    ),
    PinnedRepo(
        name="libpng",
        url="https://github.com/pnggroup/libpng.git",
        commit="890812a28da480f84f3b0198d31ac611c864ed98",
        lang="c",
        targets=(".",),
        note="C library; memory pointers, buffers, and system IO",
    ),
    PinnedRepo(
        name="axum",
        url="https://github.com/tokio-rs/axum.git",
        commit="86aa6153e47b7862737acdcfe3a0eb3a162b939a",
        lang="rust",
        targets=(".",),
        note="Rust async framework; trait-based handler extraction",
    ),
)


DEFAULT_TIMEOUT_S = 1800
TIMEOUT_ENV = "FRENSENSE_BLINDNESS_TIMEOUT"


def parse_timeout(value: Any) -> Optional[int]:
    """Seconds, or None for "no limit" (0, none, off, unlimited)."""
    text = str(value).strip().lower()
    if text in ("0", "none", "off", "unlimited", "no"):
        return None
    try:
        seconds = int(text)
    except ValueError:
        raise ValueError(f"timeout must be a number of seconds or 'none', got {value!r}") from None
    if seconds < 0:
        raise ValueError(f"timeout must not be negative, got {seconds}")
    return seconds


def effective_timeout(explicit: Optional[str], repo_timeout: Optional[int]) -> Optional[int]:
    """Command line or environment wins, then the repo's own pin, then the default."""
    if explicit not in (None, ""):
        return parse_timeout(explicit)
    if repo_timeout is not None:
        return repo_timeout
    return DEFAULT_TIMEOUT_S


def get_git_commit_info() -> Dict[str, str]:
    """Capture current git commit metadata for historical tracking."""
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        short_sha = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], text=True).strip()
        branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
        author = subprocess.check_output(["git", "log", "-1", "--format=%an <%ae>"], text=True).strip()
        date = subprocess.check_output(["git", "log", "-1", "--format=%cI"], text=True).strip()
        msg = subprocess.check_output(["git", "log", "-1", "--format=%s"], text=True).strip()
    except Exception:
        sha = "unknown"
        short_sha = "unknown"
        branch = "unknown"
        author = "unknown"
        date = datetime.datetime.now(datetime.timezone.utc).isoformat()
        msg = "Local uncommitted scan"
    return {
        "commit": sha,
        "short_sha": short_sha,
        "branch": branch,
        "author": author,
        "date": date,
        "message": msg,
    }


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


def _resolve_targets(root: Path, targets: Tuple[str | list[str], ...]) -> List[str]:
    """Normalize the scanner target specification into existing absolute paths.

    A pin may specify one target or a list of targets. The audited CLI accepts
    either `<path>` or `<path> <path> ...`; we flatten any list into a sequence
    of dirs/files that actually exist under the pinned checkout. A target that
    disappeared is an error, not a reason to scan the whole repository: silently
    widening the input would change the memory profile and the blindness rate
    while still publishing them under the pin's SHA.
    """
    resolved: List[str] = []
    for t in targets:
        p = root / t if isinstance(t, str) else Path(t)
        if p.is_dir():
            resolved.append(str(p))
        elif p.is_file():
            resolved.append(str(p.parent))
        else:
            raise FileNotFoundError(
                f"{root.name}: scanned target '{t}' missing from pinned checkout at {root}. "
                f"Re-run --prepare, or fix the pin's targets."
            )
    return resolved


def count_files(root: Path, targets: Tuple[str, ...]) -> int:
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


def scan_repo(repo: PinnedRepo, cache: Path, binary: Path, timeout: Optional[int]) -> Dict[str, Any]:
    root = cache / repo.name
    meta: Dict[str, Any] = {
        "name": repo.name,
        "lang": repo.lang,
        "commit": repo.commit,
        "note": repo.note,
        "files": count_files(root, repo.targets),
    }

    # `--run` without `--prepare` used to measure whatever the cache held. A
    # checkout at a different commit is a different measurement, so refuse it
    # rather than publish it under the pin's SHA.
    head = _head_sha(root)
    if head and head != repo.commit:
        meta.update(wall_s=0.0, peak_rss_mb=None, total_sinks=0, unknown_sinks=0,
                    clean_sinks=0, sanitized_sinks=0, vulnerable_sinks=0,
                    blindness_rate=0.0, truncation_caps=0, caps_breakdown={},
                    files_scanned=0, files_partial=0, files_failed=0, functions=0,
                    timings={}, exit=None,
                    failed=f"checkout is at {head[:7]}, pin is {repo.commit[:7]} (re-run --prepare)")
        return meta

    target_paths = _resolve_targets(root, repo.targets)
    explain_json = cache / f"{repo.name}.explain.json"
    explain_json.unlink(missing_ok=True)
    rss_file = cache / f"{repo.name}.rss"

    run = run_scan(
        time_wrapped(binary, target_paths, rss_file, ["--json", "--explain-json", str(explain_json)]),
        timeout,
        rss_file,
    )
    raw = run["stdout"]
    meta["exit"] = run["exit"]
    meta["wall_s"] = run["wall_s"]
    meta["stderr_tail"] = run["stderr_tail"]
    meta["explain_json"] = str(explain_json)
    meta["peak_rss_mb"] = run["peak_rss_mb"]
    if run["timeout"]:
        meta["timeout"] = True
        meta["failed"] = f"timed out after {timeout}s (raise it with --timeout or {TIMEOUT_ENV}; 0 removes the limit)"
    elif meta["exit"] not in (0, 1):
        meta["failed"] = f"exit code {meta['exit']}"

    try:
        report = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        meta["bad_json"] = True
        meta.setdefault("failed", "unreadable JSON report")
        report = {}

    analysis = report.get("analysis", {})
    verdicts = analysis.get("verdicts", {})
    clean = verdicts.get("clean", 0)
    sanitized = verdicts.get("sanitized", 0)
    vulnerable = verdicts.get("vulnerable", 0)
    unknown = verdicts.get("unknown", 0)
    total_sinks = clean + sanitized + vulnerable + unknown

    blindness_rate = round((unknown / total_sinks * 100), 2) if total_sinks > 0 else 0.0

    truncations_list = analysis.get("truncations", [])
    truncations_dict: Dict[str, int] = {}
    total_caps = 0
    for item in truncations_list:
        cap_id = item.get("cap", "unknown_cap")
        hits = item.get("hits", 0)
        truncations_dict[cap_id] = truncations_dict.get(cap_id, 0) + hits
        total_caps += hits

    coverage = analysis.get("coverage", {})
    advisories = report.get("advisories", [])

    meta["producer"] = report.get("producer", {})
    meta["advisories"] = len(advisories)
    meta["total_sinks"] = total_sinks
    meta["unknown_sinks"] = unknown
    meta["clean_sinks"] = clean
    meta["sanitized_sinks"] = sanitized
    meta["vulnerable_sinks"] = vulnerable
    meta["blindness_rate"] = blindness_rate
    meta["truncation_caps"] = total_caps
    meta["caps_breakdown"] = truncations_dict
    meta["files_scanned"] = coverage.get("files_scanned", meta["files"])
    meta["files_partial"] = coverage.get("files_partial", 0)
    meta["files_failed"] = coverage.get("files_failed", 0)
    meta["functions"] = coverage.get("functions", 0)
    meta["timings"] = {t.get("phase"): t.get("ms") for t in analysis.get("timings", [])}

    return meta


def parse_synthetic_spec(spec: str) -> Tuple[str, Path]:
    """`name=dir` or bare `dir` -> (suite name, resolved directory)."""
    if "=" in spec:
        name, _, raw = spec.partition("=")
        name, raw = name.strip(), raw.strip()
    else:
        name, raw = "", spec.strip()
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"synthetic suite '{spec}': {root} is not a directory")
    if not name:
        name = root.name
    return name, root


def _synthetic_cases(root: Path) -> List[Path]:
    """Every supported source file, scanned one process per file (no shared state)."""
    cases: List[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix not in SUFFIXES:
            continue
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel.parts[:-1]):
            continue
        cases.append(p)
    return cases


_LANG_OF_SUFFIX = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".c": "c", ".h": "c", ".rs": "rust", ".go": "go",
}


def _lang_of(cases: List[Path]) -> str:
    counts: Dict[str, int] = {}
    for c in cases:
        lang = _LANG_OF_SUFFIX.get(c.suffix, "unknown")
        counts[lang] = counts.get(lang, 0) + 1
    return max(counts, key=counts.get) if counts else "unknown"


def scan_synthetic(
    name: str,
    root: Path,
    binary: Path,
    case_timeout: Optional[int],
    workers: int,
    cache: Path,
) -> Dict[str, Any]:
    """Score a directory of independent cases (OWASP-shaped), one process per file.

    A synthetic suite is not a program: each case must be scanned on its own, or
    a symbol from one case changes the verdicts of the next. The per-case timeout
    is what `--case-timeout` bounds.
    """
    cases = _synthetic_cases(root)
    if not cases:
        raise ValueError(f"synthetic suite '{name}': no supported files under {root}")

    work = cache / f"{name}.synthetic"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    explain_json = cache / f"{name}.explain.json"
    explain_json.unlink(missing_ok=True)

    def one(item: Tuple[int, Path]) -> Tuple[Path, Dict[str, Any], Path, Optional[float]]:
        i, case = item
        ex = work / f"{i:05d}.explain.json"
        rss = work / f"{i:05d}.rss"
        run = run_scan(time_wrapped(binary, [case], rss, ["--json", "--explain-json", str(ex)]), case_timeout, rss)
        return case, run, ex, run["peak_rss_mb"]

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(one, enumerate(cases)))
    wall = round(time.monotonic() - started, 2)

    records: List[Dict[str, Any]] = []
    verdicts: Dict[str, int] = {"clean": 0, "sanitized": 0, "vulnerable": 0, "unknown": 0}
    caps: Dict[str, int] = {}
    phases: Dict[str, int] = {}
    failed: Dict[str, str] = {}
    producer: Dict[str, Any] = {}
    peak: Optional[float] = None
    scanned = partial = functions = 0

    for case, run, ex, rss in results:
        rel = case.relative_to(root).as_posix()
        if rss is not None and (peak is None or rss > peak):
            peak = rss
        if run["timeout"]:
            failed[rel] = f"timed out after {case_timeout}s"
            continue
        if run["exit"] not in (0, 1):
            failed[rel] = f"exit code {run['exit']}"
            continue
        try:
            report = json.loads(run["stdout"]) if run["stdout"].strip() else {}
        except json.JSONDecodeError:
            failed[rel] = "unreadable JSON report"
            continue
        analysis = report.get("analysis", {})
        producer = producer or report.get("producer", {})
        v = analysis.get("verdicts", {})
        for key in verdicts:
            verdicts[key] += int(v.get(key, 0))
        coverage = analysis.get("coverage", {})
        scanned += int(coverage.get("files_scanned", 1))
        partial += int(coverage.get("files_partial", 0))
        functions += int(coverage.get("functions", 0))
        for t in analysis.get("timings", []):
            phases[str(t.get("phase", "other"))] = phases.get(str(t.get("phase", "other")), 0) + int(t.get("ms", 0))
        for item in analysis.get("truncations", []):
            cap = str(item.get("cap", "unknown_cap"))
            caps[cap] = caps.get(cap, 0) + int(item.get("hits", 0))
        if ex.exists():
            try:
                records.extend(json.loads(ex.read_text()).get("records", []))
            except (json.JSONDecodeError, OSError):
                failed[rel] = "unreadable --explain-json"

    explain_json.write_text(json.dumps({"schema": 1, "records": records}))
    shutil.rmtree(work, ignore_errors=True)  # only the merged explain file is kept

    total = sum(verdicts.values())
    meta: Dict[str, Any] = {
        "name": name,
        "lang": _lang_of(cases),
        "commit": "",
        "note": f"synthetic suite: {len(cases)} independent cases",
        "synthetic": True,
        "files": len(cases),
        "files_scanned": scanned,
        "files_partial": partial,
        "files_failed": len(failed),
        "functions": functions,
        "advisories": 0,
        "total_sinks": total,
        "unknown_sinks": verdicts["unknown"],
        "clean_sinks": verdicts["clean"],
        "sanitized_sinks": verdicts["sanitized"],
        "vulnerable_sinks": verdicts["vulnerable"],
        "blindness_rate": round(verdicts["unknown"] / total * 100, 2) if total else 0.0,
        "truncation_caps": sum(caps.values()),
        "caps_breakdown": caps,
        "peak_rss_mb": peak,
        "wall_s": wall,
        "timings": phases,
        "cases": len(cases),
        "failed_cases": failed,
        "producer": producer,
        "explain_json": str(explain_json),
        "exit": 0 if not failed else 1,
    }
    if failed:
        shown = ", ".join(sorted(failed)[:3])
        more = "" if len(failed) <= 3 else f" (+{len(failed) - 3} more)"
        meta["failed"] = f"{len(failed)} of {len(cases)} cases failed: {shown}{more}"
    return meta


def generate_markdown_card(commit_info: Dict[str, str], overall: Dict[str, Any], rows: List[Dict[str, Any]]) -> str:
    lines = [
        "# Frensense Engine Blindness & Capability Card",
        "",
        f"> **Commit**: `{commit_info['short_sha']}` ({commit_info['date'][:10]}) | "
        f"**Author**: {commit_info['author']} | "
        f"**Branch**: `{commit_info['branch']}`",
        f"> **Headline**: {commit_info['message']}",
        "",
        "### Key Capability Metrics",
        f"- **Global Blindness Rate**: **{overall['blindness_rate']}%** ({overall['unknown_sinks']} unknown / {overall['total_sinks']} explored sinks)",
        f"- **Safety Valve Caps Fired**: **{overall['truncation_caps']}** bounds hit across scans",
        f"- **Peak RSS**: **{str(overall['peak_rss_mb']) + ' MB' if overall['peak_rss_mb'] is not None else 'n/a'}** | **Total Wall Time**: **{overall['wall_s']}s**",
        "",
        "### Repository Telemetry Breakdown",
        "",
        "| Repository | Lang | Scanned Files | Partial | Explored Sinks | Unknown (Blind) | Blindness Rate | Caps Hit | Peak RSS | Wall Time |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for r in rows:
        if r.get("failed"):
            status = "**FAILED**"
        else:
            status = f"{r.get('wall_s', 0.0)}s"
        rss = f"{r['peak_rss_mb']} MB" + (" (per case)" if r.get("synthetic") else "") if r.get("peak_rss_mb") is not None else "-"
        lines.append(
            f"| **{r['name']}** | {r['lang']} | {r['files_scanned']} | {r['files_partial']} | "
            f"{r['total_sinks']} | {r['unknown_sinks']} | **{r['blindness_rate']}%** | "
            f"{r['truncation_caps']} | {rss} | {status} |"
        )

    lines.append("")
    if overall.get("failed_repos"):
        lines.append("### Failed scans (never counted as clean)")
        lines.append("")
        for name, why in overall["failed_repos"].items():
            lines.append(f"- **{name}**: {why}")
        lines.append("")

    lines.append("### Memory & Phase Profile")
    lines.append("")
    sampled = [r for r in rows if r.get("peak_rss_mb") is not None]
    if sampled:
        lines.append("| Repository | Peak RSS | RSS / scanned file | Scanned Files | Functions | Wall Time |")
        lines.append("| :--- | ---: | ---: | ---: | ---: | ---: |")
        for r in sorted(sampled, key=lambda x: -(x.get("peak_rss_mb") or 0)):
            per_file = r["peak_rss_mb"] / r["files_scanned"] if r.get("files_scanned") else 0.0
            suffix = " (per case)" if r.get("synthetic") else ""
            lines.append(
                f"| **{r['name']}** | {r['peak_rss_mb']} MB{suffix} | {per_file:.2f} MB | "
                f"{r.get('files_scanned', 0)} | {r.get('functions', 0)} | {r.get('wall_s', 0)}s |"
            )
    else:
        lines.append("*No peak-RSS samples: `/usr/bin/time` is required for memory profiling.*")
    phases = overall.get("phases") or {}
    if phases:
        parts = " · ".join(f"`{k}` {v / 1000:.2f}s" for k, v in sorted(phases.items(), key=lambda kv: -kv[1]) if k != "total")
        lines.append("")
        lines.append(f"Engine-reported phase totals (engine CPU, summed across scans): {parts}")
    budget = overall.get("max_rss_mb")
    if budget is not None:
        lines.append("")
        if overall.get("over_budget"):
            lines.append(f"**Memory budget exceeded**: limit {budget} MB; over: " + ", ".join(overall["over_budget"]) + ".")
        else:
            lines.append(f"Memory budget: every scan stayed under {budget} MB.")

    lines.append("")
    lines.append("### Safety Valve Caps Breakdown (Where Dataflow Halted)")
    lines.append("")
    if overall["caps_breakdown"]:
        lines.append("| Cap Identifier | Occurrences | Analytical Impact |")
        lines.append("| :--- | :--- | :--- |")
        effects = {
            "value_iterations": "Value lattice stopped worklist rounds; constant branch sharpening dropped",
            "call_context_depth": "Call-site stack depth exceeded MAX_CTX_DEPTH; collapsed to context-insensitive (k=0)",
            "call_context_chains": "Context table full; subsequent call walks collapsed to context-insensitive",
            "contexts_per_function": "Single function exceeded context budget; additional call sites merged",
            "forward_hops": "Enclosing lexical chain limit reached; free name resolution aborted",
            "callgraph_hops": "Alias chain limit reached; target callee unresolved",
            "points_to_passes": "Points-to analysis failed to converge within pass budget; field precision dropped",
        }
        for cap, count in sorted(overall["caps_breakdown"].items(), key=lambda kv: -kv[1]):
            effect = effects.get(cap, "Safety boundary hit")
            lines.append(f"| `{cap}` | **{count}** | {effect} |")
    else:
        lines.append("*No truncation caps fired during this run.*")

    lines.append("")
    lines.append("---")
    lines.append("*(Report automatically generated by `frensense-bench/suites/blindness.py`)*")
    return "\n".join(lines)


def update_history_json(history_file: Path, record: Dict[str, Any]) -> None:
    history: List[Dict[str, Any]] = []
    if history_file.exists():
        try:
            history = json.loads(history_file.read_text())
            if not isinstance(history, list):
                history = []
        except Exception:
            history = []

    # Update or append record by commit hash
    commit_sha = record.get("commit")
    existing_idx = next((i for i, r in enumerate(history) if r.get("commit") == commit_sha), None)
    if existing_idx is not None:
        history[existing_idx] = record
    else:
        history.append(record)

    # Sort history chronologically by date
    history.sort(key=lambda r: r.get("date", ""))
    history_file.parent.mkdir(parents=True, exist_ok=True)
    history_file.write_text(json.dumps(history, indent=2))


def update_csv_sheet(csv_file: Path, record: Dict[str, Any]) -> None:
    csv_file.parent.mkdir(parents=True, exist_ok=True)
    file_exists = csv_file.exists()
    
    headers = [
        "commit", "short_sha", "date", "branch", "author", "message",
        "global_blindness_rate", "total_sinks", "unknown_sinks", "clean_sinks",
        "vulnerable_sinks", "total_caps_hit", "peak_rss_mb", "wall_time_s",
        "repos_scanned", "total_files_scanned", "partial_files"
    ]
    
    row = {
        "commit": record.get("commit"),
        "short_sha": record.get("short_sha"),
        "date": record.get("date"),
        "branch": record.get("branch"),
        "author": record.get("author"),
        "message": record.get("message"),
        "global_blindness_rate": record["overall"].get("blindness_rate"),
        "total_sinks": record["overall"].get("total_sinks"),
        "unknown_sinks": record["overall"].get("unknown_sinks"),
        "clean_sinks": record["overall"].get("clean_sinks"),
        "vulnerable_sinks": record["overall"].get("vulnerable_sinks"),
        "total_caps_hit": record["overall"].get("truncation_caps"),
        "peak_rss_mb": record["overall"].get("peak_rss_mb"),
        "wall_time_s": record["overall"].get("wall_s"),
        "repos_scanned": len(record.get("by_repo", {})),
        "total_files_scanned": record["overall"].get("files_scanned"),
        "partial_files": record["overall"].get("files_partial"),
    }

    # If file exists, check if row exists and update, or rewrite
    rows: List[Dict[str, Any]] = []
    if file_exists:
        try:
            with open(csv_file, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = [r for r in reader]
        except Exception:
            rows = []

    commit_sha = record.get("commit")
    existing_idx = next((i for i, r in enumerate(rows) if r.get("commit") == commit_sha), None)
    if existing_idx is not None:
        rows[existing_idx] = {k: str(v) for k, v in row.items()}
    else:
        rows.append({k: str(v) for k, v in row.items()})

    rows.sort(key=lambda r: r.get("date", ""))

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def aggregate(rows: List[Dict[str, Any]], max_rss_mb: Optional[float]) -> Dict[str, Any]:
    """Sum the per-repository rows into the headline record.

    A row with no `peak_rss_mb` (no `/usr/bin/time` on the host) is not 0 MB:
    the ceiling is computed over the sampled rows only and stays `None` when
    nothing was sampled, so "unknown" never displays as "tiny".
    """
    total = sum(r["total_sinks"] for r in rows)
    unknown = sum(r["unknown_sinks"] for r in rows)
    caps: Dict[str, int] = {}
    phases: Dict[str, int] = {}
    for r in rows:
        for cap, count in (r.get("caps_breakdown") or {}).items():
            caps[cap] = caps.get(cap, 0) + count
        for phase, ms in (r.get("timings") or {}).items():
            phases[phase] = phases.get(phase, 0) + int(ms or 0)

    rss_values = [r["peak_rss_mb"] for r in rows if r.get("peak_rss_mb") is not None]
    peak_repo = max(rows, key=lambda r: r.get("peak_rss_mb") or -1)["name"] if rss_values else None
    identity = next((r.get("producer") for r in rows if r.get("producer")), {})
    return {
        "blindness_rate": round(unknown / total * 100, 2) if total else 0.0,
        "total_sinks": total,
        "unknown_sinks": unknown,
        "clean_sinks": sum(r["clean_sinks"] for r in rows),
        "sanitized_sinks": sum(r["sanitized_sinks"] for r in rows),
        "vulnerable_sinks": sum(r["vulnerable_sinks"] for r in rows),
        "truncation_caps": sum(r["truncation_caps"] for r in rows),
        "caps_breakdown": caps,
        "files_scanned": sum(r["files_scanned"] for r in rows),
        "files_partial": sum(r["files_partial"] for r in rows),
        "peak_rss_mb": max(rss_values) if rss_values else None,
        "peak_rss_repo": peak_repo,
        "wall_s": round(sum(r["wall_s"] for r in rows), 2),
        "phases": phases,
        "failed_repos": {r["name"]: r["failed"] for r in rows if r.get("failed")},
        "max_rss_mb": max_rss_mb,
        "over_budget": [
            r["name"] for r in rows
            if max_rss_mb is not None and (r.get("peak_rss_mb") or 0) > max_rss_mb
        ],
        "engine_version": identity.get("engine_version") or identity.get("version"),
    }


def emit_artifacts(
    out_dir: Path,
    cache: Path,
    rows: List[Dict[str, Any]],
    selected: List[PinnedRepo],
    synthetic: List[Tuple[str, Path]],
    commit_info: Dict[str, str],
    overall: Dict[str, Any],
    baseline: Optional[Path] = None,
) -> Dict[str, Any]:
    """Write the report, time series, Markdown card and the challenge page.

    Only a full, failure-free pinned run touches the history and CSV: a debugging
    `--only` run must never publish a row for the commit.
    """
    full_suite = not synthetic and {r.name for r in selected} == {r.name for r in PINNED_REPOS} \
        and not overall["failed_repos"]
    identity = next((r.get("producer") for r in rows if r.get("producer")), {})
    record = {
        **commit_info,
        "scope": [r["name"] for r in rows],
        "partial": not full_suite,
        "producer": identity,
        "overall": overall,
        "by_repo": {r["name"]: r for r in rows},
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "report": out_dir / "blindness_report.json",
        "history": out_dir / "blindness_history.json",
        "sheet": out_dir / "blindness_sheet.csv",
        "card": out_dir / "blindness_card.md",
    }
    paths["report"].write_text(json.dumps(record, indent=2))
    if full_suite:
        update_history_json(paths["history"], record)
        update_csv_sheet(paths["sheet"], record)
    else:
        reason = "a scan failed" if overall["failed_repos"] else "this was not the full pinned suite"
        print(f"\n[note] not updating the history/sheet: {reason}.")

    markdown = generate_markdown_card(commit_info, overall, rows)
    paths["card"].write_text(markdown)

    # Challenge cards: one per unknown sink argument, with a stable ID.
    by_name = {r["name"]: r for r in rows}
    sources: List[Tuple[str, str, Path, str, str]] = [
        (r.name, r.lang, cache / r.name, r.url, r.commit)
        for r in selected if not by_name[r.name].get("failed")
    ]
    sources += [
        (meta["name"], meta["lang"], root, "", "")
        for (name, root), meta in zip(synthetic, [by_name[n] for n, _ in synthetic])
        if not meta.get("failed")
    ]
    challenges: List[Dict[str, Any]] = []
    for name, lang, root, url, commit in sources:
        ex = cache / f"{name}.explain.json"
        if not ex.exists():
            continue
        try:
            records = json.loads(ex.read_text()).get("records", [])
        except (json.JSONDecodeError, OSError):
            continue
        challenges += build_challenges(name, lang, root, records, url, commit)

    baseline = baseline or (out_dir / "challenges.json")
    previous = None
    if baseline.exists():
        try:
            previous = json.loads(baseline.read_text()).get("challenges")
        except (json.JSONDecodeError, OSError):
            previous = None
    scanned = {r["name"] for r in rows if not r.get("failed")}
    # Only a repo this run scanned can have a challenge solved; cards for the
    # rest stay on the page so --only cannot read as "the backlog is empty".
    previous_scanned = restrict_previous(previous, scanned) if previous is not None else None
    carried = carry_forward(previous, scanned) if previous is not None else []
    produced = write_outputs(
        out_dir,
        challenges,
        commit_info["commit"],
        previous_scanned,
        roots={r.name: cache / r.name for r in PINNED_REPOS} | {name: root for name, root in synthetic},
        carried=carried,
        profile={"identity": identity, "rows": rows, "overall": overall},
    )
    markdown += "\n" + produced["markdown"]
    return {"paths": paths, "markdown": markdown, "full_suite": full_suite,
            "open": len(challenges), "carried": len(carried)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Frensense Engine Blindness & Capability Benchmark")
    ap.add_argument("--prepare", action="store_true", help="clone pinned repositories")
    ap.add_argument("--run", action="store_true", help="run the blindness scan suite")
    ap.add_argument("--only", default="", help="comma-separated repository names to scan")
    ap.add_argument("--binary", type=Path, default=None, help="path to frensense binary")
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE, help="repo cache directory")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="output directory for reports")
    ap.add_argument(
        "--timeout",
        default=None,
        help=f"seconds allowed per scan (default {DEFAULT_TIMEOUT_S}; env {TIMEOUT_ENV}; 0 or 'none' = no limit). "
        "A scan that times out fails the run, it never counts as clean",
    )
    ap.add_argument(
        "--synthetic",
        action="append",
        default=[],
        metavar="[NAME=]DIR",
        help="score a directory of independent cases (OWASP-shaped), one process per file. "
        "Repeatable. With --synthetic, the pinned repos run only when --only names them",
    )
    ap.add_argument("--case-timeout", type=int, default=120, help="seconds allowed per file in a --synthetic suite (default 120)")
    ap.add_argument("--workers", type=int, default=8, help="concurrent scans for --synthetic (default 8)")
    ap.add_argument("--max-rss-mb", type=float, default=None, help="fail (exit 4) when any scan peaks above this many MB")
    ap.add_argument("--baseline", type=Path, default=None, help="previous challenges.json; solved/new challenges are reported against it")
    ap.add_argument("--ci-summary", action="store_true", help="write to $GITHUB_STEP_SUMMARY if present")
    args = ap.parse_args()

    if not (args.prepare or args.run):
        ap.error("pass --prepare and/or --run")

    binary = args.binary
    if binary is None:
        if DEFAULT_BIN.exists():
            binary = DEFAULT_BIN
        elif DEFAULT_DEBUG_BIN.exists():
            binary = DEFAULT_DEBUG_BIN
        else:
            binary = DEFAULT_BIN

    explicit_timeout = args.timeout if args.timeout not in (None, "") else os.environ.get(TIMEOUT_ENV)
    try:
        effective_timeout(explicit_timeout, None)
    except ValueError as exc:
        ap.error(str(exc))

    # A name that matches nothing must be an error, not an empty run: it used to
    # write a 0-sink row into the history and sheet, which reads exactly like a
    # perfect scan (0% blindness) on a commit nobody measured.
    known = {r.name for r in PINNED_REPOS}
    wanted = [n.strip() for n in args.only.split(",") if n.strip()]
    unknown_names = [n for n in wanted if n not in known]
    if unknown_names:
        ap.error(f"unknown repository name(s): {', '.join(unknown_names)}; known: {', '.join(sorted(known))}")
    selected = [r for r in PINNED_REPOS if not wanted or r.name in wanted]

    synthetic: List[Tuple[str, Path]] = []
    for spec in args.synthetic:
        try:
            synthetic.append(parse_synthetic_spec(spec))
        except ValueError as exc:
            ap.error(str(exc))
    if synthetic and not wanted:
        selected = []  # a synthetic run is about that suite, not about the pinned repos
    if not selected and not synthetic:
        ap.error("nothing to scan: name a pinned repo with --only, or pass --synthetic DIR")

    if args.max_rss_mb is not None and args.max_rss_mb <= 0:
        ap.error("--max-rss-mb must be a positive number of megabytes")
    # `--case-timeout 0` is not "no limit": `communicate(timeout=0)` expires
    # immediately and would kill every case. Only `--timeout 0` means unbounded.
    if args.case_timeout <= 0:
        ap.error("--case-timeout must be a positive number of seconds")

    if args.prepare:
        print(f"Preparing {len(selected)} pinned repositories under {args.cache}...")
        for repo in selected:
            clone_repo(repo, args.cache)
            print(f"  [ok] {repo.name:12} ({repo.commit[:7]})")

    if args.run:
        if not binary.exists():
            print(f"Error: binary '{binary}' not found. Run 'cargo build --release' first.", file=sys.stderr)
            return 2

        print(f"Running Engine Blindness & Capability Scan using {binary}...\n")
        rows: List[Dict[str, Any]] = []
        for repo in selected:
            meta = scan_repo(repo, args.cache, binary, effective_timeout(explicit_timeout, repo.timeout))
            rows.append(meta)
            status = f"FAILED ({meta['failed']})" if meta.get("failed") else f"{meta['wall_s']}s"
            rss = f"{meta['peak_rss_mb']} MB" if meta.get("peak_rss_mb") is not None else "N/A"
            print(
                f"  {repo.name:12} {repo.lang:11} {meta['files_scanned']:>4} files | "
                f"Sinks: {meta['total_sinks']:>4} | "
                f"Unknown: {meta['unknown_sinks']:>3} ({meta['blindness_rate']:>5.1f}%) | "
                f"Caps: {meta['truncation_caps']:>3} | "
                f"RSS: {rss:>7} | {status}"
            )

        for name, root in synthetic:
            meta = scan_synthetic(name, root, binary, args.case_timeout, args.workers, args.cache)
            rows.append(meta)
            status = f"FAILED ({meta['failed']})" if meta.get("failed") else f"{meta['wall_s']}s"
            rss = f"{meta['peak_rss_mb']} MB" if meta.get("peak_rss_mb") is not None else "N/A"
            print(
                f"  {name:12} {meta['lang']:11} {meta['files_scanned']:>4} files | "
                f"Sinks: {meta['total_sinks']:>4} | "
                f"Unknown: {meta['unknown_sinks']:>3} ({meta['blindness_rate']:>5.1f}%) | "
                f"Caps: {meta['truncation_caps']:>3} | "
                f"RSS: {rss:>7} | {status}  [{meta['cases']} cases]"
            )

        # Aggregate overall statistics
        overall = aggregate(rows, args.max_rss_mb)
        commit_info = get_git_commit_info()

        produced = emit_artifacts(
            args.out_dir, args.cache, rows, selected, synthetic, commit_info, overall, args.baseline
        )
        markdown_text = produced["markdown"]

        print(f"\nArtifacts generated:")
        print(f"  - Report (JSON):   {produced['paths']['report']}")
        if produced["full_suite"]:
            print(f"  - History (JSON):  {produced['paths']['history']}")
            print(f"  - Sheet (CSV):     {produced['paths']['sheet']}")
        print(f"  - Card (Markdown): {produced['paths']['card']}")
        print(f"  - Challenges:      {args.out_dir / 'challenges.json'} "
              f"({produced['open']} open + {produced['carried']} carried), challenges.html")

        if args.ci_summary or os.environ.get("GITHUB_STEP_SUMMARY"):
            summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
            if summary_path:
                with open(summary_path, "a", encoding="utf-8") as f:
                    f.write("\n" + markdown_text + "\n")
                print(f"  - Appended to GITHUB_STEP_SUMMARY: {summary_path}")

        if overall["failed_repos"]:
            for name, why in overall["failed_repos"].items():
                print(f"[FAILED] {name}: {why}", file=sys.stderr)
            return 3
        if overall["over_budget"]:
            by_name = {r["name"]: r for r in rows}
            for name in overall["over_budget"]:
                print(
                    f"[RSS] {name}: {by_name[name].get('peak_rss_mb')} MB exceeds --max-rss-mb {args.max_rss_mb}",
                    file=sys.stderr,
                )
            return 4

    return 0


if __name__ == "__main__":
    sys.exit(main())
