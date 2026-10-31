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
3. Resource Profile: Peak RSS (MB) and wall-clock phase breakdown.
4. Historical Tracking: generates CSV sheets and JSON history logs across git commits.

Usage:
    python3 frensense-bench/suites/blindness.py --prepare
    python3 frensense-bench/suites/blindness.py --run
    python3 frensense-bench/suites/blindness.py --run --only flask,express
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from blindness_challenges import build_challenges, write_outputs  # noqa: E402

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


def clone_repo(repo: PinnedRepo, cache: Path) -> Path:
    """Fetch exactly the pinned commit (full 40-char SHA required: servers do
    not resolve abbreviated SHAs in `git fetch`)."""
    dest = cache / repo.name
    if dest.exists():
        return dest
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
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)  # never leave a half-cloned cache that later runs trust
        raise
    return dest


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


def scan_repo(repo: PinnedRepo, cache: Path, binary: Path, timeout: int) -> Dict[str, Any]:
    root = cache / repo.name
    meta: Dict[str, Any] = {
        "name": repo.name,
        "lang": repo.lang,
        "commit": repo.commit,
        "note": repo.note,
        "files": count_files(root, repo.targets),
    }

    target_paths = [str(root / t) for t in repo.targets]
    explain_json = cache / f"{repo.name}.explain.json"
    explain_json.unlink(missing_ok=True)
    argv = [str(binary), *target_paths, "--json", "--explain-json", str(explain_json)]
    rss_file = cache / f"{repo.name}.rss"
    
    # Use /usr/bin/time -f %M to record peak RSS in kilobytes if available
    time_bin = Path("/usr/bin/time")
    if time_bin.exists():
        argv = [str(time_bin), "-f", "%M", "-o", str(rss_file), *argv]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        meta["exit"] = proc.returncode
        meta["stderr_tail"] = proc.stderr.strip().splitlines()[-3:] if proc.stderr else []
        raw = proc.stdout
    except subprocess.TimeoutExpired as exc:
        meta["exit"] = None
        meta["timeout"] = True
        meta["stderr_tail"] = (exc.stderr or b"").decode("utf-8", "replace").strip().splitlines()[-3:]
        raw = (exc.stdout or b"").decode("utf-8", "replace")
    
    meta["wall_s"] = round(time.monotonic() - started, 2)
    meta["explain_json"] = str(explain_json)

    if rss_file.exists():
        try:
            meta["peak_rss_mb"] = round(int(rss_file.read_text().strip()) / 1024, 1)
        except ValueError:
            meta["peak_rss_mb"] = None
        rss_file.unlink()
    else:
        meta["peak_rss_mb"] = None

    try:
        report = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        meta["bad_json"] = True
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
        status = "TIMEOUT" if r.get("timeout") else f"{r.get('wall_s', 0.0)}s"
        rss = f"{r['peak_rss_mb']} MB" if r.get("peak_rss_mb") is not None else "-"
        lines.append(
            f"| **{r['name']}** | {r['lang']} | {r['files_scanned']} | {r['files_partial']} | "
            f"{r['total_sinks']} | {r['unknown_sinks']} | **{r['blindness_rate']}%** | "
            f"{r['truncation_caps']} | {rss} | {status} |"
        )

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


def main() -> int:
    ap = argparse.ArgumentParser(description="Frensense Engine Blindness & Capability Benchmark")
    ap.add_argument("--prepare", action="store_true", help="clone pinned repositories")
    ap.add_argument("--run", action="store_true", help="run the blindness scan suite")
    ap.add_argument("--only", default="", help="comma-separated repository names to scan")
    ap.add_argument("--binary", type=Path, default=None, help="path to frensense binary")
    ap.add_argument("--cache", type=Path, default=DEFAULT_CACHE, help="repo cache directory")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="output directory for reports")
    ap.add_argument("--timeout", type=int, default=300, help="per-repo timeout seconds")
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

    selected = [r for r in PINNED_REPOS if not args.only or r.name in args.only.split(",")]

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
            meta = scan_repo(repo, args.cache, binary, args.timeout)
            rows.append(meta)
            status = "TIMEOUT" if meta.get("timeout") else f"{meta['wall_s']}s"
            rss = f"{meta['peak_rss_mb']} MB" if meta.get("peak_rss_mb") is not None else "N/A"
            print(
                f"  {repo.name:12} {repo.lang:11} {meta['files_scanned']:>4} files | "
                f"Sinks: {meta['total_sinks']:>4} | "
                f"Unknown: {meta['unknown_sinks']:>3} ({meta['blindness_rate']:>5.1f}%) | "
                f"Caps: {meta['truncation_caps']:>3} | "
                f"RSS: {rss:>7} | {status}"
            )

        # Aggregate overall statistics
        total_sinks = sum(r["total_sinks"] for r in rows)
        unknown_sinks = sum(r["unknown_sinks"] for r in rows)
        clean_sinks = sum(r["clean_sinks"] for r in rows)
        sanitized_sinks = sum(r["sanitized_sinks"] for r in rows)
        vulnerable_sinks = sum(r["vulnerable_sinks"] for r in rows)
        total_caps = sum(r["truncation_caps"] for r in rows)
        files_scanned = sum(r["files_scanned"] for r in rows)
        files_partial = sum(r["files_partial"] for r in rows)
        wall_s = round(sum(r["wall_s"] for r in rows), 2)
        rss_values = [r["peak_rss_mb"] for r in rows if r.get("peak_rss_mb") is not None]
        max_rss = max(rss_values) if rss_values else None

        blindness_rate = round((unknown_sinks / total_sinks * 100), 2) if total_sinks > 0 else 0.0

        all_caps: Dict[str, int] = {}
        for r in rows:
            for cap, count in r.get("caps_breakdown", {}).items():
                all_caps[cap] = all_caps.get(cap, 0) + count

        overall = {
            "blindness_rate": blindness_rate,
            "total_sinks": total_sinks,
            "unknown_sinks": unknown_sinks,
            "clean_sinks": clean_sinks,
            "sanitized_sinks": sanitized_sinks,
            "vulnerable_sinks": vulnerable_sinks,
            "truncation_caps": total_caps,
            "caps_breakdown": all_caps,
            "files_scanned": files_scanned,
            "files_partial": files_partial,
            "peak_rss_mb": max_rss,
            "wall_s": wall_s,
        }

        commit_info = get_git_commit_info()

        full_record = {
            **commit_info,
            "overall": overall,
            "by_repo": {r["name"]: r for r in rows},
        }

        # Write artifacts
        args.out_dir.mkdir(parents=True, exist_ok=True)
        report_json = args.out_dir / "blindness_report.json"
        report_json.write_text(json.dumps(full_record, indent=2))

        history_json = args.out_dir / "blindness_history.json"
        update_history_json(history_json, full_record)

        sheet_csv = args.out_dir / "blindness_sheet.csv"
        update_csv_sheet(sheet_csv, full_record)

        card_md = args.out_dir / "blindness_card.md"
        markdown_text = generate_markdown_card(commit_info, overall, rows)
        card_md.write_text(markdown_text)

        # Challenge cards: one per unknown sink argument, with a stable ID.
        challenges: List[Dict[str, Any]] = []
        for repo in selected:
            ex = args.cache / f"{repo.name}.explain.json"
            if not ex.exists():
                continue
            try:
                records = json.loads(ex.read_text()).get("records", [])
            except (json.JSONDecodeError, OSError):
                continue
            challenges += build_challenges(repo.name, repo.lang, args.cache / repo.name, records, repo.url, repo.commit)
        baseline = args.baseline or (args.out_dir / "challenges.json")
        previous = None
        if baseline.exists():
            try:
                previous = json.loads(baseline.read_text()).get("challenges")
            except (json.JSONDecodeError, OSError):
                previous = None
        produced = write_outputs(
            args.out_dir, challenges, commit_info["commit"], previous, {r.name: args.cache / r.name for r in selected}
        )
        markdown_text += "\n" + produced["markdown"]

        print(f"\nArtifacts generated:")
        print(f"  - Report (JSON):   {report_json}")
        print(f"  - History (JSON):  {history_json}")
        print(f"  - Sheet (CSV):     {sheet_csv}")
        print(f"  - Card (Markdown): {card_md}")
        print(f"  - Challenges:      {args.out_dir / 'challenges.json'} ({len(challenges)} open), challenges.html")

        if args.ci_summary or os.environ.get("GITHUB_STEP_SUMMARY"):
            summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
            if summary_path:
                with open(summary_path, "a", encoding="utf-8") as f:
                    f.write("\n" + markdown_text + "\n")
                print(f"  - Appended to GITHUB_STEP_SUMMARY: {summary_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
