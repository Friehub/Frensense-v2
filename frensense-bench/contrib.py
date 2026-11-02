#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Challenge claims, pull-request verification, the credit ledger and badges.

The flow this file implements:

1. A contributor writes `Solves: BG-0123456789` in a pull request description.
2. `verify` (PR workflow, read-only) rescans the repos those challenges belong to with the PR's
   engine and compares against the published baseline. It reports, and it never awards anything.
3. After the merge, the main-branch run calls `ledger`. Credit is computed there, from main's own
   scan, so a PR cannot talk its way into points: a sink counts as solved only when it is gone from
   a scan of merged code.
4. Badges are derived from the ledger on every run (`badges.json` holds the thresholds).

Subcommands (all file in, file out; no network):

    contrib.py claims --body-file pr.md --baseline challenges.json --out claims.json
    contrib.py verify --baseline old.json --current new.json --claims claims.json --out result.json --comment comment.md
    contrib.py ledger --ledger old_ledger.json --prs prs.json --baseline old.json --current new.json --out ledger.json
"""

import argparse
import json
import math
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

HERE = Path(__file__).resolve().parent
BADGES_FILE = HERE / "badges.json"
MARKER = "<!-- frensense-challenge-verify -->"
MAX_CLAIMS = 10
LEDGER_SCHEMA = 1

_GROUP_ID = re.compile(r"\bBG-[0-9a-f]{10}\b")
_CLAIM_LINE = re.compile(r"(?im)^[ \t>*-]*(?:solves|solve|fixes challenges?|closes challenges?)[ \t]*:?[ \t]*(.+)$")


# ----------------------------------------------------------------------------- claims


def parse_claims(body: Optional[str]) -> List[str]:
    """Challenge IDs named on `Solves:` lines of a PR description, in order, without duplicates.

    Only lines that start with the keyword count, so an ID mentioned in prose ("this is related to
    BG-...") is not a claim.
    """
    seen: List[str] = []
    for line in _CLAIM_LINE.findall(body or ""):
        for gid in _GROUP_ID.findall(line):
            if gid not in seen:
                seen.append(gid)
    return seen


def _groups(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {g["id"]: g for g in doc.get("groups", [])}


def resolve_claims(claims: List[str], baseline: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """(known groups, unknown ids, ids beyond the per-PR limit)."""
    groups = _groups(baseline)
    kept, extra = claims[:MAX_CLAIMS], claims[MAX_CLAIMS:]
    known = [groups[c] for c in kept if c in groups]
    return known, [c for c in kept if c not in groups], extra


def repo_of(item: Dict[str, Any]) -> str:
    """Labelled challenges are grouped under their source (`recent-cves`), not the per-case repo."""
    return item.get("group_repo") or item["repo"]


# ----------------------------------------------------------------------------- verification


def _open_by_repo(doc: Dict[str, Any], repos: Set[str]) -> Dict[str, int]:
    counts: Dict[str, int] = {r: 0 for r in repos}
    for c in doc.get("challenges", []):
        r = repo_of(c)
        if r in repos:
            counts[r] += 1
    return counts


def _scores_by_name(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {s["name"]: s for s in doc.get("scores", [])}


def evaluate(baseline: Dict[str, Any], current: Dict[str, Any], claims: List[str], scanned: Iterable[str]) -> Dict[str, Any]:
    """Compare a scan of the PR against the published baseline.

    A claimed challenge is *solved* when every one of its sinks is gone, *partial* when some are.
    The PR fails when a scanned repo ends with more open challenges than it started with, or when a
    labelled source lost a detection or gained a false alarm: a fix must not trade one blind spot for
    another. Sink IDs encode the stop site, so a sink that merely changed shape is not progress.
    """
    scanned_set = set(scanned)
    known, unknown, extra = resolve_claims(claims, baseline)
    still_open = {c["id"] for c in current.get("challenges", [])}
    results = []
    for g in known:
        sinks = g.get("sinks", [])
        gone = [s for s in sinks if s not in still_open]
        status = "solved" if sinks and len(gone) == len(sinks) else "partial" if gone else "none"
        results.append({
            "id": g["id"], "repo": g["repo"], "title": g.get("title") or f"{g['repo']}: {g.get('detail') or g['kind']}",
            "difficulty": g["difficulty"], "before": len(sinks), "solved": len(gone), "remaining": len(sinks) - len(gone),
            "status": status, "outside_scan": g["repo"] not in scanned_set,
        })

    before, after = _open_by_repo(baseline, scanned_set), _open_by_repo(current, scanned_set)
    regressions: List[str] = []
    for r in sorted(scanned_set):
        if after[r] > before[r]:
            regressions.append(f"`{r}` has more open challenges than before ({before[r]} to {after[r]})")
    base_scores, cur_scores = _scores_by_name(baseline), _scores_by_name(current)
    for name, now in sorted(cur_scores.items()):
        was = base_scores.get(name)
        if not was or name not in scanned_set:
            continue
        if now["tp"] < was["tp"]:
            regressions.append(f"`{name}` lost detections ({was['tp']} to {now['tp']} true positives)")
        if now["fp"] > was["fp"]:
            regressions.append(f"`{name}` gained false alarms ({was['fp']} to {now['fp']})")

    progress = any(r["solved"] for r in results if not r["outside_scan"])
    problems: List[str] = []
    if not claims:
        problems.append("no `Solves: BG-...` line in the description")
    if unknown:
        problems.append("unknown challenge ID(s): " + ", ".join(f"`{u}`" for u in unknown) + " (already solved, or from another baseline)")
    if claims and known and not progress:
        problems.append("none of the claimed challenges lost a sink")
    return {
        "ok": not regressions and not problems,
        "claims": results, "unknown": unknown, "ignored": extra,
        "regressions": regressions, "problems": problems,
        "scanned": sorted(scanned_set), "open_before": before, "open_after": after,
    }


def render_comment(result: Dict[str, Any]) -> str:
    icon = {"solved": "✅", "partial": "🟡", "none": "⚪"}
    lines = [MARKER, "### Challenge check", ""]
    lines.append("**Verified against a fresh scan of this branch.**" if result["ok"] else "**This branch does not verify yet.**")
    lines.append("")
    if result["claims"]:
        lines += ["| Challenge | Result | Sinks left |", "|---|---|---|"]
        for c in result["claims"]:
            note = " (not scanned in this run)" if c["outside_scan"] else ""
            lines.append(f"| `{c['id']}` {c['title']} ({c['difficulty']}) | {icon[c['status']]} {c['status']}{note} | {c['remaining']} of {c['before']} |")
        lines.append("")
    for p in result["problems"] + result["regressions"]:
        lines.append(f"- ⚠️ {p}")
    if result["ignored"]:
        lines.append(f"- Only the first {MAX_CLAIMS} claims are checked; ignored: " + ", ".join(f"`{i}`" for i in result["ignored"]))
    lines += [
        "",
        "Credit is awarded after merge, from the scan of `main`, not from this check. "
        "Points, badges and the leaderboard are on the [challenge board](https://frensense.friehub.cloud/challenges).",
    ]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------- ledger


def load_badges(path: Path = BADGES_FILE) -> Dict[str, Any]:
    cfg = json.loads(path.read_text())
    for b in cfg["badges"]:
        for stat in b["all"]:
            if stat not in STATS:
                raise ValueError(f"badge {b['id']}: unknown stat {stat!r}")
    return cfg


STATS = ("prs", "points", "sinks", "cleared", "hard_cleared", "languages")


def points_for(difficulty: str, solved: int, cleared: bool, table: Dict[str, int]) -> int:
    """Weight x (1 + log2 sinks), plus the weight again for taking the challenge to zero.

    The log keeps a 300-sink group from being worth 300 small ones: the hard part is the first fix.
    """
    weight = table.get(difficulty, 2)
    return weight * (1 + int(math.log2(max(solved, 1)))) + (weight if cleared else 0)


def award(
    ledger: Dict[str, Any],
    prs: List[Dict[str, Any]],
    baseline: Dict[str, Any],
    current: Dict[str, Any],
    now: Optional[str] = None,
    cfg: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Add an entry for every (merged PR, claimed challenge) that removed sinks. Idempotent.

    `current` is main's scan after the merges, so a sink is credited only when it is really gone.
    PRs are processed in merge order and a sink is credited once: when two PRs claim the same
    challenge the earlier merge gets the sinks it removed, the later one only what is left.
    """
    cfg = cfg or load_badges()
    now = now or datetime.now(timezone.utc).isoformat(timespec="seconds")
    groups, cur_groups = _groups(baseline), _groups(current)
    still_open = {c["id"] for c in current.get("challenges", [])}
    existing = {e["id"] for e in ledger.get("entries", [])}
    credited: Set[str] = {s for e in ledger.get("entries", []) for s in e.get("sink_ids", [])}
    new: List[Dict[str, Any]] = []
    for pr in sorted(prs, key=lambda p: (p.get("merged_at") or "", p["number"])):
        author = (pr.get("author") or "").strip()
        if not author or author.endswith("[bot]"):
            continue
        for gid in parse_claims(pr.get("body"))[:MAX_CLAIMS]:
            g = groups.get(gid)
            entry_id = f"{pr['number']}:{gid}"
            if g is None or entry_id in existing:
                continue
            sinks = g.get("sinks", [])
            solved = [s for s in sinks if s not in still_open and s not in credited]
            if not solved:
                continue
            credited.update(solved)
            cleared = gid not in cur_groups and all(s not in still_open for s in sinks)
            entry = {
                "id": entry_id, "pr": pr["number"], "pr_url": pr.get("url", ""), "pr_title": pr.get("title", ""),
                "author": author, "merged_at": pr.get("merged_at", ""), "sha": pr.get("sha", ""),
                "challenge": gid, "repo": g["repo"], "lang": g.get("lang", ""), "track": g.get("track", ""),
                "kind": g.get("kind", ""), "difficulty": g["difficulty"],
                "sinks_solved": len(solved), "cleared": cleared,
                "points": points_for(g["difficulty"], len(solved), cleared, cfg["points"]),
                "awarded_at": now, "sink_ids": solved,
            }
            ledger.setdefault("entries", []).append(entry)
            existing.add(entry_id)
            new.append(entry)
    ledger["schema"] = LEDGER_SCHEMA
    ledger["updated"] = now
    ledger["contributors"] = contributors(ledger["entries"], cfg)
    return ledger, new


def _stats_template() -> Dict[str, Any]:
    return {"prs": set(), "points": 0, "sinks": 0, "cleared": 0, "hard_cleared": 0, "languages": set()}


def _snapshot(s: Dict[str, Any]) -> Dict[str, int]:
    return {"prs": len(s["prs"]), "points": s["points"], "sinks": s["sinks"], "cleared": s["cleared"],
            "hard_cleared": s["hard_cleared"], "languages": len(s["languages"])}


def contributors(entries: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Per author totals and badges, replayed in order so each badge carries the date it was earned."""
    stats: Dict[str, Dict[str, Any]] = defaultdict(_stats_template)
    earned: Dict[str, Dict[str, str]] = defaultdict(dict)
    meta: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"first": "", "last": "", "entries": 0})
    for e in sorted(entries, key=lambda x: (x.get("merged_at", ""), x["id"])):
        a = e["author"]
        s = stats[a]
        s["prs"].add(e["pr"])
        s["points"] += e["points"]
        s["sinks"] += e["sinks_solved"]
        if e.get("cleared"):
            s["cleared"] += 1
            if e["difficulty"] == "hard":
                s["hard_cleared"] += 1
        if e.get("lang"):
            s["languages"].add(e["lang"])
        m = meta[a]
        m["first"] = m["first"] or e.get("merged_at", "")
        m["last"] = e.get("merged_at", "")
        m["entries"] += 1
        snap = _snapshot(s)
        for b in cfg["badges"]:
            if b["id"] not in earned[a] and all(snap[k] >= v for k, v in b["all"].items()):
                earned[a][b["id"]] = e.get("merged_at", "")
    by_id = {b["id"]: b for b in cfg["badges"]}
    out = []
    for a, s in stats.items():
        snap = _snapshot(s)
        out.append({
            "login": a, **snap, "first_at": meta[a]["first"], "last_at": meta[a]["last"],
            "badges": [{"id": i, "name": by_id[i]["name"], "description": by_id[i]["description"], "earned_at": at}
                       for i, at in sorted(earned[a].items(), key=lambda kv: kv[1])],
            "next": _next_badge(snap, earned[a], cfg),
        })
    out.sort(key=lambda c: (-c["points"], -c["sinks"], c["login"]))
    return out


def _next_badge(snap: Dict[str, int], have: Dict[str, str], cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The unearned badge that is closest, as the stats still missing."""
    best = None
    for b in cfg["badges"]:
        if b["id"] in have:
            continue
        missing = {k: v - snap[k] for k, v in b["all"].items() if snap[k] < v}
        gap = sum(missing[k] / b["all"][k] for k in missing)  # fraction of each requirement still to go
        if best is None or gap < best[0]:
            best = (gap, {"id": b["id"], "name": b["name"], "missing": missing})
    return best[1] if best else None


# ----------------------------------------------------------------------------- CLI


def _load(path: Optional[str], default: Any = None) -> Any:
    if not path or not Path(path).exists():
        return default
    try:
        return json.loads(Path(path).read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: not valid JSON: {exc}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("claims", help="read Solves: lines from a PR description")
    c.add_argument("--body-file", required=True)
    c.add_argument("--baseline", required=True)
    c.add_argument("--out", required=True)

    v = sub.add_parser("verify", help="compare a scan of the PR with the baseline")
    v.add_argument("--baseline", required=True)
    v.add_argument("--current", required=True)
    v.add_argument("--claims", required=True)
    v.add_argument("--out", required=True)
    v.add_argument("--comment", required=True)

    l = sub.add_parser("ledger", help="award credit for merged PRs (main-branch run)")
    l.add_argument("--ledger", default=None, help="previous ledger.json (missing = start empty)")
    l.add_argument("--prs", required=True)
    l.add_argument("--baseline", required=True)
    l.add_argument("--current", required=True)
    l.add_argument("--out", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "claims":
        baseline = _load(args.baseline)
        if baseline is None:
            raise SystemExit(f"{args.baseline}: baseline missing; nothing to verify against")
        ids = parse_claims(Path(args.body_file).read_text(encoding="utf-8", errors="replace"))
        known, unknown, extra = resolve_claims(ids, baseline)
        doc = {"claims": ids, "unknown": unknown, "ignored": extra, "repos": sorted({g["repo"] for g in known})}
        Path(args.out).write_text(json.dumps(doc, indent=2))
        print(",".join(doc["repos"]))
        return 0

    if args.cmd == "verify":
        baseline, current, claims = _load(args.baseline), _load(args.current), _load(args.claims)
        if baseline is None or current is None or claims is None:
            raise SystemExit("verify needs --baseline, --current and --claims files")
        result = evaluate(baseline, current, claims["claims"], claims["repos"])
        Path(args.out).write_text(json.dumps(result, indent=2))
        Path(args.comment).write_text(render_comment(result))
        print(render_comment(result))
        return 0 if result["ok"] else 1

    if args.cmd == "ledger":
        baseline, current = _load(args.baseline), _load(args.current)
        if baseline is None or current is None:
            raise SystemExit("ledger needs --baseline and --current")
        ledger = _load(args.ledger, {"schema": LEDGER_SCHEMA, "entries": []})
        ledger, new = award(ledger, _load(args.prs, []), baseline, current)
        Path(args.out).write_text(json.dumps(ledger, indent=1))
        for e in new:
            print(f"+{e['points']:>3} {e['author']} PR #{e['pr']} {e['challenge']} ({e['sinks_solved']} sinks{', cleared' if e['cleared'] else ''})")
        print(f"{len(new)} new entr{'y' if len(new) == 1 else 'ies'}; {len(ledger['entries'])} total")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
