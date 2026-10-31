#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Engine blindness challenges: the sink arguments the engine could not decide, grouped by the
thing it could not see through.

Input is the `--explain-json` file the scanner writes for each pinned repo. Every
`unknown` record becomes a challenge with:

* a stable ID that survives line shifts (hash of repo, file, function, sink, slot and
  the stop site), so a fixed challenge disappears and an unfixed one keeps its ID;
* the sink location and the *stop site*: the call, parameter or global the engine
  could not see through, with its file and line;
* a code excerpt from the pinned checkout, a track, and a reproduction command.

Outputs (written next to the blindness report):
    challenges.json   machine-readable list, the source of truth
    challenges.html   self-contained, filterable card page (no network, no build step)
    challenges.md     short index for the CI job summary

Nothing here is hand-written per repository: the records come from the scanner, the
group title and counts are computed, and only the five per-kind hints/pointers above are
prose. Adding a repo to the suite adds its cards.
"""

import hashlib
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

SLOT_NONE = 18446744073709551615  # usize::MAX: the call's receiver / return slot

# stop-site kind -> (track, difficulty, what a fix looks like)
TRACKS: Dict[str, Dict[str, str]] = {
    "external-call": {
        "track": "Library call",
        "difficulty": "easy",
        "hint": "The engine has no model for this call's result. Teach it whether the "
        "result carries its arguments (passthrough), is fresh, or is attacker-neutral.",
    },
    "param-no-caller": {
        "track": "Unseen caller",
        "difficulty": "medium",
        "hint": "A parameter with no analysed caller (often a method's `self`/receiver, a "
        "callback or an entry point). Resolve how values reach it, or classify the "
        "receiver so field reads on it stop being unknown.",
    },
    "global": {
        "track": "Global state",
        "difficulty": "medium",
        "hint": "The value comes from a global/module variable. Track assignments to it "
        "across the program instead of giving up at the read.",
    },
    "pointer-deref": {
        "track": "Indirection",
        "difficulty": "hard",
        "hint": "The value is read through a pointer. Needs points-to information to "
        "find what was stored there.",
    },
    "indirect-call": {
        "track": "Indirection",
        "difficulty": "hard",
        "hint": "A call through a function value. Resolve the possible targets from the "
        "call graph.",
    },
}
# Where in the engine the walk gives up for each stop-site kind (function names, not
# line numbers, so the pointer stays valid as the file changes).
ENGINE_POINTER = {
    "external-call": "walk.rs `node_is_unresolvable`: the result of a call with no analysed callee is a dead end. "
    "Model the callee (does its result carry its arguments?) so the walk can continue or stop clean.",
    "param-no-caller": "walk.rs `node_is_unresolvable`: a FormalParam no cross edge feeds is a dead end. "
    "Link the call sites that reach it (method receivers, callbacks) or classify the receiver.",
    "global": "walk.rs `node_is_unresolvable`: LoadGlobal is a dead end. Connect the reads to the stores of that global.",
    "pointer-deref": "walk.rs `node_is_unresolvable`: Dereference is a dead end. Needs points-to results for the pointer.",
    "indirect-call": "walk.rs `node_is_unresolvable`: CallPointer is a dead end. Resolve targets from the call graph.",
}

DEFAULT_TRACK = {
    "track": "Unclassified",
    "difficulty": "medium",
    "hint": "The engine stopped without naming a stop site. Run with --explain and find out why.",
}
DIFFICULTY_ORDER = {"easy": 0, "medium": 1, "hard": 2}


NON_PRODUCT_DIRS = {"tests", "test", "examples", "example", "benches", "bench", "fixtures", "docs"}


def is_non_product(rel_file: str) -> bool:
    """Test, example and benchmark code: a blind spot there is not worth a contributor's time."""
    return any(part in NON_PRODUCT_DIRS for part in rel_file.split("/")[:-1])


def in_test_code(repo_root: Path, rel_file: str, line: int, function: str) -> bool:
    """Per-language test code the path alone cannot reveal (inline test modules)."""
    name = rel_file.rsplit("/", 1)[-1]
    if name.endswith(("_test.go", "_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")) or name.startswith("test_"):
        return True
    if function.startswith("test_") or function.startswith("Test"):
        return True
    if rel_file.endswith(".rs") and line > 0:
        try:
            head = (repo_root / rel_file).read_text(encoding="utf-8", errors="replace").splitlines()[: line - 1]
        except OSError:
            return False
        return any(l.strip() == "#[cfg(test)]" for l in head)
    return False


def _unqualified(function: str) -> str:
    return function.rsplit("::", 1)[-1]


def challenge_id(repo: str, rel_file: str, function: str, sink: str, slot: int, sites: Iterable[Dict[str, Any]]) -> str:
    """Stable across line shifts and unrelated edits; changes when the sink or its blind spot changes."""
    parts = [repo, rel_file, _unqualified(function), sink, str(slot)]
    parts += sorted(f"{s['kind']}:{s.get('detail', '')}:{_unqualified(s.get('function', ''))}" for s in sites)
    return "BL-" + hashlib.sha1("|".join(parts).encode()).hexdigest()[:10]


def _rel(path: str, repo_root: Path) -> str:
    p = Path(path)
    try:
        return p.resolve().relative_to(repo_root.resolve()).as_posix()
    except (ValueError, OSError):
        s = path.replace("\\", "/")
        marker = f"/{repo_root.name}/"
        return s.split(marker, 1)[1] if marker in s else s


def excerpt(repo_root: Path, rel_file: str, line: int, radius: int = 3) -> List[Dict[str, Any]]:
    if line <= 0:
        return []
    try:
        lines = (repo_root / rel_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    lo, hi = max(1, line - radius), min(len(lines), line + radius)
    return [{"n": i, "text": lines[i - 1][:200], "hit": i == line} for i in range(lo, hi + 1)]


def build_challenges(
    repo_name: str,
    lang: str,
    repo_root: Path,
    records: List[Dict[str, Any]],
    url: str = "",
    commit: str = "",
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for r in records:
        if r.get("verdict") != "unknown":
            continue
        rel = _rel(r["file"], repo_root)
        if is_non_product(rel) or in_test_code(repo_root, rel, r["line"], _unqualified(r.get("function", ""))):
            continue
        sites = []
        for s in r.get("cut_sites", []):
            sites.append(
                {
                    "kind": s["kind"],
                    "function": _unqualified(s.get("function", "")),
                    "detail": s.get("detail", ""),
                    "file": _rel(s["file"], repo_root) if s.get("file") else "",
                    "line": s.get("line", 0),
                }
            )
        cid = challenge_id(repo_name, rel, r.get("function", ""), r["sink"], r["arg_slot"], sites)
        if cid in seen:
            continue
        seen.add(cid)
        primary = sites[0]["kind"] if sites else ""
        meta = TRACKS.get(primary, DEFAULT_TRACK)
        slot = "receiver/return" if r["arg_slot"] == SLOT_NONE else f"arg {r['arg_slot']}"
        out.append(
            {
                "id": cid,
                "repo": repo_name,
                "lang": lang,
                "file": rel,
                "line": r["line"],
                "function": _unqualified(r.get("function", "")),
                "sink": r["sink"],
                "slot": slot,
                "track": meta["track"],
                "difficulty": meta["difficulty"],
                "hint": meta["hint"],
                "reason": r.get("reason", ""),
                "stop_sites": sites,
                "code": excerpt(repo_root, rel, r["line"]),
                "repro": f"frensense {rel} --explain",
                "engine_pointer": ENGINE_POINTER.get(primary, ""),
                "pin": {"url": url, "commit": commit},
            }
        )
    return out


def diff_against(previous: Optional[List[Dict[str, Any]]], current: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """IDs that were solved (present before, gone now) and new ones (appeared since)."""
    before = {c["id"] for c in previous or []}
    now = {c["id"] for c in current}
    return {"solved": sorted(before - now), "new": sorted(now - before) if previous is not None else []}


def sort_challenges(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(items, key=lambda c: (DIFFICULTY_ORDER[c["difficulty"]], c["repo"], c["file"], c["line"], c["id"]))


# ---------------------------------------------------------------- grouping


def group_key(c: Dict[str, Any]) -> str:
    """Sinks blocked by the same unseen thing in the same repo are one challenge."""
    site = c["stop_sites"][0] if c["stop_sites"] else {"kind": "unclassified", "detail": ""}
    return f"{c['repo']}|{site['kind']}|{site['detail']}"


def group_challenges(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}
    for c in items:
        k = group_key(c)
        g = groups.get(k)
        if g is None:
            site = c["stop_sites"][0] if c["stop_sites"] else {"kind": "unclassified", "detail": "", "function": "", "file": "", "line": 0}
            g = groups[k] = {
                "id": "BG-" + hashlib.sha1(k.encode()).hexdigest()[:10],
                "repo": c["repo"],
                "lang": c["lang"],
                "kind": site["kind"],
                "detail": site["detail"],
                "track": c["track"],
                "difficulty": c["difficulty"],
                "hint": c["hint"],
                "engine_pointer": c.get("engine_pointer", ""),
                "pin": c.get("pin"),
                "stop": {"function": site["function"], "file": site["file"], "line": site["line"]},
                "members": [],
            }
        g["members"].append(c)
    out = list(groups.values())
    for g in out:
        g["impact"] = len(g["members"])
        g["members"].sort(key=lambda m: (m["file"], m["line"]))
    return sorted(out, key=lambda g: (-g["impact"], DIFFICULTY_ORDER[g["difficulty"]], g["repo"], g["detail"]))


def title_for(g: Dict[str, Any]) -> str:
    d = g["detail"]
    return {
        "external-call": f"Unmodelled call: {d}",
        "param-no-caller": f"No caller feeds parameter: {d or 'unnamed'}",
        "global": f"Global read: {d}",
        "pointer-deref": "Value read through a pointer",
        "indirect-call": "Call through a function value",
    }.get(g["kind"], "Engine stopped here")


def windows(repo_root: Optional[Path], marks: List[Dict[str, Any]], radius: int = 2) -> List[Dict[str, Any]]:
    """Code windows around the marked lines (`file`, `line`, `label`); overlapping windows merge."""
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for m in marks:
        if m["file"] and m["line"] > 0:
            by_file.setdefault(m["file"], []).append(m)
    out = []
    for f, ms in by_file.items():
        try:
            lines = (repo_root / f).read_text(encoding="utf-8", errors="replace").splitlines() if repo_root else []
        except OSError:
            lines = []
        if not lines:
            continue
        spans: List[List[Any]] = []
        for m in sorted(ms, key=lambda x: x["line"]):
            lo, hi = max(1, m["line"] - radius), min(len(lines), m["line"] + radius)
            if spans and lo <= spans[-1][1] + 1:
                spans[-1][1] = max(spans[-1][1], hi)
                spans[-1][2].append(m)
            else:
                spans.append([lo, hi, [m]])
        for lo, hi, mk in spans:
            labels = {x["line"]: x["label"] for x in mk}
            out.append(
                {
                    "file": f,
                    "lines": [
                        {"n": i, "text": lines[i - 1][:160], "mark": labels.get(i, "")} for i in range(lo, hi + 1)
                    ],
                }
            )
    return out


# ---------------------------------------------------------------- rendering


def render_markdown(groups: List[Dict[str, Any]], delta: Optional[Dict[str, List[str]]] = None) -> str:
    total = sum(g["impact"] for g in groups)
    head = f"**{len(groups)}** open challenges blocking **{total}** sinks"
    if delta and (delta["solved"] or delta["new"]):
        head += f" (sinks solved since last run: **{len(delta['solved'])}**, new: **{len(delta['new'])}**)"
    lines = ["### Open engine blind spots", "", head, "", "Biggest wins first:", ""]
    for g in groups[:10]:
        lines.append(f"- `{g['id']}` {g['repo']}: {title_for(g)} (unblocks {g['impact']}, {g['difficulty']})")
    return "\n".join(lines) + "\n"


_CSS = """
:root{--bg:#fafafa;--card:#fff;--ink:#16181d;--mute:#6b7280;--line:#e7e8ec;--accent:#4f46e5;--code:#f4f5f8;
--sink:#fde9b0;--stop:#cfeedd;--easy:#15803d;--medium:#b45309;--hard:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f14;--card:#151922;--ink:#e9ebf1;--mute:#98a1b3;--line:#232a38;--accent:#9193fa;--code:#0e1219;
--sink:#4a3d12;--stop:#14402d;--easy:#4ade80;--medium:#fbbf24;--hard:#f87171}}
*{box-sizing:border-box}code{overflow-wrap:anywhere}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header,.bar,main{max-width:1000px;margin:auto;padding:0 16px}
header{padding-top:32px}h1{margin:0;font-size:24px;letter-spacing:-.01em}
header p{margin:4px 0 0;color:var(--mute)}
.bar{display:flex;flex-wrap:wrap;gap:6px;margin-top:18px;margin-bottom:16px;align-items:center}
.bar button,.bar input{font:inherit;font-size:14px;padding:5px 12px;border:1px solid var(--line);border-radius:999px;background:var(--card);color:var(--ink);cursor:pointer}
.bar button.on{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.bar input{cursor:text;min-width:170px;margin-left:auto}
main{display:grid;grid-template-columns:repeat(auto-fill,minmax(440px,1fr));gap:14px;padding-bottom:56px}
@media (max-width:520px){main{grid-template-columns:1fr}}
.card[hidden]{display:none}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;display:flex;flex-direction:column;gap:12px;min-width:0}
.meta{display:flex;align-items:center;gap:8px;color:var(--mute);font-size:13px}
.dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.easy{color:var(--easy)}.medium{color:var(--medium)}.hard{color:var(--hard)}
.impact{margin-left:auto;font-weight:600;color:var(--ink)}
h2{margin:0;font-size:18px;line-height:1.3}
.sub{margin:0;color:var(--mute);font-size:14px}
.win{margin:0;background:var(--code);border-radius:10px;padding:6px 0;overflow:auto;font:12.5px/1.55 ui-monospace,Menlo,monospace}
.win .f{display:block;padding:2px 12px 4px;color:var(--mute);font-size:11.5px}
.win span.l{display:block;white-space:pre;padding:0 12px}.win i{color:var(--mute);font-style:normal;display:inline-block;width:34px}
.win .sink{background:var(--sink)}.win .stop{background:var(--stop)}
.legend{display:flex;align-items:center;gap:6px;color:var(--mute);font-size:12.5px;margin-bottom:-4px}.legend .k{width:10px;height:10px;border-radius:3px}.legend .k:not(:first-child){margin-left:10px}.k.stop{background:var(--stop)}.k.sink{background:var(--sink)}
details{border-top:1px solid var(--line);padding-top:8px}
summary{cursor:pointer;color:var(--mute);font-size:13.5px;list-style:none}
summary::-webkit-details-marker{display:none}summary::before{content:"+";display:inline-block;width:16px}
details[open] summary::before{content:"-"}
.body{margin-top:8px;font-size:14px;display:flex;flex-direction:column;gap:6px}
.body ul{margin:0;padding:0;list-style:none;max-height:220px;overflow:auto}
.body li{display:flex;gap:10px;justify-content:space-between;padding:3px 0;border-bottom:1px dashed var(--line)}
.body li span{color:var(--mute);font:12px ui-monospace,Menlo,monospace}
.mono{font:12px ui-monospace,Menlo,monospace;color:var(--mute);word-break:break-all}
.id{background:none;border:0;color:var(--mute);font:12px ui-monospace,Menlo,monospace;cursor:pointer;padding:0;text-align:left}
"""

_JS = """
const cards=[...document.querySelectorAll('.card')];const st={track:'',diff:'',q:''};
function apply(){let n=0;for(const c of cards){const ok=(!st.track||c.dataset.track===st.track)&&(!st.diff||c.dataset.diff===st.diff)&&(!st.q||c.dataset.text.includes(st.q));c.hidden=!ok;if(ok)n++}document.getElementById('n').textContent=n+' of '+cards.length}
document.querySelectorAll('[data-f]').forEach(b=>b.onclick=()=>{const k=b.dataset.f,v=b.dataset.v;st[k]=st[k]===v?'':v;
document.querySelectorAll('[data-f="'+k+'"]').forEach(x=>x.classList.toggle('on',st[k]===x.dataset.v));apply()});
document.getElementById('q').oninput=e=>{st.q=e.target.value.toLowerCase();apply()};
document.querySelectorAll('.id').forEach(b=>b.onclick=()=>{try{navigator.clipboard.writeText(b.dataset.id)}catch(e){};b.textContent='copied'});
apply();
"""


def _window_html(w: Dict[str, Any]) -> str:
    e = html.escape
    rows = ""
    for r in w["lines"]:
        cls = {"sink": " sink", "stop": " stop"}.get(r["mark"], "")
        rows += f"<span class='l{cls}'><i>{r['n']}</i>{e(r['text'])}</span>"
    return f"<span class=f>{e(w['file'])}</span>{rows}"


def _card(g: Dict[str, Any], roots: Dict[str, Path]) -> str:
    e = html.escape
    n = g["impact"]
    rep = g["members"][0]
    rs = rep["stop_sites"][0] if rep["stop_sites"] else {"file": "", "line": 0, "function": ""}
    marks = [
        {"file": rs["file"], "line": rs["line"], "label": "stop"},
        {"file": rep["file"], "line": rep["line"], "label": "sink"},
    ]
    wins = windows(roots.get(g["repo"]), marks)
    legend = "<div class=legend><span class='k stop'></span>engine lost the value here<span class='k sink'></span>sink it blocks</div>"
    code = legend + "<div class=win>" + "".join(_window_html(w) for w in wins) + "</div>" if wins else ""
    fn = f" in <code>{e(rs['function'])}()</code>" if rs.get("function") else ""
    summary = (
        f"The engine could not see through <code>{e(g['detail'] or g['kind'].replace('-', ' '))}</code>{fn}, "
        f"so {n} sink{'s' if n != 1 else ''} stay{'s' if n == 1 else ''} unknown."
    )
    sinks = "".join(f"<li><b>{e(m['sink'])}</b><span>{e(m['file'])}:{m['line']}</span></li>" for m in g["members"])
    pin = g.get("pin") or {}
    where = (
        f"{e(pin['url'].removesuffix('.git'))} @ {e(pin['commit'][:7])}" if pin.get("url") and pin.get("commit") else ""
    )
    pointer = f"<div>{e(g['engine_pointer'])}</div>" if g.get("engine_pointer") else ""
    text = " ".join([g["id"], g["repo"], g["detail"], g["track"]] + [m["file"] for m in g["members"]]).lower()
    return (
        f"<article class=card data-track='{e(g['track'])}' data-diff='{g['difficulty']}' data-text='{e(text)}'>"
        f"<div class=meta><span class='dot {g['difficulty']}'></span>{g['difficulty']} · {e(g['track'])} · {e(g['repo'])}"
        f"<span class=impact>unblocks {n} sink{'s' if n != 1 else ''}</span></div>"
        f"<h2>{e(title_for(g))}</h2>"
        f"<p class=sub>{summary}</p>{code}"
        f"<details><summary>Affected sinks ({n})</summary><div class=body><ul>{sinks}</ul></div></details>"
        f"<details><summary>Where to start</summary><div class=body><div>{e(g['hint'])}</div>{pointer}"
        f"<div class=mono>{where}</div><div class=mono>$ {e(rep['repro'])}</div>"
        f"<button class=id data-id='{g['id']}' title='copy'>{g['id']}</button></div></details>"
        "</article>"
    )


def render_html(groups: List[Dict[str, Any]], commit: str, delta: Optional[Dict[str, List[str]]] = None, roots: Optional[Dict[str, Path]] = None) -> str:
    roots = roots or {}
    tracks = sorted({g["track"] for g in groups})
    total = sum(g["impact"] for g in groups)
    solved = f" · {len(delta['solved'])} sinks solved since last run" if delta and delta["solved"] else ""
    btns = "".join(f"<button data-f=diff data-v={d}>{d}</button>" for d in ("easy", "medium", "hard"))
    btns += "".join(f"<button data-f=track data-v='{html.escape(t)}'>{html.escape(t)}</button>" for t in tracks)
    cards = "".join(_card(g, roots) for g in groups) or "<p>No open challenges. The engine sees everything here.</p>"
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Engine Blind Spots</title><style>" + _CSS + "</style></head><body>"
        f"<header><h1>Engine blind spots</h1><p>{len(groups)} challenges block {total} sinks at "
        f"<code>{html.escape(commit[:7])}</code>{solved}. Fix one and its card shrinks or disappears on the next run.</p></header>"
        f"<div class=bar>{btns}<input id=q placeholder='Filter'><span class=meta id=n></span></div>"
        f"<main>{cards}</main><script>{_JS}</script></body></html>"
    )


def sort_challenges(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(items, key=lambda c: (DIFFICULTY_ORDER[c["difficulty"]], c["repo"], c["file"], c["line"], c["id"]))


def write_outputs(
    out_dir: Path,
    challenges: List[Dict[str, Any]],
    commit: str,
    previous: Optional[List[Dict[str, Any]]] = None,
    roots: Optional[Dict[str, Path]] = None,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    delta = diff_against(previous, challenges) if previous is not None else None
    groups = group_challenges(challenges)
    doc = {
        "schema": 2,
        "commit": commit,
        "count": len(challenges),
        "groups": [{k: v for k, v in g.items() if k != "members"} | {"sinks": [m["id"] for m in g["members"]]} for g in groups],
        "challenges": sort_challenges(challenges),
        "delta": delta,
    }
    (out_dir / "challenges.json").write_text(json.dumps(doc, indent=2))
    (out_dir / "challenges.html").write_text(render_html(groups, commit, delta, roots))
    md = render_markdown(groups, delta)
    (out_dir / "challenges.md").write_text(md)
    return {"markdown": md, "delta": delta}
