#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
"""Labelled blindness challenges: code whose answer is known.

The "unknown" challenges only cover places the engine *knows* it is blind. Labelled
code covers the rest, where the engine is silent or wrong without saying so:

* **missed**       the code is labelled vulnerable and the engine reported nothing there;
* **false-alarm**  the code is labelled safe and the engine reported it anyway.

Label sources, all pinned and all machine-checkable:

* ``juice-shop``  the upstream ``// vuln-code-snippet vuln-line <challenge>`` markers (line-exact);
* ``owasp-python`` the OWASP BenchmarkPython ``expectedresults`` CSV (file-level, includes safe cases);
* ``nodegoat``    anchors in ``labels/nodegoat.json``: a text anchor per known flaw, resolved to a
                  line at run time so a drifting checkout fails loudly instead of mislabelling;
* ``recent-cves`` fix commits from 2024-2026 (``labels/recent_cves.json``): the lines the fix removed
                  or changed are the vulnerable region, the fixed file is the safe control.

A challenge produced here has the same shape as an "unknown" one (see blindness_challenges.py)
plus ``kind`` and ``label``, so IDs, grouping, the delta and the page work unchanged.
"""

import csv
import difflib
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import scanproc  # noqa: E402

LABELS_DIR = HERE.parent / "labels"

CWE_NAMES = {
    "22": "path traversal", "78": "command injection", "79": "cross-site scripting", "88": "argument injection",
    "89": "SQL injection", "90": "LDAP injection", "94": "code injection", "95": "code injection",
    "327": "weak cryptography", "328": "weak hash", "330": "weak randomness", "502": "unsafe deserialization",
    "601": "open redirect", "611": "XML external entity", "614": "insecure cookie", "643": "XPath injection",
    "918": "server-side request forgery", "943": "NoSQL injection", "501": "trust boundary violation",
}
CLASS_CWE = {
    "file.traversal": "22", "file.zip_slip": "22", "inj.shell_metachar": "78", "inj.argument": "88",
    "net.ssrf": "918", "web.xss": "79", "inj.sql": "89",
}
HINTS = {
    "missed": "The code is labelled vulnerable, yet nothing was reported. Find where the walk to this "
    "sink stops (run with --explain) and teach the engine the missing step.",
    "false-alarm": "The code is labelled safe, yet the engine reports it. Find the guard, constant or "
    "sanitiser on the reported path (run with --show-flows) that the walk did not credit.",
}
POINTERS = {
    "missed": "`frensense <file> --explain` lists every sink the engine explored here. No sink listed: the call "
    "is not recognised. Listed as unknown or clean: follow its stop site (walk.rs `node_is_unresolvable`).",
    "false-alarm": "`frensense <file> --show-flows` prints the reported path. The false positive is a step on that "
    "path the engine should have cut (guard dominance, constant folding, sanitiser roles in walk.rs).",
}


def cwe_name(cwe: str) -> str:
    return CWE_NAMES.get(str(cwe).replace("CWE-", ""), f"CWE-{cwe}" if cwe else "unclassified")


# ----------------------------------------------------------------------------- label adapters
# A label: {repo, file (relative to the repo root), line (0 = file-level), vulnerable, cwe, case}


def juice_labels(root: Path, dirs=("routes", "lib", "models")) -> List[Dict[str, Any]]:
    marker = re.compile(r"vuln-code-snippet\s+vuln-line\s+((?:[a-z][A-Za-z0-9]*\s*)+)")
    out = []
    for d in dirs:
        for f in sorted((root / d).rglob("*.ts")):
            for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                m = marker.search(line) if "vuln-code-snippet vuln-line" in line else None
                for case in (m.group(1).split() if m else []):
                    out.append({"file": f.relative_to(root).as_posix(), "line": n, "vulnerable": True, "cwe": "", "case": case})
    return out


def owasp_labels(root: Path) -> List[Dict[str, Any]]:
    out = []
    for row in csv.reader((root / "expectedresults-0.1.csv").open()):
        if len(row) < 4 or row[0].startswith("#"):
            continue
        name, cat, real, cwe = (c.strip() for c in row[:4])
        f = root / "testcode" / f"{name}.py"
        if not f.exists():
            continue
        out.append(
            # File-level label: `line` stays 0 so any advisory in the file counts; `show_line`
            # is only where the card points the reader (the first line that reads request data).
            {"file": f"testcode/{name}.py", "line": 0, "file_level": True, "show_line": _source_line(f), "vulnerable": real == "true", "cwe": cwe, "case": f"{cat}:{name}"}
        )
    return out


def _source_line(path: Path) -> int:
    """First line that reads request data: where the flow starts, a good line to show for a file-level label."""
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if re.search(r"request\.(args|form|cookies|headers|values|json|get_json|data|files)", line):
            return n
    return 0


def anchored_labels(root: Path, spec_path: Path) -> List[Dict[str, Any]]:
    """Hand labels pinned by a text anchor. A missing anchor raises: the label would be wrong."""
    out = []
    for item in json.loads(spec_path.read_text())["labels"]:
        lines = (root / item["file"]).read_text(errors="replace").splitlines()
        hit = next((i for i, l in enumerate(lines, 1) if item["anchor"] in l), None)
        if hit is None:
            raise ValueError(f"label anchor not found in {item['file']}: {item['anchor']!r}")
        out.append({"file": item["file"], "line": hit, "vulnerable": True, "cwe": item["cwe"], "case": item["case"]})
    return out


NON_TAINT_CWE = {"327", "328", "330", "614"}  # pattern checks (weak crypto, randomness, cookie flags), not flows
_CALL = re.compile(r"\b([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*\(")
_NOISE = {
    "if", "for", "while", "return", "def", "function", "switch", "catch", "print", "len", "str", "int", "dict", "list",
    "set", "tuple", "range", "isinstance", "super", "init", "get", "format", "append", "join", "strip", "split",
    "lower", "upper", "replace", "startswith", "endswith", "bool", "type", "min", "max", "sorted", "enumerate",
    "request.cookies.get", "request.args.get", "request.form.get", "request.headers.get", "urllib.parse.unquote_plus",
    "make_response", "render_template", "url_for", "escape_for_html",
}


def calls_in(lines: List[str]) -> List[str]:
    """Distinct callees on these lines, minus plumbing nobody could mean by 'the sink'."""
    seen: List[str] = []
    for ln in lines:
        code = ln.split("#", 1)[0] if not ln.lstrip().startswith(("//", "*", "/*")) else ""
        for m in _CALL.finditer(code):
            name = m.group(1)
            if name in _NOISE or name.rsplit(".", 1)[-1] in _NOISE or name in seen:
                continue
            seen.append(name)
    return seen


def pick_line(lines: List[str], lo: int, hi: int) -> int:
    """The changed line that best stands for the vulnerable code: the first one that makes a call."""
    for n in range(lo, min(hi, len(lines)) + 1):
        text = lines[n - 1].strip()
        if text and not text.startswith(("#", "//", "*", "/*", "import ", "from ", "def ", "func ", "function ")) and calls_in([text]):
            return n
    for n in range(lo, min(hi, len(lines)) + 1):
        if lines[n - 1].strip() and not lines[n - 1].strip().startswith(("#", "//", "*", "/*")):
            return n
    return lo


def changed_regions(pre: str, post: str) -> List[Tuple[int, int]]:
    """1-based inclusive line ranges in `pre` that the fix removed, rewrote or guarded.

    A fix that only *adds* lines (a validation, a containment check) removes nothing, so the
    vulnerable code is the statement the new lines now protect: the lines right after the
    insertion point.
    """
    a, b = pre.splitlines(), post.splitlines()
    out = []
    for tag, i1, i2, _j1, _j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "delete") and i2 > i1:
            out.append((i1 + 1, i2))
        elif tag == "insert" and i1 < len(a):
            out.append((i1 + 1, min(len(a), i1 + 3)))
    return out


def added_lines(pre: str, post: str, limit: int = 4) -> List[str]:
    """What the fix added (trimmed), so a card can show the guard the engine should have understood."""
    a, b = pre.splitlines(), post.splitlines()
    out: List[str] = []
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("replace", "insert"):
            out += [l.strip()[:140] for l in b[j1:j2] if l.strip() and not l.strip().startswith(("#", "//", "*", "/*"))]
    return out[:limit]


# ----------------------------------------------------------------------------- matching


def near(line: int, label_line: int, tol: int) -> bool:
    return label_line > 0 and abs(line - label_line) <= tol


def match(labels: List[Dict[str, Any]], advisories: List[Dict[str, Any]], tol: int = 1) -> Dict[str, List[Dict[str, Any]]]:
    """Split labels/advisories into detected, missed (vulnerable, silent) and false alarms (safe, flagged).

    Line labels need an advisory within `tol` lines in the same file. File-level labels (line 0) are
    detected by any advisory in the file.
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for a in advisories:
        by_file.setdefault(_norm(a.get("file_path", "")), []).append(a)
    detected, missed, false_alarms, clean = [], [], [], []
    for lab in labels:
        hits = by_file.get(lab["file"], [])
        if lab["line"] > 0 and lab["vulnerable"]:
            hits = [a for a in hits if near(a.get("line", 0), lab["line"], tol)]
        if lab["vulnerable"]:
            (detected if hits else missed).append(dict(lab, advisory=hits[0] if hits else None))
        elif hits:
            false_alarms.append(dict(lab, advisory=hits[0]))
        else:
            clean.append(lab)  # labelled safe and left alone: a true negative
    return {"detected": detected, "missed": missed, "false_alarms": false_alarms, "clean": clean}


def _rates(tp: int, fn: int, fp: int, tn: int) -> Dict[str, float]:
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    # OWASP Benchmark's own score: true-positive rate minus false-positive rate. 0 is a coin flip.
    return {"recall": round(recall, 4), "fpr": round(fpr, 4), "score": round(recall - fpr, 4)}


def scorecard(name: str, lang: str, result: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Confusion counts for one labelled source, in total and per vulnerability category."""
    buckets = (("tp", "detected"), ("fn", "missed"), ("fp", "false_alarms"), ("tn", "clean"))
    total = {k: len(result.get(key, [])) for k, key in buckets}
    cats: Dict[str, Dict[str, int]] = {}
    for k, key in buckets:
        for lab in result.get(key, []):
            c = cats.setdefault(cwe_name(lab.get("cwe", "")), {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
            c[k] += 1
    categories = [dict(name=n, **c, **_rates(**c)) for n, c in cats.items()]
    categories.sort(key=lambda c: (-(c["fn"] + c["fp"]), c["name"]))
    return {"name": name, "lang": lang, **total, **_rates(**total), "categories": categories}


def drop_caught(res: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    """A case with several labelled hunks is caught when any one of them is detected."""
    caught = {d["case"] for d in res["detected"]}
    return dict(res, missed=[m for m in res["missed"] if m["case"] not in caught])


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def _read_lines(root: Optional[Path], rel: str) -> List[str]:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="replace").splitlines() if root else []
    except OSError:
        return []


def nearest_record(records: List[Dict[str, Any]], file: str, line: int, tol: int = 4) -> Optional[Dict[str, Any]]:
    """The engine's own explanation for staying quiet near a line, if it explored a sink there."""
    best = None
    for r in records:
        if _norm(r.get("file", "")) == file and abs(r.get("line", 0) - line) <= tol:
            if best is None or abs(r["line"] - line) < abs(best["line"] - line):
                best = r
    return best


# ----------------------------------------------------------------------------- challenges


def _cid(repo: str, kind: str, file: str, case: str, cwe: str) -> str:
    return "BL-" + hashlib.sha1("|".join([repo, kind, file, case, cwe]).encode()).hexdigest()[:10]


def make_challenges(
    repo: str,
    lang: str,
    result: Dict[str, List[Dict[str, Any]]],
    records: List[Dict[str, Any]],
    pin: Dict[str, str],
    group_repo: Optional[str] = None,
    root: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    out, seen = [], set()
    for kind, key in (("missed", "missed"), ("false-alarm", "false_alarms")):
        for lab in result[key]:
            cid = _cid(repo, kind, lab["file"], lab["case"], lab["cwe"])
            if cid in seen:
                continue
            seen.add(cid)
            adv = lab.get("advisory") or {}
            rec = nearest_record(records, lab["file"], lab["line"]) if kind == "missed" else None
            category = cwe_name(lab["cwe"]) if lab["cwe"] else (lab["case"].split(":")[0] if ":" in lab["case"] else "labelled flaw")
            track, calls = "False alarm", []
            if kind == "missed":
                shown = lab.get("show_line") or lab["line"]
                src = _read_lines(root, lab["file"])
                if lab.get("file_level"):
                    window = src[shown - 1 : shown + 24] if shown else src[-30:]
                else:
                    lo, hi = lab.get("span") or (lab["line"], lab["line"] + 1)
                    window = src[max(0, lo - 1) : min(hi, lo + 14)]
                calls = calls_in(window)[:4]
                if lab["cwe"] in NON_TAINT_CWE:
                    track, difficulty = "Missed pattern check", "medium"
                    why = f"no rule matched this {category} pattern" + (f" (calls: {', '.join('`'+c+'`' for c in calls)})" if calls else "")
                elif rec:
                    track, difficulty = "Missed: silent sink", "medium"
                    why = f"it explored `{rec['sink']}` near here and stayed silent: {rec['reason']}"
                elif calls:
                    track, difficulty = "Missed: unrecognised call", "easy"
                    why = "it recognised none of the calls here as a sink: " + ", ".join(f"`{c}`" for c in calls)
                else:
                    track, difficulty = "Missed: no call here", "hard"
                    why = "no call near this line, so the flow reaches its sink some other way (field, operator, template)"
            else:
                why = f"it reports {adv.get('rule_id', 'a finding')}: {adv.get('observation', '')}".strip()
                difficulty = "medium"
            out.append(
                {
                    "id": cid,
                    "kind": kind,
                    "repo": repo,
                    "lang": lang,
                    "file": lab["file"],
                    "line": lab.get("show_line") or lab["line"] or adv.get("line", 0),
                    "function": "",
                    "sink": (rec or {}).get("sink", adv.get("rule_id", "")),
                    "slot": "",
                    "track": track,
                    "difficulty": difficulty,
                    "hint": HINTS[kind],
                    "reason": why,
                    "stop_sites": (rec or {}).get("cut_sites", []),
                    "engine_pointer": POINTERS[kind],
                    "repro": f"frensense {lab['file']} --explain" if kind == "missed" else f"frensense {lab['file']} --show-flows",
                    "pin": pin,
                    "fix_added": lab.get("fix_added", []),
                    "label": {"cwe": lab["cwe"], "case": lab["case"], "category": category, "file_level": bool(lab.get("file_level"))},
                    "group_key": f"{group_repo or repo}|{kind}|{category}|{track}",
                    "group_repo": group_repo or repo,
                    "group_detail": category,
                }
            )
    return out


# ----------------------------------------------------------------------------- scanning


def run_scan(binary: Path, root: Path, targets: List[str], out_json: Path, timeout: Optional[int] = 600) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(advisories, explain records) with every path made relative to `root`."""
    out_json.unlink(missing_ok=True)
    argv = [str(binary), *[str(root / t) for t in targets], "--json", "--explain-json", str(out_json)]
    # scanproc kills the whole process group on timeout (a plain subprocess timeout leaves the scanner running).
    proc = scanproc.run_scan(argv, timeout)
    # A scan that failed must not read as "found nothing": that would turn every labelled flaw into a
    # false "missed" challenge and every earlier challenge into a false "solved" one.
    if proc["timeout"]:
        raise RuntimeError(f"scan of {targets} timed out after {timeout}s")
    if proc["exit"] not in (0, 1):
        raise RuntimeError(f"scan of {targets} failed with exit {proc['exit']}: {' '.join(proc['stderr_tail'])[-300:]}")
    try:
        advisories = json.loads(proc["stdout"]).get("advisories", []) if proc["stdout"].strip() else []
        records = json.loads(out_json.read_text()).get("records", []) if out_json.exists() else []
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"scan of {targets} produced unreadable output: {exc}") from exc

    def rel(p: str) -> str:
        try:
            return Path(p).resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            return _norm(p)

    for a in advisories:
        a["file_path"] = rel(a.get("file_path", ""))
    for r in records:
        r["file"] = rel(r.get("file", ""))
        for c in r.get("cut_sites", []):
            c["file"] = rel(c.get("file", ""))
    return advisories, records


def run_scan_each(binary: Path, root: Path, files: List[str], cache: Path, workers: int = 8, case_timeout: int = 120) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Scan every file in its own process and merge the results.

    Synthetic suites (OWASP Benchmark) are built from hundreds of independent test cases that reuse
    function and file names. One whole-directory scan merges them into a single program, where those
    names collide and flows from one case leak into another, so the standard scoring scans each case
    alone. Real repositories are scanned as one program instead (see `run_scan`).
    """
    from concurrent.futures import ThreadPoolExecutor

    tmp = cache / f"{root.name}.each"
    tmp.mkdir(parents=True, exist_ok=True)

    def one(item: Tuple[int, str]):
        i, f = item
        return run_scan(binary, root, [f], tmp / f"{i}.json", timeout=case_timeout)

    advisories: List[Dict[str, Any]] = []
    records: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(workers) as ex:
        for adv, rec in ex.map(one, enumerate(files)):
            advisories += adv
            records += rec
    shutil.rmtree(tmp, ignore_errors=True)
    return advisories, records


def fetch_commit(url: str, sha: str, files_filter, dest: Path) -> Optional[List[str]]:
    """Put pre/ and post/ copies of the changed source files of one commit under `dest`."""
    tmp = Path(tempfile.mkdtemp(prefix="blind-fetch-"))
    try:
        for cmd in (
            ["git", "init", "-q"],
            ["git", "fetch", "-q", "--depth", "2", url, sha],
        ):
            if subprocess.run(cmd, cwd=tmp, capture_output=True).returncode:
                return None
        names = subprocess.run(["git", "diff", "--name-only", f"{sha}^", sha], cwd=tmp, capture_output=True, text=True).stdout.split("\n")
        keep = [n for n in names if n and files_filter(n)]
        saved = []
        for n in keep:
            a = subprocess.run(["git", "show", f"{sha}^:{n}"], cwd=tmp, capture_output=True, text=True)
            b = subprocess.run(["git", "show", f"{sha}:{n}"], cwd=tmp, capture_output=True, text=True)
            if a.returncode or b.returncode or len(a.stdout) > 400_000:
                continue
            flat = n.replace("/", "__")
            for side, text in (("pre", a.stdout), ("post", b.stdout)):
                (dest / side).mkdir(parents=True, exist_ok=True)
                (dest / side / flat).write_text(text)
            saved.append(flat)
        return saved
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


EXT = {"PyPI": (".py",), "npm": (".js", ".ts", ".mjs", ".cjs"), "Go": (".go",)}
LANG = {"PyPI": "python", "npm": "javascript", "Go": "go"}


def merge_results(parts: List[Dict[str, List[Dict[str, Any]]]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {"detected": [], "missed": [], "false_alarms": [], "clean": []}
    for part in parts:
        for k in out:
            out[k] += part.get(k, [])
    return out


def merge_results(parts: List[Dict[str, List[Dict[str, Any]]]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {"detected": [], "missed": [], "false_alarms": [], "clean": []}
    for part in parts:
        for k in out:
            out[k] += part.get(k, [])
    return out


def recent_cve_challenges(
    binary: Path, cache: Path, tol: int = 8, case_timeout: int = 120, results: Optional[List[Dict[str, List[Dict[str, Any]]]]] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, Path]]:
    """Missed (vulnerable file silent near the fixed lines) and still-flagged-after-fix challenges."""
    spec = json.loads((LABELS_DIR / "recent_cves.json").read_text())["cases"]
    challenges: List[Dict[str, Any]] = []
    roots: Dict[str, Path] = {}
    for case in spec:
        repo = f"cve-{case['id']}"
        root = cache / repo
        done = root / "done"
        if not done.exists():
            shutil.rmtree(root, ignore_errors=True)
            m = re.match(r"https://github.com/([^/]+)/([^/]+)/commit/([0-9a-f]{40})$", case["commit"])
            if not m:
                continue
            exts = EXT[case["ecosystem"]]
            saved = fetch_commit(
                f"https://github.com/{m.group(1)}/{m.group(2)}.git",
                m.group(3),
                lambda n: n.endswith(exts) and not re.search(r"(test|spec|mock|fixture|vendor|node_modules)", n, re.I),
                root,
            )
            if not saved:
                shutil.rmtree(root, ignore_errors=True)
                continue
            done.write_text("\n".join(saved))
        roots[repo] = root
        cwe = CLASS_CWE.get(case["class"], "")
        labels_pre, labels_post = [], []
        for flat in done.read_text().split("\n"):
            pre = (root / "pre" / flat).read_text(errors="replace")
            post = (root / "post" / flat).read_text(errors="replace")
            pre_lines = pre.splitlines()
            # Regions that make a call first: a fix often also touches data and comments, and the
            # card should point at the code that could be a sink.
            regions = sorted(changed_regions(pre, post), key=lambda r: (not calls_in(pre_lines[r[0] - 1 : r[1]]), r[0]))
            for lo, hi in regions:
                labels_pre.append(
                    {
                        "file": f"pre/{flat}", "line": lo, "show_line": pick_line(pre_lines, lo, hi),
                        "vulnerable": True, "cwe": cwe, "case": f"{case['id']}:{flat}", "span": (lo, hi),
                        "fix_added": added_lines(pre, post),
                    }
                )
                labels_post.append({"file": f"post/{flat}", "line": lo, "vulnerable": False, "cwe": cwe, "case": f"{case['id']}:{flat}"})
        advisories, records = run_scan(binary, root, ["pre", "post"], cache / f"{repo}.explain.json", timeout=case_timeout)
        # a region is "detected" when an advisory sits inside it, give or take `tol` lines
        res = {"detected": [], "missed": [], "false_alarms": []}
        for lab in labels_pre:
            lo, hi = lab["span"]
            hits = [a for a in advisories if a["file_path"] == lab["file"] and lo - tol <= a.get("line", 0) <= hi + tol]
            (res["detected"] if hits else res["missed"]).append(dict(lab, advisory=hits[0] if hits else None))
        # One fix, several hunks: if the engine reported inside any of them the case is caught.
        res = drop_caught(res)
        for lab in labels_post:
            hits = [a for a in advisories if a["file_path"] == lab["file"] and abs(a.get("line", 0) - lab["line"]) <= tol]
            if hits:
                res["false_alarms"].append(dict(lab, advisory=hits[0]))
            else:
                res.setdefault("clean", []).append(lab)
        if results is not None:
            results.append(res)
        pin = {"url": case["commit"], "commit": case["commit"].rsplit("/", 1)[-1]}
        challenges += make_challenges(repo, LANG[case["ecosystem"]], res, records, pin, group_repo="recent-cves", root=root)
    return challenges, roots
