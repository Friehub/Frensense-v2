#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""Mutation-ladder triage for OWASP BenchmarkPython verdicts.

Turns the scorecard's false negatives and false positives into a cause
queue. For each missed case the script copies the file and applies one
small rewrite at a time, rescanning after each. The first rewrite that
flips the verdict names the cause:

  knowledge-sink          sink API unmodeled (codecs.open -> open)
  knowledge-propagator    wrapper stripped (unquote_plus(...))
  knowledge-objectstate   configparser set/get -> direct assignment
  knowledge-pathlib       Path(x)/y + .exists() -> open() sink
  engine-branch           const-membership if/else folded away
  engine-match            match/case rewritten as if/elif chain
  engine-fstring          f-string rewritten as concatenation
  engine-imports          indented imports hoisted to module top
  engine-const-fold       (FP) constant ternary folded by hand
  harness                 (with --root-scan) verdict flips when the
                          helpers/ package is importable
  absent-rule             class has zero TPs in the whole scorecard and
                          no rewrite flipped it - missing checker/sink
  unexplained             no rewrite flipped it; needs human eyes

If no SINGLE rewrite flips an FN, the ladder retries cumulatively
(rewrite 1, rescan, rewrite 2 on top, ...) and records the minimal set
- stacked causes are the common shape (BenchmarkTest00001 is sink +
propagator + f-string + local imports at once).

Engine-bucket and unexplained outcomes write the mutated file plus a
ready-to-run scan command to --repro-dir. Each engine repro should
become a bundle-free probe in frensense-engine's dataflow_probes_tests
so CI catches the gap even after a corpus fact papers over it.

The harness bucket needs no mutation: OWASP's helpers/ package lives at
the benchmark repo ROOT (sibling of testcode/), so a per-file scan can
never resolve `from helpers.utils import escape_for_html`. With
--root-scan the ladder first checks each case twice - once per-file
(the scorecard's mode) and once copied into a full repo-root layout -
and labels import-dependent verdicts before blaming the engine.

Usage:

  # 1. produce (or reuse) a scorecard
  python3 scripts/owasp_benchmark.py --json-out scorecard.json

  # 2. triage up to 40 FNs and 20 FPs
  python3 scripts/owasp_mutation_ladder.py \
    --scorecard scorecard.json --limit 40 \
    --json-out ladder.json --md-out ladder.md

Exit codes: 0 ok, 1 setup error.
"""

import argparse
import concurrent.futures
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_BIN = Path(__file__).resolve().parent.parent / "target" / "release" / "frensense"

# ---------------------------------------------------------------------------
# Scanning (same invocation contract as owasp_benchmark.py)
# ---------------------------------------------------------------------------


def scan_file(binary: Path, path: Path, env: dict | None = None) -> dict:
    """Scan one file; returns {"findings": n} or {"error": msg}."""
    try:
        proc = subprocess.run(
            [str(binary), str(path), "--json"],
            capture_output=True, text=True, timeout=120, env=env,
        )
        if proc.returncode not in (0, 1):
            return {"findings": 0, "error": f"exit {proc.returncode}"}
        data = json.loads(proc.stdout) if proc.stdout.strip() else []
        advisories = data if isinstance(data, list) else data.get("advisories", [])
        if not isinstance(advisories, list):
            return {"findings": 0, "error": "unexpected JSON shape"}
        return {"findings": len(advisories)}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        return {"findings": 0, "error": str(e)}


# ---------------------------------------------------------------------------
# Rewrites: each takes source text, returns (new_source, changed)
# ---------------------------------------------------------------------------


def _strip_calls(src: str, names: list[str]) -> tuple[str, bool]:
    """Replace `name(arg)` with `arg` for each name (paren-aware)."""
    changed = False
    for name in names:
        while True:
            idx = src.find(name + "(")
            if idx == -1:
                break
            open_paren = idx + len(name)
            depth, i = 1, open_paren + 1
            while i < len(src) and depth:
                if src[i] == "(":
                    depth += 1
                elif src[i] == ")":
                    depth -= 1
                i += 1
            if depth:
                break  # unbalanced; leave the file alone
            arg = src[open_paren + 1 : i - 1]
            src = src[:idx] + arg + src[i:]
            changed = True
    return src, changed


def rewrite_sink_codecs_open(src: str) -> tuple[str, bool]:
    if "codecs.open" not in src:
        return src, False
    return src.replace("codecs.open", "open"), True


def rewrite_strip_unquote(src: str) -> tuple[str, bool]:
    return _strip_calls(src, [
        "urllib.parse.unquote_plus", "urllib.parse.unquote",
        "unquote_plus", "unquote",
    ])


_FSTRING_RE = re.compile(r"""f(["'])((?:[^{}\\"]|\\.|\{[^{}]*\})+)\1""")


def rewrite_fstring_to_concat(src: str) -> tuple[str, bool]:
    changed = False

    def conv(m: re.Match) -> str:
        nonlocal changed
        body = m.group(2)
        if "{" not in body:
            return m.group(0)
        parts, pos = [], 0
        for expr in re.finditer(r"\{([^{}]*)\}", body):
            literal = body[pos : expr.start()]
            if literal:
                parts.append(m.group(1) + literal + m.group(1))
            inner = expr.group(1)
            if ":" in inner or "!" in inner:
                return m.group(0)  # format spec: too risky, skip this string
            parts.append("(" + inner + ")")
            pos = expr.end()
        tail = body[pos:]
        if tail:
            parts.append(m.group(1) + tail + m.group(1))
        if not parts:
            return m.group(0)
        changed = True
        return " + ".join(parts)

    return _FSTRING_RE.sub(conv, src), changed


_IMPORT_LINE_RE = re.compile(r"^([ \t]+)((?:import |from )\S.*|import \w.*)$")
_TOP_IMPORT_RE = re.compile(r"^(?:import |from )")


def rewrite_hoist_imports(src: str) -> tuple[str, bool]:
    lines = src.splitlines(keepends=True)
    kept, hoisted = [], []
    for line in lines:
        m = _IMPORT_LINE_RE.match(line.rstrip("\n"))
        if m and not line.lstrip().startswith("#"):
            hoisted.append(m.group(2).strip() + "\n")
        else:
            kept.append(line)
    if not hoisted:
        return src, False
    insert_at = 0
    for i, line in enumerate(kept):
        if _TOP_IMPORT_RE.match(line):
            insert_at = i + 1
    kept[insert_at:insert_at] = hoisted
    return "".join(kept), True


_CONST_ASSIGN_RE = re.compile(r"(\w+)\s*=\s*(\d+)\b")
_TERNARY_RE = re.compile(
    r"^(?P<lhs>\s*\w+\s*=\s*)(?P<true>.+?)\s+if\s+(?P<cond>.+?)\s+else\s+(?P<false>.+)$"
)
_SAFE_ARITH = re.compile(r"[0-9+\-*/%()<>=! ]+")


def rewrite_fold_const_ternary(src: str) -> tuple[str, bool]:
    consts = dict(_CONST_ASSIGN_RE.findall(src))
    changed = False
    out = []
    for line in src.splitlines(keepends=True):
        m = _TERNARY_RE.match(line.rstrip("\n"))
        if not m:
            out.append(line)
            continue
        cond = m.group("cond")
        for name, val in consts.items():
            cond = re.sub(rf"\b{name}\b", val, cond)
        if not _SAFE_ARITH.fullmatch(cond.strip()):
            out.append(line)
            continue
        try:
            value = eval(cond.strip(), {"__builtins__": {}}, {})  # noqa: S307
        except Exception:
            out.append(line)
            continue
        chosen = m.group("true") if value else m.group("false")
        out.append(m.group("lhs") + chosen + "\n")
        changed = True
    return "".join(out), changed


def rewrite_fold_string_membership(src: str) -> tuple[str, bool]:
    """Fold `if '<lit>' [not ]in <var>:` when <var> holds a string literal,
    keeping only the branch the membership test selects. The OWASP cases
    all use the same shape (TestParam = '...'; if 'should' not in
    TestParam: ... else: bar = param) - empirically the engine drops the
    tainted else-branch of this construct (BenchmarkTest00085), so
    folding it isolates the branch/value-analysis cause."""
    str_lits = {m.group(1): m.group(3)
                for m in re.finditer(r"""^\s*(\w+)\s*=\s*(['"])(.*?)\2\s*$""",
                                     src, flags=re.MULTILINE)}
    mem_re = re.compile(
        r"^(?P<i>\s*)if\s+(?P<lit>['\"])(?P<needle>.*?)\2\s+(?P<neg>not\s+)?in\s+"
        r"(?P<var>\w+)\s*:\s*$"
    )
    lines = src.splitlines(keepends=True)
    changed, out, i = False, [], 0
    while i < len(lines):
        m = mem_re.match(lines[i].rstrip("\n"))
        if not m or m.group("var") not in str_lits:
            out.append(lines[i])
            i += 1
            continue
        indent = m.group("i")
        haystack = str_lits[m.group("var")]
        present = m.group("needle") in haystack
        taken_else = (present == bool(m.group("neg")))
        # collect if-body and else-body at deeper indent / else:
        j, if_body, else_body, seen_else = i + 1, [], [], False
        while j < len(lines):
            line = lines[j]
            stripped = line.strip()
            at_if_indent = (line.startswith(indent)
                            and not line.startswith(indent + "\t"))
            if stripped.startswith("else") and at_if_indent:
                seen_else = True
                j += 1
                continue
            if not stripped or line.startswith(indent + "\t"):
                (else_body if seen_else else if_body).append(line)
                j += 1
                continue
            break
        if not seen_else:
            out.append(lines[i])  # no else to select; leave alone
            i += 1
            continue
        out.extend(else_body if taken_else else if_body)
        changed = True
        i = j
    return "".join(out), changed


def rewrite_objectstate_direct(src: str) -> tuple[str, bool]:
    """Rewrite configparser-style `<obj>.set('s', 'k', val)` +
    `x = <obj>.get('s', 'k')` into `x = val` (object-state round-trip;
    BenchmarkTest00074-class FNs, CWE-94)."""
    sets = {m.group("obj"): m.group("val")
            for m in re.finditer(
                r"""(?P<obj>\w+)\.set\(\s*(['"])([^'"]+)\2\s*,\s*(['"])([^'"]+)\4\s*,\s*(?P<val>\w+)\s*\)""",
                src)}
    if not sets:
        return src, False
    changed = False

    def sub_get(m: re.Match) -> str:
        nonlocal changed
        val = sets.get(m.group("obj"))
        if val is None:
            return m.group(0)
        changed = True
        return f"{m.group('lhs')} = {val}"

    new = re.sub(
        r"(?P<lhs>\w+)\s*=\s*(?P<obj>\w+)\.get\(\s*(['\"])[^'\"]+\3\s*,\s*(['\"])[^'\"]+\4\s*\)",
        sub_get, src)
    if not changed:
        return src, False
    # drop the now-dead .set() calls
    new = re.sub(
        r"""^\s*\w+\.set\(\s*(['"])[^'"]+\1\s*,\s*(['"])[^'"]+\2\s*,\s*\w+\s*\)\s*$""",
        "", new, flags=re.MULTILINE)
    return new, True


def rewrite_pathlib_to_open(src: str) -> tuple[str, bool]:
    """Replace a `Path(base) / tainted; p.exists()` probe with a direct
    `open()` sink on the joined path. If this flips, flow reached the
    path join fine and Path-join/exists is the blocker (knowledge-pathlib),
    not the sink vocabulary."""
    pat = re.compile(
        r"^(?P<i>\s*)(?P<base>\w+)\s*=\s*pathlib\.Path\((?P<dir>.+)\)\s*\n"
        r"(?P=i)(?P<p>\w+)\s*=\s*(?P=base)\s*/\s*(?P<u>\w+)\s*\n"
        r"(?P=i)if\s+(?P=p)\.exists\(\)\s*:\s*$", flags=re.MULTILINE)
    changed = False

    def conv(m: re.Match) -> str:
        nonlocal changed
        changed = True
        i = m.group("i")
        return (f"{i}fileTarget = open('/tmp/' + {m.group('u')})\n"
                f"{i}{m.group('p')} = pathlib.Path('/tmp/' + {m.group('u')})\n"
                f"{i}if True:")

    return pat.sub(conv, src), changed


def rewrite_strip_split(src: str) -> tuple[str, bool]:
    """`x.split(...)[0]` -> `x` (str.split not a known propagator)."""
    new, n = re.subn(r"""(\w+)\.split\([^)]*\)\[0\]""", r"\1", src)
    return new, n > 0


_MATCH_RE = re.compile(
    r"^(?P<i>\s*)match\s+(?P<subj>\w+)\s*:\s*\n(?P<body>(?:(?P=i)\t.*\n|\n)+)", re.M)


def rewrite_match_to_if(src: str) -> tuple[str, bool]:
    """Convert a simple `match <subj>: case <lit>: ...` block to an
    if/elif chain (match-statement lowering gap)."""
    changed = False

    def conv(m: re.Match) -> str:
        nonlocal changed
        indent, subj = m.group("i"), m.group("subj")
        out, first = [], True
        for raw in m.group("body").splitlines():
            stripped = raw.strip()
            if stripped.startswith("case "):
                pat = stripped[5:].rstrip(":").strip()
                kw = "if" if first else "elif"
                first = False
                if pat == "_":
                    out.append(f"{indent}else:")
                elif "|" in pat:
                    alts = ", ".join(p.strip() for p in pat.split("|"))
                    out.append(f"{indent}{kw} {subj} in ({alts}):")
                else:
                    out.append(f"{indent}{kw} {subj} == {pat}:")
            elif stripped and not stripped.startswith("case "):
                # body line: one tab deeper under match -> flatten one level
                if raw.startswith(indent + "\t\t"):
                    out.append(indent + "\t" + raw[len(indent) + 2:])
                elif raw.startswith(indent + "\t"):
                    out.append(raw)
                else:
                    out.append(raw)
        changed = True
        return "\n".join(out) + "\n"

    return _MATCH_RE.sub(conv, src), changed


# (name, bucket, fn) - FN order matters: cheapest/most-likely first.
FN_LADDER = [
    ("strip_unquote", "knowledge-propagator", rewrite_strip_unquote),
    ("strip_split", "knowledge-propagator", rewrite_strip_split),
    ("fold_string_membership", "engine-branch", rewrite_fold_string_membership),
    ("objectstate_direct", "knowledge-objectstate", rewrite_objectstate_direct),
    ("pathlib_to_open", "knowledge-pathlib", rewrite_pathlib_to_open),
    ("match_to_if", "engine-match", rewrite_match_to_if),
    ("sink_codecs_open", "knowledge-sink", rewrite_sink_codecs_open),
    ("fstring_to_concat", "engine-fstring", rewrite_fstring_to_concat),
    ("hoist_imports", "engine-imports", rewrite_hoist_imports),
]

FP_LADDER = [
    ("fold_const_ternary", "engine-const-fold", rewrite_fold_const_ternary),
]


# ---------------------------------------------------------------------------
# Harness A/B: per-file scan vs repo-root layout with helpers/ importable
# ---------------------------------------------------------------------------


def root_layout_scan(binary: Path, case_file: Path, root: Path) -> dict | None:
    """Rescan the case in a copy of the benchmark repo root so
    `helpers` resolves. Returns None when the root layout is absent."""
    if not (root / "helpers").is_dir():
        return None
    work = Path(tempfile.mkdtemp(prefix="owasp-root-"))
    try:
        shutil.copytree(root / "helpers", work / "helpers")
        dest = work / "testcode" / case_file.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(case_file, dest)
        return scan_file(binary, dest)
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# The ladder
# ---------------------------------------------------------------------------


def run_case_ladder(binary: Path, case: dict, testcode: Path, root: Path,
                    kinds: set[str], repro_dir: Path | None,
                    use_root_scan: bool, cwe_tp: dict) -> dict | None:
    case_file = testcode / f"{case['id']}.py"
    if not case_file.exists():
        return None
    kind = "FN" if case["class"] == "FN" else "FP" if case["class"] == "FP" else None
    if kind is None or kind not in kinds:
        return None

    work = Path(tempfile.mkdtemp(prefix="owasp-ladder-"))
    try:
        target = work / case_file.name
        original_src = case_file.read_text()
        shutil.copy(case_file, target)

        # Harness A/B first: does making helpers/ importable flip it?
        if use_root_scan:
            rooted = root_layout_scan(binary, case_file, root)
            per_file = scan_file(binary, target)
            if rooted is not None and "error" not in rooted and "error" not in per_file:
                if kind == "FN" and rooted["findings"] > per_file["findings"] == 0:
                    return _record(case, kind, "harness", [], repro_dir, target)
                if kind == "FP" and per_file["findings"] > rooted["findings"] == 0:
                    return _record(case, kind, "harness", [], repro_dir, target)

        ladder = FN_LADDER if kind == "FN" else FP_LADDER
        steps = []

        def flipped(n: int) -> bool:
            return n >= 1 if kind == "FN" else n == 0

        # Phase A: single rewrites, original source each time.
        for name, bucket, fn in ladder:
            mutated, changed = fn(original_src)
            if not changed:
                steps.append({"step": name, "changed": False, "findings": None})
                continue
            target.write_text(mutated)
            res = scan_file(binary, target)
            n = res.get("findings", 0)
            steps.append({"step": name, "changed": True, "findings": n,
                          **({"error": res["error"]} if "error" in res else {})})
            if "error" not in res and flipped(n):
                return _record(case, kind, bucket, [name], repro_dir, target)
        target.write_text(original_src)

        # Phase B: cumulative - stacked causes need the whole ladder.
        src, applied = original_src, []
        for name, bucket, fn in ladder:
            mutated, changed = fn(src)
            if not changed:
                continue
            src = mutated
            applied.append((name, bucket))
            target.write_text(src)
            res = scan_file(binary, target)
            n = res.get("findings", 0)
            if "error" not in res and flipped(n):
                return _record(case, kind, "+".join(b for _, b in applied),
                               [n for n, _ in applied], repro_dir, target)

        # No rewrite flipped it. If the whole scorecard has ZERO true
        # positives for this CWE class, the wall is an absent checker or
        # sink model - not case-specific flow. (FP-only: an FP already
        # proves the rule fires; a surviving FP is a misfiring rule.)
        if kind == "FN" and cwe_tp.get(case["cwe"], 0) == 0:
            return _record(case, kind, "absent-rule", [], repro_dir, target)
        return _record(case, kind, "unexplained", [], repro_dir, target)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _record(case: dict, kind: str, cause: str, fired: list[str],
            repro_dir: Path | None, mutated_file: Path) -> dict:
    if (repro_dir is not None and cause not in ("harness", "absent-rule")
            and mutated_file.exists()):
        repro_dir.mkdir(parents=True, exist_ok=True)
        dest = repro_dir / f"{case['id']}--{cause.replace('+', '_')}.py"
        shutil.copy(mutated_file, dest)
        return {"id": case["id"], "cwe": case["cwe"], "kind": kind,
                "cause": cause, "fired": fired, "repro": str(dest)}
    return {"id": case["id"], "cwe": case["cwe"], "kind": kind,
            "cause": cause, "fired": fired}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def summarize(results: list[dict]) -> dict:
    by_cause = Counter(r["cause"] for r in results)
    by_cwe: dict = defaultdict(Counter)
    for r in results:
        by_cwe[r["cwe"]][r["cause"]] += 1
    return {
        "total": len(results),
        "by_cause": dict(by_cause.most_common()),
        "by_cwe": {k: dict(v) for k, v in sorted(by_cwe.items())},
    }


def markdown(summary: dict, results: list[dict]) -> str:
    lines = [
        "# OWASP Mutation-Ladder Triage", "",
        f"Verdicts triaged: **{summary['total']}**", "",
        "## Causes", "",
        "| Cause | Count | Meaning |", "| :--- | ---: | :--- |",
    ]
    meaning = {
        "knowledge-sink": "sink API unmodeled - mining/corpus queue",
        "knowledge-propagator": "wrapper not a known propagator - corpus queue",
        "knowledge-objectstate": "obj.set/get round-trip unmodeled - corpus queue",
        "knowledge-pathlib": "Path(x)/y + .exists() not tracked - corpus queue",
        "engine-branch": "tainted else-branch of a const-membership if dropped - engine backlog",
        "engine-match": "match/case not lowered - engine backlog",
        "engine-fstring": "f-string lowering gap - engine backlog",
        "engine-imports": "indented-import lowering gap - engine backlog",
        "engine-const-fold": "value analysis missed a constant fold - engine backlog",
        "harness": "verdict depends on helpers/ being importable - scan setup",
        "absent-rule": "class has ZERO TPs in the whole scorecard and no rewrite flipped it - missing checker/sink model",
        "unexplained": "no rewrite flipped it - needs human eyes",
    }
    for cause, n in summary["by_cause"].items():
        lines.append(f"| `{cause}` | {n} | {meaning.get(cause, '')} |")
    lines += ["", "## Per CWE", "", "| CWE | Breakdown |", "| :--- | :--- |"]
    for cwe, counts in summary["by_cwe"].items():
        breakdown = ", ".join(f"{c} x{n}" for c, n in counts.items())
        lines.append(f"| `{cwe}` | {breakdown} |")
    unexplained = [r for r in results if r["cause"] == "unexplained"]
    if unexplained:
        lines += ["", "## Unexplained (blocked on human review)", ""]
        lines += [f"- `{r['id']}` ({r['kind']}, {r['cwe']})" for r in unexplained]
    repros = [r for r in results if r.get("repro") and "engine" in r["cause"]]
    if repros:
        lines += ["", "## Engine repros", ""]
        lines += [f"- `{r['id']}` ({r['cause']}): `{r['repro']}`" for r in repros]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Triage OWASP scorecard verdicts into cause buckets via mutation ladders.")
    ap.add_argument("--scorecard", required=True,
                    help="scorecard JSON from owasp_benchmark.py --json-out")
    ap.add_argument("--bin", default=None, help="frensense binary (auto-detected)")
    ap.add_argument("--owasp-testcode", default="/tmp/BenchmarkPython/testcode",
                    help="testcode dir of the OWASP cases")
    ap.add_argument("--kinds", choices=("FN", "FP", "both"), default="both")
    ap.add_argument("--limit", type=int, default=0,
                    help="max cases per kind (0 = all)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--root-scan", action="store_true",
                    help="A/B each verdict against a repo-root layout where helpers/ imports")
    ap.add_argument("--repro-dir", default="/tmp/owasp_ladder_repro")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--md-out", default=None)
    args = ap.parse_args()

    binary = Path(args.bin) if args.bin else DEFAULT_BIN
    if not binary.exists():
        print(f"[ERROR] binary not found at {binary}; build with cargo build --release",
              file=sys.stderr)
        sys.exit(1)
    try:
        card = json.loads(Path(args.scorecard).read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] cannot read scorecard: {e}", file=sys.stderr)
        sys.exit(1)
    testcode = Path(args.owasp_testcode)
    if not testcode.is_dir():
        print(f"[ERROR] testcode dir not found: {testcode}", file=sys.stderr)
        sys.exit(1)
    root = testcode.parent

    kinds = {"FN", "FP"} if args.kinds == "both" else {args.kinds}
    selected = [c for c in card.get("cases", []) if c.get("class") in kinds]
    if args.limit:
        per = args.limit if args.kinds == "both" else args.limit
        capped: dict[str, int] = defaultdict(int)
        trimmed = []
        for c in selected:
            k = c["class"]
            if capped[k] < per:
                trimmed.append(c)
                capped[k] += 1
        selected = trimmed
    print(f"[INFO] triaging {len(selected)} verdicts "
          f"({', '.join(sorted(kinds))}) with {args.workers} workers")

    repro_dir = Path(args.repro_dir)
    # CWE classes that produced at least one true positive overall:
    # classes at zero wall off every case in that class.
    cwe_tp: dict[str, int] = defaultdict(int)
    for c in card.get("cases", []):
        if c.get("class") == "TP" and c.get("cwe"):
            cwe_tp[c["cwe"]] += 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = [r for r in ex.map(
            lambda c: run_case_ladder(binary, c, testcode, root, kinds,
                                      repro_dir, args.root_scan, cwe_tp),
            selected) if r is not None]

    summary = summarize(results)
    print(f"\n{'=' * 62}\nMutation-ladder triage  ({summary['total']} verdicts)\n{'=' * 62}")
    for cause, n in summary["by_cause"].items():
        print(f"  {cause:<22} {n:4d}")
    for cwe, counts in summary["by_cwe"].items():
        parts = ", ".join(f"{c} x{n}" for c, n in counts.items())
        print(f"  {cwe:<10} {parts}")

    out = {"summary": summary, "results": results}
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(out, indent=1))
        print(f"\n[INFO] triage JSON -> {args.json_out}")
    if args.md_out:
        Path(args.md_out).write_text(markdown(summary, results))
        print(f"[INFO] triage markdown -> {args.md_out}")


if __name__ == "__main__":
    main()
