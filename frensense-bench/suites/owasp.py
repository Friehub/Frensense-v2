#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""OWASP BenchmarkPython runner for Frensense.

Scores the engine against the OWASP Benchmark for Python (v0.1): 1,230
test cases authored by the OWASP project with an authoritative
expected-results CSV. Third-party ground truth, zero overlap with any
Frensense knowledge bundle. Use it as a diagnostic: the per-CWE misses
are the engine's work queue.

Scoring follows the OWASP Benchmark accuracy metric:

  vulnerable case + finding  -> TP     safe case + no finding  -> TN
  vulnerable case + no find  -> FN     safe case + finding     -> FP

  score = TPR - FPR

What counts as "a finding" is set by --match:

  conservative (default)  A vulnerable case is a TP only if a finding is
                          attributed to the case's CWE. A safe case is a FP
                          if a finding is attributed to its CWE OR a finding
                          could not be attributed to any CWE. Gives a lower
                          bound on TPR and an upper bound on FPR.
  cwe                     Strict: findings with no resolvable CWE are
                          ignored on both sides.
  any                     Legacy: any finding in the file counts, whatever
                          its class. Overstates TPR; shown as an upper bound.

A finding's CWE comes from a "CWE-n" tag (built-in and bundle-backed
findings carry one since 0.7.1-beta) or from --tag-cwe-map / the small
built-in map for legacy binaries whose findings predate engine tagging.

A scan that crashes, times out, exits with a code other than 0 or 1, or
prints invalid JSON is class ERR: reported separately, excluded from the
rates, and fails the run (exit 3) unless --allow-errors is given.

Exit codes: 0 ok, 1 setup error, 3 scan errors, 4 regression vs
--baseline (only with --fail-on-regression).

Usage:

  # 1. get the benchmark (one-time)
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython /tmp/BenchmarkPython

  # 2. build the engine (one-time)
  cargo build --release

  # 3. run
  python3 scripts/owasp_benchmark.py \\
    --owasp-csv /tmp/BenchmarkPython/expectedresults-0.1.csv \\
    --owasp-testcode /tmp/BenchmarkPython/testcode \\
    --json-out owasp_scorecard.json

  # 4. track progress: compare against a committed baseline in CI
  python3 scripts/owasp_benchmark.py --baseline owasp_baseline.json --fail-on-regression

Results are printed as a summary table and, with --json-out, written as
a machine-readable scorecard with per-CWE breakdowns and per-case
verdicts.
"""

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_BIN = Path(__file__).resolve().parent.parent.parent / "target" / "release" / "frensense"

# Tags whose CWE is unambiguous. Sink-role tags such as "execution" or
# "resource" span several CWEs and are deliberately absent; extend with
# --tag-cwe-map (JSON object: {"tag": "CWE-n"}).
DEFAULT_TAG_CWE = {
    "weak_hash": "CWE-328",
    "xss": "CWE-79",
}

# Tags present on every advisory of a kind; no information for attribution.
GENERIC_TAGS = {"checker", "taint", "policy"}

CWE_RE = re.compile(r"^CWE-0*(\d+)$", re.IGNORECASE)

CWE_NAMES = {
    "CWE-22": "Path Traversal",
    "CWE-78": "Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-94": "Code Injection",
    "CWE-328": "Weak Cryptographic Hash",
    "CWE-330": "Insufficient Randomness",
    "CWE-501": "Trust Boundary Violation",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-614": "Sensitive Cookie Insecure Transport",
    "CWE-643": "XPath Injection",
}

# --- WI-74: per-rule scoring + merge gate ---------------------------------

# Baseline merged-fact format: {"rule_id": {"TP": n, "FP": n, "FN": n, "TN": n}}
BASELINE_FACTS_RE = re.compile(r"^BLF:\s*(.+)$")


def load_baseline_facts(path: str | Path) -> dict[str, dict[str, int]]:
    """Load the committed per-rule baseline from a BLF file."""
    facts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = BASELINE_FACTS_RE.match(line)
            if not m:
                raise ValueError(f"bad baseline line: {line!r}")
            parts = m.group(1).split(":", 1)
            if len(parts) != 2:
                raise ValueError(f"baseline line has no count separator: {line!r}")
            rule, tag = parts
            facts[rule.strip()][tag.strip()] = int(count.strip())
    return facts


def advisory_cwes(tags: list[str], tag_cwe: dict[str, str]) -> set[str]:
    """CWE ids an advisory can be attributed to (empty set = unattributed)."""
    out = set()
    for t in tags:
        c = norm_cwe(t) or tag_cwe.get(t)
        if c:
            out.add(c)
    return out


def classify(vul: bool, mode: str, case_cwe: str, adv_cwes: list[set[str]]) -> str:
    n = len(adv_cwes)
    attributed_hit = any(case_cwe in s for s in adv_cwes)
    unattributed = sum(1 for s in adv_cwes if not s)
    if mode == "any":
        hit = n > 0
    elif mode == "cwe":
        hit = attributed_hit
    else:  # conservative: unattributed findings never earn a TP, always cost a FP
        hit = attributed_hit or (not vul and unattributed > 0)
    if vul:
        return "TP" if hit else "FN"
    return "FP" if hit else "TN"


def rates(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        tp, fp, fn, tn = (v.get(c, 0) for c in ("TP", "FP", "FN", "TN"))
        tpr = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        out[k] = {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn, "ERR": v.get("ERR", 0),
            "tpr": round(tpr, 3),
            "fpr": round(fpr, 3),
            "score": round(tpr - fpr, 3),
        }
    return out


def tally(per_case: list[dict], field: str) -> dict:
    by_cwe = defaultdict(lambda: defaultdict(int))
    total = defaultdict(lambda: defaultdict(int))
    for c in per_case:
        by_cwe[c["cwe"]][c[field]] += 1
        total["all"][c[field]] += 1
    return {"total": rates(total)["all"], "by_cwe": dict(sorted(rates(by_cwe).items()))}


def count_per_rule_tag(cases: dict[str, dict], results: list[dict]) -> dict[str, dict[str, int]]:
    """WI-74: per-rule scorer.

    The engine findings carry tags (OWASP categories such as `traversal`,
    `xss`, `weak_hash`, `cookie_secure_missing`, and the CWE tags). For
    every distinct tag a case file contains, classify the case with the
    OWASP accuracy metric and accumulate TP/FP/FN/TN.

    Returns {tag: {"TP": n, "FP": n, "FN": n, "TN": n}}.
    """
    tally: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in results:
        meta = cases[r["id"]]
        for tags in r.get("tag_sets", []):
            for t in tags:
                if t in GENERIC_TAGS:
                    continue
                vul = meta["vul"]
                cwe = meta["cwe"]
                attributed_hit = cwe in tags
                if attributed_hit:
                    cls = "TP" if vul else "FP"
                else:
                    cls = "FN" if vul else "TN"
                tally[t][cls] += 1
    return {
        rule: {k: counts.get(k, 0) for k in ("TP", "FP", "FN", "TN")}
        for rule, counts in tally.items()
    }


def rules_from_cases(cases: dict[str, dict], results: list[dict]) -> dict[str, dict[str, int]]:
    """Per-rule verdicts: dedupe findings per case, then classify per tag."""
    tally: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in results:
        meta = cases[r["id"]]
        seen = set()
        for tags in r.get("tag_sets", []):
            key = tuple(sorted(tags))
            if key in seen:
                continue
            seen.add(key)
            for t in tags:
                if t in GENERIC_TAGS:
                    continue
                vul = meta["vul"]
                cwe = meta["cwe"]
                attributed_hit = cwe in tags
                if attributed_hit:
                    cls = "TP" if vul else "FP"
                else:
                    cls = "FN" if vul else "TN"
                tally[t][cls] += 1
    return {
        rule: {k: counts.get(k, 0) for k in ("TP", "FP", "FN", "TN")}
        for rule, counts in tally.items()
    }


def score(results: list[dict], cases: dict[str, dict], mode: str,
          tag_cwe: dict[str, str]) -> dict:
    per_case = []
    unattributed_tags: dict[str, int] = {}
    advisories_total = unattributed_total = 0
    for r in results:
        meta = cases[r["id"]]
        adv_cwes = [advisory_cwes(t, tag_cwe) for t in r.get("tag_sets", [])]
        for tags, cwes in zip(r.get("tag_sets", []), adv_cwes):
            advisories_total += 1
            if not cwes:
                unattributed_total += 1
                for t in tags:
                    unattributed_tags[t] = unattributed_tags.get(t, 0) + 1
        if "error" in r:
            cls = cls_any = "ERR"
        else:
            cls = classify(meta["vul"], mode, meta["cwe"], adv_cwes)
            cls_any = classify(meta["vul"], "any", meta["cwe"], adv_cwes)
        per_case.append({
            "id": r["id"],
            "cwe": meta["cwe"],
            "lang": "py",
            "expected": "vulnerable" if meta["vul"] else "safe",
            "findings": r["findings"],
            "cwes_found": sorted(set().union(*adv_cwes)),
            "unattributed": sum(1 for s in adv_cwes if not s),
            "class": cls,
            "class_any": cls_any,
            "rule_scores": count_per_rule_tag(cases, [r]),
            **({"error": r["error"]} if "error" in r else {}),
        })

    main = tally(per_case, "class")
    # Rates-shaped (TP/FP/FN/TN + tpr/fpr/score): the report printers and the
    # baseline comparison all read those keys off the per-rule entries.
    rule_tally = rates(rules_from_cases(cases, results))
    return {
        "meta": {"match": mode, "tag_cwe_entries": len(tag_cwe)},
        "total": main["total"],
        "by_cwe": main["by_cwe"],
        "legacy_any": tally(per_case, "class_any"),
        "attribution": {
            "advisories": advisories_total,
            "unattributed": unattributed_total,
            "unattributed_tags": dict(sorted(unattributed_tags.items(), key=lambda kv: -kv[1])[:20]),
        },
        "rules": rule_tally,
        "cases": per_case,
    }


def compare_to_baseline(cur: dict, base: dict, tpr_tol: float, fpr_tol: float) -> dict:
    """Deltas vs a previous scorecard plus a list of regressions."""
    diff = {"total": {}, "by_cwe": {}, "rules": {}, "regressions": []}
    for k in ("tpr", "fpr", "score"):
        diff["total"][k] = round(cur["total"][k] - base["total"].get(k, 0.0), 3)
    if diff["total"]["fpr"] > fpr_tol + 1e-9:
        diff["regressions"].append(
            f"overall FPR rose {diff['total']['fpr']*100:+.1f} pp "
            f"({base['total'].get('fpr', 0)*100:.1f}% -> {cur['total']['fpr']*100:.1f}%)")
    for cwe, v in cur["by_cwe"].items():
        b = base.get("by_cwe", {}).get(cwe)
        if not b:
            continue
        dt = round(v["tpr"] - b["tpr"], 3)
        diff["by_cwe"][cwe] = dt
        if dt < -tpr_tol - 1e-9:
            diff["regressions"].append(
                f"{cwe} TPR fell {dt*100:+.1f} pp ({b['tpr']*100:.1f}% -> {v['tpr']*100:.1f}%)")
    for rule, v in cur["rules"].items():
        b = base.get("rules", {}).get(rule)
        if not b:
            continue
        denom = v.get("TP") + v.get("FN")
        dt = round(v["tpr"] - b["tpr"], 3) if denom > 0 else 0.0
        diff["rules"][rule] = dt
        if dt < -tpr_tol - 1e-9:
            diff["regressions"].append(
                f"{rule} TPR fell {dt*100:+.1f} pp ({b['tpr']*100:.1f}% -> {v['tpr']*100:.1f}%)")
    if cur["total"]["ERR"] > base["total"].get("ERR", 0):
        diff["regressions"].append(
            f"scan errors rose ({base['total'].get('ERR', 0)} -> {cur['total']['ERR']})")
    return diff


def _pp(x: float | None) -> str:
    return "n/a" if x is None else f"{x*100:+.1f} pp"


def print_scorecard(s: dict, elapsed: float, diff: dict | None) -> None:
    t = s["total"]
    print(f"\n{'=' * 62}")
    print(f"FRENESENSE on OWASP BenchmarkPython  ({t['TP'] + t['FP'] + t['FN'] + t['TN'] + t['ERR']} cases, {elapsed:.0f}s)")
    print(f"{'=' * 62}")
    print(f"match mode: {s['meta']['match']}")
    print(f"TPR {t['tpr']*100:5.1f}%   FPR {t['fpr']*100:5.1f}%   SCORE (TPR-FPR) {t['score']*100:5.1f}%")
    print(f"   TP {t['TP']:4d}   FP {t['FP']:4d}   FN {t['FN']:4d}   TN {t['TN']:4d}   ERR {t['ERR']:4d}")
    if diff is not None:
        print(f"vs baseline: TPR {_pp(diff['total']['tpr'])}  FPR {_pp(diff['total']['fpr'])}  "
              f"score {_pp(diff['total']['score'])}")
    print("\nPer-rule (category + CWE tags):")
    for rule, v in sorted(s.get("rules", {}).items()):
        tpr = v["tpr"] if (v.get("TP") + v.get("FN")) else 0.0
        fpr = v["fpr"] if (v.get("FP") + v.get("TN")) else 0.0
        print(f"  {rule:<20} TP {v['TP']:4d} FP {v['FP']:4d} FN {v['FN']:4d} TN {v['TN']:4d} "
              f"TPR {tpr*100:5.1f}% FPR {fpr*100:5.1f}% score {round(tpr-fpr,3):+.3f}")


def generate_markdown_report(s: dict, elapsed: float, binary_version: str,
                             repo_commit: str, ctx: dict, diff: dict | None) -> str:
    t = s["total"]
    n = t["TP"] + t["FP"] + t["FN"] + t["TN"] + t["ERR"]
    mode = s["meta"]["match"]
    date_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    d_tot = diff["total"] if diff else {}

    def delta(key):
        return _pp(d_tot.get(key)) if diff else "n/a"

    mode_note = {
        "conservative": "findings count toward TP only when attributed to the case's CWE; "
                        "unattributed findings on safe cases count as FP (lower bound on TPR, "
                        "upper bound on FPR)",
        "cwe": "findings count only when attributed to the case's CWE; unattributed findings "
               "are ignored on both sides",
        "any": "any finding in the file counts, whatever its class (overstates TPR)",
    }[mode]

    lines = [
        "# Frensense Benchmark Report",
        "",
        "> Scorecard on **OWASP Benchmark for Python (v0.1)**, produced by `scripts/owasp_benchmark.py`.",
        "> Run by the Frensense maintainers; not independently audited. Reproduce with the command below.",
        "",
        "## Benchmark Environment",
        "",
        f"- **Date**: `{date_str}`",
        f"- **Engine Version**: `{binary_version}`",
        f"- **Frensense Commit**: `{repo_commit}`",
        f"- **Suite**: OWASP Benchmark for Python (v0.1, {n} test cases)",
        f"- **Knowledge bundle**: {ctx['bundle']}",
        f"- **Matching**: `{mode}`: {mode_note}",
        f"- **Scan Time**: `{elapsed:.1f}s` wall-clock, {ctx['workers']} workers "
        f"({elapsed/max(n,1)*1000:.1f} ms/case throughput)",
        "",
        "## Scorecard",
        "",
        "| Metric | Value | Δ vs baseline |",
        "| :--- | :--- | :--- |",
        f"| **Score (TPR - FPR)** | **{t['score']*100:.1f}%** | {delta('score')} |",
        f"| **False Positive Rate (FPR)** | **{t['fpr']*100:.1f}%** | {delta('fpr')} |",
        f"| **True Positive Rate (TPR)** | **{t['tpr']*100:.1f}%** | {delta('tpr')} |",
        f"| **Cases Evaluated** | {n} | |",
        f"| **True Positives (TP)** | `{t['TP']}` | |",
        f"| **False Positives (FP)** | `{t['FP']}` | |",
        f"| **False Negatives (FN)** | `{t['FN']}` | |",
        f"| **True Negatives (TN)** | `{t['TN']}` | |",
        f"| **Scan errors (excluded from rates)** | `{t['ERR']}` | |",
        "",
    ]

    a = s["attribution"]
    lines += [
        "## Finding attribution",
        "",
        f"{a['advisories']} advisories in total; {a['unattributed']} carry no CWE the scorer can resolve. "
        "Engine findings tagged since 0.7.1-beta resolve their CWE in the engine; anything still "
        "unattributed is a sink class without a single mapping (or a pre-0.7.1 binary) and can be "
        "extended with `--tag-cwe-map`.",
        "",
    ]
    if a["unattributed_tags"]:
        lines += ["| Tag on unattributed advisories | Count |", "| :--- | ---: |"]
        lines += [f"| `{tag}` | {cnt} |" for tag, cnt in a["unattributed_tags"].items()]
        lines.append("")

    lines += [
        "## Per-rule capability (category + CWE tags)",
        "",
        "| Rule | TPR | FPR | Score | Cases | Δ TPR |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]
    for rule, v in sorted(s.get("rules", {}).items(), key=lambda kv: -(kv[1]["tpr"] - kv[1]["fpr"])):
        tpr = v["tpr"] if (v.get("TP") + v.get("FN")) else 0.0
        fpr = v["fpr"] if (v.get("FP") + v.get("TN")) else 0.0
        d = _pp(diff["rules"].get(rule)) if diff else "n/a"
        lines.append(
            f"| `{rule}` | {tpr*100:.1f}% | {fpr*100:.1f}% | "
            f"**{round(tpr-fpr,3)*100:.1f}%** | {v['TP']+v['FP']+v['FN']+v['TN']} | {d} |"
        )

    if diff is not None and diff["regressions"]:
        lines += ["", "## Regressions vs baseline", ""]
        lines += [f"- {r}" for r in diff["regressions"]]

    lines.extend([
        "",
        "## Reproduction Command",
        "",
        "```bash",
        "# 1. Clone frensense and build release binary",
        "git clone https://github.com/Friehub/frensense-v2.git",
        "cd frensense-v2 && cargo build --release",
        "",
        "# 2. Run the reproduction runner",
        "python3 frensense-bench/run.py --suite owasp",
        "```",
        "",
        "---",
        "*(Report generated automatically by `frensense-bench/suites/owasp.py`)*",
    ])
    return "\n".join(lines)


def publish_github_gist(description: str, files: dict[str, str], public: bool = True) -> str | None:
    """Publish report files to GitHub Gist using GITHUB_TOKEN or GH_TOKEN."""
    import urllib.request
    import urllib.error
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        print("[WARN] Neither GITHUB_TOKEN nor GH_TOKEN is set. Cannot auto-publish Gist.", file=sys.stderr)
        print("       Set export GITHUB_TOKEN=... to enable automatic Gist upload.", file=sys.stderr)
        return None
    url = "https://api.github.com/gists"
    payload = {
        "description": description,
        "public": public,
        "files": {fname: {"content": content} for fname, content in files.items()},
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "Frensense-Benchmark-Reporter",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("html_url")
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8")
        print(f"[ERROR] Failed to create GitHub Gist: HTTP {e.code} - {err_msg}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[ERROR] Failed to create GitHub Gist: {e}", file=sys.stderr)
        return None


def resolve_binary(bin_arg: str | None) -> Path | None:
    if bin_arg:
        p = Path(bin_arg)
        if p.exists():
            return p
    # Look in common local release/debug locations
    repo_root = Path(__file__).resolve().parent.parent.parent
    for candidate in [
        repo_root / "target" / "release" / "frensense",
        repo_root / "target" / "debug" / "frensense",
    ]:
        if candidate.exists() and candidate.is_file():
            return candidate
    # Look in PATH
    import shutil
    which = shutil.which("frensense")
    if which:
        return Path(which)
    return None


def describe_bundle(bundle: Path | None, testcode: Path) -> tuple[str, dict | None]:
    """Human description of the knowledge bundle in effect, plus the
    subprocess environment that makes a 'bare' run actually bare.

    The engine auto-discovers `frensense-corpus.frc` in the scanned root and
    honours FRENSENSE_CORPUS_BUNDLE, so a run without --bundle is only bare if
    neither is present.
    """
    if bundle is not None:
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()[:12]
        return f"`{bundle.name}` (sha256 `{digest}`)\n", None
    env = {k: v for k, v in os.environ.items() if k != "FRENSENSE_CORPUS_BUNDLE"}
    ambient = [
        p for p in (testcode / "frensense-corpus.frc",
                    testcode.parent / "frensense-corpus.frc",
                    Path.cwd() / "frensense-corpus.frc")
        if p.exists()
    ]
    if ambient:
        print(f"[WARN] auto-discoverable bundle found: {ambient[0]}. "
              "This run may not be bare; remove it or pass --bundle explicitly.", file=sys.stderr)
        return f"**none passed, but `{ambient[0]}` is auto-discoverable; run may not be bare**", env
    return "none (bare engine; `FRENSENSE_CORPUS_BUNDLE` cleared)\n", env


def load_cases(csv_path: Path, testcode: Path) -> list[dict]:
    """Load ground truth: expectedresults CSV (name, category,
    real_vulnerability, cwe) plus the testcode directory of .py cases."""
    cases = []
    with open(csv_path) as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            name = row[0]
            vul = row[2].strip().lower() == "true"
            raw = f"CWE-{row[3].strip()}"
            cwe = norm_cwe(raw) or raw
            f = testcode / f"{name}.py"
            if f.exists():
                cases.append({"file": f, "vul": vul, "cwe": cwe})
    return cases


def norm_cwe(value: str) -> str | None:
    """'CWE-022' / 'cwe-22' -> 'CWE-22'; None if not a CWE id."""
    m = CWE_RE.match(value.strip())
    return f"CWE-{int(m.group(1))}" if m else None


def load_tag_cwe_map(path: str | None) -> dict[str, str]:
    mapping = dict(DEFAULT_TAG_CWE)
    if path:
        with open(path) as fh:
            for tag, cwe in json.load(fh).items():
                n = norm_cwe(str(cwe))
                if n is None:
                    raise ValueError(f"--tag-cwe-map: {tag!r} -> {cwe!r} is not a CWE id")
                mapping[tag] = n
    return mapping


def scan_case(binary: Path, case: dict, bundle: Path | None = None,
              env: dict | None = None) -> dict:
    """Scan one case file in isolation (own process: no cross-case state)."""
    cid = case["file"].stem
    try:
        cmd = [str(binary), str(case["file"])]
        if bundle is not None:
            cmd += ["--corpus-bundle", str(bundle)]
        cmd += ["--json"]
        proc = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=120, env=env,
        )
        # 0 = clean run; 1 = findings under --strict / baseline regression.
        # Anything else (2 = engine error, negative = killed by signal) is a
        # failed scan, not a clean file.
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"exit code {proc.returncode}: {proc.stderr.strip()[-200:]}")
        data = json.loads(proc.stdout) if proc.stdout.strip() else []
        advisories = data if isinstance(data, list) else data.get("advisories", [])
        if not isinstance(advisories, list):
            raise ValueError("unexpected JSON shape")
        tag_sets = [list(a.get("tags", [])) if isinstance(a, dict) else [] for a in advisories]
        return {"id": cid, "findings": len(advisories), "tag_sets": tag_sets}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, RuntimeError,
            ValueError, OSError) as e:
        return {"id": cid, "findings": 0, "tag_sets": [], "error": str(e)}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Score Frensense against the OWASP Benchmark for Python.")
    ap.add_argument("--bin", default=None, help="frensense binary path (auto-detected if omitted)")
    ap.add_argument("--workers", type=int, default=8, help="concurrent scan threads (default: 8)")
    ap.add_argument("--json-out", default=None, help="write machine-readable scorecard JSON here")
    ap.add_argument("--md-out", default=None, help="write markdown summary report here")
    ap.add_argument("--publish-gist", action="store_true", help="upload report to a public GitHub Gist via GITHUB_TOKEN")
    ap.add_argument("--owasp-csv", default=None,
                    help="OWASP BenchmarkPython expectedresults CSV (auto-detected if omitted)")
    ap.add_argument("--owasp-testcode", default=None,
                    help="testcode dir with the .py cases (default: CSV dir / testcode)")
    ap.add_argument("--bundle", default=None,
                    help=".frc corpus bundle passed to every scan via --corpus-bundle")
    ap.add_argument("--match", choices=("conservative", "cwe", "any"), default="conservative",
                    help="how findings are matched to a case's CWE (default: conservative)")
    ap.add_argument("--tag-cwe-map", default=None,
                    help="JSON object mapping advisory tags to CWE ids, e.g. {\"crypto\": \"CWE-328\"}")
    ap.add_argument("--baseline", default=None,
                    help="previous scorecard JSON (from --json-out) to diff against")
    ap.add_argument("--fail-on-regression", action="store_true",
                    help="exit 4 if FPR rises or any per-rule/per-CWE TPR drops vs --baseline")
    ap.add_argument("--tpr-tolerance", type=float, default=0.0,
                    help="allowed per-rule/per-CWE TPR drop before it counts as a regression (0.01 = 1 pp)")
    ap.add_argument("--fpr-tolerance", type=float, default=0.0,
                    help="allowed overall FPR rise before it counts as a regression")
    ap.add_argument("--allow-errors", action="store_true",
                    help="do not fail the run when some scans errored")
    args = ap.parse_args()

    binary = resolve_binary(args.bin)
    if not binary or not binary.exists():
        print("[ERROR] frensense binary not found.", file=sys.stderr)
        print("        Build it with: cargo build --release", file=sys.stderr)
        print("        Or specify with: --bin /path/to/frensense", file=sys.stderr)
        sys.exit(1)

    bundle = Path(args.bundle) if args.bundle else None
    if bundle is not None and not bundle.exists():
        print(f"[ERROR] bundle not found at {bundle}", file=sys.stderr)
        sys.exit(1)

    try:
        tag_cwe = load_tag_cwe_map(args.tag_cwe_map)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"[ERROR] cannot load --tag-cwe-map: {e}", file=sys.stderr)
        sys.exit(1)

    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"[ERROR] cannot read --baseline: {e}", file=sys.stderr)
            sys.exit(1)
        base_mode = baseline.get("meta", {}).get("match", "any")  # pre-patch scorecards were any-finding
        if base_mode != args.match:
            print(f"[ERROR] baseline was scored with --match {base_mode}, this run uses "
                  f"--match {args.match}; regenerate the baseline with the same mode.", file=sys.stderr)
            sys.exit(1)

    # Auto-resolve OWASP CSV
    csv_candidates = [
        Path(args.owasp_csv) if args.owasp_csv else None,
        Path("/tmp/BenchmarkPython/expectedresults-0.1.csv"),
        Path.home() / ".cache" / "BenchmarkPython" / "expectedresults-0.1.csv",
    ]
    csv_path = next((c for c in csv_candidates if c and c.exists()), None)
    if not csv_path:
        print("[INFO] OWASP BenchmarkPython not found locally. Auto-cloning to /tmp/BenchmarkPython...", file=sys.stderr)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "https://github.com/OWASP-Benchmark/BenchmarkPython.git", "/tmp/BenchmarkPython"],
                check=True,
            )
            csv_path = Path("/tmp/BenchmarkPython/expectedresults-0.1.csv")
        except Exception as e:
            print(f"[ERROR] Failed to auto-clone BenchmarkPython: {e}", file=sys.stderr)
            print("        Please clone manually: git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython.git /tmp/BenchmarkPython", file=sys.stderr)
            sys.exit(1)

    testcode = Path(args.owasp_testcode or csv_path.parent / "testcode")
    cases_list = load_cases(csv_path, testcode)
    if not cases_list:
        print(f"[ERROR] no OWASP cases resolved from {csv_path}", file=sys.stderr)
        sys.exit(1)
    cases = {c["file"].stem: c for c in cases_list}

    bundle_desc, scan_env = describe_bundle(bundle, testcode)

    # Query binary version and commit
    try:
        ver_proc = subprocess.run([str(binary), "--version"], capture_output=True, text=True, check=True)
        binary_version = ver_proc.stdout.strip()
    except Exception:
        binary_version = "frensense 0.7.0"

    try:
        commit_proc = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True)
        repo_commit = commit_proc.stdout.strip()
    except Exception:
        repo_commit = "unknown"

    print(f"[INFO] Using binary: {binary} ({binary_version})")
    print(f"[INFO] {len(cases_list)} OWASP ground-truth cases from {csv_path}")
    print(f"[INFO] Scanning with {args.workers} workers...")
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda c: scan_case(binary, c, bundle, scan_env), cases_list))
    elapsed = time.time() - t0

    errors = [r for r in results if "error" in r]
    if errors:
        print(f"[WARN] {len(errors)} scan errors (excluded from rates); first: "
              f"{errors[0]['id']}: {errors[0]['error']}", file=sys.stderr)

    scorecard = score(results, cases, args.match, tag_cwe)
    diff = compare_to_baseline(scorecard, baseline, args.tpr_tolerance, args.fpr_tolerance) if baseline else None
    print_scorecard(scorecard, elapsed, diff)

    scorecard_json_str = json.dumps(scorecard, indent=1)
    if args.json_out:
        Path(args.json_out).write_text(scorecard_json_str)
        print(f"\n[INFO] full scorecard JSON -> {args.json_out}")

    ctx = {"bundle": bundle_desc, "workers": args.workers}
    md_report = generate_markdown_report(scorecard, elapsed, binary_version, repo_commit, ctx, diff)
    if args.md_out:
        Path(args.md_out).write_text(md_report)
        print(f"[INFO] markdown report -> {args.md_out}")

    if args.publish_gist:
        print("\n[INFO] Publishing benchmark reproduction to GitHub Gist...")
        files = {
            "benchmark_report.md": md_report,
            "benchmark_scorecard.json": scorecard_json_str,
        }
        gist_url = publish_github_gist("Frensense 0.7.0 Benchmark Reproduction Scorecard", files, public=True)
        if gist_url:
            print(f"[SUCCESS] Benchmark Gist published: {gist_url}")
            step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
            if step_summary:
                try:
                    with open(step_summary, "a") as f:
                        f.write(f"\n\n### Published Benchmark Gist\n- [{gist_url}]({gist_url})\n")
                except Exception:
                    pass
        else:
            print("[INFO] You can manually paste 'benchmark_report.md' into https://gist.github.com")

    if errors and not args.allow_errors:
        print(f"[ERROR] {len(errors)} scans failed; scorecard is incomplete "
              "(rerun with --allow-errors to accept).", file=sys.stderr)
        sys.exit(3)
    if diff is not None and diff["regressions"]:
        print("\nRegressions vs baseline:")
        for r in diff["regressions"]:
            print(f"  - {r}")
        if args.fail_on_regression:
            sys.exit(4)


if __name__ == "__main__":
    main()
