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

DEFAULT_BIN = Path(__file__).resolve().parent.parent / "target" / "release" / "frensense"

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

# Rule ids are the segment before the first ':' in a finding identity
# (e.g. "cookie_secure_missing" from "cookie_secure_missing|sess").
RULE_ID_RE = re.compile(r"^([^:]+)")

# Baseline merged-fact format: {"rule_id": {"TP": n, "FP": n, "FN": n, "TN": n}}
BASELINE_FACTS_RE = re.compile(r"^BLF:\s*(.+)$")


def rule_id_of(identity: str) -> str | None:
    """Extract the rule id from a finding identity string."""
    m = RULE_ID_RE.match(identity)
    return m.group(1) if m else None


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
            rule = rule_id_of(m.group(1))
            if not rule:
                raise ValueError(f"no rule id in baseline line: {line!r}")
            rest = m.group(1)
            if ":" not in rest or rest.count(":") != 1:
                raise ValueError(f"baseline line has no count separator: {line!r}")
            tag, count = rest.split(":", 1)
            facts[rule][tag.strip()] = int(count.strip())
    return facts


def per_rule_scores(cases: dict[str, dict], case_id: str,
                    adv_cwes: list[set[str]], vul: bool) -> list[str]:
    """Classify one case per rule id present in the findings list."""
    out = []
    for adv_cwes_list in adv_cwes:
        if not adv_cwes_list:
            continue
        matched_rule = next(
            (r for r in adv_cwes_list if rule_id_of(r) is not None), None
        )
        if matched_rule is None:
            continue
        cwe = cases[case_id]["cwe"]
        attributed_hit = any(cwe in s for s in adv_cwes_list)
        if matched_rule == "cookie_secure_missing":
            # WI-74: per-rule scorer for the cookie rule; rule id is the
            # segment before ':' in the finding identity.
            out.append("TP" if attributed_hit else "FN")
            continue
        # Generic path: same OWASP accuracy metric as the main scorer.
        if any(cwe in s for s in adv_cwes_list):
            out.append("TP" if vul else "FP")
        else:
            out.append("FN" if vul else "TN")
    return out
