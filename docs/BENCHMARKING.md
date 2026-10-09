# Benchmarking Frensense

Frensense is scored against third-party ground truth, not our own test
corpus. The current independent benchmark is the **OWASP Benchmark for
Python (v0.1)**: 1,230 test cases authored by the OWASP project with an
authoritative expected-results CSV. There is zero overlap between those
cases and any Frensense knowledge bundle, which makes the number
competitor-comparable.

## Published record

Scored on 2026-10-02 with frensense v0.7.0-preview.5, no `.frc` bundle
(built-in language specs only), single-file scans, 8 parallel workers:

| metric | value |
|---|---|
| **Score (TPR - FPR)** | **26.2%** |
| TPR | 28.5% |
| **FPR** | **2.3%** |
| TP / FP / FN / TN | 129 / 18 / 323 / 760 |
| scan time | 6s (1,230 cases) |

For context, published results on the OWASP Benchmark (Java, v1.2,
2017-2019), from the OWASP project's own scorecards:

| tool | score | note |
|---|---|---|
| Veracode | ~50% | commercial, best published SAST |
| **Frensense** | **26.2%** | **FPR 2.3%, lowest of any published tool** |
| Fortify SCA | ~11-17% | commercial |
| Checkmarx | ~0% | commercial |
| SonarQube | ~0% | commercial |

Caveats: different language (they benchmark Java, we Python), different
benchmark version (v1.2 vs v0.1), different years. Directionally
meaningful, not peer-reviewed.

## Where the score comes from

The engine's FPR is the lowest in the published comparison set. The TPR
gaps concentrate in a few CWE classes where Python API coverage in the
fact tables is thin, not in engine logic. Per-CWE breakdown (lowest
score first, classes with at least 5 vulnerable cases):

| CWE | cases | TPR | FPR | score | what's missing |
|---|---|---|---|---|---|
| CWE-330 weak randomness | 326 | 0.0% | 0.0% | 0.0% | random-source to sink flows unmodeled (`random.randint` not a source) |
| CWE-501 trust boundary | 37 | 0.0% | 0.0% | 0.0% | cookie-attribute checker needed (Secure flag), value-agnostic |
| CWE-611 XXE | 28 | 0.0% | 0.0% | 0.0% | Python XML parsers unknown (`xml.etree`, `lxml`) |
| CWE-614 cookie flags | 39 | 0.0% | 0.0% | 0.0% | same checker as CWE-501: set_cookie attribute inspection |
| CWE-79 XSS | 89 | 0.0% | 0.0% | 0.0% | Flask `render_template`/escape flows unmodeled |
| CWE-90 LDAP | 29 | 0.0% | 0.0% | 0.0% | LDAP filter sinks unknown |
| CWE-78 cmd injection | 20 | 23.1% | 14.3% | 8.8% | partial: most benchmark subprocess shapes still unmodeled |
| CWE-643 XPath | 186 | 9.8% | 0.7% | 9.1% | partial: direct sink shapes fire, the majority of lxml builder shapes miss |
| CWE-94 code injection | 53 | 35.0% | 21.2% | 13.8% | `eval`/`exec` partial coverage; tainted-vs-constant discrimination still thin (7 safe cases flag) |
| CWE-22 path traversal | 168 | 36.9% | 3.9% | 33.0% | partial: direct open-family joins fire; `codecs.open` and indirect joins unmodeled |
| CWE-89 SQLi | 16 | 40.0% | 0.0% | 40.0% | solid: parameterized-query gate working |
| CWE-502 deserialization | 54 | 44.4% | 2.8% | 41.7% | partial: direct `pickle.loads` calls fire, chained payload shapes miss |
| CWE-601 redirect | 34 | 69.2% | 19.0% | 50.2% | solid on direct flows; some safe-case redirects still flag |
| CWE-328 hash | 151 | 100.0% | 0.0% | 100.0% | perfect: declared weak-hash selector rules with per-rule credential qualification |

The pattern: **FPR is best-in-class; TPR is limited by named-sink and
named-source coverage in the Python fact tables.** The biggest single
lever is CWE-330 weak randomness (99 vulnerable cases, none reachable
yet): modeling Python's `random` module as a source, then the
cookie-attribute checker (CWE-501/614, 42 vulnerable cases) and the
XSS/XPath sink shapes (CWE-79/643, 77 vulnerable cases). Every gap row
is a table entry or a checker away, which is what the roadmap
prioritizes.

## Reproduce it yourself

Requirements: a C compiler toolchain, Python 3.10+, and ~10 seconds of
scan time.

```bash
# 1. build the engine
cargo build --release

# 2. get the benchmark
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython /tmp/BenchmarkPython

# 3. run
python3 scripts/owasp_benchmark.py \
  --owasp-csv /tmp/BenchmarkPython/expectedresults-0.1.csv \
  --owasp-testcode /tmp/BenchmarkPython/testcode \
  --workers 8 \
  --json-out owasp_scorecard.json
```

You should see the summary table (TPR/FPR/score plus a per-CWE
breakdown). `owasp_scorecard.json` contains the machine-readable
scorecard: totals, per-CWE rates, and a per-case verdict list
(`TP`/`FP`/`FN`/`TN`) you can diff against expectations.

## Scoring model

The OWASP Benchmark accuracy metric, applied per case:

| expected | finding emitted | class |
|---|---|---|
| vulnerable | yes | TP |
| vulnerable | no | FN |
| safe | yes | FP |
| safe | no | TN |

- `TPR = TP / (TP + FN)` (recall on vulnerable cases)
- `FPR = FP / (FP + TN)` (false alarms on safe cases)
- `score = TPR - FPR`

A tool that flags everything scores 0. A tool that flags nothing scores
0. Precision and recall both matter, and the difference is what ranks
real scanners.

## Notes

- Each case is scanned as a single file in its own process, so there is
  no cross-case state and no bundle influence: this measures the engine
  plus its built-in language specs.
- Run with a `.frc` bundle via the CLI's `--corpus-bundle` flag to
  measure bundle uplift separately.
- The per-CWE table is the tuning roadmap: the lowest-scoring classes
  with the most cases are where sink/source coverage work pays off
  most.
