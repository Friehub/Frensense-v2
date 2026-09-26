# Benchmarking Frensense

Frensense is scored against third-party ground truth, not our own test
corpus. The current independent benchmark is the **OWASP Benchmark for
Python (v0.1)**: 1,230 test cases authored by the OWASP project with an
authoritative expected-results CSV. There is zero overlap between those
cases and any Frensense knowledge bundle, which makes the number
competitor-comparable.

## Published record

Scored on 2026-09-26 with frensense v0.7.0-preview.1, no `.frc` bundle
(built-in language specs only), single-file scans, 8 parallel workers:

| metric | value |
|---|---|
| **Score (TPR - FPR)** | **18.7%** |
| TPR | 22.8% |
| **FPR** | **4.1%** |
| TP / FP / FN / TN | 103 / 32 / 349 / 746 |
| scan time | 9s (1,230 cases) |

For context, published results on the OWASP Benchmark (Java, v1.2,
2017-2019), from the OWASP project's own scorecards:

| tool | score | note |
|---|---|---|
| Veracode | ~50% | commercial, best published SAST |
| **Frensense** | **18.7%** | FPR 4.1%, competitive |
| Fortify SCA | ~11-17% | commercial |
| Checkmarx | ~0% | commercial |
| SonarQube | ~0% | commercial |

Caveats: different language (they benchmark Java, we Python), different
benchmark version (v1.2 vs v0.1), different years. Directionally
meaningful, not peer-reviewed. The interesting signal is FPR: 4.1% is
commercially competitive, and the misses are concentrated in a handful
of CWE classes where Python API coverage in the fact tables is thin
(weak-randomness flows, XPath sinks, Python XML parsers), not in engine
logic.

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
