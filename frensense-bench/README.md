# Frensense Benchmark Suite (`frensense-bench`)

Deterministic evaluation harness and ground-truth validation suites for the Frensense static analysis engine.

This directory consolidates all macro-benchmarks, CVE verification suites, real-repository stress runners, and capability scorecards into a unified interface.

---

## Quickstart

Run core benchmark suites through the unified CLI entrypoint:

```bash
# Run core benchmark suites (Curated CVE pairs + OWASP Benchmark)
python3 frensense-bench/run.py --suite all

# Run only the Curated CVE Verification Suite (enforces Zero-FP contract)
python3 frensense-bench/run.py --suite cve

# Run the OWASP Benchmark for Python (1,230 standardized test cases)
python3 frensense-bench/run.py --suite owasp --workers 8

# Run real-world repository benchmarks (Django, Next.js, Redis, etc.)
python3 frensense-bench/run.py --suite real-repos --prepare
python3 frensense-bench/run.py --suite real-repos --run

# Run Engine Blindness & Capability Benchmark (tracks unknown sinks, bounds, and RSS)
python3 frensense-bench/run.py --suite blindness --prepare
python3 frensense-bench/run.py --suite blindness --run

# Run static correctness assertions
python3 frensense-bench/run.py --suite correctness

# Run OWASP Juice Shop challenge-line benchmark
python3 frensense-bench/run.py --suite juice-shop

# Run synthetic scale benchmark
python3 frensense-bench/run.py --suite scale

# Run OWASP mutation ladder triage
python3 frensense-bench/run.py --suite mutation
```

---

## Directory Structure

```
frensense-bench/
├── run.py                          # Unified benchmark CLI entrypoint
├── README.md                       # Documentation & guide
├── cve_corpus/                     # Curated paired CVE source files (vuln vs fixed)
│   └── cwe_416_uaf/
│       └── cve_2026_56109_alsa/
├── suites/                         # Benchmark test suites
│   ├── blindness.py                # Engine Blindness & Capability suite (telemetry & history)
│   ├── cve.py                      # Paired CVE runner & datasheet generator
│   ├── owasp.py                    # OWASP Benchmark for Python (1,230 cases)
│   ├── real_repos.py               # Pinned open-source repos benchmark
│   ├── correctness.py              # Positive/negative static sample assertions
│   ├── juice_shop.py               # OWASP Juice Shop line-exact marker gate
│   ├── scale.py                    # Synthetic file scaling benchmark
│   ├── mutation_ladder.py          # Systematic false-negative mutation ladder
│   └── rules.py                    # Rule card variant runner
├── profiling/                      # Diagnostic and profiling tools
│   ├── memory.py                   # Semantic graph memory profiler
│   ├── memory_benchmark.sh         # Memory RSS benchmark
│   ├── depth.py                    # Taint depth hop benchmark
│   ├── fp_ab.py                    # A/B false-positive regression comparison
│   └── historical.sh               # Historical commit regression runner
└── tests/                          # Benchmark suite unit tests
    └── test_owasp_scorer.py        # Scorer logic & regression test suite
```

---

## Running Unit Tests

Verify the scoring algorithms and regression gates:

```bash
python3 -m unittest discover -s frensense-bench/tests -v
```

---

## Benchmark Suites Detailed

### 1. Curated CVE Verification Suite (`--suite cve`)
* **Objective**: Verifies detection accuracy on real-world vulnerability pairs.
* **Contract**: Evaluates paired codebases (vulnerable target vs vendor fix patch). The vulnerable version must be flagged with the declared rule and symbol, while the fixed version must produce zero findings (**Zero False-Positive Contract**).
* **Output**: Updates [`docs/CVE_DATASHEET.md`](../docs/CVE_DATASHEET.md).

### 2. OWASP Benchmark for Python (`--suite owasp`)
* **Objective**: 1,230 standardized test cases scored against official expected-results ground truth.
* **Metrics**: True Positive Rate (TPR), False Positive Rate (FPR), and Youden's Index (`TPR - FPR`).
* **Output**: Writes `benchmark_scorecard.json` and `benchmark_report.md`. Supports uploading to GitHub Gist with `--publish-gist`.

### 3. Real-World Repositories (`--suite real-repos`)
* **Objective**: Scans pinned commits of real-world open-source frameworks (Django, Flask, Express, Next.js, Redis, Juice-shop, Axum, libpng).
* **Metrics**: Measures wall clock time, peak RSS memory consumption, exit status, and findings distribution.
