# Frensense Benchmark Suite (`frensense-bench`)

Deterministic evaluation harness and ground-truth validation suites for Frensense.

## Available Benchmark Suites

1. **OWASP Benchmark for Python (`--suite owasp`)**:
   - 1,230 standardized test cases scored against official expected-results ground truth.
   - Measures True Positive Rate (TPR), False Positive Rate (FPR), and Youden's Index (`TPR - FPR`).
   - Current baseline: **26.6% Score / 1.5% FPR** across 1,230 cases in ~14 seconds.

2. **Curated CVE Verification Suite (`--suite cve`)**:
   - Evaluates paired real-world CVE cases (vulnerable source vs. vendor fix patch).
   - Validates that vulnerabilities are accurately detected while enforcing the **Zero False-Positive Contract** (0.0% FPR) on patched code.
   - Automatically updates [`docs/CVE_DATASHEET.md`](../docs/CVE_DATASHEET.md).

## Usage

```bash
# Run all benchmark suites
python3 frensense-bench/run.py --suite all

# Run only the OWASP Python Benchmark
python3 frensense-bench/run.py --suite owasp

# Run only the Curated CVE Verification Suite
python3 frensense-bench/run.py --suite cve

# Run with Gist publication (requires GITHUB_TOKEN)
python3 frensense-bench/run.py --suite owasp --publish-gist
```

## Structure

```
frensense-bench/
├── cve_benchmark.py       # Curated real-world CVE pair runner & datasheet generator
├── cve_corpus/            # Curated paired CVE source files (vuln vs fixed)
│   └── cwe_416_uaf/
│       └── cve_2026_56109_alsa/
├── run.py                 # Unified benchmark CLI entrypoint
└── README.md              # Documentation
```
