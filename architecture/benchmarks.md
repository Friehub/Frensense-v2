---
url: https://frensense.friehub.cloud/architecture/benchmarks.md
description: >-
  How Frensense is scored, the current OWASP Benchmark for Python record, and
  how to reproduce it.
---

# Benchmarks

Frensense is scored against third-party ground truth, not only its own test
corpus. The independent benchmark used today is the **OWASP Benchmark for
Python (v0.1)**: 1,230 test cases written by the OWASP project, each labelled
vulnerable or safe in an expected-results file. None of those cases appear in
any Frensense knowledge bundle.

One benchmark is a narrow view. It covers a handful of vulnerability classes in
one language, in small single-file programs. Read the numbers as a progress
measure for the engine, not as a statement about how it performs on your code.

## Published record

Scored on 2026-11-06 with Frensense 0.8.0 built from the `main` branch at
commit `c2e6ade`. No `.frc` bundle (built-in knowledge only), single-file
scans, conservative matching (see "Scoring model").

| metric | value |
|---|---|
| **Score (TPR - FPR)** | **31.0%** |
| TPR (vulnerable cases found) | 38.1% |
| FPR (safe cases flagged) | 7.1% |
| TP / FP / FN / TN | 172 / 55 / 280 / 723 |
| scan time | about 4 s for 1,230 cases (2 workers) |

Compared with the previous record (v0.7.0, 2026-10-02):

| | v0.7.0 | 0.8.0 (`c2e6ade`) |
|---|---|---|
| Score | 26.2% | 31.0% |
| TPR | 28.5% | 38.1% |
| FPR | 2.3% | 7.1% |
| TP / FP | 129 / 18 | 172 / 55 |

The engine finds more vulnerable cases, and it also raises more false alarms:
the false-positive rate roughly tripled. Reducing it is an open engine
priority, and many of the [challenges](/challenges) target it.

We do not publish a ranking against other tools on this benchmark. The OWASP
project's published scorecards are for the Java benchmark, a different language
and test suite, so their numbers cannot be compared with these.

## Per-category results

Lowest score first. A "case" is one test file. A finding counts for a
vulnerable case only if it is attributed to that case's CWE.

| CWE | class | cases | TP | FP | FN | TN | TPR | FPR | score |
|---|---|---|---|---|---|---|---|---|---|
| CWE-330 | weak randomness | 326 | 0 | 0 | 99 | 227 | 0.0% | 0.0% | 0.0% |
| CWE-79 | cross-site scripting | 89 | 0 | 0 | 31 | 58 | 0.0% | 0.0% | 0.0% |
| CWE-501 | trust boundary | 37 | 0 | 0 | 18 | 19 | 0.0% | 0.0% | 0.0% |
| CWE-90 | LDAP injection | 29 | 0 | 0 | 16 | 13 | 0.0% | 0.0% | 0.0% |
| CWE-611 | XML external entities | 28 | 0 | 0 | 8 | 20 | 0.0% | 0.0% | 0.0% |
| CWE-643 | XPath injection | 186 | 14 | 25 | 37 | 110 | 27.5% | 18.5% | 8.9% |
| CWE-94 | code injection | 53 | 11 | 14 | 9 | 19 | 55.0% | 42.4% | 12.6% |
| CWE-601 | open redirect | 34 | 8 | 7 | 5 | 14 | 61.5% | 33.3% | 28.2% |
| CWE-22 | path traversal | 168 | 26 | 6 | 39 | 97 | 40.0% | 5.8% | 34.2% |
| CWE-78 | command injection | 20 | 5 | 0 | 8 | 7 | 38.5% | 0.0% | 38.5% |
| CWE-89 | SQL injection | 16 | 2 | 0 | 3 | 11 | 40.0% | 0.0% | 40.0% |
| CWE-502 | deserialization | 54 | 11 | 3 | 7 | 33 | 61.1% | 8.3% | 52.8% |
| CWE-328 | weak hash | 151 | 71 | 0 | 0 | 80 | 100.0% | 0.0% | 100.0% |
| CWE-614 | cookie flags | 39 | 24 | 0 | 0 | 15 | 100.0% | 0.0% | 100.0% |

What this shows:

* **Five classes score zero.** The built-in knowledge does not recognise the
  sources or sinks those cases use. Weak randomness alone is 99 vulnerable
  cases.
* **Three classes have a high false-alarm rate**: XPath injection, code
  injection and open redirect flag 18%, 42% and 33% of their safe cases. These
  are the classes where the safe variant looks most like the vulnerable one.
* **Weak hashes and cookie flags are solved** on this benchmark, because they
  need no data-flow reasoning.

## Reproduce it yourself

Requirements: Python 3.10+, git, and a built `frensense` binary (or Rust toolchain to auto-build).

### Quick reproduction (one-command runner)

From the root of the repository:

```bash
# Automated run: auto-locates binary, caches OWASP suite, generates markdown & JSON reports
python3 frensense-bench/run.py --suite owasp
```

This generates:

* `benchmark_report.md`: formatted Markdown scorecard ready to share on GitHub Discussions or Gist.
* `benchmark_scorecard.json`: complete machine-readable scorecard with per-case verdicts (`TP`/`FP`/`FN`/`TN`).

### Sharing via GitHub Gist

You can upload the scorecard directly to a GitHub Gist to share with the community:

```bash
# If GITHUB_TOKEN is exported in your environment:
python3 frensense-bench/run.py --suite owasp --publish-gist

# Or manually upload the generated report:
# Visit https://gist.github.com and paste the contents of benchmark_report.md
```

### Advanced runner flags

You can also run the underlying Python runner directly with custom parameters:

```bash
python3 frensense-bench/suites/owasp.py \
  --bin ./target/release/frensense \
  --workers 8 \
  --md-out benchmark_report.md \
  --json-out benchmark_scorecard.json \
  --bundle dist/frensense-default.frc   # optional: measure bundle uplift
```

## Scoring model

The OWASP Benchmark accuracy metric, applied per case:

| expected | finding emitted | class |
|---|---|---|
| vulnerable | yes, attributed to the case's CWE | TP |
| vulnerable | no | FN |
| safe | yes | FP |
| safe | no | TN |

The default matching mode is `conservative`: a finding counts as a true
positive only when it is attributed to the CWE the case is about. A finding
with no CWE attribution can never earn a true positive. `--match any` counts
any finding on a vulnerable case and gives a more generous number, which is not
comparable with the record above.

* `TPR = TP / (TP + FN)` (recall on vulnerable cases)
* `FPR = FP / (FP + TN)` (false alarms on safe cases)
* `score = TPR - FPR`

A tool that flags everything scores 0. A tool that flags nothing scores
0\. Precision and recall both matter, and the difference is what ranks
real scanners.

## Notes

* Each case is scanned as a single file in its own process, so there is
  no cross-case state and no bundle influence: this measures the engine
  plus its built-in language specs.
* Pass `--bundle <file.frc>` to the runner to measure what a bundle adds.
  A bundle can raise false alarms as well as detections, so compare both.
* The per-CWE table is the tuning roadmap: the lowest-scoring classes
  with the most cases are where sink/source coverage work pays off
  most.
