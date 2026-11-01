---
title: Engine Blindness & Capability Profile
description: Real-world static analysis limits, safety valve truncations, and commit-by-commit dataflow tracking across open-source codebases.
---

# Engine Blindness & Capability Profile

Traditional static analysis benchmarks like OWASP measure synthetic detection rates on deliberately crafted samples. While valuable, they cannot answer how the compiler behaves on complex, multi-thousand-file open-source codebases it was never trained on.

The **Engine Blindness & Capability Profile** evaluates Frensense on real software (Flask, Express, libpng, Axum) to measure where the engine's abstractions hit limits, where dataflow halts, and what resources are consumed.

---

## Live Commit Tracking Sheet

The sheet below tracks the global blindness rate and resource profile for every engine commit.

<BlindnessSheet />

---

## What is the Blindness Rate?

When Frensense explores potential vulnerability sinks (SQL queries, system commands, deserializers, buffer allocations), it performs demand-driven backward taint traversal. 

For each sink argument, the traversal yields one of four verdicts:
1. **`vulnerable`**: The backward path traced cleanly to an untrusted attacker source.
2. **`sanitized`**: The path crossed a recognized validation guard or sanitizer.
3. **`clean`**: The backward walk exhausted all predecessors without finding a source.
4. **`unknown`**: **The Blindspot.** The backward walk halted at an opaque boundary, unmodeled dynamic call, or missing library stub.

The **Blindness Rate** is the proportion of sink arguments that could not be proved clean, sanitized, or vulnerable:

$$\text{Blindness Rate} = \frac{\text{Unknown Sinks}}{\text{Total Sinks Explored}} \times 100\%$$

A declining blindness rate over time signifies an engine that understands more real-world idioms with fewer blindspots.

---

## Safety Valve Truncation Caps

Static analysis must balance precision against halting. To guarantee fast termination, Frensense includes bounded safety valves recorded in scan telemetry:

| Cap Identifier | Default Limit | When it Fires | Analytical Impact |
| :--- | :--- | :--- | :--- |
| `call_context_depth` | `k = 1` | Call stack exceeds depth ceiling | Collapses to context-insensitive ($k=0$) for that walk |
| `call_context_chains` | 4,096 chains | Call context interning table full | Subsequent calls become context-insensitive |
| `contexts_per_function` | 64 | Single function called from too many distinct contexts | Merges remaining call sites |
| `forward_hops` | 16 hops | Lexical enclosing scope traversal limit hit | Free name / outer variable resolution aborted |
| `callgraph_hops` | 8 hops | Function alias indirection walk hit limit | Callee target marked unresolved |
| `value_iterations` | $10 \times (\text{blocks} + 1)$ | Worklist rounds exceed budget | Early exit; branch constant sharpening dropped |
| `points_to_passes` | 12 passes | Andersen/Steensgaard fixed point does not converge | Field-sensitivity dropped for that function |

When a cap fires, the engine remains sound and safe, but may miss a deeper taint chain or record an `unknown` verdict.

---

## Memory & Capability Profile

Blind spots are only half of a benchmark: a scan that stops early because it
ran out of memory is not *more* precise, it is truncated. The challenge page
therefore carries a profile band above the cards with, per repository:

- **peak RSS** and **RSS per scanned file** — the number that turns "redis needs 2.5 GB" into a line item,
- scanned files, analysed functions, explored / unknown sinks, truncation caps, wall time,
- the engine-reported **phase totals** (lower, graph, taint, checks) and the binary identity (`frensense 0.8.0 · engine 0.8.0`).

Peak RSS is the high-water mark of the scan process (`/usr/bin/time %M`), sampled
per repository (per case for a `--synthetic` suite). To make it a gate rather
than an observation:

```bash
python3 frensense-bench/run.py --suite blindness --run --max-rss-mb 1024
```

A scan above the budget is highlighted on the page, named in the Markdown card,
and the run exits **4**, so a memory regression fails like a blindness
regression instead of being found by a user.

---

## Contributing: Solving Engine Blindspots

Our CI tracks blindness regressions on every commit. Open-source contributors can help drive the blindness rate down by tackling specific gaps:

### 1. Add Missing Library Facts (`.frc`)
Many `unknown` sink arguments occur because third-party libraries (e.g. specialized ORMs, sanitization libraries) have not been modeled. Contributors can author declarative rules in `.frc` bundles without touching the Rust compiler.

### 2. Sharpen Pointer and Alias Resolution
If `callgraph_hops` or `call_context_depth` is high in dynamic languages like Python or JavaScript, contributors can improve type-feedback heuristics or string constant propagation in `frensense-engine`.

### 3. Tree-sitter AST Gaps
If `files_partial` is greater than 0, Tree-sitter encountered syntax errors or unsupported grammar constructs. Improving Tree-sitter node mappings in `frensense-lang` restores 100% clean parsing.

---

## Timeouts, failures and exit codes

Every scan has a time limit so a runaway analysis cannot hold CI forever, but a limit must never change the answer. The rules:

| What | Default | How to change it |
| :--- | :--- | :--- |
| Time allowed per repository scan | 1800 s | `--timeout SECONDS`, or `FRENSENSE_BLINDNESS_TIMEOUT=SECONDS`, or `timeout=` on that repo's pin in `PINNED_REPOS` |
| No limit | n/a | `--timeout 0` (also `none`, `off`, `unlimited`) |
| Time allowed per file in synthetic suites (OWASP) | 120 s | `--case-timeout SECONDS` |
| Memory allowed per scan | no limit | `--max-rss-mb N` (exit **4** when exceeded) |
| Whole CI job | 240 min | `timeout-minutes` in `.github/workflows/engine-blindness.yml` |

Order of precedence for a repository: the command line, then the environment variable, then the repo's own `timeout=`, then the 1800 s default. In CI, **Run workflow** has a `timeout` box that sets the same thing for one run.

```bash
# One slow repo, give it two hours
python3 frensense-bench/run.py --suite blindness --run --timeout 7200

# Remove the limit while investigating
FRENSENSE_BLINDNESS_TIMEOUT=0 python3 frensense-bench/run.py --suite blindness --run --only flask,express
```

A scan that times out, crashes or prints unreadable output is a **failure, not a clean result**:

- the run exits with code **3** and prints `[FAILED] <repo>: <reason>`; CI goes red and nothing is published;
- the repo contributes no challenges, and its earlier challenges are **not** reported as solved (only repos that scanned successfully can have challenges solved).

There is no cap on the number of challenges: every unknown sink becomes one, grouped by what blocks it. The only filters are deliberate and visible: test, example and benchmark paths are not worth a contributor's time, and the engine itself skips test files and machine-minified JavaScript (lines averaging over 300 bytes) before scanning.

---

## Running the Benchmark Locally

You can run the blindness benchmark locally using the unified runner:

```bash
# 1. Build the release binary
cargo build --release

# 2. Clone the pinned repositories (one-time setup)
python3 frensense-bench/run.py --suite blindness --prepare

# 3. Run the scan and generate the scorecard, CSV sheet, and history JSON
python3 frensense-bench/run.py --suite blindness --run

# Run against a specific repository
python3 frensense-bench/run.py --suite blindness --run --only flask

# Score a case-isolated synthetic suite (e.g. the OWASP BenchmarkPython cases)
python3 frensense-bench/run.py --suite blindness --run \
  --synthetic owasp=/path/to/BenchmarkPython/testcode --workers 8
```

Results are saved to:
- `target/blindness/blindness_card.md` (Markdown summary)
- `target/blindness/blindness_sheet.csv` (Spreadsheet format)
- `target/blindness/blindness_history.json` (Commit history time-series)
- `target/blindness/challenges.html` (the contributor-facing blind-spot cards and memory profile)
- `target/blindness/challenges.json` (the same cards, machine-readable; `--baseline` diffs against it)
