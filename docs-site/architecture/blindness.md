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

## Contributing: Solving Engine Blindspots

Our CI tracks blindness regressions on every commit. Open-source contributors can help drive the blindness rate down by tackling specific gaps:

### 1. Add Missing Library Facts (`.frc`)
Many `unknown` sink arguments occur because third-party libraries (e.g. specialized ORMs, sanitization libraries) have not been modeled. Contributors can author declarative rules in `.frc` bundles without touching the Rust compiler.

### 2. Sharpen Pointer and Alias Resolution
If `callgraph_hops` or `call_context_depth` is high in dynamic languages like Python or JavaScript, contributors can improve type-feedback heuristics or string constant propagation in `frensense-engine`.

### 3. Tree-sitter AST Gaps
If `files_partial` is greater than 0, Tree-sitter encountered syntax errors or unsupported grammar constructs. Improving Tree-sitter node mappings in `frensense-lang` restores 100% clean parsing.

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
```

Results are saved to:
- `target/blindness/blindness_card.md` (Markdown summary)
- `target/blindness/blindness_sheet.csv` (Spreadsheet format)
- `target/blindness/blindness_history.json` (Commit history time-series)
