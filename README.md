<div align="left">
  <h1>Frensense</h1>
  <p><strong>Deterministic static analysis and code scanning for TypeScript, JavaScript, Python, Go, Rust, and C. Taint analysis that proves every flaw from source to sink.</strong></p>
  <p>
    <a href="https://crates.io/crates/frensense"><img src="https://img.shields.io/crates/v/frensense.svg" alt="crates.io" /></a>
    <a href="https://www.npmjs.com/package/@friehub/frensense"><img src="https://img.shields.io/npm/v/@friehub/frensense.svg" alt="npm" /></a>
    <a href="https://frensense.friehub.cloud"><img src="https://img.shields.io/badge/docs-frensense.friehub.cloud-blue.svg" alt="Documentation" /></a>
    <a href="https://github.com/Friehub/Frensense-v2/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-green.svg" alt="License" /></a>
  </p>
  <p>
    <a href="https://frensense.friehub.cloud">Documentation</a> &bull;
    <a href="https://frensense.friehub.cloud/bundles">Security Bundles (.frc)</a> &bull;
    <a href="https://crates.io/crates/frensense">crates.io</a> &bull;
    <a href="https://www.npmjs.com/package/@friehub/frensense">npm</a> &bull;
    <a href="https://github.com/Friehub/Frensense-v2/releases">Releases</a>
  </p>
</div>

<br />

Frensense is a static application security testing (SAST) engine that detects
vulnerabilities by combining compiler-grade dataflow analysis with a learned
knowledge base. No brittle YAML rule packs, no regex heuristics: the engine
builds an AST, def-use chains, and a program dependence graph for your code,
then runs taint analysis to verify whether untrusted data can actually reach a
dangerous sink. Every finding carries the concrete source-to-sink path with
file positions, so code scanning output points at the exact line to fix.

**AI agents:** a machine-readable documentation index is published at
[llms.txt](https://frensense.friehub.cloud/llms.txt); the full docs in one
file are at [llms-full.txt](https://frensense.friehub.cloud/llms-full.txt).

## How It Works

1. **IR & Graphs**: Every file is lowered to a lightweight IR; the engine builds
   def-use chains, a call graph, heap/points-to summaries, and an SVFG.
2. **Taint Analysis**: Taint paths are tracked from sources (`req.body`,
   query params) to sinks (`exec`, `db.query`, `fetch`) with path-sensitive
   pruning through the taint engine.
3. **Knowledge Merge**: A `.frc` bundle's learned facts (framework-aware
   sources, sinks, sanitizers, and modelled APIs) are merged into the config,
   teaching the engine framework-specific semantics.
4. **Composition**: A finding is emitted only when the dataflow result and the
   structural evidence agree, keeping the false-positive rate low.

## Quick Start

Install via [crates.io](https://crates.io/crates/frensense) or [npm](https://www.npmjs.com/package/@friehub/frensense):

```bash
# Install (Cargo or npm)
cargo install frensense
npm install -g @friehub/frensense

# Or run instantly without installing
npx @friehub/frensense .

# Scan a project
frensense .

# Scan with a security rules bundle (.frc)
frensense . -b ruleset.frc

# Save report to file (text, json, sarif, or github)
frensense . -o report.sarif --sarif

# Diff-only (changed files since last commit)
frensense . --diff-only --strict

# Baseline workflow: save current findings, then fail on new ones
# (findings are identified by stable IDs: a finding that moves lines
# after an unrelated edit is NOT a regression)
frensense . --emit-baseline baseline.json
frensense . --compare-baseline baseline.json --strict

# Watch mode: re-scan on file changes, print only NEW findings
frensense watch .

# GitHub Actions annotations: findings render on the PR's Files Changed tab
frensense . --github
```

The engine auto-discovers a `frensense-corpus.frc` in the project root, or you
can pass `-b, --bundle <path>` to use any rule bundle.

## Security Rule Bundles (`.frc`) & Capability Datasheets

Frensense uses compiled `.frc` rule bundles to expand analysis capabilities with framework-specific sources, sinks, sanitizers, and zero-day CVE reproductions.

### Acquiring Rule Bundles
Download pre-compiled rule bundles and their cryptographic verification datasheets at:  
👉 **[https://frensense.friehub.cloud/bundles](https://frensense.friehub.cloud/bundles)**

- **Free Community Starter Bundles**:
  - Covers fundamental OWASP Top 10 vulnerabilities across TypeScript, JavaScript, Python, and C.
  - Pre-packaged in release distributions and community downloads.
- **Commercial & Enterprise Domain Bundles (Subscription / Paywall)**:
  - Deep web framework modeling (Express, Next.js, Django, FastAPI, Spring).
  - Advanced systems security & memory safety (C/C++ interprocedural ownership contracts, UAF, uninitialized pointer leaks).
  - Specialized industry compliance (Fintech, Cloud Infrastructure, Healthcare).
  - Rigorous Zero False-Positive guarantee (100% TPR / 0.0% FPR) verified against held-out blind test suites.

### Auditable Capability Datasheets
Every rule bundle ships with a signed **CWE Capability Datasheet** (`CWE_DATASHEET.md` and `cwe_datasheet.json`) detailing:
- Exact CWE classifications and vulnerability descriptions.
- Real-world ground-truth CVE reproductions.
- Benchmark verification status (100.0% TPR, 0.00% FPR).
- Execution latency and peak RSS memory requirements.

### One binary, every surface

The `frensense` crate ships a single binary with everything built in. The
CLI, the MCP server for AI agents, and the LSP server for editors are
subcommands of the same binary:

| command | consumer | transport |
|---|---|---|
| `frensense [path]` | humans, CI | files/exit code |
| `frensense mcp` | AI agents (Claude, Cursor, Zed, …) | JSON-RPC over stdio |
| `frensense lsp` | editors (VS Code, Neovim, …) | LSP over stdio |

`cargo install frensense`, `npm install -g @friehub/frensense`, or a release binary
gives you all of them. They share one analysis engine, one
knowledge-bundle format, and one finding-identity scheme, so a finding in
your editor, in an agent's scan, and in CI is the same finding with the
same stable ID.

## What It Catches

- **Injection**: SQL/NoSQL injection, command injection, XPath/XXE.
- **Broken Access Control**: IDOR, missing auth guards, mass assignment.
- **Cryptographic Weaknesses**: weak hashes, ECB mode, hardcoded keys.
- **Server-Side Issues**: SSRF, path traversal, XXE, unsafe deserialization.
- **Client-Side**: Reflected/DOM XSS, prototype pollution, open redirects.
- **Memory Safety**: Use-after-free on graph-validated paths (UAF),
  allocation-lifetime leaks (CWE-401), integer-overflow heap overflows
  (CWE-190/680).
- **Misconfiguration**: Missing security headers, session mismanagement,
  insecure cookies, TLS verification disabled.

## Languages

| Language | Parser | Compiler Mode |
|----------|--------|---------------|
| TypeScript / JavaScript / TSX | Tree-sitter | Oxc (`--use-compiler`) |
| Python | Tree-sitter | - |
| Go | Tree-sitter | - |
| Rust | Tree-sitter | rust-analyzer HIR (`--use-compiler`) |
| C | Tree-sitter | - |

## MCP Integration (AI Agents)

Frensense ships an MCP server built into the same binary, so AI coding agents
can scan their own output before committing:

```bash
frensense mcp
```

The server speaks newline-delimited JSON-RPC over stdio.

### Tools

| tool | what it does |
|---|---|
| `frensense_audit` | directory audit; returns `clean` + advisories |
| `frensense_scan_file` | single-file scan for edit loops ("is THIS file clean?") |
| `frensense_diff` | scan a git diff / patch and report only findings on added lines |

Every tool supports `.frc` corpus bundles (`corpus_bundle` argument, or set
`FRENSENSE_CORPUS_BUNDLE` in the server's environment for the whole session),
and results carry stable finding IDs (`FRN-…`) so an agent can track "did I
fix THIS finding yet" across edit cycles.

### Registering the server with your MCP client

The server is a subcommand of the binary you already installed: no runtime,
no package manager step, and no plugin. MCP clients (Claude Desktop,
Claude Code, Cursor, Zed, ...) launch it themselves as a subprocess over
stdio, so you only tell them the command. In Claude Desktop's
`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "frensense": {
      "command": "frensense",
      "args": ["mcp"],
      "env": {
        "FRENSENSE_CORPUS_BUNDLE": "/path/to/frensense-corpus.frc"
      }
    }
  }
}
```

Or run zero-install via `npx` (no manual download or PATH setup required):

```json
{
  "mcpServers": {
    "frensense": {
      "command": "npx",
      "args": ["-y", "@friehub/frensense", "mcp"]
    }
  }
}
```

If using a local binary not on PATH, use the absolute path as `"command"`; clients
accept both. In Claude Code, the equivalent one-liner is:

```bash
claude mcp add frensense -- frensense mcp
```

That's it: no daemon, no port, no Python/Node runtime. The client spawns the
command per session, speaks JSON-RPC over stdin/stdout, and kills it when the
session ends. The same story applies to the LSP server (see below).

## LSP (Editors)

The LSP server is a subcommand of the same binary. It publishes diagnostics
as you open and save files: same findings, same stable IDs, same severity
mapping as the CLI.

```json
// e.g. VS Code settings.json / Neovim LSP config: point the client at the subcommand
{ "command": "frensense", "args": ["lsp"] }
```

Diagnostics appear on `didOpen` and `didSave`; the server scans the saved
file on disk, so what the editor shows is exactly what CI scans. Like the
MCP server it is a single self-contained binary launched by the editor over
stdio.

## Benchmark Results

Scored against the OWASP Benchmark for Python: 1,230 third-party test
cases with an authoritative expected-results CSV. Zero overlap with any
Frensense knowledge bundle. This run uses the engine alone, no `.frc`
bundle (`v0.7.0-preview.5`):

| metric | value |
|---|---|
| **Score (TPR - FPR)** | **26.2%** |
| TPR | 28.5% |
| **FPR** | **2.3%** |
| TP / FP / FN / TN | 129 / 18 / 323 / 760 |
| scan time | 6s |

For comparison, the OWASP project's published Benchmark scorecards
(Java, v1.2): Veracode ~50%, Fortify SCA ~11-17%, Checkmarx ~0%,
SonarQube ~0%. The standout number is the false-positive rate: 2.3% is
commercially competitive, and the recall gaps are concentrated in a few
CWE classes where Python API coverage is still thin, not in engine
logic. The weak-hash class (CWE-328) scores a perfect 100% (71/71, zero
false positives). See the caveats and the full per-CWE table in
[docs/BENCHMARKING.md](docs/BENCHMARKING.md).

Run it yourself:

```bash
cargo build --release
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython /tmp/BenchmarkPython
python3 scripts/owasp_benchmark.py \
  --owasp-csv /tmp/BenchmarkPython/expectedresults-0.1.csv \
  --owasp-testcode /tmp/BenchmarkPython/testcode
```

## Detailed Guides

- [docs/MCP_USAGE.md](docs/MCP_USAGE.md): MCP setup, tool reference, and a
  worked end-to-end agent session (edit → diff-gate → fix → verify by
  stable ID).
- [docs/LSP_USAGE.md](docs/LSP_USAGE.md): editor setup (Neovim, Helix,
  VS Code) and the protocol walkthrough.
- [docs/AGENT_INTEGRATION.md](docs/AGENT_INTEGRATION.md): CI wiring,
  baseline gating, `--github` annotations, and the agent-fixes/CI-judges
  workflow.
- [docs/BENCHMARKING.md](docs/BENCHMARKING.md): benchmark methodology and
  per-CWE results.

## Knowledge Bundles (.frc)

Detection knowledge ships as `.frc` bundles, compiled, checksummed archives
produced by `frensense-bundler`. A bundle carries two kinds of content:

- **Patterns**: fingerprinted positive/negative code pairs the engine matches
  against your functions.
- **Learned facts**: replay-verified sources, sinks, sanitizers, and modelled
  framework APIs.

At scan time the engine loads a bundle in this priority order:

1. `--corpus-bundle <file>` CLI flag
2. Auto-discovered `frensense-corpus.frc` in the project root
3. Embedded bytes via the library API (`set_corpus_bundle`)

The envelope is validated (`FRC1` magic, version, checksum) and the learned
facts are merged into the engine's fact table on top of the built-in language
specs, the bundle teaches the engine at runtime, without touching engine code.

## Contributing

Contributions are welcome under GPL-3.0. Read [CONTRIBUTING.md](CONTRIBUTING.md)
and sign the lightweight [CLA](CLA.md), one click via the CLA bot on your first
pull request.

## License

GPL-3.0, see [LICENSE](LICENSE). Commercial licensing available at
https://www.friehub.cloud/contact.
