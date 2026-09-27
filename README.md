<div align="left">
  <h1>Frensense</h1>
  <p><strong>A deterministic, dataflow-driven security scanner for TypeScript, JavaScript, Python, Go, and Rust.</strong></p>
</div>

<br />

Frensense detects security vulnerabilities by combining compiler-grade dataflow
analysis with a learned knowledge base. No brittle YAML rule packs, no regex
heuristics, the engine builds an AST, def-use chains, and a program dependence
graph for your code, then verifies whether untrusted data can actually reach a
dangerous sink.

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

```bash
# Install (one crate, three binaries: frensense, frensense-mcp, frensense-lsp)
cargo install frensense

# Scan a project
frensense .

# Teach the engine with a .frc knowledge bundle
frensense . --corpus-bundle frensense-corpus.frc

# JSON / SARIF output
frensense . --json
frensense . --sarif

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
can point `--corpus-bundle` at any bundle file.

### One crate, three binaries

The `frensense` crate ships everything. The CLI, the MCP server for AI
agents, and the LSP server for editors are three binaries built from the same
versioned code:

| binary | consumer | transport |
|---|---|---|
| `frensense` | humans, CI | files/exit code |
| `frensense-mcp` | AI agents (Claude, Cursor, Zed, …) | JSON-RPC over stdio |
| `frensense-lsp` | editors (VS Code, Neovim, …) | LSP over stdio |

`cargo install frensense` (or `cargo build --release`) gives you all three;
each delivery surface in this README assumes the others exist. They share one
analysis engine, one knowledge-bundle format, and one finding-identity
scheme, so a finding in your editor, in an agent's scan, and in CI is the
same finding with the same stable ID.

## What It Catches

- **Injection**: SQL/NoSQL injection, command injection, XPath/XXE.
- **Broken Access Control**: IDOR, missing auth guards, mass assignment.
- **Cryptographic Weaknesses**: weak hashes, ECB mode, hardcoded keys.
- **Server-Side Issues**: SSRF, path traversal, XXE, unsafe deserialization.
- **Client-Side**: Reflected/DOM XSS, prototype pollution, open redirects.
- **Misconfiguration**: Missing security headers, session mismanagement,
  insecure cookies, TLS verification disabled.

## Languages

| Language | Parser | Compiler Mode |
|----------|--------|---------------|
| TypeScript / JavaScript / TSX | Tree-sitter | Oxc (`--use-compiler`) |
| Python | Tree-sitter |, |
| Go | Tree-sitter |, |
| Rust | Tree-sitter | rust-analyzer HIR (`--use-compiler`) |

## MCP Integration (AI Agents)

Frensense ships an MCP server so AI coding agents can scan their own output
before committing:

```bash
frensense-mcp
```

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

### Installing the MCP server from a single binary

`frensense-mcp` is a self-contained binary: there is no runtime, no package
manager step, and no plugin to install. Installation is just "put the binary
somewhere on PATH":

1. **Get the binary.** Either download a release build from the
   [GitHub releases](https://github.com/Friehub/frensense-v2/releases) page
   (SLSA L3 provenance attached), or build it yourself:

   ```bash
   cargo build --release --bin frensense-mcp
   # → target/release/frensense-mcp
   ```

2. **Put it on PATH** (any directory works; PATH just makes config cleaner):

   ```bash
   # system-wide (needs write access to /usr/local/bin):
   install -m 755 target/release/frensense-mcp /usr/local/bin/
   # or, user-local (create ~/.local/bin if it does not exist):
   install -m 755 target/release/frensense-mcp ~/.local/bin/
   # or keep it wherever it is and use the absolute path in the config below
   ```

3. **Register it with your MCP client.** MCP clients (Claude Desktop,
   Claude Code, Cursor, Zed, ...) launch the server themselves as a
   subprocess over stdio, so you only tell them the command. For example, in
   Claude Desktop's `claude_desktop_config.json`:

   ```json
   {
     "mcpServers": {
       "frensense": {
         "command": "frensense-mcp",
         "env": {
           "FRENSENSE_CORPUS_BUNDLE": "/path/to/frensense-corpus.frc"
         }
       }
     }
   }
   ```

   If the binary is not on PATH, use the absolute path (e.g.
   `/opt/frensense/frensense-mcp`) as `"command"`; clients accept both.
   In Claude Code, the equivalent one-liner is:

   ```bash
   claude mcp add frensense -- frensense-mcp
   ```

That's it: no daemon, no port, no Python/Node runtime. The client spawns the
binary per session, speaks JSON-RPC over stdin/stdout, and kills it when the
session ends. The same single-binary story applies to `frensense-lsp` (see
below) and the `frensense` CLI itself.

## LSP (Editors)

`frensense-lsp` publishes diagnostics as you open and save files: same
findings, same stable IDs, same severity mapping as the CLI.

```json
// e.g. VS Code settings.json / Neovim LSP config: point the client at the binary
{ "command": "frensense-lsp", "args": [] }
```

Diagnostics appear on `didOpen` and `didSave`; the server scans the saved
file on disk, so what the editor shows is exactly what CI scans. Like the
MCP server it is a single self-contained binary launched by the editor over
stdio.

## Benchmark Results

Scored against the OWASP Benchmark for Python: 1,230 third-party test
cases with an authoritative expected-results CSV. Zero overlap with any
Frensense knowledge bundle. This run uses the engine alone, no `.frc`
bundle:

| metric | value |
|---|---|
| **Score (TPR - FPR)** | **18.7%** |
| TPR | 22.8% |
| **FPR** | **4.1%** |
| TP / FP / FN / TN | 103 / 32 / 349 / 746 |
| scan time | 9s |

For comparison, the OWASP project's published Benchmark scorecards
(Java, v1.2): Veracode ~50%, Fortify SCA ~11-17%, Checkmarx ~0%,
SonarQube ~0%. The standout number is the false-positive rate: 4.1% is
commercially competitive, and the recall gaps are concentrated in a few
CWE classes where Python API coverage is still thin, not in engine
logic. See the caveats and the full per-CWE table in
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
- [docs/FRENSENSE_CORPUS_GUIDE.md](docs/FRENSENSE_CORPUS_GUIDE.md):
  building and using `.frc` knowledge bundles.

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
https://friehub.com/licensing.
