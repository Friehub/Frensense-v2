<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub. All rights reserved. -->

# frensense-lsp: Usage Guide

`frensense-lsp` puts the Frensense engine inside your editor: findings
appear as diagnostics when you open or save a file, with the same severity
mapping, messages, and stable IDs as the CLI and MCP server. It speaks the
standard Language Server Protocol over stdio and ships in the same
`frensense` crate as the CLI and MCP server.

## Installation

`frensense-lsp` is a self-contained binary — no Node.js runtime, no VS
Code extension marketplace step. Get it and put it on `PATH`:

**Download a release binary** (recommended):

```bash
# Linux x86_64 — replace the tag with the latest release
curl -L https://github.com/Friehub/frensense-v2/releases/latest/download/frensense-lsp-x86_64-unknown-linux-gnu \
  -o /usr/local/bin/frensense-lsp && chmod +x /usr/local/bin/frensense-lsp
```

**Or install from source** (requires a Rust toolchain):

```bash
cargo install frensense   # installs frensense, frensense-mcp, frensense-lsp
```

## What it does (and deliberately doesn't)

- Scans on `textDocument/didOpen` and `textDocument/didSave`, publishing
  `textDocument/publishDiagnostics` for that file.
- Scans the **saved file on disk** through the same per-file engine path as
  `frensense watch` and the MCP tools: the engine is the single source of
  truth, so what the editor shows is exactly what CI scans. No in-memory
  AST fork, no incremental-edit replay divergence.
- Diagnostics map advisories 1:1: Critical → Error (1), Warning → Warning
  (2), Info → Information (3); ranges are 0-based; `code` carries the
  stable finding ID (`FRN-…`) and `data` carries the raw fingerprint and
  tags; `source` is `"frensense"`.
- Closing a file clears its diagnostics; unsupported file types clear
  rather than error (closing a deleted file's tab doesn't spam).
- **Diagnostics only.** `initialize` advertises just `textDocumentSync`;
  no hover, completion, or code actions are claimed or supported.

## Client configuration

Any LSP client that launches a stdio server works. Set
`FRENSENSE_CORPUS_BUNDLE` in the server's launch environment if you want
learned `.frc` facts to participate in editor scans — this is read once
when the binary starts, so it must be in the environment the editor passes
to the subprocess, not a shell export after the fact.

### Neovim (built-in LSP, Lua)

```lua
vim.lsp.config('frensense', {
  cmd = { 'frensense-lsp' },
  filetypes = { 'python', 'javascript', 'typescript', 'rust', 'go' },
})
vim.lsp.enable('frensense')
```

With a corpus bundle:

```lua
vim.lsp.config('frensense', {
  cmd = { 'frensense-lsp' },
  filetypes = { 'python', 'javascript', 'typescript', 'rust', 'go' },
  on_new_config = function(config)
    config.cmd_env = { FRENSENSE_CORPUS_BUNDLE = '/path/to/frensense-corpus.frc' }
  end,
})
vim.lsp.enable('frensense')
```

### Helix

```toml
# languages.toml
[[language]]
name = "python"
language-servers = ["frensense"]

[language-server.frensense]
command = "frensense-lsp"
environment = { "FRENSENSE_CORPUS_BUNDLE" = "/path/to/frensense-corpus.frc" }
```

### VS Code (generic LSP client extension)

Point any LSP client extension at the binary:

```json
{
  "frensense.server": {
    "command": "frensense-lsp",
    "args": [],
    "env": {
      "FRENSENSE_CORPUS_BUNDLE": "/path/to/frensense-corpus.frc"
    }
  }
}
```

If the binary isn't on `PATH`, use the absolute path (e.g.
`/opt/frensense/frensense-lsp`).

## Protocol walkthrough

The transcript below is real v0.7.0-preview.2 output (captured by piping
framed messages into the binary). File on disk:

```python
import hashlib


def digest(data):
    return hashlib.md5(data).hexdigest()
```

**1. Client → server: `initialize`** (framed with `Content-Length`):

```
Content-Length: 63

{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

**Server → client:** capabilities + server info. Note only
`textDocumentSync` is claimed:

```json
{"jsonrpc":"2.0","id":1,"result":{"capabilities":
  {"textDocumentSync":{"openClose":true,"change":1,"save":true},
   "positionEncoding":"utf-16"},
 "serverInfo":{"name":"frensense-lsp","version":"0.7.0-preview.2"}}}
```

**2. Client → server:** `initialized`, then open the document:

```json
{"jsonrpc":"2.0","method":"initialized","params":{}}
{"jsonrpc":"2.0","method":"textDocument/didOpen","params":
  {"textDocument":{"uri":"file:///work/project/app.py",
                   "languageId":"python","version":1,"text":"..."}}}
```

**Server → client:** the diagnostics for the file:

```json
{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":
  {"uri":"file:///work/project/app.py",
   "diagnostics":[{
     "range":{"start":{"line":3,"character":11},
              "end":{"line":3,"character":11}},
     "severity":2,
     "code":"FRN-a441e6e7b795@/work/project/app.py:4",
     "source":"frensense",
     "message":"Weak hash function `md5`, not acceptable for passwords or
                security-sensitive digests (use bcrypt/argon2/scrypt or
                SHA-256+)",
     "data":{"fingerprint":"a441e6e7b795f2f2",
             "tags":["checker","weak_hash"]}}]}}
```

Line 3 (0-based) is line 4 (1-based): the editor underline and the CLI's
`app.py:4` are the same position. The `code` is the stable finding ID:
if you insert ten lines above, the underline moves and this string's hash
portion does not change, so issue-tracker references stay valid.

**3. Fix the file and save** (`didSave`): the next publish contains an
**empty** diagnostics array. The finding is gone because the code changed,
not because it was filtered:

```json
{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":
  {"uri":"file:///work/project/app.py","diagnostics":[]}}
```

**4. Close the file** (`didClose`): diagnostics are cleared for that URI.
**`shutdown` + `exit`** end the session.

## Combining surfaces

A finding has one identity across every delivery surface:

| surface | where you see it | identity |
|---|---|---|
| editor (LSP) | underline + hover message | `code: "FRN-…"` |
| agent (MCP) | `stable_ids` in tool results | `FRN-…` |
| CI (annotations) | `--github` output on the PR | title + file:line |
| baseline gate | `--compare-baseline` regressions | fingerprint |

An agent can fix a finding the editor flagged and prove it fixed *that*
finding (ID disappears from `frensense_diff` output) without CI ever
seeing a regression.

## Troubleshooting

- **No diagnostics appear**: check the file extension is a supported
  language (Python, JavaScript/TypeScript, Rust, Go). Unsupported files
  publish empty diagnostics by design.
- **Client logs**: most editors show the server's stderr in an output
  panel (VS Code: *Output → your LSP client*). `frensense-lsp` writes scan
  failures there; stdout is protocol-only.
- **Findings differ from the CLI**: make sure both use the same
  `.frc` bundle (`FRENSENSE_CORPUS_BUNDLE` / `--corpus-bundle`); learned
  facts change what the engine can see.
- **`FRENSENSE_CORPUS_BUNDLE` has no effect**: the variable must be set in
  the environment the editor passes when it spawns the `frensense-lsp`
  subprocess, not in a shell that is already running.

## Related

- `docs/MCP_USAGE.md`: the same engine for AI agents
- `docs/AGENT_INTEGRATION.md`: CI wiring and baseline gating
- README: install, quick start, single-binary notes
