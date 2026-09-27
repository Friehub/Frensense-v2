<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (c) 2024-2026 Friehub. All rights reserved. -->

# frensense-mcp: Usage Guide

`frensense-mcp` exposes the Frensense engine to AI coding agents over the
[Model Context Protocol](https://modelcontextprotocol.io) (JSON-RPC on
stdio). Every tool calls the same analysis engine as the CLI — same
lowering, same fact tables, same stable finding IDs.

## Setup

**Build / install** (one crate, three binaries — see the README's
"One crate, three binaries" section):

```bash
cargo build --release --bin frensense-mcp
# → target/release/frensense-mcp
```

**Register with your MCP client** — the client launches the server as a
subprocess over stdio, so it only needs the command. Claude Code:

```bash
claude mcp add frensense -- /path/to/frensense-mcp
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "frensense": {
      "command": "/path/to/frensense-mcp",
      "env": {
        "FRENSENSE_CORPUS_BUNDLE": "/path/to/frensense-corpus.frc"
      }
    }
  }
}
```

`FRENSENSE_CORPUS_BUNDLE` is optional and session-wide: point it at a
`.frc` bundle and every tool call merges its learned facts into the
built-in tables. `frensense_scan_file` and `frensense_diff` also accept a
per-call `corpus_bundle` argument, which overrides the environment value.

## The three tools

### `frensense_audit` — is this tree clean?

Directory-level audit. Best for "scan the whole project before you commit".

```json
{ "name": "frensense_audit",
  "arguments": { "path": "src", "severity_threshold": "warning" } }
```

Returns `{ "clean": bool, "advisories": [...] }` — `clean: true` means the
tree satisfies all invariants.

### `frensense_scan_file` — is THIS file clean?

Single-file scan for agent edit loops. Faster and fully scoped; the result
labels every advisory with file/line/column, plus top-level `stable_ids`.

```json
{ "name": "frensense_scan_file",
  "arguments": { "path": "src/pay.py" } }
```

Unsupported extensions (`.txt`, `.md`, …) return
`{ "unsupported_file": true, ... }` rather than an error — the agent can
skip them without exception handling. `path` on a missing file returns an
explicit error message; a nonexistent `corpus_bundle` does too.

### `frensense_diff` — does MY change introduce findings?

Scans a unified diff and reports **only findings whose line falls inside
the diff's added-line ranges**. Without `diff_text`, it runs
`git diff HEAD` in `repo` and also treats untracked files as all-added
(`git diff` alone never shows untracked files; a brand-new file is exactly
what a gate must not miss).

```json
{ "name": "frensense_diff", "arguments": { "repo": "." } }
```

or with an explicit patch (works outside any git repository):

```json
{ "name": "frensense_diff",
  "arguments": { "repo": "/work/project", "diff_text": "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -4,2 +5,3 @@\n def digest(data):\n+    return hashlib.md5(data).hexdigest()\n     pass\n" } }
```

The result carries the parsed `added_ranges` per file (so the agent can
see what was considered "the change"), `files_scanned`, `advisories`
filtered to added lines, and their `stable_ids`.

## End-to-end agent session

A realistic loop: agent edits a file → checks the diff → fixes → verifies
the fix by stable ID. The session below is real output from
v0.7.0-preview.1 against this change to `src/pay.py` in a git repo
(`hash_password` was holding an MD5 password hash and `find_user` built
SQL by concatenation; the agent rewrote both, but also added a new
`hash_token` helper that still uses MD5):

```diff
diff --git a/src/pay.py b/src/pay.py
--- a/src/pay.py
+++ b/src/pay.py
@@ -5,3 +5,3 @@ import sqlite3
 def hash_password(password: str) -> str:
-    return hashlib.md5(password).hexdigest()
+    return hashlib.sha256(password).hexdigest()

@@ -10,3 +10,7 @@ def find_user(conn: sqlite3.Connection, name: str) -> tuple:
     cur = conn.cursor()
-    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
+    cur.execute("SELECT * FROM users WHERE name = ?;", (name,))
     return cur.fetchone()
+
+
+def hash_token(token: str) -> str:
+    return hashlib.md5(token).hexdigest()
```

**1. Gate the change before committing:**

```json
→ {"jsonrpc":"2.0","id":3,"method":"tools/call",
   "params":{"name":"frensense_diff","arguments":{"repo":"/work/project"}}}
```

```json
← {"clean": false,
   "files_touched": 1, "files_scanned": 1,
   "added_ranges": [{"path": "src/pay.py",
                     "added_ranges": [{"start": 6,  "end": 6},
                                      {"start": 11, "end": 11},
                                      {"start": 13, "end": 16}]}],
   "stable_ids": ["FRN-a441e6e7b795@src/pay.py:16"],
   "advisories": [{ "file_path": "src/pay.py", "line": 16,
                    "title": "Policy violation: weak_hash (hash_token)",
                    "observation": "Weak hash function `md5` ...", ... }]}
```

Note what the gate did: the agent *removed* two findings (the md5 password
hash and the string-concatenated SQL) and *added* one. The diff tool
correctly reports only the added one — pre-existing findings elsewhere in
the file are invisible to this gate, which is exactly what "does my change
introduce findings?" means. `clean: false` with exactly one stable ID is
the signal to iterate.

**2. Fix the flagged function and re-gate:**

```json
→ {"jsonrpc":"2.0","id":4,"method":"tools/call",
   "params":{"name":"frensense_diff","arguments":{"repo":"/work/project"}}}
```

```json
← {"clean": true, "stable_ids": [],
   "message": "added lines introduce no findings", ...}
```

The change is clean. Compare IDs, not lines: `FRN-a441e6e7b795…` appearing
in step 1 and disappearing in step 2 is proof *that specific finding* was
fixed — the ID is stable across line shifts, so it survives unrelated
edits anywhere above the finding.

**3. Optional: focus on the single file** while iterating (faster than a
diff when the agent is only touching one buffer):

```json
→ {"jsonrpc":"2.0","id":5,"method":"tools/call",
   "params":{"name":"frensense_scan_file","arguments":{"path":"src/pay.py"}}}
```

```json
← {"clean": false,
   "file": "/work/project/src/pay.py",
   "stable_ids": ["FRN-a441e6e7b795@/work/project/src/pay.py:16"],
   "advisories": [{ "line": 16,
                    "title": "Policy violation: weak_hash (hash_token)", ... }]}
```

**4. Optional: whole-tree audit** before opening the PR:

```json
→ {"jsonrpc":"2.0","id":6,"method":"tools/call",
   "params":{"name":"frensense_audit","arguments":{"path":"src"}}}
```

## Protocol notes

- The server speaks the standard MCP lifecycle: `initialize` →
  `initialized` → tool calls; `shutdown`/`exit` to stop. `tools/list`
  always reflects the current tool set.
- Logs go to **stderr**; stdout is protocol-only. Never parse stderr.
- Advisory JSON is the same `Advisory` schema the CLI's `--json` emits
  (fingerprint, taint path steps, tags), so agent-side parsing code works
  for both surfaces.
- A scan failure on one file (syntax errors, unreadable) is reported per
  call as `"error": "..."` with `clean: false` — the agent can retry after
  fixing the file.

## Related

- `docs/LSP_USAGE.md` — the same engine inside your editor
- `docs/FRENSENSE_CORPUS_GUIDE.md` — building `.frc` bundles
- README: single-binary installation details
