# MCP server (AI agents)

Frensense ships an MCP server **inside the same `frensense` binary**. There is
no separate `frensense-mcp` package to install; if you have the CLI, you have
the server. Run it as a subcommand:

```bash
frensense mcp
```

The server speaks newline-delimited JSON-RPC over stdio, so it plugs straight
into any MCP client (Claude Desktop, Cursor, Claude Code, your own agent):

```json
{
  "mcpServers": {
    "frensense": {
      "command": "frensense",
      "args": ["mcp"]
    }
  }
}
```

## Tools

### `frensense_audit`

Directory audit. Supports the `FRENSENSE_CORPUS_BUNDLE` environment variable
so learned facts participate in agent scans.

### `frensense_scan_file`

Single-file scan designed for agent edit loops. Scan a file right after
writing it. Supports a `corpus_bundle` argument and reports tool-level
`unsupported_file` outcomes for file types the engine does not lower.

### `frensense_diff`

Scan a unified diff (patch text, or `git diff HEAD` plus untracked files) and
report only findings on added-line ranges. The result answers "does **my**
change introduce findings?" without re-auditing the whole tree.

All three tools accept `.frc` corpus bundles so learned facts participate in
MCP scans exactly as in CLI scans.
