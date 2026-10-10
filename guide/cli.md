---
url: https://frensense.friehub.cloud/guide/cli.md
---
# CLI reference

The `frensense` binary is the single entry point for the engine.

## Commands

| Command | Description |
| --- | --- |
| `frensense [path]` | Scan a file or directory and print findings. |
| `frensense watch [path]` | Watch mode: re-scan changed files, print only new findings. |
| `frensense mcp` | Run the MCP server (stdio, newline-delimited JSON-RPC) for AI agents. |
| `frensense lsp` | Run the LSP server (stdio, Content-Length framing) for editors. |

One binary carries all of this; there is no separate MCP or LSP package.

## Options

| Flag | Description |
| --- | --- |
| `--github` | Emit GitHub Actions workflow commands (`::error`/`::warning`) per finding. |
| `--corpus-bundle <file>` | Load a `.frc` knowledge bundle into the engine for this scan. |
| `--emit-baseline <file>` | Write the current finding fingerprints as a baseline. |
| `--compare-baseline <file>` | Only report findings that are new relative to the baseline. |
| `--language <lang>` | Restrict scanning to one language (`rust`, `typescript`, `javascript`, `python`). |
| severity / confidence filters | Limit output to findings above a threshold. |

## Environment variables

| Variable | Description |
| --- | --- |
| `FRENSENSE_CORPUS_BUNDLE` | Default `.frc` bundle for MCP/LSP scans. |
