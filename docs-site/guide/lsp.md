# LSP server (editors)

Frensense ships an LSP server **inside the same `frensense` binary**. There is
no separate `frensense-lsp` package to install. Run it as a subcommand:

```bash
frensense lsp
```

It publishes diagnostics on `textDocument/didOpen` and `textDocument/didSave`
for Python, JavaScript/TypeScript, Rust, and Go files.

- Diagnostics carry **0-based ranges**, the stable finding ID in `code`, and
  the taint observation in `message`.
- Zero extra dependencies: the server hand-rolls `Content-Length` framing.
- The engine stays the single source of truth: the server scans the saved
  file on disk through the same per-file path as watch mode and MCP.

Set `FRENSENSE_CORPUS_BUNDLE` to make learned `.frc` facts participate in
editor diagnostics.

## Editor setup

Most editors let you register a custom language server. The command is
always `frensense lsp`:

```json
{
  "languageserver": {
    "frensense": {
      "command": "frensense",
      "args": ["lsp"],
      "filetypes": ["python", "javascript", "typescript", "go", "rust"]
    }
  }
}
```

Or zero-install via `npx` (Node.js users):

```json
{
  "languageserver": {
    "frensense": {
      "command": "npx",
      "args": ["-y", "@friehub/frensense", "lsp"],
      "filetypes": ["python", "javascript", "typescript", "go", "rust"]
    }
  }
}
```

For Neovim (nvim-lspconfig):

```lua
require'lspconfig'.configure('frensense', {
  cmd = { 'frensense', 'lsp' },
  filetypes = { 'python', 'javascript', 'typescript', 'go', 'rust' },
})
```
