# Installation

Frensense ships as **one binary** that does everything: scanning, watch mode,
the MCP server (`frensense mcp`), and the LSP server (`frensense lsp`). Pick
whichever install path matches your setup.

## Install from crates.io

The quickest path if you have Rust installed:

```bash
cargo install frensense
```

This compiles and installs the `frensense` binary into `~/.cargo/bin`.

## Install from npm

If you are a Node.js user, the npm package downloads the prebuilt binary for
your platform during install (no compiler needed):

```bash
npm install -g frensense
```

The npm launcher (`frensense`) wraps the native binary, so all commands work
identically to the direct binary.

## Prebuilt binaries

Release binaries for Linux x64, macOS (x64/arm64), and Windows x64 are
published on the
[GitHub releases](https://github.com/Friehub/frensense-v2/releases) page,
each with SLSA L3 provenance:

```bash
# example: linux x64
curl -LO https://github.com/Friehub/frensense-v2/releases/latest/download/frensense-linux-x64
chmod +x frensense-linux-x64
sudo mv frensense-linux-x64 /usr/local/bin/frensense
```

## Verify

```bash
frensense --version
frensense --help
```

`--help` lists every subcommand, including `watch`, `mcp`, and `lsp`.

## Build from source (contributors)

You only need this if you want to hack on the engine. A recent Rust
toolchain (1.95+) is required:

```bash
git clone https://github.com/Friehub/frensense-v2.git
cd frensense-v2
cargo build --release
```

The binary lands in `target/release/frensense`.
