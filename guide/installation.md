---
url: https://frensense.friehub.cloud/guide/installation.md
description: Install the frensense binary with Cargo, npm, or a release download.
---

# Install

Frensense is one binary named `frensense`. Pick the route that fits your
machine, then run `frensense --version` to check it worked.

| Route | Needs | Command |
| --- | --- | --- |
| npm | Node.js 18 or newer | `npm install -g @friehub/frensense` |
| No install | Node.js 18 or newer | `npx @friehub/frensense .` |
| Cargo | Rust 1.95 or newer | `cargo install frensense` |
| Release download | nothing | see below |

## npm

The npm package carries prebuilt binaries, so you do not need a Rust
compiler. It supports Linux x64, macOS (Intel and Apple Silicon) and Windows
x64.

```bash
npm install -g @friehub/frensense
frensense --version
```

The `frensense` command from npm is a small launcher around the native
binary. Every subcommand (`watch`, `mcp`, `lsp`, ...) works the same way.

## Cargo

```bash
cargo install frensense
```

This compiles the binary and puts it in `~/.cargo/bin`. It needs Rust 1.95 or
newer, and takes a few minutes.

## Release download

Each [GitHub release](https://github.com/Friehub/frensense-v2/releases)
attaches one binary per platform, named after its Rust target:

| Platform | File |
| --- | --- |
| Linux x64 | `frensense-x86_64-unknown-linux-gnu` |
| macOS Intel | `frensense-x86_64-apple-darwin` |
| macOS Apple Silicon | `frensense-aarch64-apple-darwin` |
| Windows x64 | `frensense-x86_64-pc-windows-msvc.exe` |

There is no Linux arm64 build yet. On Linux x64:

```bash
curl -L -o frensense \
  https://github.com/Friehub/frensense-v2/releases/latest/download/frensense-x86_64-unknown-linux-gnu
chmod +x frensense
sudo mv frensense /usr/local/bin/
```

Releases are built by a GitHub Actions workflow that also produces a SLSA
provenance file (`*.intoto.jsonl`) for the binaries. You can check a download
against it with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier).

## Check the install

```bash
frensense --version     # prints: frensense 0.8.0
frensense --help        # lists every flag and subcommand
```

If a scan ends with `Status: Failed analysis` and a warning about
"unsupported or absent source input", the folder holds no
[supported files](/guide/#what-it-scans). Try it inside a project that has a
`.py`, `.ts`, `.js`, `.go`, `.rs` or `.c` file.

## Build from source

Only needed if you want to change the engine:

```bash
git clone https://github.com/Friehub/frensense-v2.git
cd frensense-v2
cargo build --release
```

The binary is `target/release/frensense`. See
[CONTRIBUTING.md](https://github.com/Friehub/frensense-v2/blob/main/CONTRIBUTING.md)
before opening a pull request.

## Next

[Run your first scan](/guide/first-scan).
