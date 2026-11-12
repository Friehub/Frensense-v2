---
url: https://frensense.friehub.cloud/whats-new.md
description: A plain-language summary of what each Frensense version added.
---

# What's New in Frensense

A quick look at what changed in each release, written for everyone — no compiler knowledge required.

***

## 0.8.1 — Scan Progress

**You can now watch Frensense work.**

Before this release, running a scan showed the header and then went quiet until it finished. That silence made it hard to tell whether the scan was progressing or stuck.

Starting with 0.8.1:

* **In your terminal**, a live progress bar updates as each file is processed. It shows the current phase (lowering files, then analyzing the program), how many files have been scanned out of the total, any errors encountered, and how much memory is in use.
* **In CI or when piping output**, clean log lines appear at regular milestones so your pipeline logs stay readable without any special terminal codes.
* **In machine-output modes** (`--json`, `--sarif`), nothing changes — structured output goes to stdout untouched; progress goes to stderr.
* Use `--no-progress` to suppress all progress output if you prefer silence.

The scan summary at the end also now shows **Peak Memory (RSS)** and a **Files Scanned** count.

***

## 0.8.0 — Package-Aware Scanning and AI Agents

**Fewer false positives. Built-in AI agent support.**

Frensense 0.8.0 was a major release focused on accuracy and integration:

* **Package-scoped facts** — rules now understand which library a call belongs to, so a `.query()` on a harmless UI library no longer triggers the same finding as one on a database driver.
* **MCP server** — Frensense ships a built-in Model Context Protocol server so AI coding agents can run security scans directly without shell commands.
* **Diff-only mode** — scan only the files changed in a pull request, not the whole codebase.
* **Baseline suppression** — accept known findings and only alert on new ones.
* **Hidden source directory scanning** — `.vitepress` and similar dot-prefixed source trees are now scanned alongside regular source files.

***

## 0.7.0 — Compiler-Mode Engine

**Exact taint paths across functions and files.**

Frensense 0.7.0 rewrote the engine to treat code like a compiler does:

* Every file is lowered to a program graph (IR + SSA form) before analysis.
* Findings include the full source-to-sink path, not just a flagged line.
* Language knowledge (sinks, sanitizers, guards) is separated from the engine and stored in teachable `.frc` bundles.
* Initial language support: TypeScript, JavaScript, Python, Go, Rust, and C.
