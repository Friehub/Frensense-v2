---
title: What's New
description: A plain-language summary of what each Frensense version added.
---

# What's New in Frensense

A quick look at what changed in each release, written for everyone (no compiler knowledge required).

---

## 0.9.1 - Sanitizers That Know What They Sanitize

**A sanitizer now only clears the kind of risk it was actually proven to handle, so "sanitized" can no longer hide a different bug.**

A sanitizer is code that makes a value safe — a SQL escaper, a URL validator, an allow-list checker. Until now, a sanitizer that showed up anywhere on a value's path counted as safe for *every* kind of sink. A helper written to stop SQL injection could therefore silence a command-injection warning about the same value. This release ties each sanitizer to the vulnerability classes it was proven to defeat.

- **One sanitizer, one kind of risk.** A fact learned as "this makes SQL safe" clears SQL findings only; a URL check no longer validates a shell command, and an allow-list guard no longer covers an unrelated sink reached on the same branch. Under the hood each fact carries the class it was proven for and the engine matches the sink's class against it.
- **Bundles say how much they should be trusted.** A bundle is now `certified`, `community` or `custom`. A custom bundle may add sinks, sources and policies but never sanitizers. A community bundle may ship a sanitizer only when it names both the class it defeats and the package it belongs to. Anything weaker is filtered out at load, so a thinly-evidenced community bundle cannot silence your findings.
- **Policies can be retired without breaking anyone.** A bundle can mark a rule `deprecated` — it still fires, but is announced as deprecated and kept out of the default report — or `removed`, which drops it entirely. No more silently deleting a rule id that a pinned bundle still refers to.
- **New ways to see and steer what is hidden.** `--show-suppressed` names the bundle sanitizer that silenced an argument and the classes it was proven for; `--disable-rule` and `--only` (also `[rules]` in `.frensense.toml`) choose which rules a run reports; `--config` points the run at a specific config file.
- **Nothing to migrate.** Existing bundles keep loading with the old, unscoped reading of their sanitizers. Rebuild one as a v8 bundle and its sanitizers gain the class scope.

---

## 0.9.0 - Explainable Scans and Sharper Sinks

**A scan now shows its work at every stage, and more dangerous operations are recognized.**

Frensense has always been able to say "clean" or "vulnerable"; 0.9.0 makes it easier to see *why* it reached that answer, and closes a set of gaps where a real sink was never matched.

- **The summary accounts for every stage.** The scan summary now has one line per phase — parse and lower, graph, checks, taint, report — showing what each phase consumed and produced. A stage that read nothing or took too long is visible without a flag. The graph line counts the value-flow nodes and edges the taint phase walked, and the taint line follows the calls (`1,889 call(s) -> 17 sink call(s) -> 23 argument(s) walked`). The same numbers are in the JSON report under `analysis.graph` and `analysis.funnel`.
- **`--explain` names the calls it flowed through.** When a backward walk crosses a library call the engine has no model for, it now prints `flowed through: callee` instead of hiding that assumption in the stop sites. The explanation also prints the pipeline behind the taint line — call sites skipped and why, calls that matched no sink, sinks armed, and findings each reporting-gate reason dropped — plus the busiest callees that matched no sink, so a large `not_a_sink` points at vocabulary you can teach rather than only a number. `--explain-json` gains an `arg` field, and a method receiver now reads as `receiver` instead of a slot number.
- **More sinks and sources are recognized.** Property assignments (`el.innerHTML = user`, `el.outerHTML`) and JSX attributes such as `dangerouslySetInnerHTML` now report, and the finding points at the write itself. Destructured, rest and nested parameters, destructuring assignments, and Go parameters are bound so their values reach the sink. Quoted subscripts (`cmds['a']`) resolve to the same field as `cmds.a`, library objects that accumulate state (`ConfigParser`, `StringIO`) keep what was stored into them, inline delimiter escapes (`value.replace("'", "&apos;")`) act as sanitizers for the sinks they protect, and multi-hop barrel re-exports resolve deeper. Measured on the OWASP Python suite, the score moved from **0.339 to 0.392** (false positives 32 → 20).
- **"Clean" means the scan decided.** When findings are suppressed or fall below the confidence threshold, the report now says `Status: No findings (N dropped below confidence threshold)` and sets `clean: false`, instead of reporting a clean scan. Unsupported files in a mixed-language tree no longer mark an otherwise complete scan as partial.
- **Severity is one vocabulary everywhere.** The CLI `--severity` flag and the MCP `severity_threshold` now accept the same six labels — `critical`, `high`, `medium`, `warning`, `low`, `info` — and reject anything else before scanning. A severity authored in a corpus family or bundle now reaches the report instead of being overridden by the rule registry's default.
- **The default pack knows more frameworks.** The shipped vocabulary now includes package-scoped facts for Next.js (`next/server`, `next/navigation`, `next/headers`, `next/cache`), Vue 3 and Pinia, NestJS (TypeORM and Mongoose), and Nuxt 3 / Nitro / ofetch.
- **Truncation is no longer silent.** Safety caps that stop a use-after-free walk, a callee scan, or an SSA budget now record themselves in `truncations`, so an incomplete analysis cannot look clean. `FRENSdbg_CAPS` prints each cap firing during a debug run.

---

## 0.8.2 - Honest Coverage

**"Clean" never means "not analyzed": Frensense no longer reports clean when it couldn't scan a codebase.**

Every scanner has two silent failures: it can find nothing because the code is safe, or because it never looked. Frensense used to print the same words ("Status: Clean", "Analysis Complete: No findings.") for both. On the OWASP Benchmark for Python, that meant calling a 1,230-file tree complete while 622 files contained nothing the engine models and 19 dangerous calls were left undecided.

Starting with 0.8.2, a scan has to show its work:

- **The summary shows the real ratio.** `Files Scanned: 20/400` counts every source file the scan found, including files in languages Frensense cannot read (Ruby, PHP, Java and the rest). A second line names how many were skipped and why, and `Sink Sites` / `Not Recognized` / `Undecided` say how many dangerous operations were actually inspected and how many the analysis could not resolve. `Status: Clean` is reserved for a scan that read everything it found and decided every site; otherwise the status says which part is missing.
- **`--explain` lists the files you did not get.** Alongside the existing "why the engine stayed quiet" records, it prints every unsupported language, the files that failed to parse, the files where nothing was recognized, and the exact sink sites that ended undecided.
- **AI agents get the same answer.** The MCP tools (`frensense_scan_file`, `frensense_audit`, `frensense_diff`) now return an `analysis` block with the coverage numbers, and `clean: true` means "reported nothing, read every file, and decided every site it recognized", not just "reported nothing". An agent that edits code and gates on `clean` is told when a file was never analyzed.
- **CI sees it too.** SARIF reports add coverage fields and a warning notification when files were not analyzed, so a pipeline cannot read a green result for a tree that was only partly scanned.
- **JSON reports gain a few fields** (`analysis.clean`, and `files_found` / `files_not_analyzed` / `files_unsupported` under `analysis.coverage`). Nothing existing was renamed or removed.

This is a reporting change only: the analysis engine is untouched, and every count comes from verdicts the scan already produced.

---

## 0.8.1 - Scan Progress

**You can now watch Frensense work.**

Before this release, running a scan showed the header and then went quiet until it finished. That silence made it hard to tell whether the scan was progressing or stuck.

Starting with 0.8.1:

- **In your terminal**, a live progress bar updates as each file is processed. It shows the current phase (lowering files, then analyzing the program), how many files have been scanned out of the total, any errors encountered, and how much memory is in use.
- **In CI or when piping output**, clean log lines appear at regular milestones so your pipeline logs stay readable without any special terminal codes.
- **In machine-output modes** (`--json`, `--sarif`), nothing changes: structured output goes to stdout untouched; progress goes to stderr.
- Use `--no-progress` to suppress all progress output if you prefer silence.

The scan summary at the end also now shows **Peak Memory (RSS)** and a **Files Scanned** count.

---

## 0.8.0 - Package-Aware Scanning and AI Agents

**Fewer false positives. Built-in AI agent support.**

Frensense 0.8.0 was a major release focused on accuracy and integration:

- **Package-scoped facts**: rules now understand which library a call belongs to, so a `.query()` on a harmless UI library no longer triggers the same finding as one on a database driver.
- **MCP server**: Frensense ships a built-in Model Context Protocol server so AI coding agents can run security scans directly without shell commands.
- **Diff-only mode**: scan only the files changed in a pull request, not the whole codebase.
- **Baseline suppression**: accept known findings and only alert on new ones.
- **Hidden source directory scanning**: `.vitepress` and similar dot-prefixed source trees are now scanned alongside regular source files.

---

## 0.7.0 - Compiler-Mode Engine

**Exact taint paths across functions and files.**

Frensense 0.7.0 rewrote the engine to treat code like a compiler does:

- Every file is lowered to a program graph (IR + SSA form) before analysis.
- Findings include the full source-to-sink path, not just a flagged line.
- Language knowledge (sinks, sanitizers, guards) is separated from the engine and stored in teachable `.frc` bundles.
- Initial language support: TypeScript, JavaScript, Python, Go, Rust, and C.
