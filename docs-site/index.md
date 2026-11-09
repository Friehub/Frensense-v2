---
layout: home

hero:
  name: "Frensense"
  text: "Code scanning that shows its work"
  tagline: "A deterministic static analyser that follows untrusted input through your code and reports each path from source to dangerous call. Open source, one binary, no network."
  actions:
    - theme: brand
      text: Get started
      link: /guide/
    - theme: alt
      text: Install
      link: /guide/installation
    - theme: alt
      text: GitHub
      link: https://github.com/Friehub/frensense-v2

features:
  - title: Exact taint paths
    details: Every finding comes with the path the data took, with file positions, so you can check it yourself. The same input always gives the same result.
  - title: Teachable engine
    details: Label a vulnerable example and its fixed twin, and the bundler learns the missing sources, sinks and sanitizers into a .frc bundle you can load.
  - title: Multi-language
    details: TypeScript, JavaScript, Python, Go, Rust and C, with early Vue support. Each language is a small tree-sitter provider on a shared engine.
  - title: Memory safety
    details: Use-after-free, double-free, out-of-bounds and leak checks, built on allocation summaries and value tracking.
  - title: Built for agents
    details: MCP and LSP servers are built into the same binary, so an AI agent or an editor can check code with the same engine. Read why in our essay.
    link: /blog/2026-10-09-static-analysis-in-the-age-of-frontier-ai
  - title: Open core
    details: The engine is GPL-3.0 free software. Knowledge bundles extend what it can detect, and commercial licences are available.
---

<DownloadStrip />
