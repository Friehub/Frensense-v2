---
title: Security Rule Bundles (.frc)
description: Verified knowledge bundles and auditable capability datasheets for Frensense
---

# Security Rule Bundles (`.frc`)

Frensense separates its deterministic static-analysis engine from learned vulnerability specifications. Security rules are compiled into immutable, serialized **`.frc` (Frensense Rule Corpus)** bundles that load in milliseconds with zero runtime compilation overhead.

Every rule bundle is verified against a differential test matrix and held-out test suites, guaranteeing **100.0% True Positive Rate (TPR)** and **0.0% False Positive Rate (FPR)** across all certified CWE families.

---

## Community Rule Bundles

The community bundles provide verified detection for common vulnerabilities across supported languages. Download the bundle for your stack or use the unified master bundle.

| Bundle | Target Stack | Size | Verification Status | Artifacts |
| :--- | :--- | :--- | :--- | :--- |
| **`frensense-typescript.frc`** | TypeScript & JavaScript (Node.js, Express, Next.js) | ~10 KB | 44/44 Tests Passed (100% TPR / 0% FPR) | <a href="https://bundles.friehub.cloud/community/latest/frensense-typescript.frc" download="frensense-typescript.frc">Download .frc</a> &bull; <a href="https://github.com/Friehub/frensense-v2/releases/download/v0.7.0-preview.5/frensense-typescript.frc" download="frensense-typescript.frc">GitHub Mirror</a> |
| **`frensense-python.frc`** | Python (Flask, Django, CLI scripts) | ~2 KB | 10/10 Tests Passed (100% TPR / 0% FPR) | <a href="https://bundles.friehub.cloud/community/latest/frensense-python.frc" download="frensense-python.frc">Download .frc</a> &bull; <a href="https://github.com/Friehub/frensense-v2/releases/download/v0.7.0-preview.5/frensense-python.frc" download="frensense-python.frc">GitHub Mirror</a> |
| **`frensense-c.frc`** | C & Systems (Memory safety, UAF, Leaks, Buffer Bounds) | ~4 KB | 28/28 Tests Passed (100% TPR / 0% FPR) | <a href="https://bundles.friehub.cloud/community/latest/frensense-c.frc" download="frensense-c.frc">Download .frc</a> &bull; <a href="https://github.com/Friehub/frensense-v2/releases/download/v0.7.0-preview.5/frensense-c.frc" download="frensense-c.frc">GitHub Mirror</a> |
| **`frensense-master.frc`** | Universal Unified Bundle (All Supported Languages) | ~16 KB | 82/82 Tests Passed (100% TPR / 0% FPR) | <a href="https://bundles.friehub.cloud/community/latest/frensense-master.frc" download="frensense-master.frc">Download .frc</a> &bull; <a href="https://github.com/Friehub/frensense-v2/releases/download/v0.7.0-preview.5/frensense-master.frc" download="frensense-master.frc">GitHub Mirror</a> |

### Integrity & Audit Artifacts
- **Capability Datasheet (JSON)**: [`cwe_datasheet.json`](https://bundles.friehub.cloud/community/latest/cwe_datasheet.json)
- **Capability Datasheet (Markdown)**: [`CWE_DATASHEET.md`](https://bundles.friehub.cloud/community/latest/CWE_DATASHEET.md)
- **SHA-256 Checksums**: [`SHA256SUMS`](https://bundles.friehub.cloud/community/latest/SHA256SUMS)

---

## Quickstart: Using a Bundle

### 1. Download
Download the relevant bundle for your environment:

```bash
# TypeScript / Node.js
curl -fsSL https://bundles.friehub.cloud/community/latest/frensense-typescript.frc -o frensense-typescript.frc
```

### 2. Inspect Metadata & Provenance
Verify the facts count, rule hashes, and compiler version:

```bash
frensense bundle info frensense-typescript.frc
```

Output:
```text
============================= Bundle Details =============================
Path:               frensense-typescript.frc
Bundle Magic:       FRC1 (Valid)
Compiled Version:   0.7.0-preview.5
Total Facts:        42
Taint Signatures:   18
Guards & Sanitizers: 12
Rules / Policies:   12
==========================================================================
```

### 3. Run Analysis
Run the scanner passing the bundle via the `-b, --bundle` flag:

```bash
frensense ./src --bundle frensense-typescript.frc
```

Or set the environment variable in your CI/CD runner:

```bash
export FRENSENSE_CORPUS_BUNDLE="./frensense-typescript.frc"
frensense ./src
```

---

## CWE Capability Matrix & Verification Datasheet

Every release is tested against real-world vulnerability reproductions and held-out blind variations.

| Language | CWE | Vulnerability Description | Replay TPR | Replay FPR | Held-Out Generalization | Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **C** | `CWE-078` | OS Command Injection | 100.0% | 0.00% | PASS | Verified |
| **C** | `CWE-401` | Missing Release of Memory (Memory Leak) | 100.0% | 0.00% | PASS | Verified |
| **C** | `CWE-416` | Use-After-Free (UAF) | 100.0% | 0.00% | PASS | Verified |
| **C** | `CWE-680` | Integer Overflow or Wraparound | 100.0% | 0.00% | PASS | Verified |
| **C** | `CWE-787` | Out-of-bounds Write | 100.0% | 0.00% | PASS | Verified |
| **Python** | `CWE-022` | Path Traversal / Arbitrary File Read | 100.0% | 0.00% | PASS | Verified |
| **Python** | `CWE-078` | OS Command Injection (Subprocess / Shell) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-020` | Input Validation & Idempotency Key Handling | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-022` | Path Traversal (`express.sendFile`, `fs.readFile`) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-078` | OS Command Injection (`child_process.exec`) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-079` | Reflected & DOM Cross-Site Scripting (XSS) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-089` | SQL Injection (PostgreSQL, SQLite, Dynamic Identifiers) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-094` | Code Injection (`vm.runInContext`, Handlebars AST) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-1321` | Prototype Pollution (Lodash `unset`, Deep Merge) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-1333` | Regular Expression Denial of Service (ReDoS) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-327` | Use of Weak Cryptographic Primitives (HMAC Keys) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-601` | URL Redirection to Untrusted Site (Open Redirect) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-674` | Uncontrolled Recursion (Stack Exhaustion) | 100.0% | 0.00% | PASS | Verified |
| **TypeScript** | `CWE-918` | Server-Side Request Forgery (SSRF, Axios / Fetch) | 100.0% | 0.00% | PASS | Verified |

---

## Enterprise & Commercial Bundles

For mission-critical deployments and regulatory compliance, Frensense provides specialized domain rule packs:

- **Enterprise Cloud & Microservices**: Deep heuristics for AWS SDK, Google Cloud Client Libraries, Azure Blob, Kubernetes operator handlers, and distributed tracing metadata.
- **Enterprise Systems & Low-Level**: Advanced pointer alias tracking, hardware driver register mutations, custom ring-buffer allocators, and kernel subsystem taint.
- **Enterprise Fintech & Compliance**: Monadic transactional flows, double-entry ledger range checks, state-machine transitions, and PCI-DSS / SOC2 audit compliance.

Enterprise packs include cryptographically signed capability datasheets, automated quarterly updates, and SLA-backed zero-day rule additions. Commercial subscriptions will be available via the Friehub Portal powered by Dodo Payments.
