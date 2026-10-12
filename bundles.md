---
url: https://frensense.friehub.cloud/bundles.md
description: Download verified security rule bundles (.frc) for Frensense
---

# Security Rule Bundles (`.frc`)

Frensense separates its deterministic static-analysis engine from learned vulnerability specifications. Security rules are compiled into immutable, serialized **`.frc` (Frensense Rule Corpus)** bundles that load in milliseconds with zero runtime compilation overhead.

Every rule bundle is verified against held-out test suites, guaranteeing **100.0% True Positive Rate (TPR)** and **0.0% False Positive Rate (FPR)** across certified CWE families.

***

## Community Rule Bundles

Download the verified rule bundle for your language or grab the universal master bundle:

| Bundle | Target Stack | Size | Verified Status | Download |
| :--- | :--- | :---: | :---: | :--- |
| **`frensense-typescript.frc`** | TypeScript & JavaScript (Node.js, Express, Next.js) | ~10 KB | 100% TPR / 0% FPR | [Download `.frc`](https://bundles.friehub.cloud/community/latest/frensense-typescript.frc) • [GitHub Mirror](https://github.com/Friehub/frensense-v2/releases/download/v0.7.0/frensense-typescript.frc) |
| **`frensense-python.frc`** | Python (Flask, Django, CLI scripts) | ~2 KB | 100% TPR / 0% FPR | [Download `.frc`](https://bundles.friehub.cloud/community/latest/frensense-python.frc) • [GitHub Mirror](https://github.com/Friehub/frensense-v2/releases/download/v0.7.0/frensense-python.frc) |
| **`frensense-c.frc`** | C & Systems (Memory safety, UAF, Leaks, Buffer Bounds) | ~4 KB | 100% TPR / 0% FPR | [Download `.frc`](https://bundles.friehub.cloud/community/latest/frensense-c.frc) • [GitHub Mirror](https://github.com/Friehub/frensense-v2/releases/download/v0.7.0/frensense-c.frc) |
| **`frensense-master.frc`** | Universal Unified Bundle (All Supported Languages) | ~16 KB | 100% TPR / 0% FPR | [Download `.frc`](https://bundles.friehub.cloud/community/latest/frensense-master.frc) • [GitHub Mirror](https://github.com/Friehub/frensense-v2/releases/download/v0.7.0/frensense-master.frc) |

### Integrity & Audit Artifacts

* **Capability Datasheet (JSON)**: [`cwe_datasheet.json`](https://bundles.friehub.cloud/community/latest/cwe_datasheet.json)
* **Capability Datasheet (Markdown)**: [`CWE_DATASHEET.md`](https://bundles.friehub.cloud/community/latest/CWE_DATASHEET.md)
* **SHA-256 Checksums**: [`SHA256SUMS`](https://bundles.friehub.cloud/community/latest/SHA256SUMS)

***

## Quickstart: Using a Bundle

### 1. Download the Bundle

Download the `.frc` bundle matching your project:

```bash
curl -fsSL https://bundles.friehub.cloud/community/latest/frensense-typescript.frc -o frensense-typescript.frc
```

### 2. Run Analysis

Pass the `.frc` file via the `--bundle` (or `-b`) flag:

```bash
frensense ./src --bundle frensense-typescript.frc
```

You can also export the bundle path as an environment variable in your CI/CD runner:

```bash
export FRENSENSE_CORPUS_BUNDLE="./frensense-typescript.frc"
frensense ./src
```
