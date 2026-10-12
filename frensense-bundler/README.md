# frensense-bundler

Compiles paired vulnerability corpus families into `.frc` knowledge bundles consumed by the Frensense engine, CLI, and MCP server.

---

## Overview

Frensense is corpus-driven rather than rule-scripted. Security knowledge is expressed as paired source-file fixtures - a vulnerable variant and its safe counterpart - which the bundler compiles into a binary `.frc` bundle. The engine loads these bundles at scan time to detect the modelled vulnerability class across real codebases.

```sh
frensense bundle <corpus-dir> <output.frc>
```

---

## Corpus Directory & File Structure

Families are organized hierarchically by language and CWE taxonomy:

```text
my-corpus/
├── c/
│   └── cwe_416_uaf/
│       ├── c_cve_2026_56109_alsa_positive.c
│       ├── c_cve_2026_56109_alsa_negative.c
│       ├── c_cve_2026_56109_alsa_heldout_positive.c
│       └── c_cve_2026_56109_alsa_heldout_negative.c
├── python/
│   └── cwe_022_traversal/
│       ├── py_file_traversal_positive.py
│       └── py_file_traversal_negative.py
├── typescript/
│   └── cwe_089_sqli/
│       ├── ts_pg_sqli_positive.ts
│       └── ts_pg_sqli_negative.ts
└── dist/
    └── my-corpus.frc
```

### File Naming

| Convention | Meaning |
|:---|:---|
| `*_positive.<ext>` | Primary vulnerable variant |
| `*_negative.<ext>` | Primary safe/remediated variant |
| `*_positive2.<ext>`, `*_negative2.<ext>` | Additional training variants (multi-path evidence) |
| `*_heldout_positive.<ext>` | Blind validation variant - excluded from bundle compilation |
| `*_heldout_negative.<ext>` | Blind validation variant - excluded from bundle compilation |

**Language prefixes** are required on file stems: `c_`, `py_`, `ts_`, `rs_`, `go_`. Mixing languages under the same stem causes bundle collisions.

**Held-out files** (`_heldout_`) are skipped during fact extraction. They are used by the replay runner to verify that the compiled bundle generalizes beyond the training fixtures rather than memorizing file-specific AST structure.

---

## Metadata Block (`[frensense]`)

Every positive variant must begin with a structured `[frensense]` metadata comment block within the first 30 lines. This is parsed by the bundler and embedded in the `.frc` bundle as a `BundlePattern` surfaced to end users in CLI, LSP, and MCP outputs.

```typescript
// [frensense]
// observation: User-controlled target URL passed directly to fetch without host verification
// impact: SSRF allows internal network scanning and cloud metadata exfiltration
// improvement: Validate target hostname against an allowlist before dispatching fetch
// cwe: CWE-918
// cvss: 8.6
// owasp: A10:2021
// severity: High
```

### Fields

| Key | Type | Required | Description |
|:---|:---|:---:|:---|
| `observation` | String | Yes | Precise technical summary of the unmitigated condition |
| `impact` | String | Yes | Realistic security consequence if exploited in production |
| `improvement` | String | Yes | Actionable, prescriptive remediation guidance |
| `cwe` | String | Yes | Standard identifier (e.g. `CWE-89`, `CWE-918`, `CWE-79`) |
| `cvss` | Float | Yes | Base score between `0.0` and `10.0` |
| `owasp` | String | Recommended | OWASP Top 10 category (e.g. `A01:2021`, `A03:2021`) |
| `severity` | Enum | Yes | `Critical`, `High`, `Warning`, or `Info` |
| `package` | String | Recommended | Framework package provenance - see [Framework Provenance Scoping](#framework-provenance-scoping-package) |

### Formatting Constraints

- **Comment syntax**: Python uses `#`; C, TypeScript, Rust, and Go use `//`.
- **Block termination**: The block ends at the first blank line or code line.
- **Negative files**: Must NOT contain a `[frensense]` block. Begin with a single descriptive comment:
  ```typescript
  // SAFE: target hostname is validated against an allowed host list before calling fetch
  ```

---

## Framework Provenance Scoping (`package:`)

For framework-specific or third-party library rules, declare the framework package in the metadata block:

```typescript
// [frensense]
// observation: User-controlled file parameter passed to res.sendFile without directory boundary check
// package: express
```

- **Format v6+ feature**: Qualified facts carry `package: Option<String>` in `.frc` bundles.
- **Engine scoping**: The engine binds sinks, sanitizers, and policies to files that explicitly import or declare the specified package. Calls to matching method names in other frameworks (e.g. Next.js, Electron, Hono) remain unaffected.
- **Blast-radius quarantine**: A candidate fact carrying a `package` field may only be published into the bundle if the voting family actually imports or declares that package.

Common values: `express`, `next`, `hono`, `fastify`, `sequelize`, `typeorm`, `jspdf`, `multer`.

---

## Quality Contract

For a corpus family to compile into a published bundle, the bundler enforces:

- **True Positive Rate = 100%** on all declared positive variants.
- **False Positive Rate = 0%** on all declared negative variants.

A family that fails either condition is rejected and blocked from bundle compilation. CI runs the replay gate on every push.

---

## License

GPL-3.0-only - see [LICENSE](../LICENSE).
