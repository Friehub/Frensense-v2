---
url: https://frensense.friehub.cloud/corpus/authoring.md
---

# Corpus authoring guide

> How to teach Frensense new vulnerabilities. Frensense is **corpus-based, not
> rule-based**: there is no rule language to learn and no YAML to write. You
> provide a vulnerable example and its remediated counterpart, and the
> bundler verifies and distills the difference into a portable `.frc` bundle.

## 1. The mental model

A Frensense **family** represents one vulnerability concept, expressed as a pair of files:

* `<family>_positive.<ext>`: the vulnerable version
* `<family>_negative.<ext>`: the fixed / safe version

The bundler lowers both through the same engine that the scanner uses, computes the semantic delta (e.g., what call the negative avoids, what guard or sanitizing transform it adds), and proposes a *fact*. Every proposed fact then passes a **replay gate**: the fact is only published if, after installing it, the positive alerts, the negative stays silent, and no other family that already separated at baseline regresses. If a fact cannot prove itself against your corpus, it is never published. That provides built-in quality control without manual rule linting.

Facts ship inside an `.frc` bundle (binary, versioned, checksummed). The engine merges bundle facts **over** its built-in tables, bundle knowledge always wins on collision, and coarse all-args facts never widen precise slot-restricted ones.

Supported languages: `ts`, `tsx`, `js`, `jsx`, `py`, `go`, `rs`, `c`.

## 2. Quick start (5 minutes)

Build a family, compile the bundle, and scan with it:

```bash
mkdir -p mycorpus/ts_sqli
cat > mycorpus/ts_sqli/ts_sqli_positive.ts <<'EOF'
// [frensense]
// observation: User id concatenated into SQL query string
// impact: Attacker can read or modify arbitrary database rows
// improvement: Use parameterized query binding ($1)
// cwe: CWE-89
// severity: Critical

import { Pool } from "pg";
const pool = new Pool();
export async function getUser(req: any) {
  const id = req.body.id;
  return pool.query("SELECT * FROM users WHERE id = " + id);
}
EOF

cat > mycorpus/ts_sqli/ts_sqli_negative.ts <<'EOF'
// SAFE: parameterized query keeps user data out of the SQL string.
import { Pool } from "pg";
const pool = new Pool();
export async function getUser(req: any) {
  const id = req.body.id;
  return pool.query("SELECT * FROM users WHERE id = $1", [id]);
}
EOF

# Build the bundle (using the frensense CLI or frensense-bundler)
frensense bundle mycorpus my.frc
# [facts] 1 families grouped from mycorpus
# [facts] round-trip OK: 1 learned facts in bundle
#   [provisional] sanitizer:... <- ts_sqli

# Scan a target project with the learned bundle
frensense path/to/target --corpus-bundle my.frc
```

You can also drop the bundle into your project root as `frensense-corpus.frc`; it is picked up automatically. The MCP server and LSP pick it up via the `FRENSENSE_CORPUS_BUNDLE` environment variable.

## 3. Naming and layout rules

* **Family ID**: Filename stem before `_positive` / `_negative`.\
  `ts_sqli_positive.ts` -> family `ts_sqli`.
* **Language Prefixes**: Always prefix stems with the language (`c_`, `py_`, `ts_`, `rs_`, `go_`). Mixing languages under the same stem collides during grouping.
* **Multiple Variants**: You can add multiple positive and negative variants to strengthen the gate (`ts_sqli_negative.ts`, `ts_sqli_negative2.ts`).
* **Held-Out Blinding Variants (`_heldout_`)**:\
  To verify generalization without training memorization, add blind check pairs:
  ```text
  ts_sqli_heldout_positive.ts
  ts_sqli_heldout_negative.ts
  ```
  The bundler explicitly skips any file with `_heldout` during fact extraction, allowing your test runner to verify detection against unseen variants.
* **Directory Layout**: Directories are free-form metadata (`<lang>/<cwe>/<family>/`). Moving a family between directories does not alter its learned facts.

## 4. The `[frensense]` metadata block

The positive file may open with a structured comment block in the first 30 lines. This text is baked directly into the `.frc` bundle and displayed across all scanner interfaces (CLI, MCP, LSP):

```typescript
// [frensense]
// observation: User id concatenated into SQL query string
// impact: Attacker can read or modify arbitrary database rows
// improvement: Use parameterized query binding ($1)
// cwe: CWE-89
// cvss: 9.1
// owasp: A03:2021
// severity: Critical
```

* **Comment Prefixes**: Python uses `#`; C, TypeScript, Rust, and Go use `//`.
* **Fields**:
  * `observation`: Specific description of the vulnerability pattern.
  * `impact`: Technical consequence if exploited.
  * `improvement`: Recommended remediation guidance.
  * `cwe`: Standard identifier (e.g. `CWE-89`, `CWE-918`).
  * `cvss`: Float score (0.0 to 10.0).
  * `owasp`: OWASP Top 10 category (e.g. `A03:2021`).
  * `severity`: `Critical`, `High`, `Warning`, or `Info`.
* **Negative Files**: Negative files must **not** carry the `[frensense]` block. Open negative files with:
  ```typescript
  // SAFE: <explanation of why this variant is secure>
  ```

## 5. What each family shape teaches

### 5.1 Dataflow taint families (sinks & sanitizers)

Default shape: no special annotation needed.

* **Sanitizers**: If the negative contains a function that sanitizes or validates input before the sink, the bundler extracts a sanitizer fact:
  * *Predicate guards (`allowlist`)*: Functions returning booleans feeding branch conditions (`if (!isValid(x)) return`).
  * *Transforms (`encode`)*: Functions that encode or transform values (`x = sanitize(x)`).
* **Sinks**: If the positive calls an un-modeled sensitive function that does not alert under built-in tables, the bundler proposes the call as a new sink.

#### Avoid reserved collection & utility names

The bundler filters common utility and accessor calls to avoid noise. The following names are **never** proposed as sanitizers or sinks:

```text
get, set, has, then, catch, finally, toString, valueOf, push,
pop, map, filter, reduce, forEach, join, split, len, length,
keys, values, entries, stringify, parse
```

Always use descriptive names like `isValid()`, `isAllowed()`, or `cleanInput()`.

### 5.2 Policy families (`check-call:`)

Used when the flaw is not data flowing into a sink, but rather an unmitigated action executed without required authorization or checks:

1. Add `// check-call: <trigger>` (or `# check-call:`) in the first 30 lines of the positive variant.
2. In the positive variant, invoke the trigger without protection.
3. In the negative variant, invoke the trigger guarded by a validation helper (`if (isAuthorized())`) or numeric range comparison.

```typescript
// ts_priv_positive.ts
// check-call: deleteAccount
export function handle(req: any) {
  deleteAccount(req.body.userId); // Unguarded call -> alerts
}

// ts_priv_negative.ts
// SAFE: guarded by permission check
function hasAdminRole(): boolean { return true; }
export function handle(req: any) {
  if (hasAdminRole()) {
    deleteAccount(req.body.userId); // Guarded -> clean
  }
}
```

The resulting bundle learns `check:policy_deleteAccount(deleteAccount, guard=Some("hasAdminRole"))`.

### 5.3 Integer overflow rules (`check-rule:`)

For systems languages (C/C++), integer overflow prover rules can be declared via metadata:

```c
// [frensense]
// check-rule: integer_overflow_alloc
// wrap-max: 18446744073709551615
// observation: Integer multiplication in allocation size wraps on 64-bit platforms
// severity: Critical
```

This registers an allocation size overflow check in the prover table.

## 6. Statuses: `provisional` vs `confirmed`

When compiling a bundle, the bundler outputs a status for each learned fact:

* `provisional`: Supported by 1 corpus family (support = 1). Fully active and installed.
* `confirmed`: Independently supported by 2 or more distinct corpus families (support >= 2).

To upgrade a fact to `confirmed`, author a second independent family demonstrating the same defense pattern in a different context.

## 7. Verification workflow

```bash
# 1. Compile bundle and review published facts
frensense bundle mycorpus my.frc

# 2. Run with debug trace if a fact failed to appear
FXDBG=1 frensense bundle mycorpus my.frc

# 3. Verify on target test files
frensense test_targets/ --corpus-bundle my.frc --json

# 4. Verify against clean code to ensure zero false positives
frensense clean_codebase/ --corpus-bundle my.frc
```

## 8. Common pitfalls

| Symptom | Cause | Remedy |
|---|---|---|
| Expected fact missing | Family did not separate: positive stayed silent or negative still alerted. | Run with `FXDBG=1` to inspect baseline alert flags. |
| Sanitizer not proposed | Name matches the built-in noise list (`has`, `get`, `map`). | Rename helper to a domain-specific guard (e.g. `isValidDomain`). |
| Exception treated as guard | Guard name ends with `Error` or `Exception`. | Guard names ending in `Error` are filtered out; name the function `validate()` or `check()`. |
| Cross-family regression | Proposed fact suppresses an existing positive or causes another negative to alert. | Ensure the negative variant does not use overly broad sanitizers. |

## 9. Authoring checklist

* \[ ] Language-prefixed filename stem (`ts_`, `py_`, `c_`).
* \[ ] Positive file contains complete `[frensense]` block with observation, impact, and improvement.
* \[ ] Negative file contains `// SAFE:` comment.
* \[ ] Negative differs from positive strictly in the remediation logic.
* \[ ] Guard and sanitizer functions avoid reserved accessor names.
* \[ ] `frensense bundle` succeeds with `round-trip OK`.
* \[ ] Positive alerts, negative stays silent, clean code produces zero findings.
