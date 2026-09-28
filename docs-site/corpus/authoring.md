---
outline: [2, 3]
---

# Corpus authoring guide

> How to teach Frensense new vulnerabilities. Frensense is **corpus-based, not
> rule-based**: there is no rule language to learn and no YAML to write. You
> show the engine a vulnerable example and its fixed counterpart, and the
> bundler verifies and distills the difference into a portable `.frc` bundle.

## 1. The mental model

A Frensense **family** is one vulnerability idea, expressed as a pair:

- `<family>_positive.<ext>`, the vulnerable version
- `<family>_negative.<ext>`, the fixed / safe version

The bundler lowers both through the same engine a scan uses, computes the
delta (what call the negative avoids, what guard it adds), and proposes a
*fact*. Every proposed fact then passes a **replay gate**: the fact is only
published if, after installing it, the positive alerts and the negative stays
silent, and no other family that already separated regresses. If a fact
cannot prove itself against your corpus, it is never published. That is the
quality control, and it is why there is no rule linting to do.

Facts ship inside an `.frc` bundle (binary, versioned, blake3-checksummed).
The engine merges bundle facts **over** its built-in tables, bundle knowledge
always wins on collision, and coarse all-args facts never widen precise
slot-restricted ones.

Supported languages: `ts`, `tsx`, `js`, `jsx`, `py`, `go`, `rs`.

## 2. Quick start (5 minutes)

Build a family, run the bundler, scan with the bundle:

```bash
mkdir -p mycorpus/ts_sqli
cat > mycorpus/ts_sqli/ts_sqli_positive.ts <<'EOF'
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

# Build the bundle (bundler binary ships alongside the frensense CLI)
frensense-bundler mycorpus my.frc
# [facts] 1 families grouped from mycorpus
# [facts] round-trip OK: 1 learned facts in bundle
#   [provisional] sink:... ← ts_sqli        (support 1 = provisional)

# Scan a target with it
frensense path/to/target --corpus-bundle my.frc
```

Or drop the bundle into the scanned project root as
`frensense-corpus.frc`, it is picked up automatically. The MCP server and
LSP pick it up via the `FRENSENSE_CORPUS_BUNDLE` environment variable.

## 3. Naming and layout rules

- Family id = filename stem before `_positive` / `_negative`.
  `ts_sqli_positive.ts` → family `ts_sqli`.
- Multiple negatives are allowed (`..._negative.ts`, `..._negative2.ts`) and
  multiple positives too. More negatives = stronger gate.
- Directories are free-form metadata. `<lang>/<CWE>/<family>/` works, and
  moving a family between directories does not change its id.
- **Do not mix languages under one stem.** `foo_positive.py` and
  `foo_negative.ts` would collide; the bundler detects this and splits them
  into `foo (python)` / `foo (typescript)` with a warning. Prefer explicit
  language prefixes (`py_foo_positive.py`, `ts_foo_positive.ts`), that is
  how the upstream corpus is organized.
- Facts are matched by **call name** (last segment), language-blind by
  design: a learned `execute` sink fires in any language that calls
  `execute`. Name your triggers specifically.

## 4. The `[frensense]` metadata block

The positive file may open with a comment block carrying advisory text that
is baked into the bundle and shown to users of every surface (CLI, MCP, LSP):

```typescript
// [frensense]
// observation: User id concatenated into the SQL string.
// impact: An attacker can read or modify any row in the database.
// improvement: Use the parameterized binding channel ($1) instead.
// cwe: CWE-89
// cvss: 9.1
// owasp: A03:2021
// severity: Critical

import { Pool } from "pg";
...
```

- Python families use `#` comments; everything else `//`.
- All fields are optional; the block ends at the first non-comment line.
- The negative file must **not** carry the block. Start it with
  `// SAFE: <why this version is safe>`.

## 5. What each family shape teaches

### 5.1 Taint families (sinks & sanitizers)

Default shape: no special annotation needed. If the positive does not alert
under the current tables and contains an unknown call, the bundler proposes
it as a **sink**; if the negative avoids a call the positive makes (or guards
with a predicate-style call), it proposes a **sanitizer**.

Use this when: your framework/API has an injection-shaped call the engine
does not know, or a function that neutralizes input.

### 5.2 Policy families (non-dataflow rules)

Use this when the bug is *not* about data flowing anywhere, it is about a
call being **present without its enforcement** (missing authz, raw render,
unaudited privileged action). Taint cannot see these; policy facts can.

Authoring rules:

1. In the positive, add `// check-call: <trigger>` in the first 30 lines
   (Python: `# check-call:`). The trigger is the call whose *unguarded
   presence* is the violation. The trigger must be **called** somewhere in
   the file, a bare declaration teaches nothing.
2. Positives call the trigger **without** enforcement; negatives call the
   trigger **with** enforcement (a guard helper before it, or an inline
   range check on its argument).
3. The learned fact fires only when the guard is absent, so scanning clean
   code stays silent.

```typescript
// ts_priv_positive.ts
// check-call: resetPassword
function resetPassword(email: string) { return email; }
export function handler(req: any) {
  resetPassword(req.body.email);          // no guard → violation
}

// ts_priv_negative.ts
function authorize() { return true; }
function resetPassword(email: string) { return email; }
export function handler(req: any) {
  if (authorize()) {
    resetPassword(req.body.email);        // guarded → silent
  }
}
```

Verified end-to-end: after bundling this pair, a target calling
`resetPassword` unguarded reports
`Policy violation: policy_resetPassword`; the same target calling it behind
`authorize()` reports nothing.

The generalized `Policy` facts (required calls, banned calls, module-scope
enforcement) are produced by the same declared-trigger shape, the bundler
mines what the negatives demonstrate and the gate validates it.

## 6. Statuses: `provisional` vs `confirmed`

The bundler prints each published fact with its status:

- `provisional`, one family voted for the fact (support = 1)
- `confirmed`, two or more independent families voted (support ≥ 2)

Both kinds are installed by the engine. To upgrade a fact to `confirmed`,
author a second family for the same call/behavior (different code, same
lesson), the votes accumulate.

## 7. Verification workflow (do this before publishing a bundle)

```bash
# 1. Build and read the bundler's report: every fact must be one you intended.
frensense-bundler mycorpus my.frc

# 2. Build a small "target" directory mixing vulnerable and fixed snippets
#    and scan it with the bundle. Unguarded positives must alert; guarded
#    negatives must stay silent.
frensense targets/ --corpus-bundle my.frc --json

# 3. Scan a real clean project with the bundle, zero findings on untouched
#    code is the FP gate. If a fact fires on clean code, your negatives
#    under-specified the enforcement: tighten the family and rebuild.
```

Set `FXDBG=1` when running the bundler to see every candidate and where the
gate accepted or rejected it, useful when a fact you expected does not
appear (its family failed to separate).

## 8. Common mistakes

| Symptom | Cause |
|---|---|
| Fact you expected is missing | The family never separated: check the positive actually alerts (it may need taint from a param named `req`/`request`/...), or the negative still alerts. |
| `check-call` ignored | It must be in the first 30 lines, `//`/`#` prefix matching the language, and the trigger must be *called*, not just declared. |
| Policy fires on clean code | The negative's guard helper was named with a synthetic lowering name, or the guard is genuinely absent in the "clean" code. Re-check the negative. |
| Bundle silently ignored | Wrong `--corpus-bundle` path, or a bundle from an older engine (version mismatch), the bundler round-trip check catches format errors at build time. |
| Two languages merged into one family | Same stem used across languages; rename with language prefixes. |
| A `<fn@...>`-looking rule name appears | The bundler never publishes these (filtered), but if you see one, file a bug, it means a synthetic lowering name leaked into a fact. |

## 9. Distributing bundles

- The engine accepts `--corpus-bundle <file>`, auto-discovers
  `frensense-corpus.frc` in the scanned root, and (for MCP/LSP) reads
  `FRENSENSE_CORPUS_BUNDLE`.
- Bundles are small (typically kilobytes), checksummed, and merge cleanly, 
  a project may use your framework bundle plus its own deployment bundle
  simultaneously; facts from both are installed, later merges never lose
  earlier ones, and dedup is by rule id.
- `FRENSENSE_SEED_FACTS` / `corpus/facts/seed_facts.json` add deployment
  hints (e.g. trusted session-store roots) that are merged before bundle
  facts.

## 10. Authoring checklist

- [ ] Family named `<id>_positive.<ext>` / `<id>_negative.<ext>`, language-prefixed stem
- [ ] Negative differs from positive **only** in the fix (same imports, same structure)
- [ ] `[frensense]` block on the positive with observation / impact / improvement / cwe / severity
- [ ] `check-call:` only for policy families, and the trigger is called in both variants
- [ ] Bundler output reviewed, every published fact intended, statuses noted
- [ ] Unguarded target alerts, guarded target silent, clean project silent
- [ ] Second family authored for facts you want `confirmed`
