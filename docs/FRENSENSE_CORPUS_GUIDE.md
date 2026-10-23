# Frensense Corpus Authoring Guide

> How to teach Frensense new vulnerabilities. Frensense is **corpus-based, not
> rule-based**: there is no rule language to learn and no YAML to write. You
> provide a vulnerable example and its remediated counterpart, and the
> bundler verifies and distills the difference into a portable `.frc` bundle.

Everything in this guide is what the shipped `frensense lint` and
`frensense bundle` actually enforce, and the example is a complete family you
can paste into a directory and build.

## 1. The mental model

A Frensense **family** is one vulnerability concept, expressed as a pair of files:

- `<family>_positive.<ext>`: the vulnerable version
- `<family>_negative.<ext>`: the fixed / safe version

The bundler lowers both through the same engine the scanner uses, computes the
semantic delta (what call the negative avoids, what guard the negative adds),
and proposes a *fact*. Every proposed fact then passes a **replay gate**: it is
published only if, with the fact installed, the positive alerts, the negative
stays silent, and no family that already separated regresses.

Facts ship inside an `.frc` bundle (binary, versioned, checksummed). The engine
merges bundle facts **over** its built-in tables; bundle knowledge wins on
collision, and coarse all-arguments facts never widen a precise slot-restricted
one.

Supported extensions: `ts`, `tsx`, `js`, `jsx`, `py`, `go`, `rs`, `c`, `cpp`,
`h`, `hpp`. Any other file in the corpus tree is ignored.

## 2. Quick start: one family, end to end

The example teaches **missing authorization** around a privileged call, because
that shape needs no framework vocabulary and produces a reportable finding
today. Substitute your own trigger and class.

### 2.1 Declare the class registry

Every corpus root needs a `bug_classes.json`. The lint resolves each family's
`class:` against it, and coverage is reported per class:

```json
{"version":1,"class":[
 {"id":"authz.missing","name":"Missing authorization","cwe":"CWE-862","related_cwe":[]}
]}
```

### 2.2 Write the pair

```text
mycorpus/
├── bug_classes.json
└── ts/authz.missing/ts_priv/
    ├── ts_priv_positive.ts
    ├── ts_priv_negative.ts
    ├── ts_priv_heldout_positive.ts
    └── ts_priv_heldout_negative.ts
```

**Positive** — the vulnerable version. The `[frensense]` block is the advisory
text every report will show, plus the fields the lint checks:

```typescript
// [frensense]
// observation: A password reset is issued for an account with no check that the caller owns it.
// impact: Anyone who knows an address can reset that account's credentials.
// improvement: Require the caller's own identity to match the account before resetting.
// cwe: CWE-862
// severity: high
// class: authz.missing
// purpose: knowledge
// shape: unguarded-privileged-call
// check-call: resetPassword
// source: synthetic: minimal reproduction of the unguarded privileged call
function resetPassword(email: string) { return email; }
export function handler(req: any) {
  resetPassword(req.body.email);
}
```

**Negative** — the same call, enforced. No `[frensense]` block, and it starts
with `SAFE:`:

```typescript
// SAFE: the reset only runs behind the caller check.
function authorize() { return true; }
function resetPassword(email: string) { return email; }
export function handler(req: any) {
  if (authorize()) {
    resetPassword(req.body.email);
  }
}
```

**Held-out pair** — proof the fact generalizes to code the bundle was never
built from. Different framework, different source, same trigger and same
enforcement helper:

```typescript
// ts_priv_heldout_positive.ts - Next.js route, still unguarded
import type { NextApiRequest, NextApiResponse } from "next";
function resetPassword(email: string, token: string) { return { email, token }; }
export default function route(request: NextApiRequest, response: NextApiResponse) {
  const accountEmail = String(request.query.email);
  response.status(200).json(resetPassword(accountEmail, "issued"));
}
```

```typescript
// ts_priv_heldout_negative.ts - same route, guarded
// SAFE: the reset only runs behind the learned caller check.
import type { NextApiRequest, NextApiResponse } from "next";
function resetPassword(email: string, token: string) { return { email, token }; }
export default function route(request: NextApiRequest, response: NextApiResponse) {
  const accountEmail = String(request.query.email);
  if (authorize()) {
    response.status(200).json(resetPassword(accountEmail, "issued"));
  } else {
    response.status(403).end();
  }
}
```

### 2.3 Lint, bundle, scan

```bash
frensense lint mycorpus --strict
# (no output)
# 1 families, 0 errors, 0 warnings

frensense bundle mycorpus my.frc
# [facts] 1 families grouped from mycorpus
# [facts] round-trip OK: 1 learned facts in bundle
#   [provisional] policy:policy_resetPassword(resetPassword) <- ts_priv
# Facts bundle written to my.frc (641 bytes)

frensense targets/ -b my.frc
# [WARNING] Policy violation: resetPassword
#   --> admin.ts:3:3 (in `handler`)
#     |
#   2 | export function handler(req: any) {
#   3 |   resetPassword(req.body.email);
#     |   ^^^^^^^^^^^^^
#     |
#   = rule: policy.resetPassword  (CWE-862)
#   = why:  Anyone who knows an address can reset that account's credentials.
#   = fix:  Require the caller's own identity to match the account before resetting.
#   = note: A password reset is issued for an account with no check that the caller owns it.
```

The `why`, `fix` and `note` lines come from the family's `improvement`,
`impact` and `observation`. The CWE comes from `cwe:`. Nothing else describes
the advisory - that is why the prose is required, not decorative.

The held-out pair is what tells you the fact generalizes:

```bash
frensense mycorpus/ts/authz.missing/ts_priv/ts_priv_heldout_positive.ts -b my.frc   # 1 finding
frensense mycorpus/ts/authz.missing/ts_priv/ts_priv_heldout_negative.ts -b my.frc   # 0 findings
```

Inspect what was actually published before shipping:

```bash
frensense bundle info my.frc
# ============================= Bundle Details =============================
# Path:               my.frc
# Magic:              FRC1
# Format Version:     v7
# Payload Size:       641 bytes
# BLAKE3 Checksum:    01735461baf1591f47f03793bcc5d06fc938ff1ea87118e5f6bbea512aedac93
# Fact Vocabulary:    0x499427a8ed94e470
# Requires Engine:    frensense >=0.8.0,<0.9.0
# Built By Engine:    frensense 0.8.0-beta
# Pattern Count:      1
# Learned Facts:      1
#   - Co-occurrence:  1
# ==========================================================================
#
# Advisory Patterns:
#   - [ts_priv] CWE-862 (Severity: high)
#       Rules: policy_resetPassword
```

The bundle is usable three ways: `-b/--bundle/--corpus-bundle <file>`, dropped
at the root of the scanned project as `frensense-corpus.frc` (auto-discovered),
or `FRENSENSE_CORPUS_BUNDLE` for the MCP server and LSP.

## 3. Naming and layout rules

- **Family id** is the filename stem before `_positive` / `_negative`.
  `ts_priv_positive.ts` → family `ts_priv`. Files without that infix are
  ignored, so a helper module can live beside the pair.
- **Language prefix**: start every stem with the language (`ts_`, `py_`, `c_`,
  `rs_`, `go_`). One stem must never mix languages; the bundler splits a
  collision into `<stem> (typescript)` / `<stem> (python)` with a warning, and
  a split family cannot confirm anything.
- **Several variants are allowed** (`..._negative.ts`, `..._negative2.ts`).
  Every negative is part of the gate, so more negatives = a stricter test.
- **Held-out**: `<family>_heldout_positive.<ext>` and
  `<family>_heldout_negative.<ext>`, in the same directory as the family. The
  bundler drops these before extraction (§6).
- **Directories are metadata**, conventionally `<lang>/<class>/<family>/`.
  Moving a family between directories never changes its id or its facts.

## 4. The `[frensense]` metadata block

The positive may open with a comment block in its first 30 lines. Python uses
`#`; every other language uses `//`. The block ends at the first non-comment
line.

```typescript
// [frensense]
// observation: A request field is concatenated into a SQL statement and executed.
// impact: An attacker controls the query text and can read or rewrite any row.
// improvement: Bind the value through the driver's parameter channel.
// cwe: CWE-89
// cvss: 9.1
// owasp: A03:2021
// severity: high
// class: inj.sql
// purpose: knowledge
// shape: string-concat-into-query
// source: CVE-2026-28207, https://github.com/org/repo/commit/<sha>, MIT
// package: pg
```

### 4.1 What the lint requires

The bundler compiles a pair with sparse metadata; `frensense lint` does not.
Every training positive needs:

| Key | Requirement |
|---|---|
| `observation`, `impact`, `improvement` | The advisory text users see in every report; placeholders and one-word values are rejected (`M002`, `M003`). |
| `cwe` | Canonical `CWE-<n>`, and it must belong to the declared class (`C002`, `C003`). |
| `severity` | `critical`, `high`, `medium`, `low`, `warning` or `info` (`M006`). |
| `class` | One id from `bug_classes.json`; an unknown id gets a nearest-match hint (`C001`). |
| `purpose` | `knowledge`, `precision` or `anchor` - see §7.3 (`C005`). |
| `source` | `<advisory id>, <https url>, <SPDX license>` or `synthetic: <reason>` - see §8 (`P001`). |
| `shape` | Required on knowledge families: comma-separated tags that keep two families from restating one shape (`C006`, `D002`). |

Optional keys that are parsed today: `cvss` (`M005`), `owasp`, `package`
(§4.2), `check-call` (§5.2), `check-rule` and `wrap-max` (§5.3), `expect`.

Two rules that surprise people:

- **Unknown keys are an error** (`M004`), with a nearest-match hint. A typo
  like `obsveration` fails the lint instead of silently dropping the text.
  `expect` is accepted but nothing in this repo reads it yet.
- **Negatives never carry the block** (`S002`). Their only required opener is
  `// SAFE: <why this version is safe>`.

### 4.2 Framework provenance scoping (`package:`)

For framework-specific or third-party library rules, declare the package:

```typescript
// [frensense]
// observation: User-controlled file parameter passed to res.sendFile without a directory boundary check.
// package: express
```

- **Engine scoping**: the fact binds to files that import or declare that
  package. A same-named method in another framework (Next.js, Electron, Hono)
  stays unaffected.
- **Blast-radius quarantine**: the bundler refuses to publish a
  package-scoped candidate unless the voting family actually imports that
  package. A rule that claims `express` while the family imports nothing is
  rejected with that reason.
- **Generic trigger names need it.** The lint rejects an everyday method name
  (`get`, `set`, `send`, `query`, ...) used as a trigger without `package:`
  (`E040`), because such a fact fires on every receiver in the language.

## 5. What each family shape teaches

These nine are the fact kinds the bundler can mine from a family. Anything else
(propagators, grammar roles, IDOR vocabulary) ships in the built-in pack or a
hand-built bundle and cannot be taught by a pair yet.

| Family shape | The bundler proposes | Author notes |
|---|---|---|
| Positive calls a privileged function with no guard; negative guards it | `Policy` / `Check` (declare `check-call:`) | The trigger must be called in both variants; the guard must feed or dominate the trigger. |
| Positive reaches an unknown dangerous call | `Sink` (all arguments, then slot-narrowed) | Read §5.1 before relying on this shape: an unknown call also needs a class to report. |
| Negative inserts a call between source and sink | `Sanitizer` (`encode`, or `allowlist` if it is a predicate) | The inserted call must be the real defense, with a normal name. |
| Weak primitive in positive, strong in negative | `WeakCrypto` | Keep the non-security use as a separate `precision` family. |
| Allocation size arithmetic | `IntegerOverflowRule` (declare `check-rule:`) | The negative clamps operands with literal-bound guards. |
| Allocator/deallocator wrappers | `MemoryContract` | Include a method-style deallocator family (`Close`, `Release`). |
| URL/redirect or credential value handed to a call | `GuardBypass` | Name the parameter `url`/`redirect`/`password`/`secret`-style. |
| Numeric bound stated in a schema description; negative enforces it | `SchemaPolicy` | The digits in `describe(...)` are the trigger; the negative's schema calls become enforcers. |
| Second family teaching the same defense in a different context | upgrades support, not a new fact | Two independent votes make a fact `confirmed` (§6). |

### 5.1 A learned sink arms but does not report (today)

A `Sink` candidate is installed as a language-scoped, slot-only fact. It has no
vulnerability class of its own: the engine reports a taint finding only when the
sink names one (role or label). A call the built-in pack already classifies
keeps that class and reports; a call the pack has never classified arms, but is
reported as `unclassified` and suppressed from advisories. You can see it:

```bash
frensense targets/app.ts --explain
# Explain: 1 silent sink argument(s) explored (no advisory)
#   unclassified   app.ts:5  rawQuery(arg 0)
#       why: taint reaches `rawQuery` but the sink names no vulnerability class, so no advisory is reported
#       source: req.body.id
```

So for a **new** dangerous call, pair the sink with a reportable fact: keep the
matched pair (the sink fact still narrows slots for the pack's vocabulary) and
add a `check-call:` policy variant of the same defect so the family produces a
finding, or author the family as a policy family from the start. Do not ship a
sink-only family and assume the CLI will alert - it will not, even though the
replay gate published the fact.

### 5.2 Policy families (`check-call:`)

Use this when the bug is not data flowing into a sink but a privileged action
executed without its enforcement:

1. Put `// check-call: <trigger>` (Python: `# check-call:`) in the first 30
   lines of the positive.
2. Call the trigger unguarded in the positive.
3. Call the trigger guarded in the negative - behind a predicate
   (`if (authorize())`) or an inline range check on its argument.

```typescript
// ts_priv_positive.ts
// check-call: resetPassword
function resetPassword(email: string) { return email; }
export function handler(req: any) {
  resetPassword(req.body.email);          // unguarded -> violation
}

// ts_priv_negative.ts
// SAFE: guarded by the caller check.
function authorize() { return true; }
function resetPassword(email: string) { return email; }
export function handler(req: any) {
  if (authorize()) {
    resetPassword(req.body.email);        // guarded -> silent
  }
}
```

The published fact names both the trigger and the guard, for example
`policy:policy_resetPassword(resetPassword)`. The guard is accepted only when
it is **grounded in the negative**: it feeds the trigger's arguments through a
dataflow chain, dominates the trigger call, or decorates the entry point. A
helper that merely exists somewhere in the file (`new Date()` in a `where`
clause) is dropped as coincidental, with a `guard ... rejected` note under
`FXDBG`.

A policy fact remembers **names**, not concepts. Its held-out pair must keep
the same trigger and the same enforcement helper the training negative taught
(a different wrapper, framework, source and call site are all fine). A held-out
negative that enforces with a new helper name `canReset(...)` still alerts - and
that is a correct "no" from the generalization test, not a bug. To teach a
generalized rule that accepts several helpers, author a second family whose
negative uses the other helper: the bundler merges the guards into one `Policy`
requiring any of them.

### 5.3 Integer overflow rules (`check-rule:`)

```c
// [frensense]
// check-rule: integer_overflow_alloc
// wrap-max: 18446744073709551615
// observation: Integer multiplication in an allocation size wraps on 64-bit platforms.
// severity: critical
```

## 6. Statuses, held-out pairs, and `confirmed`

Each published fact carries a status:

- `provisional`: one family voted (support = 1). Installed and active.
- `confirmed`: two or more distinct families voted. To upgrade, author a second
  family teaching the same defense in a different context - votes accumulate
  across families, never across variants of one family.

Held-out files are a different machine from the bundle:

- **`frensense bundle` never reads them.** `group_families` drops every stem
  containing `_heldout` before extraction, so a bundle cannot be learned from
  its own test.
- **The identity assertion lives in the corpus repository's harness**
  (`scripts/test_bundles.sh`: the held-out positive fires with the declared
  identity, the held-out negative produces no alert). This repo has no such
  script.
- **`frensense lint` checks the pair's shape**: both halves present (`S005`), a
  training pair to generalize from (`S003`), no copy of the training file
  (`D004`, at 85% token-shingle similarity), and no `[frensense]` block on a
  held-out file (`S010`). A training pair with no held-out is the `S004`
  warning; `--require-heldout` turns it into an error.

Never edit a held-out file to make it pass. A failing held-out is the signal:
fix the training pair or the engine, and record the failure.

## 7. Linting the corpus (`frensense lint`)

The replay gate proves a *fact*; it cannot tell whether the pair deserves to
teach one. `frensense lint` is the pre-flight for the family set. It never scans
target code unless you ask it to, and it refuses the mistakes a gate cannot see:
mislabeled metadata, copied families, and pairs that would end up teaching
nothing.

```bash
frensense lint mycorpus               # text report; exits 1 on any error
frensense lint mycorpus --strict      # warnings are errors too
frensense lint mycorpus --json        # machine-readable report
frensense lint mycorpus --coverage    # class x language coverage table
frensense lint mycorpus --no-gate     # skip the checks that need a scan
```

`frensense-bundler lint <corpus>` is the same entry point. Exit codes: `0`
acceptable, `1` issues (or any warning under `--strict`), `2` bad configuration
such as a missing registry or an unknown flag.

Other flags: `--classes <file>` (default: `bug_classes.json` next to or above
the corpus), `--advisories <index.json>`, `--require-heldout`,
`--dup-threshold <0..1>` (default `0.8`).

### 7.1 What it checks

| Codes | It refuses |
|---|---|
| `S001`-`S013` | Layout: a positive without a negative or the reverse, an incomplete held-out pair, a `[frensense]` block on a negative, a marker after the first 30 lines, one stem used by two languages. |
| `M001`-`M008` | Metadata: missing required keys, unknown keys (with a nearest-match hint), duplicate keys, placeholder prose, bad `severity`/`cvss`, a second positive that disagrees with the first. |
| `C001`-`C006` | Classification: missing or unknown `class:`, a CWE outside the class, missing or invalid `purpose:`, no `shape:` tags on a knowledge family. |
| `P001`-`P008` | Provenance: missing `source:`, malformed advisory ids or URLs, an advisory missing from the offline index or disagreeing with the CWE, one advisory cited by several families. |
| `D001`-`D008` | Diversity: near-duplicate call sets, structural clones with names and literals abstracted, families teaching identical facts, families whose facts are a subset of another's. |
| `E040` | An everyday method name (`get`, `set`, `send`, `query`, ...) used as a trigger without `package:` scoping. |
| `PU001`-`PU004` | Purpose against the engine: a declared `knowledge`/`precision`/`anchor` the bare engine contradicts, and a family the replay gate would learn nothing from. |

### 7.2 `purpose:` is a claim the lint verifies

- **`knowledge`**: the bare engine misses the positive, and this family must
  teach the fact that catches it.
- **`precision`**: the bare engine alerts on the negative, and this family must
  teach the fact that silences it.
- **`anchor`**: the bare engine already separates the pair and the family exists
  to keep it that way. Anchors teach nothing by design and are exempt from
  `PU004`.

Declaring the wrong purpose is an error (`PU001`, `PU002`, `PU003`), because the
lint can check it by scanning both twins under the bare engine. The message
names the fix:

```text
sqli_raw
  error PU001: declared knowledge but the bare engine already alerts on the
        positive; it adds no fact, so declare anchor (or fix the positive so it
        exercises a gap)
```

### 7.3 `PU004`: a family that would teach nothing

A pair can satisfy every layout, metadata and purpose check and still add
nothing to the bundle. The premise holds - the positive is silent under the
bare engine - but none of the facts the pair proposes separates its own twins,
so the replay gate publishes none of them. The lint trials each proposed fact
the way the gate's vote does and reports the closest one with the verdict that
sank it:

```text
sqli_raw
  warn  S004: no held-out pair: a family without one makes no generalization claim
  warn  PU004: declared knowledge but the bundle would learn nothing from this
        family: none of its 2 proposed fact(s) separates the pair; closest is
        `sink:rawQuery` (positive_alerts=true, negative_alerts=true): the positive
        alerts but so does the negative, so the gate rejects the fact as a false
        positive waiting to happen
```

Remedies, in order of preference:

1. Teach something the negative actually demonstrates (a sanitizer or guard the
   positive lacks) instead of a sink both variants call.
2. Change the negative so the sink fact is provable - it must stop reaching the
   sink with tainted data, not merely bind the arguments.
3. Declare `anchor` if the bare engine already separates the pair.

`PU004` is a warning by default because a sibling family can still publish the
fact. Use `--strict` when curating.

## 8. Provenance and licensing

`source:` takes one of these forms, checked by the lint:

- `<advisory id>, <https url>, <SPDX license>` - for example
  `CVE-2026-28207, https://github.com/org/repo/commit/<sha>, MIT`;
- `synthetic: <reason>` with at least 10 characters when no advisory exists.

The id must be a CVE, GHSA, OSV, PYSEC, RUSTSEC or GO id; a GHSA id must link to
`github.com`, a RUSTSEC id to `rustsec.org` or `github.com`. With
`--advisories <index.json>` the id must exist in the offline index and agree
with the family's CWE, and a stem that names a CVE (`cve_2024_12345`) must cite
that same CVE. Date fetched and reviewer have no key today; record them in the
corpus manifest or the PR.

Repros are rewritten from scratch and reduced, not copied. The bundle carries
facts (call names, slots, advisory prose), not source, but the corpus is a
commercial asset and its provenance should survive a due-diligence review.

## 9. Verification workflow

Do all of this before publishing a bundle.

```bash
# 1. Metadata, layout, diversity, purpose, teachability.
frensense lint mycorpus --strict

# 2. Build and read what was published - every fact must be one you intended.
frensense bundle mycorpus my.frc
frensense bundle info my.frc

# 3. A candidate vanished: baseline flags, candidates, and the gate's reason.
FXDBG=1 frensense bundle mycorpus my.frc
FXREPORT=/tmp/learn.json frensense bundle mycorpus my.frc

# 4. Held-out: the positive fires, the negative stays silent.
frensense mycorpus/ts/authz.missing/ts_priv/ts_priv_heldout_positive.ts -b my.frc
frensense mycorpus/ts/authz.missing/ts_priv/ts_priv_heldout_negative.ts -b my.frc

# 5. Endpoints: a target that should alert, and a clean project that must not.
frensense targets/ -b my.frc
frensense clean_codebase/ -b my.frc
```

A fact that fires on the clean project means the negative under-specified the
enforcement; tighten the family and rebuild instead of narrowing the bundle.

## 10. What a finding looks like

The report is the product. Every line below is driven by the family: `why` from
`impact`, `fix` from `improvement`, `note` from `observation`, the CWE from
`cwe`, and the rule id from the published fact.

```text
[WARNING] Cross-site scripting: `req.query.q` reaches `send`
  --> app/search.ts:43:5 (in `searchMeta`)

     |
  43 |     res.send(
     |     ^^^^^^^^
     |
  = rule: taint.xss  (CWE-79)
  = why:  Attacker-supplied text is written into a page and can run script in the victim's browser.
  = fix:  Escape the value for its output context, or use an API that does not interpret markup.
```

```text
[WARNING] Policy violation: resetPassword
  --> admin.ts:3:3 (in `handler`)

    |
  2 | export function handler(req: any) {
  3 |   resetPassword(req.body.email);
    |   ^^^^^^^^^^^^^
    |
  = rule: policy.resetPassword  (CWE-862)
  = why:  Anyone who knows an address can reset that account's credentials.
  = fix:  Require the caller's own identity to match the account before resetting.
  = note: A password reset is issued for an account with no check that the caller owns it.
```

Write `impact` so it reads as the consequence of *not* fixing it, and
`improvement` so it names the remediation in the family's own vocabulary. Those
two lines are what a reviewer acts on.

## 11. Common mistakes

| Symptom | Cause | Remedy |
|---|---|---|
| Expected fact missing | The family did not separate: the positive stayed silent, or the negative still alerts. | `FXDBG=1` shows baseline flags and the gate's rejection reason. |
| `PU001`/`PU002`/`PU003` | The declared `purpose` contradicts the bare engine. | Set the purpose the scan proves; `anchor` if the engine already separates the pair. |
| `PU004` with a sink candidate | Both twins reach the same sink, so installing it makes the negative noisy. | Teach the sanitizer or guard the negative adds. |
| Sink fact published but nothing alerts | A learned sink for a call the pack does not classify reports as `unclassified` (§5.1). | Add a `check-call:` policy family for the same defect. |
| Held-out positive silent | A policy fact only knows its declared trigger; the held-out must call it. | Keep the trigger, vary the wrapper/framework/source. |
| Held-out negative alerts | The enforcement helper is not the one the fact learned. | Reuse the trained helper, or add a second family teaching the other one. |
| Sanitizer not proposed | Name matches the built-in noise list (`get`, `set`, `has`, `map`, `send`, `query`, `parse`, ...). | Rename to a domain guard such as `isValidDomain`. |
| Guard not accepted | The helper is not grounded in the negative: it neither feeds the trigger's arguments nor dominates the call. | Enforce with the helper, do not just mention it. |
| `E040` | Generic trigger name with no `package:`. | Declare the framework package, or pick a specific call. |
| Bundle ignored at scan time | Wrong path, or a bundle from an incompatible engine version. | `frensense bundle info` prints the required engine range; the load error names the mismatch. |

## 12. Checklist

- [ ] Class declared in `bug_classes.json` before the family.
- [ ] Stems are `<lang>_<family>_positive.<ext>` / `_negative.<ext>`; no stem shared across languages.
- [ ] Positive carries `observation`, `impact`, `improvement`, `cwe`, `severity`, `class`, `purpose`, `source`, and `shape` (knowledge families).
- [ ] Negative opens with `// SAFE:` and carries no `[frensense]` block.
- [ ] Negative differs from the positive only in the fix.
- [ ] Held-out pair present, same trigger and same enforcement helper, different shape.
- [ ] `frensense lint mycorpus --strict` is clean.
- [ ] `frensense bundle` publishes only facts you intended (check the statuses).
- [ ] Held-out positive fires, held-out negative silent, clean project silent.
- [ ] The finding text reads correctly, because that is what users see.

## 13. Migrating a family written against the old guide

Older corpus families (and older tutorials) use the pre-lint shape. Convert in
this order, because each step changes what the next one reports:

1. **Rename to the grouped shape.** `<id>/positive.ts` and `<id>/negative.ts`
   are never grouped - the infix is what makes a family. Move to
   `corpus/<lang>/<class>/<id>/<lang>_<id>_positive.<ext>` and the matching
   `_negative`. On old files the lint simply finds nothing and reports
   `0 families, 0 errors, 0 warnings` with exit code 0, which is usually the
   first sign of this.
2. **Use the current CLI.** `frensense-bundler <corpus> <out.frc>` became
   `frensense bundle <corpus> <out.frc>`, and `frensense-bundler lint` became
   `frensense lint`. The standalone `frensense-bundler <corpus> <out.frc>`
   form still works, but the documented entry points - the ones CI uses - are
   `frensense lint` and `frensense bundle`.
3. **Add the registry and the required keys.** `bug_classes.json` at the corpus
   root, then `class`, `purpose`, `source`, `shape` on every positive.
4. **Decide `purpose` from evidence, not intention.** Run
   `frensense lint --no-gate` first (metadata only), then the full lint and read
   `PU001`-`PU003` as measurements of what the bare engine already does.
5. **Read `PU004`.** A family that taught nothing under the old guide usually
   does not teach anything now either; that is the finding, not a regression.
6. **Add a held-out pair** if the family has none (`S004`).
7. **De-genericize triggers.** Any `get`/`send`/`query`/`execute` fact now needs
   `package:` (`E040`), and a same-named call elsewhere in the language no
   longer inherits it.
8. **Re-measure.** A family that "worked" under the old pipeline may report a
   `Sink`-only fact that never alerted in the CLI (§5.1); convert those to
   policy families or pair them with one.
