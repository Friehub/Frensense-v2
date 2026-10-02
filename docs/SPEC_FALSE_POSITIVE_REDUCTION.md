# Engineering Specification: Precision Hardening & False Positive Elimination

**Status**: Ready for Implementation  
**Audience**: Autonomous Engineering Agents & Contributors  
**Target Crates**: `frensense-lang` (Language & Frontend Specifications), `frensense-engine` (Language-Agnostic Core Algorithms)  
**Strict Architectural Boundary**: `frensense-engine` **MUST NOT** contain language-specific strings, transforms, or framework heuristics. All language transforms, built-in sanitizers, and source definitions reside exclusively in `frensense-lang`.

---

## 1. Executive Summary & Objective

In real-world deployment on modern web backends (Hono, Cloudflare Workers, Next.js, Express), static taint analyzers frequently suffer from excessive false positives (~95% noise ratio) due to four distinct phenomena:
1. **Platform Secrets Flagged as Sources**: `c.env.*` and platform bindings are flagged as attacker input.
2. **Missing Transformation Sanitizers**: Cryptographic hashing (`sha256`), type conversions (`parseInt`, `Number`), and structural decompositions (`Object.keys`) are ignored as sanitizers.
3. **Struct-Level Taint Bleed (Lack of Field Sensitivity)**: Accessing safe fields of a context object (`c.env`) inherits taint because an unrelated field (`c.req`) is user input.
4. **Blindness to Defensive Guards (Lack of Path Sensitivity)**: Values validated by strict regex or allowlist guards (`if (!RE.test(x)) return;`) are reported as unvalidated injections.

This specification details the exact implementation tasks to eliminate these false positives while preserving mathematical soundness.

---

## 2. Architectural Separation of Concerns

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   frensense-lang (Language Crates)                     │
│  - Language-specific AST analysis (Tree-sitter)                        │
│  - Source definitions (c.req.query, req.body, process.argv)           │
│  - Environment exclusions (c.env.*, env.* are NOT sources)             │
│  - Built-in language transforms & sanitizers:                          │
│      * Hashes: sha256, sha512, md5, createHmac, bcrypt, argon2         │
│      * Coercions: parseInt, parseFloat, Number(), Math.*               │
│      * Extractions: Object.keys(), Object.values(), Object.entries()    │
│      * Encoders: encodeURIComponent, base64                            │
│  - Lowered into generic TaintConfig / LanguageSpec                     │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                         Transfers generic rules
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  frensense-engine (Language-Agnostic)                  │
│  - ZERO hardcoded language keywords, regexes, or framework names       │
│  - Field-sensitive LoadField taint propagation (var.field != var)      │
│  - Generic Control Dependence Graph (CDG) guard predicate pruning      │
│  - Sparse Value-Flow Graph (SVFG) reachability                         │
│  - Temporal Typestate Invariant Checking                               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Work Breakdown Structure (Actionable Agent Tasks)

### Task 1: Refine Context & Environment Sources in `frensense-lang`

**Files to modify**:
- [`frensense-lang/src/providers/javascript.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/frensense-v2/frensense-lang/src/providers/javascript.rs)
- [`frensense-lang/src/spec.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/frensense-v2/frensense-lang/src/spec.rs)

#### Technical Requirements:
1. In `classify_js_param`, **remove bare `"c"` and `"ctx"` from blanket `UserInput` classification**:
   - Marking `c` as user input causes the entire context object to be tainted at function entry.
   - Retain explicit request parameter names: `"req"`, `"request"`, `"httpReq"`, `"incomingMsg"`.
2. Expand `JS_SOURCE_NAMES` to explicitly declare granular request paths:
   - `"c.req.query"`
   - `"c.req.param"`
   - `"c.req.json"`
   - `"c.req.raw"`
   - `"c.req.header"`
   - `"ctx.request"`
   - `"ctx.query"`
   - `"ctx.params"`
3. Explicitly declare that platform environment access is untainted:
   - Ensure `"c.env"` and `"env"` are strictly categorized as `TaintOrigin::Environment` (or excluded from `TaintConfig.sources`).
   - Add unit tests verifying that `c.env.KEY` does not generate a taint source.

---

### Task 2: Implement Built-In Universal Sanitizers in `frensense-lang`

**Files to modify**:
- [`frensense-lang/src/providers/javascript.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/frensense-v2/frensense-lang/src/providers/javascript.rs)
- [`frensense-lang/src/providers/python.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/frensense-v2/frensense-lang/src/providers/python.rs)

#### Technical Requirements:
1. In `frensense-lang/src/providers/javascript.rs`, expand `JS_SANITIZER_NAMES` with universal cryptographic, numeric, and structural transforms:
   ```rust
   // Cryptographic Hashing (irreversible mathematical transformation)
   ("crypto.createHash", SanitizerKind::Generic),
   ("sha256", SanitizerKind::Generic),
   ("sha512", SanitizerKind::Generic),
   ("createHmac", SanitizerKind::Generic),
   ("bcrypt.hash", SanitizerKind::Generic),
   ("bcrypt.hashSync", SanitizerKind::Generic),
   ("argon2.hash", SanitizerKind::Generic),

   // Structural & Type Decomposition
   ("Object.keys", SanitizerKind::Generic),
   ("Object.values", SanitizerKind::Generic),
   ("Object.entries", SanitizerKind::Generic),
   ("parseInt", SanitizerKind::Generic),
   ("parseFloat", SanitizerKind::Generic),
   ("Number", SanitizerKind::Generic),
   ("Math.floor", SanitizerKind::Generic),
   ("Math.round", SanitizerKind::Generic),
   ("Math.abs", SanitizerKind::Generic),
   ("Boolean", SanitizerKind::Generic),

   // String encoding
   ("encodeURIComponent", SanitizerKind::Generic),
   ("encodeURI", SanitizerKind::Generic),
   ```
2. Mirror corresponding Python built-ins in `frensense-lang/src/providers/python.rs`:
   - `hashlib.sha256`, `hashlib.sha512`, `hashlib.md5`, `hmac.new`
   - `int`, `float`, `bool`
   - `dict.keys`, `dict.values`
3. The engine receives these through `LanguageSpec::sanitizers()` and registers them in `TaintConfig.sanitizers`. **No engine code changes needed for this task.**

---

### Task 3: Field-Sensitive Source Resolution in `frensense-engine`

**File to modify**:
- [`frensense-engine/src/analysis/forward.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/frensense-v2/frensense-engine/src/analysis/forward.rs)

#### Problem:
Currently, lines 1365–1374 in `forward.rs` contain:
```rust
let path = member_access_path(ir, *base, field);
let root = path.split('.').next().unwrap_or("");
config.sources.contains(&path) || config.sources.contains(root)
```
If `root` is in `config.sources` (or matches a broad prefix), any field access on `root` (`root.anything`) is treated as a source.

#### Technical Requirements:
1. Refactor `is_source` for `Instruction::LoadField`:
   - If the full resolved access path `path` (e.g. `c.env.KEY`) has a known sub-path that is not in `config.sources`, it must **NOT** fall back to `config.sources.contains(root)`.
   - Specifically: if `config.sources` contains `c.req`, accessing `c.env` must not match `c`.
   - Fall back to `config.sources.contains(root)` **only** if `root` itself was explicitly registered as a whole-value source and no granular field definitions exist for that root.
2. Add a unit test in `frensense-engine/src/analysis/` proving:
   - When `sources = ["ctx.request"]`
   - `ctx.request.body` -> `is_source == true`
   - `ctx.env.SECRET` -> `is_source == false`

---

### Task 4: Control-Flow Guard Sensitivity in `frensense-engine`

**Files to modify**:
- [`frensense-engine/src/analysis/forward.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/frensense-v2/frensense-engine/src/analysis/forward.rs)
- [`frensense-engine/src/analysis/taint/engine.rs`](file:///home/oxisrael/Friehub/Taas/Frensene_main/frensense-v2/frensense-engine/src/analysis/taint/engine.rs)

#### Problem:
Defensive coding patterns like `if (!validator(x)) return;` or `if (!RE.test(x)) throw err;` prevent invalid data from reaching downstream sinks. Currently, forward taint analysis propagates along all control flow edges regardless of branch conditions.

#### Technical Requirements:
1. Utilize the existing CDG / Dominance infrastructure in `frensense-engine/src/ir/control_flow.rs`.
2. Detect Guard Predicates:
   - A conditional branch `BranchCond { cond, true_block, false_block }` where `cond` is produced by a call to a function registered as `SanitizerKind::Guard` (or standard validator boolean).
   - If one of the branch targets unconditionally exits the function (`Return` or `Throw`), the surviving branch is the guarded branch.
3. On the guarded branch, prune the taint for the operand passed into the guard check.
4. Ensure the mechanism remains completely language-agnostic by operating solely on IR instruction types and generic `SanitizerKind::Guard` flags.

---

## 4. Verification & Acceptance Criteria

1. **Compilation & Clippy**:
   ```bash
   cargo clippy --all-targets -- -D warnings
   cargo test --workspace
   ```
2. **Juice Shop & Framework Regression**:
   - Ensure existing true positive benchmarks do not regress.
   - Verify that test cases containing `env.SECRET_KEY -> createHmac` produce **0 findings**.
   - Verify that test cases containing `sha256(token) -> sql_query` produce **0 findings**.
   - Verify that test cases containing `if (!valid(name)) return; query(name)` produce **0 findings**.
3. **Corpus Replay Gate**:
   - In `frensense-corpus`:
     ```bash
     make test
     ```
   - Must achieve 100% True Positive Rate and 0.00% False Positive Rate.
