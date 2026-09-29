# Frensense Teachable Static Analysis Architecture

Frensense v2 is built with a strict separation between **analysis mechanics** and **security domain knowledge**:

1. **The Engine Core (`frensense-engine`)**: A deterministic compiler that lowers source code across multiple languages to a common Intermediate Representation (IR), builds Control Flow Graphs (CFG), Static Single Assignment (SSA) def-use chains, and an interprocedural Sparse Value Flow Graph (SVFG).
2. **Knowledge Bundles (`.frc`)**: Self-contained, blake3-checksummed binary packages carrying learned facts that teach the engine about frameworks, APIs, sinks, sources, and policies.

This design makes Frensense 100% teachable without modifying engine source code or learning proprietary query languages (such as CodeQL QL or Semgrep DSL).

---

## 1. The Twin-Example Learning Model

Knowledge extraction operates on **corpus families**: pairs of positive (vulnerable) and negative (remediated) code examples.

```
family/
  ├── family_positive.<ext>   # Vulnerable pattern
  └── family_negative.<ext>   # Remediated pattern
```

### Extraction Workflow
1. **Lowering**: Both files are parsed via Tree-Sitter and lowered to Frensense IR.
2. **Differential Analysis**: The bundler (`frensense-bundler`) compares the two IR graphs to isolate the exact point of divergence:
   - Was a dangerous sink call removed or replaced?
   - Was a sanitizer or escaping function inserted?
   - Was an authorization or range check guard added?
3. **Candidate Proposal**: The bundler formulates a candidate `LearnedFactEntry`.
4. **Replay Verification Gate**:
   - The engine is instantiated with the candidate fact.
   - The positive file is scanned; it must alert with expected severity and classification.
   - The negative file is scanned; it must produce zero findings.
   - Regression prevention: All other families in the corpus must maintain their existing verdicts.
   - Facts that fail this test are discarded. Facts that pass are serialized into the `.frc` bundle.

---

## 2. The 13 Teachable Subsystems

The table below details the 13 subsystems supported by `LearnedFactEntry` (located in `frensense-engine/src/analysis/taint/facts.rs`):

| # | Fact Variant | Scope & Responsibility | Engine Impact |
|---|---|---|---|
| **1** | `Sink { call, dangerous_args, binding_args_safe }` | Named function or method call that executes dangerous operations when tainted. Supports slot-specific danger and parameterized safe binding channels. | Taint analyzer checks if any path from an untrusted source reaches the designated argument slot. |
| **2** | `Source { pattern }` | Named call or property access that introduces untrusted external data into the function scope. | Injected into `TaintConfig::sources` during IR scanning. |
| **3** | `Sanitizer { call, kind, guard_style }` | Function that strips taint from its inputs or guards an execution branch. | Cuts taint flow on paths passing through the sanitizer. |
| **4** | `Propagator { call, input_args, preserves_taint }` | Helper call or transformation that transfers taint from arguments to return value. | Propagates taint across unmodeled utility wrappers and converters. |
| **5** | `Policy { rule, when_call, require, scope, ... }` | Co-occurrence requirement: when `when_call` is present, specified guards, bound checks, or argument requirements must also be satisfied. | Evaluated by `checks::policy` across function or module scope. |
| **6** | `Check { rule, call, message, unless_guard, ... }` | Structural, non-dataflow pattern check firing on presence of a call unless qualified by a guard or bound check. | Legacy check fact, losslessly normalized into `PolicyFact`. |
| **7** | `MemoryContract { name, returns_fresh, return_capacity, consumes_params }` | Interprocedural heap allocation and deallocation signatures for systems languages (C, Rust). | Powers Use-After-Free (UAF) and Double-Free checkers. |
| **8** | `WeakCrypto(WeakCryptoFact)` | Detection of obsolete or broken hashing, cipher, or PRNG primitives. | Evaluated by `checks::weak_hash` and cryptographic rule checkers. |
| **9** | `GuardBypass(GuardBypassFact)` | Allowlist containment callees and credential sink identifiers. | Detects flawed URL/hostname allowlist bypasses and credential leakage. |
| **10** | `SchemaPolicy(SchemaPolicyFact)` | Identifiers for schema validation builders, enforcers, and bound keywords. | Suppresses alerts when inputs pass through certified schema validators. |
| **11** | `GrammarRole { language, node_kind, role }` | Dynamic Tree-Sitter AST node role mapping (Functions, Calls, Declarations, Branches). | Allows the engine to parse and classify new language constructs dynamically. |
| **12** | `GrammarFeature { language, node_kind, feature }` | Dynamic syntax feature classification (Destructuring, Template Strings, Ternaries). | Extends IR lowering logic to support language-specific expressions. |
| **13** | `IdorFinderSink { call, keys }` | Data-access query methods and multi-tenant access control payload keys. | Flags object-level queries missing required tenant/ownership scoping keys. |

---

## 3. Working with `.frc` Bundles

### Building a Knowledge Bundle
```bash
# Group and compile all positive/negative families in a directory
frensense-bundler path/to/corpus output_bundle.frc
```

### Scanning with a Knowledge Bundle
```bash
# Explicit flag
frensense path/to/project --corpus-bundle output_bundle.frc

# Environment variable (used by MCP and LSP servers)
export FRENSENSE_CORPUS_BUNDLE=/path/to/output_bundle.frc
frensense path/to/project

# Auto-discovery
# Drop 'frensense-corpus.frc' in the project root; the CLI auto-discovers it.
```

### Safe Fact Precedence
When merging bundle facts over built-in language tables:
- Learned facts take precedence over built-in defaults.
- Narrow knowledge cannot be widened: an "all arguments dangerous" rule from a generic spec cannot overwrite a specific, slot-restricted signature learned by a bundle.
- Multiple bundles accumulate additively with deduplication on `(rule, call)` pairs.
