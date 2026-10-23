---
written-against-version: 0.7.0
fact-checked: "2026-10-24"
source-revision: 8a0ef9d-dirty
title: "Teaching a Static Analyzer Like a Human: Learning Detection from Twin Examples"
date: 2026-09-29
description: How Frensense replaced fragile pattern rules and hardcoded engine updates with a compiler that learns security vulnerabilities directly from positive and negative examples - and how every fact must prove itself before it ships.
---

> **Provenance.** Written against Frensense 0.7.x; fact-checked on source
> rev `d6cfd3f` (0.8.0-beta). Mechanism references:
> `frensense-bundler/src/pipeline.rs`, `frensense-bundler/src/builder.rs`,
> `docs/FRENSENSE_CORPUS_GUIDE.md`, `docs/TEACHABILITY.md`.

# Teaching a Static Analyzer Like a Human: Learning Detection from Twin Examples

If you want to train a junior security engineer to recognize a new vulnerability in your codebase, you do not perform brain surgery on them. You do not ask them to write a hundred lines of formal logic or wait six months for a textbook update.

Instead, you show them two examples:

1. **The Vulnerable Version**: "Here is what the vulnerable code looked like before the incident."
2. **The Fixed Version**: "Here is how our engineering team fixed it safely."

Within seconds, their brain extracts the key difference: which function was dangerous, what input was uncontrolled, and what security check neutralized the threat.

For the past twenty years, static application security testing (SAST) has operated in the exact opposite manner. If a new library was released, or if your team adopted a modern framework like Next.js or FastAPI, you faced two real options:
- First learn a query or pattern language new to your team (CodeQL's QL or Semgrep's rule DSL), then hand-author and maintain intricate AST patterns.
- Wait for a vendor to release coverage for the new framework.

Even worse, once custom rules exist they are usually kept by whoever wrote them; many encode a shape rather than the dataflow - they alert whenever a function name matches, whether or not the input is actually dangerous or already sanitized. Both CodeQL and Semgrep offer deeper taint machinery (more analysis types than Frensense ships), but someone must still write, review, and validate each rule.

With Frensense v2, we solved this problem by decoupling the engine into two distinct systems:
- **A Compiler-Grade Analysis Engine** (`frensense-engine`): It understands how data moves through variables, memory, function calls, and branch conditions, but contains zero hardcoded vendor rules.
- **A Machine-Consumable Knowledge System** (`.frc` bundles): It learns new security facts automatically from pairs of vulnerable and safe code.

---

## The Core Concept: Twin Examples Instead of Rules

In Frensense, you never write rules or YAML configurations. You author a **corpus family** consisting of two files:

```
my_bug/
  ├── my_bug_positive.ts   # The vulnerable example
  └── my_bug_negative.ts   # The safe / remediated example
```

When you run the Frensense bundler, the system lowers both files into its internal compiler representation (Intermediate Representation, or IR). It asks three deterministic questions:
1. What dangerous call or behavior occurs in the positive file?
2. What check, sanitizer, or structure in the negative file makes it safe?
3. What is the minimal, generalizable fact that separates the two?

Once the fact is extracted, the bundler runs a **replay verification gate**. It installs the candidate fact into a fresh engine instance and scans your entire corpus. The fact is published only if:
- The positive case triggers an alert.
- The negative case stays completely silent.
- Zero existing test cases in your library regress.

If a proposed rule produces false positives on clean code, it is rejected automatically at build time.

---

## What the Engine Actually Learns: The 13 Dimensions

Teachability in Frensense is not just about learning function names. Real-world vulnerabilities manifest in many different ways. The Frensense fact table supports 13 teachable dimensions:

| Security Dimension | What Frensense Learns | Real-World Example |
| :--- | :--- | :--- |
| **Dangerous Sinks** | Which argument position is dangerous vs safe. | In database queries, slot 0 is the raw query string (dangerous), while slot 1 is a parameter list (safe). |
| **Taint Sources** | Where untrusted external data enters the program. | HTTP query parameters, headers, or request bodies. |
| **Sanitizers** | Which functions neutralize the danger. | HTML entity escaping, URL encoding, or cryptographic hashing. |
| **Data Propagators** | How data transforms as it moves through helpers. | Base64 decoders, string formatters, or array appends. |
| **Security Policies** | Required checks that must happen before an action. | Requiring an authorization check before deleting a record. |
| **Structural Checks** | Code configuration and property validation. | Checking that cookies set `secure=True` and `httpOnly=True`. |
| **Memory Contracts** | Which functions allocate or free heap memory. | Custom memory pools and safe cleanup wrappers in C/Rust. |
| **Cryptographic Rules** | Obsolete or weak cryptographic primitives. | Flagging MD5 or DES in security contexts while allowing SHA-256. |
| **Authorization Guards** | Safe access-control helpers. | Validating tenant IDs before fetching sensitive records. |
| **Schema Validation** | Input schema builders and enforcers. | Recognizing Zod, Yup, or Pydantic parsers. |
| **Grammar Syntax** | How to parse new language expressions. | Supporting new syntax patterns without recompiling tree-sitter. |
| **Grammar Features** | Complex language patterns like destructuring. | Tracking data through object destructuring and template strings. |
| **IDOR & Multi-Tenancy** | Database queries missing tenant ownership filters. | Flagging lookups that filter by record ID but omit account ID. |

---

## A Real-World Example: Teaching Next.js Server Components

Consider a modern React / Next.js application. In React Server Components (RSC), code inside server components can safely access internal database secrets. However, if that data is passed across the `'use client'` boundary to a client-side component, it leaks sensitive data directly to the user's browser.

Traditional static analyzers have no built-in concept of Next.js boundaries unless an engineer hardcodes a custom plugin. In Frensense, we taught the engine this rule using twin files:

### The Vulnerable Case (`rsc_leak_positive.ts`)
```typescript
// 'use client' boundary exposes server data to browser
"use client";

export function UserProfile({ secretApiKey }: { secretApiKey: string }) {
  return <div>API Key: {secretApiKey}</div>;
}
```

### The Safe Case (`rsc_leak_negative.ts`)
```typescript
// SAFE: Public display profile omits server secrets
"use client";

export function UserProfile({ publicName }: { publicName: string }) {
  return <div>Welcome, {publicName}</div>;
}
```

### The Result
The bundler analyzed the pair, extracted the policy requirement governing data crossing the client boundary, verified that the negative version passed cleanly, and emitted a compiled `.frc` bundle.

When scanned with the bundle:
```bash
frensense src/ --corpus-bundle nextjs.frc
```
The scanner flagged the leak immediately, providing the exact variable path from server component to client rendering.

**One authoring constraint worth being explicit about:** facts are matched
by *call name* (the last segment of a call), so a family whose positive and
negative differ only in a directive or a property - without a call whose
presence/absence or guarding separates them - does not teach a fact. Aspect
shaped like the RSC example above should anchor their trigger on a call
(the data-crossing handler, or a serialization helper at the boundary).
`provisional` facts (support of one family) ship but should be confirmed by
a second independently authored family; the bundler prints the status of
every fact it publishes, and `FXDBG=1` shows why a candidate was rejected.

---

## Why This Changes Static Analysis

1. **Zero Rust Code Required**: Security teams do not need to understand Rust, compiler ASTs, or control-flow graphs. If you can write the bug and its fix in your application's native language (Python, TypeScript, Go, C), you can teach Frensense.
2. **Deterministic & Portable**: Knowledge bundles (`.frc`) are lightweight, versioned, checksummed binary files. You can commit them to your repository, share them across microservices, or load them directly into your CI/CD pipeline.
3. **False positives are bounded by the corpus, not by hope**: every learned fact must prove, at build time over the corpus it was mined from, that it separates the vulnerable code from the safe code. That is a specific, checkable guarantee - "does not fire on the negatives this family demonstrates" - not a claim of universal zero false positives on code you never showed it. The strength of a bundle scales with how many twins its families carry (more negatives per family = a stricter gate), and the `provisional`/`confirmed` status printed at build time tells you how much support each fact has.

The engine provides the reasoning power; your team provides the examples. That is how static analysis keeps pace with modern engineering.
