---
title: "Teaching a Static Analyzer Like a Human: How We Made Frensense 100% Teachable"
date: 2026-09-29
description: How Frensense replaced fragile pattern rules and hardcoded engine updates with a compiler that learns security vulnerabilities directly from positive and negative examples.
---

# Teaching a Static Analyzer Like a Human: How We Made Frensense 100% Teachable

If you want to train a junior security engineer to recognize a new vulnerability in your codebase, you do not perform brain surgery on them. You do not ask them to write a hundred lines of formal logic or wait six months for a textbook update.

Instead, you show them two examples:

1. **The Vulnerable Version**: "Here is what the vulnerable code looked like before the incident."
2. **The Fixed Version**: "Here is how our engineering team fixed it safely."

Within seconds, their brain extracts the key difference: which function was dangerous, what input was uncontrolled, and what security check neutralized the threat.

For the past twenty years, static application security testing (SAST) has operated in the exact opposite manner. If a new library was released, or if your team adopted a modern framework like Next.js or FastAPI, you faced two painful options:
- Learn a complex, proprietary query language (such as CodeQL or Semgrep DSL) and write intricate AST patterns by hand.
- Wait for a commercial SAST vendor to release an engine update months later.

Even worse, when custom rules were written, they were often dumb pattern matches. They alerted whenever a function name appeared, flooding developers with false positives because the rule could not tell whether the input was actually dangerous or already sanitized.

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

---

## Why This Changes Static Analysis

1. **Zero Rust Code Required**: Security teams do not need to understand Rust, compiler ASTs, or control-flow graphs. If you can write the bug and its fix in your application's native language (Python, TypeScript, Go, C), you can teach Frensense.
2. **Deterministic & Portable**: Knowledge bundles (`.frc`) are lightweight, versioned, checksummed binary files. You can commit them to your repository, share them across microservices, or load them directly into your CI/CD pipeline.
3. **No False-Positive Creep**: Because every learned fact must prove that it separates the vulnerable code from the safe code during replay verification, rules cannot be published if they flag safe code.

The engine provides the reasoning power; your team provides the examples. That is how static analysis keeps pace with modern engineering.
