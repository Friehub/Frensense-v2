---
title: Language crate
description: Use frensense-lang on its own — parse with the right grammar and classify nodes without the engine.
---

# Use the language crate

`frensense-lang` is the crate that holds what Frensense knows about each
language: which tree-sitter grammar a file uses, which node is a function, a
call or a member access, how imports are extracted, and which packages belong
to which sink category. It does not depend on the engine, so your own Rust
project can use that knowledge directly.

```bash
cargo add frensense-lang

# Or only the grammars you need:
cargo add frensense-lang --no-default-features --features typescript,python
```

## Parse a file

`parse` applies the spec's grammar and its preprocessing (a Vue SFC's markup is
blanked so the TypeScript parser sees only the script block, at the same byte
offsets), then returns the tree together with the text its byte ranges index.

```rust
use frensense_lang::{parse, spec_for_ext, NodeRole};

let spec = spec_for_ext("ts").expect("TypeScript is registered");
let parsed = parse(spec, "const id = req.query.id;\n")?;

assert!(!parsed.has_errors()); // false: the whole file parsed
assert_eq!(parsed.text(), "const id = req.query.id;\n");

let mut stack = vec![parsed.root_node()];
while let Some(node) = stack.pop() {
    match spec.classify(node.kind()) {
        NodeRole::Call { callee_field, .. } => {
            // `callee_field` names the grammar's callee field, so the same
            // arm works for JS, Go, Rust and Python.
        }
        _ => {}
    }
    // Push the children you want to visit.
}
```

tree-sitter does not fail on a syntax error: it returns a tree containing
`ERROR` or missing nodes. `has_errors()` is what tells a caller to report the
file as "partially analyzed" rather than clean.

## Look up a language

`spec_for_ext("py")` and `spec_for_path(path)` answer from the global registry,
which contains every language the crate's Cargo features enabled, and
`all_specs()` iterates them.

```rust
use std::path::Path;

use frensense_lang::{spec_for_ext, spec_for_path};

let spec = spec_for_path(Path::new("src/app.py")).expect("python is registered");
let same = spec_for_ext("py").expect("python is registered");
assert_eq!(spec.name(), same.name());
```

## Register your own language

A spec is a `LanguageSpec`: grammar, extensions, node classification, import
extraction, package categories. Implement it, then put it in a registry you
own. The global registry is immutable and unaffected.

```rust
use std::sync::Arc;

use frensense_lang::LanguageRegistry;

// Nothing registered: only what you add answers.
let mut registry = LanguageRegistry::new();

// ... or start from the feature-gated built-ins and add on top:
// let mut registry = LanguageRegistry::with_default_specs();

registry.register(Arc::new(MySpec));

let spec = registry.for_extension("myext").expect("just registered");
let parsed = frensense_lang::parse(spec, source)?;
```

Registering an extension a built-in already claims overrides it for that
registry only, which is how you narrow or extend one file type.

## Without parsing

Rule cards, severities, sink roles and CWE tables are usable on their own, so a
project can share Frensense's vocabulary for its own findings even if it parses
with something else.

## API reference

The generated documentation for every item is at
[`/rustdoc/frensense_lang/`](/rustdoc/frensense_lang/), and each additive
release is recorded in the crate's changelog.
