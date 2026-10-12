# frensense-devtools

Internal developer tools and probe utilities for the Frensense static analysis engine.

> **Note**: This crate is marked with `publish = false` in `Cargo.toml`. It is an internal workspace package used exclusively during engine development, AST lowering debugging, and end-to-end regression verification. It is not published to crates.io.

---

## Utilities Included

The crate provides three binary utilities in `src/bin/`:

### 1. `ast_probe`
Dumps the named Tree-sitter AST nodes of a given TypeScript source file along with token excerpts and field names.
- **Purpose**: Diagnoses missing constructs or grammar node mismatches during SSA/IR lowering.
- **Usage**:
  ```sh
  cargo run -p frensense-devtools --bin ast_probe -- <path-to-file.ts>
  ```

### 2. `e2e_taint`
End-to-end taint propagation probe that runs lowered SSA IR analysis over real corpus target files.
- **Purpose**: Exercises arrow function handlers, member calls, and router registration shapes against taint sources, sinks, and sanitizers.
- **Usage**:
  ```sh
  cargo run -p frensense-devtools --bin e2e_taint -- <path-to-file.ts>
  ```

### 3. `e2e_batch`
Batch pipeline runner executing over entire sets of corpus target files.
- **Purpose**: Validates pipeline classifications based on corpus file naming invariants (`*_positive.ts` must yield findings, `*_negative.ts` must remain clean).
- **Usage**:
  ```sh
  cargo run -p frensense-devtools --bin e2e_batch -- <corpus-directory>
  ```

---

## License

GPL-3.0-only - see [LICENSE](../LICENSE).
