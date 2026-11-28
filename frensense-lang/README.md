# frensense-lang

Per-language source knowledge for [Frensense](https://github.com/Friehub/Frensense-v2):
the tree-sitter node-kind specs each front end lowers through, plus the shared
severity and sink-role vocabulary every producer speaks.

> Part of [Frensense](https://github.com/Friehub/Frensense-v2) - a
> deterministic SAST scanner. Docs: <https://frensense.friehub.cloud>.

---

## What it does

- **AST specs** (`src/specs/`, `src/providers/`): one `LanguageSpec` per
  language (TypeScript/JavaScript, Python, Go, Rust, C, Vue), mapping node
  kinds to the roles the lowering needs. Specs are looked up by file
  extension with `spec_for_ext`, so no lowering code carries a hardcoded
  node-kind string.
- **Severity vocabulary** (`src/severity/`): `SinkRole`, `SanitizerKind` and
  the label ↔ role mapping. A sanitizer's `kind` is *what injection it
  defeats* (`html_escape`, `sql_parameterize`, `shell_quote`, ...), and the
  engine branches on it rather than on a sanitizer's name.
- **Intrinsics** (`src/intrinsics.rs`): calls whose semantics the engine must
  know regardless of project (`len`, `typeof`, allocators), so a
  language-specific shape never has to be special-cased in the walk.

The crate holds no analysis logic: it answers "what is this syntax node" and
"what does this sanitizer strength mean". The engine consumes both through
`frensense-engine`.

## Building

```sh
cargo build -p frensense-lang
cargo test -p frensense-lang
```

The public API snapshot lives in
[`api/frensense-lang.txt`](https://github.com/Friehub/Frensense-v2/blob/main/api/frensense-lang.txt).

## License

GPL-3.0-only. Using it in a proprietary product needs a separate license:
<https://friehub.cloud/licensing>.
