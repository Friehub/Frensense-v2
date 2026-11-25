# frensense-packgen

Builds the default knowledge pack of [Frensense](https://github.com/Friehub/Frensense-v2):
the committed `.frc` asset
[`frensense-bundler/assets/frensense-default.frc`](https://github.com/Friehub/Frensense-v2/blob/main/frensense-bundler/assets/frensense-default.frc)
that ships inside the scanner, generated from the per-language vocabularies in
`src/vocab/`.

> Part of [Frensense](https://github.com/Friehub/Frensense-v2) - a
> deterministic SAST scanner. Docs: <https://friehub.cloud>.

---

## What it does

`src/vocab/` is the single source of truth for built-in language knowledge -
sink names and their argument slots, sources, sanitizers and their strengths,
propagators, session roots, route patterns. `build_default_bundle()` lowers
that vocabulary into `LearnedFactEntry` values and serializes them into a
`.frc` envelope with no patterns and no metadata tables.

The scanner reads the committed asset through `include_bytes!` and parses it
lazily, so regenerating it is the only way a vocabulary change reaches a build.

## Regenerating the asset

```sh
# check the committed asset matches the generator
cargo run -p frensense-packgen -- --check

# rewrite it (writes both packgen/assets and frensense-bundler/assets)
cargo run -p frensense-packgen -- --out

# or from tests, when only the embedded copy drifted
cargo test -p frensense-packgen regenerate_default_pack_asset -- --ignored
```

A bundle is positional on the wire, so a vocabulary change must be paired with
a `BUNDLE_VERSION` bump in `frensense-bundler` (the artifact-format ratchet
enforces this). This crate is never published to crates.io.

## License

GPL-3.0-only. Using it in a proprietary product needs a separate license:
<https://friehub.cloud/licensing>.
