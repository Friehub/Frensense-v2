# Changelog
All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`frensense-packgen` is not published to a registry (`publish = false`). It is
the maintainer-side generator for the built-in vocabulary: the tables in
`src/vocab/` are emitted deterministically as `LearnedFactEntry` facts into
`frensense-bundler/assets/frensense-default.frc`, which the bundler embeds with
`include_bytes!`. Its changes reach users through that asset, so this file
records what moved in the default pack and why. `cargo run -p frensense-packgen
-- --check` fails CI if the asset drifts from the generator; the entries below
are the reasons the asset moved.

There is no semver contract here (nothing is published, and
`cargo semver-checks` excludes it). The version tracks the workspace line.

## [0.8.2]

### Added

- **Framework-specific knowledge files for JavaScript and TypeScript.**
  Reorganized the JS/TS vocabulary out of a single monolithic table into
  per-framework modules:
  - `nextjs.rs`: Package-scoped sinks for `NextResponse.redirect`, `NextResponse.rewrite`,
    `NextResponse.json` (`next/server`), `redirect`, `permanentRedirect` (`next/navigation`),
    `revalidatePath`, `revalidateTag` (`next/cache`); request sources for `cookies`, `headers`,
    `useSearchParams`, `useParams`, `usePathname`, `request.nextUrl.*`.
  - `vue.rs`: Package-scoped sinks for `navigateTo`, `router.push`, `router.replace`
    (`vue-router`, `@vue/router`); source patterns for route parameters/query; reactivity
    propagators for `ref`, `reactive`, `computed`, `toRef`, `toRefs`, and Pinia stores.
  - `nestjs.rs`: Package-scoped SQL/NoSQL sinks for `@nestjs/typeorm` (`query`,
    `createQueryBuilder`, `execute`) and `@nestjs/mongoose` (`find`, `findOne`, `findById`,
    `updateOne`, `updateMany`, `deleteOne`, `deleteMany`); route decorators (`@Get`, `@Post`,
    `@Put`, `@Delete`, `@Patch`, `@All`).
  - `nuxt.rs`: Package-scoped sinks for `sendRedirect`, `setResponseHeader`,
    `appendResponseHeader` (`h3`), `$fetch` (`ofetch`, `nuxt`), `useFetch`, `useAsyncData`,
    `navigateTo` (`nuxt`); request extractors for `getQuery`, `readBody`, etc.
  - `core.rs`: Generic DOM, Node.js, and core JavaScript/TypeScript APIs.

## [0.8.1]

### Added

- **`href` and `src` are sinks.** A JSX attribute lowers to a property store
  on the props object, so `<a href={target}>` is a `StoreField` named `href`
  and `<iframe src={user} />` one named `src`; the pack declared neither name,
  which is why #123's second repro found no sink site at all. Both are now
  declared bare in the JavaScript/TypeScript XSS vocabulary, the same shape
  `innerHTML` and `dangerouslySetInnerHTML` already use: the store path arms
  on the field name when the write has no receiver root to qualify it, and a
  URL attribute the browser resolves as code (`javascript:...`) is reflected
  XSS. The taint rule is unchanged - `<a href="/static">` stays clean and
  `<a href={req.body.target}>` alerts. `location.href` keeps its
  OpenRedirect role through its own receiver pair; the bare name only adds
  the attribute and element shapes that pair never matched.

### Changed

- **`xpath`/`XPath` take a slot signature: argument 0 only.** The Python
  vocabulary declared neither name, so the sink fell back to "all arguments
  dangerous" and every keyword binding was reported as expression injection:
  `tree.xpath(expr, name=value)` binds `value` as an XPath variable, and
  `lxml.etree.XPath(expr)` compiles the expression, so a tainted *binding* or
  namespace map cannot change the compiled query. Both calls now declare slot 0
  as the expression and mark the remaining slots as binding arguments;
  concatenated expressions keep firing. Measured on the 1,230-case OWASP suite:
  CWE-643 FP **14 → 2**, TP **14 → 22**. The regenerated
  `frensense-bundler/assets/frensense-default.frc` is committed with this
  change.
- **`getvalue` propagates its receiver; `get` does not.** `io.StringIO.getvalue`
  returns everything written with `write`, so the receiver's taint is what the
  call yields. `get` is deliberately not declared: `ConfigParser.get(s, k)` and
  `dict.get(k)` are keyed reads that the engine resolves through the keyed store
  edge, and a receiver-wide rule would return every value the object ever stored
  whichever key was asked for.
- **Built-in weak-hash, insecure-config and key-size rules carry no
  `message`.** The scanner renders a spec rule's observation from the
  `frensense-lang` template keyed by rule id and `params`; the pack's copy was
  a second source of the same prose that the engine never read (and, while it
  was part of the fact's identity, could not be overridden). Bundle-authored
  rules keep their own message. The regenerated
  `frensense-bundler/assets/frensense-default.frc` is committed with this
  change.

## [0.8.0]

### Changed
- **The guard denylist now carries the string-literal break-out characters.**
  `BOOTSTRAP_GUARD_DENYLIST` had one entry, `..`, so the engine could only
  recognize a path-traversal rejection. An early return on a quote
  (`if "'" in bar: return`, `if value.includes('"') throw ...`) is the same
  author validation for XPath, SQL, shell and HTML string contexts: the
  surviving branch has no delimiter left to break out of the literal, but the
  guard map saw an ordinary comparison and the value still reached the sink.
  Adding `'` and `"` turns those into recognized guards. Measured on OWASP
  BenchmarkPython: FP **40 -> 32** (the eight XPath/command-injection safe
  tests built on `if "'" in bar: return`), TP unchanged at **172**, score
  **32.9% -> 33.9%**. The regenerated asset is in `frensense-bundler`.
- **Cross-language sink contamination removed from the vocabulary tables**: the
  Python, Go, C, and Rust tables carried large copy-pasted blocks of foreign
  APIs (JS DOM sinks like `innerHTML`/`dangerouslySetInnerHTML`, Express
  `res.send`, Node `spawnSync`/`readFile`, prototype-pollution
  `Object.assign`/`_.set`, Cloudflare Workers and Prisma bindings, camelCase
  MongoDB driver verbs, Flask `render_template` in Go/C/Rust, Rust
  `bincode`/`serde_json` in Python/Go/C). Because the engine registers each
  dotted entry's last segment as a bare sink, every one of these was a
  false-positive generator for the host language - e.g. a Go `Object.assign`
  entry made every Go `.assign(` call a prototype-pollution sink, and Go/C's
  `_.set` made every `.set(` call one. All foreign entries are removed; each
  table now contains only APIs that exist in its own language. Default pack
  93,036 -> 82,697 bytes. OWASP score unchanged (25.9%). The engine half of the
  fix (install-time language scoping) is in `frensense-engine`, without which
  removing the entries alone was not sufficient.
- **Duplicate propagator keys removed per language**: `join`/`Join` was declared
  twice in Python, Go and JS (a string/array method and a path builder sharing
  one bare call key), and JS declared `toString` twice. Order decided which one
  won, which silently dropped the string/array-`join` receiver->return flow.
  The duplicates are gone and a regression test asserts no duplicate propagator
  keys per language, so the `last-wins` engine install has nothing to arbitrate.
- **C buffer vocabulary covers appends, copies and formatted writes**: the
  buffer contract named only `strcpy`, a source-less `strncpy` and a source-less
  `snprintf`, so `strcat(buf, argv[1]); system(buf)` stayed silent while the
  same `strcpy` flow alerted. It now carries `stpcpy`, `strlcpy`, `strcat`,
  `strncat`, `strlcat`, `sprintf` and `snprintf` with their source arguments
  (`strncat`/`strlcpy`/`strlcat` sourced from argument 1, bounded by argument 2;
  `sprintf`/`snprintf` sourced from the first variadic argument, the one the
  format consumes). Pack asset 92,422 -> 92,701 bytes.
- **The last two name-based engine guesses are now tables here**:
  `HintKind::PreparedStatementPrefix` and `HintKind::WeakHashDisclaimer` carry
  the "a call named `prepare*` returns a bound statement handle" and "a literal
  `false` argument disclaims security use of a weak digest" vocabularies. An
  empty set recognises nothing, so a config that teaches nothing never
  suppresses a flow. OWASP BenchmarkPython and the 92-finding real-repo
  baseline are unchanged by the move.
- **Default pack regenerated under the v7 envelope** so the embedded asset
  records its fact-vocabulary fingerprint. Any vocabulary edit here changes
  `FACT_VOCABULARY_FINGERPRINT`, which `scripts/format-ratchet.py` requires to
  come with a `BUNDLE_VERSION` bump and a note in
  `frensense-bundler/CHANGELOG.md`.

### Added
- **`package:` metadata parsing**: a corpus family's `// package: <framework>`
  header is parsed here and forwarded to the emitted facts, so the generated
  tables and bundle-compiled facts carry the same provenance field.
