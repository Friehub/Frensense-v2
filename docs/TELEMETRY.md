# Telemetry

Frensense collects telemetry **on the machine that runs the scan**. It is
written into the report you asked for and nowhere else.

- No network call. The `frensense` crate has no HTTP client and no background
  sender; a scan is fully offline and deterministic.
- No home-directory write. The only telemetry file is the one you name with
  `--profile-out`.
- No analytics, no identifiers, no machine fingerprint, no usage ping.

The word "telemetry" here means the scan's accounting of itself: what it read,
what it skipped, which safety valve truncated it, and what it cost. It exists
because "No findings" is only checkable when the report also says how much of
the code was actually looked at.

## Where it appears

| Surface | What it adds |
|---|---|
| `--json` | the `analysis` object |
| `--profile-out <file>` | `{schema_version, kind, collection, producer, telemetry}`, where `telemetry` is the same `analysis` object |
| SARIF | `invocations` plus coverage, cap and check notifications |
| MCP | the same `analysis` object, under `analysis` |
| text | coverage, undecided-site and caveat lines, the `Telemetry:` block in the scan summary, and a `Telemetry File:` line naming the `--profile-out` path when one was written |

All four come from one builder (`src/cli/telemetry.rs`), so a key means the
same thing on every surface. `analysis.schema_version` (currently `1`) versions
the payload independently of the report envelope; the committed key inventory
in that module's tests fails when a field is added without updating it.

`analysis.collection` is always `"local"`. It is in the payload so a reader
never has to guess, and so a future opt-in uploader would have to change a
value instead of silently reusing this one.

## What you see on a terminal

An interactive text scan prints one line on stderr before it starts:

```
frensense: telemetry is recorded in this report and never uploaded (paths included);
         FRENSENSE_TELEMETRY_PATHS=basename redacts them.
```

There is no first-run state: no marker file in your home directory or your
repository, because the line above promises neither. So it prints on every
interactive scan, and stays silent when stderr is not a terminal, when the
format is machine-readable (`--json`, `--sarif`, `--github`) and with
`--no-progress`.

## What is collected

Counts and timings:

- `status`, `target` (the path the scan was given, `.` included), `coverage.files_*`, `coverage.sink_sites`,
  `coverage.unresolved_sites`, `coverage.functions`
- `verdicts.{vulnerable, sanitized, unknown, no_source}`
- `graph.{functions, nodes, edges, cross_edges}`
- `funnel.{calls_examined, skipped_*, not_a_sink, sink_calls}`
- `caps[].{cap, hits, effect}`, `checks[].{id, scope, ran, findings, millis,
  outcome}`, `phases[].{phase, ms}`, `suppressed[].{reason, count}`

Engine vocabulary, not your code:

- `caps[].cap`, `suppressed[].reason`, `checks[].id`, `unresolved_sample[].sink`

Yours — file paths and symbol names:

- `coverage.failed_files_sample`, `coverage.partial_files_sample`,
  `coverage.no_sink_files_sample`, `coverage.excluded_sample[].path`,
  `coverage.unsupported_source_files.files`
- `coverage.unresolved_sample[].file`, `slowest_files[].file`,
  `slowest_functions[].{file, function}`, `funnel.unmatched_callees_sample[].callee`
- `errors[]` (worker and read failures, which may quote a path)

No source text, no findings payload, no environment variables, no secrets, and
nothing about the machine beyond what a path spells out.

## Samples are capped

Counts are bare; arrays of names end in `_sample` and are capped, because a
report is not a dump:

| Key | Cap |
|---|---|
| `coverage.failed_files_sample`, `coverage.partial_files_sample` | 25 |
| `coverage.no_sink_files_sample`, `coverage.excluded_sample`, `coverage.unresolved_sample`, `coverage.unsupported_source_files.files` | 25 |
| `slowest_files`, `slowest_functions` | 10 |
| `funnel.unmatched_callees_sample` | 8 (32 tracked while scanning) |

Every count stays exact even when its sample is truncated.

## Sharing a report

A profile attached to a bug report carries your directory layout and up to a
few dozen symbol names. Redact before you share:

```bash
FRENSENSE_TELEMETRY_PATHS=basename frensense src --profile-out profile.json
```

`FRENSENSE_TELEMETRY_PATHS` takes three values:

| Value | Effect |
|---|---|
| `absolute` (default) | the path exactly as the scan saw it |
| `relative` | relative to the current directory when the path is under it, otherwise unchanged |
| `basename` | the final component only (`index.ts`) |

Anything else is treated as `absolute`, so a typo cannot widen what a report
keeps. The policy in force is recorded in the payload as
`redaction.paths`, and `errors[]` strings are not rewritten.
