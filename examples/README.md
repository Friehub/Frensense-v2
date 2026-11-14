# A worked Frensense example

This folder is a small, self-contained lesson in the two halves of Frensense:

1. **A vulnerable application** that the built-in pack already scans.
2. **A corpus family** that teaches the engine one bug the built-in pack does
   not know, compiled into a `.frc` bundle.

Everything here is intentionally vulnerable. Do not deploy the app.

## The application

`notes-app/app.py` is a tiny Flask notes service. It contains four bugs:

| Bug | CWE | Where |
|---|---|---|
| SQL injection | CWE-89 | `search_notes` concatenates the query text |
| Path traversal | CWE-22 | `download_note` joins user input to `NOTES_DIR` |
| Open redirect | CWE-601 | `login` redirects to a query-string target |
| Weak password hash | CWE-328 | `hash_password` uses MD5 |
| Missing authorization | CWE-862 | `delete_note` runs with no ownership check |

The first four are built into Frensense. The last one is not: `delete_note` is
an application-specific privileged call, so the built-in pack has no reason to
know it is dangerous. That is the gap the corpus family fills. Only the learned
bug needs a corpus family; the built-in four need no training pair or held-out
twin.

## Scan the app without a bundle

From the repository root:

```bash
frensense examples/notes-app
```

Frensense reports **5 findings** (path traversal fires on both the `join` and
the `open`), but it does **not** report the unguarded `delete_note`. The
missing finding is the point of the example.

## The corpus family

```text
examples/
├── notes-app/
│   ├── app.py                 # the vulnerable application
│   └── requirements.txt
├── corpus/
│   ├── bug_classes.json       # declares authz.missing (CWE-862)
│   └── python/authz.missing/py_notes_delete/
│       ├── py_notes_delete_positive.py           # vulnerable twin
│       ├── py_notes_delete_negative.py           # fixed twin
│       ├── py_notes_delete_heldout_positive.py   # held-out, still broken
│       └── py_notes_delete_heldout_negative.py   # held-out, fixed
└── README.md                  # this file
```

The family is a **policy family**, not a taint family. A learned sink alone
does not produce a finding: the engine has no vulnerability class for an
arbitrary call. A policy family instead names a privileged trigger
(`# check-call: delete_note`) and teaches the guard that must run first. The
positive calls `delete_note` directly; the negative calls it only inside
`if owns_note(note_id, user)`.

The held-out pair is not read by the bundler. It is the generalization test:
the same trigger and the same `owns_note` helper, but a different framework
(Flask blueprint), call site and source.

## Build the bundle

```bash
# 1. Check the family: metadata, layout, purpose, and teachability.
frensense lint examples/corpus --strict --require-heldout

# 2. Compile the pair into a bundle.
frensense bundle examples/corpus examples/notes-delete.frc

# 3. Read exactly what was published.
frensense bundle info examples/notes-delete.frc
```

The lint prints `1 families, 0 errors, 0 warnings`. The bundle contains one
provisional fact:

```text
[provisional] policy:policy_delete_note(delete_note) <- py_notes_delete
```

## Scan again with the bundle

```bash
frensense examples/notes-app -b examples/notes-delete.frc
```

The same app now reports **6 findings**. The extra one is the learned policy:

```text
[WARNING] Policy violation: delete_note
  --> app.py (in `delete_note_route`)

  = rule: policy.delete-note  (CWE-862)
```

## Prove the fact generalizes

The held-out files were never part of the bundle. Scan them separately:

```bash
frensense examples/corpus/python/authz.missing/py_notes_delete/py_notes_delete_heldout_positive.py \
  -b examples/notes-delete.frc   # 1 finding

frensense examples/corpus/python/authz.missing/py_notes_delete/py_notes_delete_heldout_negative.py \
  -b examples/notes-delete.frc   # 0 findings
```

The positive fires because it calls `delete_note` unguarded. The negative stays
silent because it calls the same helper (`owns_note`) the training negative
taught. That is what "the fact generalizes" means here: it is not tied to the
file it was learned from.

## Why not just report every call to `delete_note`?

Because that is a rule, and Frensense is corpus-based. The negative shows the
same call in its safe form, and the replay gate publishes the fact only if the
positive alerts and the negative does not. A helper that merely exists in the
negative is ignored; it has to actually guard the call. The full contract is in
[the corpus authoring guide](../docs/FRENSENSE_CORPUS_GUIDE.md).

## Use the bundle on your own code

Load a bundle three ways:

```bash
frensense . -b path/to/my.frc             # explicit
cp my.frc ./frensense-corpus.frc           # auto-discovered at project root
export FRENSENSE_CORPUS_BUNDLE=my.frc      # MCP server and LSP
```

A bundle can add detections and it can add false alarms. Compare a scan with
and without it on your own code before you rely on it.
