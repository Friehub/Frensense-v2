---
title: Your first scan
description: Scan a small vulnerable app, read the finding, and learn what the exit code means.
---

# Your first scan

This takes about two minutes. You need [Frensense installed](/guide/installation).

## 1. Make something to scan

Save this as `app.py` in an empty folder. It is a Flask app with two
vulnerabilities: user input goes straight into a shell command and into an SQL
query.

```python
import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()

@app.route("/user")
def user():
    uid = request.args.get("id")
    db = sqlite3.connect("app.db")
    return str(db.execute("SELECT * FROM users WHERE id = " + uid).fetchall())
```

## 2. Scan it

```bash
frensense .
```

You get one block per finding, then a summary:

```text
[CRITICAL] OS command injection: `request.get` reaches `popen`
  --> app.py:10:12 (in `ping`)

     |
   9 |     host = request.args.get("host")
  10 |     return os.popen("ping -c 1 " + host).read()
     |            ^^^^^^^^
     |
  = rule: taint.command-injection  (CWE-78)
  = why:  Attacker-supplied text reaches a shell or process launcher and can run other commands.
  = fix:  Pass arguments as a list without a shell, and validate the value against an allowlist.

[CRITICAL] SQL injection: `request.get` reaches `execute`
  --> app.py:16:16 (in `user`)
  ...
Total Findings: 2
```

## 3. Read a finding

| Part | Meaning |
| --- | --- |
| `[CRITICAL]` | Severity: `critical`, `warning` or `info`. |
| `` `request.get` reaches `popen` `` | The **source** (where untrusted data enters) and the **sink** (the dangerous call it reaches). |
| `--> app.py:10:12 (in `ping`)` | File, line and column of the sink, and the function it is in. |
| `rule: taint.command-injection (CWE-78)` | The stable rule id and its CWE number. |
| `why` and `fix` | A one-line explanation and the usual remedy. |

To see every step between source and sink, add `--show-flows`. To read about a
rule without scanning anything, run `frensense explain taint.command-injection`.

## 4. Fix them and scan again

For the command, accept only known hosts before the value reaches the shell.
For the query, pass the value as a bound parameter:

```python
@app.route("/ping")
def ping():
    host = request.args.get("host")
    if host not in ("example.com", "example.org"):
        return "unknown host", 400
    return os.popen("ping -c 1 " + host).read()

@app.route("/user")
def user():
    uid = request.args.get("id")
    db = sqlite3.connect("app.db")
    return str(db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchall())
```

Run `frensense .` again and the scan reports nothing.

::: tip The scanner learns what counts as safe
Frensense clears a finding when the value passes through something it knows is
a sanitizer or a guard. Today that includes a literal allow-list check like the
one above, `shlex.quote`, and bound query parameters. It does not recognise
every validation: a `re.fullmatch` check, for example, still leaves the
finding. If a fix you believe in does not clear a finding, that is an engine
gap worth reporting, and a good [challenge](/challenges) to take on.
:::

## What the exit code means

Frensense exits with `0` after a normal scan **even when it found something**.
That keeps a first run from breaking your shell or a script. To make findings
fail a command, ask for it:

```bash
frensense . --strict    # exit 1 if there is any finding
```

For CI you usually want the gentler rule "fail only on findings that are new",
which is [baseline gating](/guide/github-actions).

## Other output formats

```bash
frensense . --json                    # one JSON object, for scripts
frensense . --sarif -o results.sarif  # SARIF 2.1.0, for code-scanning tools
frensense . --github                  # GitHub Actions annotations
```

## Where to go next

- Findings in pull requests: [CI and agent gating](/guide/github-actions)
- Every flag: [CLI reference](/guide/cli)
- Missing a finding you expected? The engine may not know your framework yet.
  See [Bundles](/bundles).
