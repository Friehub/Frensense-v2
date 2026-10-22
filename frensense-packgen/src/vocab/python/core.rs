// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Python core / framework-agnostic sink names: code execution, command
//! injection, path traversal, deserialization, log leak, NoSQL injection,
//! and the DB-API / ORM SQL-injection pairs that are not Django-web
//! specific. Kept separate from the web-framework vocabulary so that adding
//! a new web framework never touches the core sink table.

use crate::role_map::SinkLabel;

/// Framework-agnostic sink names. Shared across all Python web and
/// non-web frameworks.
pub(crate) static PY_CORE_SINKS: &[(&str, SinkLabel)] = &[
    // ── Code Execution ──
    // Python builtins: the bare name IS the API. A receiver-qualified
    // call (`engine.eval(x)`) is a different method entirely, so these
    // are marked `global_only` in the language vocabulary.
    ("eval", SinkLabel::CodeExecution),
    ("exec", SinkLabel::CodeExecution),
    ("compile", SinkLabel::CodeExecution),
    // ── Command Injection ──
    // Declared under the module that owns the API. A bare `system` /
    // `run` / `popen` / `call` is an ordinary method on an unrelated
    // object (`Workflow.run`, `RuleSystem.popen`, `Handler.call`), and
    // the bare declaration made every one of them a command-injection
    // finding in any Python file.
    ("os.system", SinkLabel::CommandInjection),
    ("os.popen", SinkLabel::CommandInjection),
    ("subprocess.call", SinkLabel::CommandInjection),
    ("subprocess.run", SinkLabel::CommandInjection),
    ("subprocess.check_output", SinkLabel::CommandInjection),
    ("subprocess.Popen", SinkLabel::CommandInjection),
    ("pty.spawn", SinkLabel::CommandInjection),
    // ── SQL Injection (DB-API + ORM) ──
    ("cur.execute", SinkLabel::SqlInjection),
    ("cursor.execute", SinkLabel::SqlInjection),
    ("con.execute", SinkLabel::SqlInjection),
    ("conn.execute", SinkLabel::SqlInjection),
    ("connection.execute", SinkLabel::SqlInjection),
    ("db.execute", SinkLabel::SqlInjection),
    ("cnx.execute", SinkLabel::SqlInjection),
    ("session.execute", SinkLabel::SqlInjection),
    ("sqlite3.execute", SinkLabel::SqlInjection),
    ("sqlite3.executescript", SinkLabel::SqlInjection),
    ("psycopg2.execute", SinkLabel::SqlInjection),
    ("psycopg.execute", SinkLabel::SqlInjection),
    ("pymysql.execute", SinkLabel::SqlInjection),
    ("MySQLdb.execute", SinkLabel::SqlInjection),
    ("pyodbc.execute", SinkLabel::SqlInjection),
    ("cur.executemany", SinkLabel::SqlInjection),
    ("cursor.executemany", SinkLabel::SqlInjection),
    ("con.executemany", SinkLabel::SqlInjection),
    ("conn.executemany", SinkLabel::SqlInjection),
    ("execute", SinkLabel::SqlInjection),
    ("executemany", SinkLabel::SqlInjection),
    ("raw", SinkLabel::SqlInjection),
    ("raw_sql", SinkLabel::SqlInjection),
    ("query", SinkLabel::SqlInjection),
    ("executeRaw", SinkLabel::SqlInjection),
    ("queryRaw", SinkLabel::SqlInjection),
    // NOTE: no bare `filter` entry. `Model.objects.filter(**kwargs)` builds a
    // *parameterized* query - Django escapes the bound values - so treating
    // the call as a raw-SQL sink flagged every ORM read as an injection
    // (`User.objects.filter(id=uid)`). The raw escape hatches are `raw()` and
    // `extra()`, declared above and below.
    ("extra", SinkLabel::SqlInjection),
    ("prepare", SinkLabel::SqlInjection),
    // ── Path Traversal ──
    // `open(path)` is Python's path sink. `read`/`write` are file-HANDLE
    // methods - `f.read(n)` reads FROM the handle, `f.write(data)` writes
    // data TO it - so neither takes a path, and a tainted handle or a
    // tainted payload is not path traversal. `join` is a path
    // CONSTRUCTOR: a tainted segment only matters where the joined path
    // reaches `open`. Declaring them bare turned every `.read(...)` and
    // `.write(...)` in a program into a path-traversal finding.
    ("open", SinkLabel::PathTraversal),
    ("os.unlink", SinkLabel::PathTraversal),
    ("os.stat", SinkLabel::PathTraversal),
    ("os.access", SinkLabel::PathTraversal),
    // Path CONSTRUCTORS: a tainted segment only matters where the joined
    // path reaches `open`, so these arm only under their own module. There
    // is no bare `join` entry - `str.join`, `pathlib.joinpath` and every
    // unrelated `.join(...)` share the name.
    ("os.path.join", SinkLabel::PathTraversal),
    ("posixpath.join", SinkLabel::PathTraversal),
    // ── Unsafe Deserialization ──
    // Qualified: `pickle.loads` is unsafe deserialization while
    // `json.loads` is a safe JSON parser. The bare `loads`/`load`
    // declarations made every JSON parse in a program an
    // unsafe-deserialization finding.
    ("pickle.loads", SinkLabel::UnsafeDeserialize),
    ("pickle.load", SinkLabel::UnsafeDeserialize),
    ("yaml.load", SinkLabel::UnsafeDeserialize),
    ("marshal.loads", SinkLabel::UnsafeDeserialize),
    ("shelve.open", SinkLabel::UnsafeDeserialize),
    // No bare `loads` / `load`: `json.loads` and every signed-token
    // serializer share those names. The unsafe loaders are named by module.
    ("cPickle.loads", SinkLabel::UnsafeDeserialize),
    ("cPickle.load", SinkLabel::UnsafeDeserialize),
    ("_pickle.loads", SinkLabel::UnsafeDeserialize),
    ("dill.loads", SinkLabel::UnsafeDeserialize),
    ("dill.load", SinkLabel::UnsafeDeserialize),
    ("cloudpickle.loads", SinkLabel::UnsafeDeserialize),
    ("marshal.load", SinkLabel::UnsafeDeserialize),
    ("jsonpickle.decode", SinkLabel::UnsafeDeserialize),
    ("yaml.unsafe_load", SinkLabel::UnsafeDeserialize),
    ("yaml.load_all", SinkLabel::UnsafeDeserialize),
    // ── Log Leak ──
    ("log", SinkLabel::LogLeak),
    ("error", SinkLabel::LogLeak),
    ("info", SinkLabel::LogLeak),
    ("debug", SinkLabel::LogLeak),
    // ── NoSQL Injection ──
    ("$where", SinkLabel::NoSqlInjection),
    ("$regex", SinkLabel::NoSqlInjection),
    ("$gt", SinkLabel::NoSqlInjection),
    ("$lt", SinkLabel::NoSqlInjection),
    ("$ne", SinkLabel::NoSqlInjection),
    ("$in", SinkLabel::NoSqlInjection),
    ("$nin", SinkLabel::NoSqlInjection),
    ("$exists", SinkLabel::NoSqlInjection),
    ("$expr", SinkLabel::NoSqlInjection),
    ("$function", SinkLabel::NoSqlInjection),
    ("$accumulator", SinkLabel::NoSqlInjection),
];
