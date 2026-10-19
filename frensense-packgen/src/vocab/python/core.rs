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
    ("eval", SinkLabel::CodeExecution),
    ("exec", SinkLabel::CodeExecution),
    ("compile", SinkLabel::CodeExecution),
    // ── Command Injection ──
    ("system", SinkLabel::CommandInjection),
    ("popen", SinkLabel::CommandInjection),
    ("call", SinkLabel::CommandInjection),
    ("run", SinkLabel::CommandInjection),
    ("check_output", SinkLabel::CommandInjection),
    ("Popen", SinkLabel::CommandInjection),
    ("execfile", SinkLabel::CommandInjection),
    // ── SQL Injection (DB-API + ORM) ──
    ("cur.execute", SinkLabel::SqlInjection),
    ("cursor.execute", SinkLabel::SqlInjection),
    ("con.execute", SinkLabel::SqlInjection),
    ("conn.execute", SinkLabel::SqlInjection),
    ("connection.execute", SinkLabel::SqlInjection),
    ("db.execute", SinkLabel::SqlInjection),
    ("cnx.execute", SinkLabel::SqlInjection),
    ("session.execute", SinkLabel::SqlInjection),
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
    ("open", SinkLabel::PathTraversal),
    ("read", SinkLabel::PathTraversal),
    ("write", SinkLabel::PathTraversal),
    ("join", SinkLabel::PathTraversal),
    ("unlink", SinkLabel::PathTraversal),
    ("stat", SinkLabel::PathTraversal),
    ("access", SinkLabel::PathTraversal),
    // ── XSS (reflected) ──
    ("make_response", SinkLabel::XssReflected),
    // ── Unsafe Deserialization ──
    ("pickle.loads", SinkLabel::UnsafeDeserialize),
    ("pickle.load", SinkLabel::UnsafeDeserialize),
    ("yaml.load", SinkLabel::UnsafeDeserialize),
    ("marshal.loads", SinkLabel::UnsafeDeserialize),
    ("shelve.open", SinkLabel::UnsafeDeserialize),
    ("loads", SinkLabel::UnsafeDeserialize),
    ("load", SinkLabel::UnsafeDeserialize),
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
