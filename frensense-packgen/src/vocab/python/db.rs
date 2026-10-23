// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Python database / ORM sink signatures: (call, dangerous-arg-slots,
//! binding_safe). Grouped so SQLAlchemy, DB-API and Jinja template sinks
//! that share the `execute`/`render_template` naming stay together.

/// Database sink signatures: (call, dangerous-arg-slots, binding_args_safe).
/// `binding_safe: true` means the args are bound and not directly
/// injectable.
pub(crate) static PY_SINK_SIGNATURES: &[(&str, &[usize], bool)] = &[
    // ── DB-API / sqlite3 / psycopg / mysql-connector: execute(sql, params) ──
    ("execute", &[0], true),
    ("executemany", &[0], true), // executemany(sql, seq_of_params)
    // ── Django raw SQL: raw(sql, params) / extra(select, params) ──
    ("raw", &[0], true),
    // Django extra(): kwargs are interpolated into SQL, only the first
    // positional (select) is the query; params still bind. Conservative:
    // restrict to slot 0 (extra's where/tables kwargs flow by keyword, not
    // position, so positional slots 1+ are the params tuple).
    ("extra", &[0], true),
    // ── SQLAlchemy: query / prepare / raw_sql ──
    ("query", &[0], true),
    ("prepare", &[0], true),
    // ── Jinja2: render is the sink; render_template(sql_string, ctx),
    // slot 0 is the template, ctx is a binding namespace ──
    ("render_template", &[0], true),
];
