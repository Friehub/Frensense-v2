// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

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
    // ── XPath: slot 0 is the expression, every other argument binds into
    // it. `tree.xpath(expr, name=value)` binds the XPath variable `$name`,
    // and `lxml.etree.XPath(expr)` compiles the expression: a tainted
    // *binding* or namespace map cannot change the compiled expression, so
    // `name=bar` is a parameter channel, not injection. Restricting the
    // slot removed the false positives on the OWASP xpathi binding family
    // while leaving the concatenated-expression findings intact.
    ("xpath", &[0], true),
    ("XPath", &[0], true),
    // elementpath.select(root, expr): slot 1 is the expression.
    ("elementpath.select", &[1], true),
];
