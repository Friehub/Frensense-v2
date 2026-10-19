// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Regressions for two recall gaps found while re-measuring the framework
//! matrix against the pre-WI-41/51/56 baseline:
//!
//! 1. Go `http.Get(url)`: the `net/http` transport functions lower to a
//!    receiver call whose method name (`Get`) collides with sqlx's per-slot
//!    signature (`db.Get(dest, query)` declares slot 1 only). The bare-name
//!    slot rule silently swallowed the SSRF at slot 0. The package-scoped
//!    `net/http` fact now supplies the all-args layout and the walk consults
//!    it through the call's import origin.
//! 2. Python `if not uid.isdigit(): return`: `not` was classified as a
//!    pass-through binary operator, so the negation was lowered away and the
//!    digit validator could never be seen as a guard on `uid`. With the
//!    operator kept as a UnaryOp and the `is*` predicate registered as a
//!    validator, the early-return guard prunes the finding.

use super::*;

/// `http.Get` is the canonical Go SSRF shape: the URL sits at slot 0.
/// Before the fix the sqlx `Get` slot rule (slot 1 only) suppressed it.
#[test]
fn probe_go_http_get_ssrf_slot_zero_fires() {
    let src = r#"
package main

import (
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request) {
	http.Get(r.URL.Query().Get("u"))
}
"#;
    assert_detected(&scan_go(src), "go_http_get_ssrf_slot_zero", "Get");
}

/// Control: the sqlx slot rule still governs a receiver whose origin is not
/// `net/http`. `dest` at slot 0 is an out-parameter, so a tainted value
/// there must stay silent rather than inheriting the transport's all-args
/// layout.
#[test]
fn probe_go_receiver_get_dest_slot_stays_silent() {
    let src = r#"
package main

import (
	"net/http"
)

type store struct{}

func (s *store) Get(dest string) string { return dest }

func h(w http.ResponseWriter, r *http.Request) {
	var s store
	_ = s.Get(r.URL.Query().Get("u"))
}
"#;
    assert_clean(&scan_go(src), "go_receiver_get_dest_slot");
}

/// The digit validator plus the `not` guard: digits-only input reaching the
/// SQL concat is a checked value, so the finding is pruned.
#[test]
fn probe_py_not_isdigit_guard_silences_sql_concat() {
    let src = r#"
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/u")
def u():
    uid = request.args.get("id")
    if not uid.isdigit():
        return "bad", 400
    return str(sqlite3.connect("x").execute("SELECT * FROM t WHERE id = " + uid).fetchall())
"#;
    assert_clean(&scan_py(src), "py_not_isdigit_guard");
}

/// Positive control for the guard test: without the check the same concat is
/// a real finding, so the clean result above is the guard doing work, not a
/// vanished sink.
#[test]
fn probe_py_unguarded_digits_concat_fires() {
    let src = r#"
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/u")
def u():
    uid = request.args.get("id")
    return str(sqlite3.connect("x").execute("SELECT * FROM t WHERE id = " + uid).fetchall())
"#;
    assert_detected(&scan_py(src), "py_unguarded_digits_concat", "execute");
}
