// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Regression fixtures for false positives and lost flows measured on real
//! repositories. Each case is the smallest program that reproduced the
//! behaviour: sinks that must stay silent, and flows that must still fire.

use crate::analysis::taint::engine::BackwardVerdict;
use crate::analysis::taint::facts::seeded_tables;
use crate::scan::{ScanResult, scan};

fn run(ext: &str, path: &str, src: &str) -> ScanResult {
    let (config, facts) = seeded_tables([ext]);
    scan(
        &[(path.to_string(), src.to_string(), ext.to_string())],
        &config,
        &facts,
    )
}

fn vulnerable(res: &ScanResult, sink: &str) -> bool {
    res.located
        .iter()
        .any(|l| l.finding.sink.contains(sink) && l.finding.verdict == BackwardVerdict::Vulnerable)
}

#[test]
fn go_tuple_assignment_keeps_taint() {
    let src = r#"
package main

import (
	"database/sql"
	"io"
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	rows, err := db.Query("SELECT * FROM t WHERE a = '" + string(body) + "'")
	_ = rows
}
"#;
    assert!(vulnerable(&run("go", "app/h.go", src), "Query"));
}

#[test]
fn python_tuple_unpack_keeps_taint() {
    let src = r#"
from flask import request
import sqlite3

def h():
    conn = sqlite3.connect("d")
    c, d = request.args.get("y").split(",")
    conn.execute("select * from t where a = '" + c + "'")
"#;
    assert!(vulnerable(&run("py", "app/t.py", src), "execute"));
}

#[test]
fn prepared_statement_arguments_are_bindings() {
    let src = r#"
package main

import (
	"database/sql"
	"net/http"
)

func h(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	uid := r.URL.Query().Get("u")
	stmt, err := db.Prepare("UPDATE sessions SET u = ? WHERE k = ?")
	if err != nil {
		return
	}
	_, err = stmt.Exec(uid, "k")
}
"#;
    assert!(!vulnerable(&run("go", "app/g.go", src), "Exec"));
}

#[test]
fn builtin_get_does_not_resolve_to_project_method() {
    // `cookies.get` is a dict read; the project's own `get` must not receive
    // that taint and carry it to an unrelated `redirect`.
    let src = r#"
from flask import redirect, request

class Globals:
    def get(self, name, default=None):
        return self.__dict__.get(name, default)

def open_session():
    return request.cookies.get("session")

def go(g):
    return redirect(g.get("next"))
"#;
    assert!(!vulnerable(&run("py", "app/s.py", src), "redirect"));
}

#[test]
fn password_wrapper_call_is_not_judged_at_the_call_site() {
    let src = r#"
package svc

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

func Register(email, password string) error {
	hashed, err := HashPassword(password)
	_ = hashed
	return err
}
"#;
    let res = run("go", "svc/auth.go", src);
    assert!(
        res.checker
            .iter()
            .all(|f| f.rule != frensense_lang::rules::CREDENTIAL_KDF_POLICY),
        "wrapper call flagged: {:?}",
        res.checker
    );
}
