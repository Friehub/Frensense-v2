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

fn run_with(
    ext: &str,
    path: &str,
    src: &str,
    facts: &crate::analysis::taint::facts::FactTable,
) -> ScanResult {
    let (config, _) = seeded_tables([ext]);
    scan(
        &[(path.to_string(), src.to_string(), ext.to_string())],
        &config,
        facts,
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

/// A Go handler parameter is a source by its declared type, not its name:
/// the binding here is `request`, which the pack's name vocabulary (`r`,
/// `req`, `c`, `ctx`, `w`) does not cover. Lowering bound no Go parameter at
/// all before (it read the C `declarator` field), so the body reference was
/// an undeclared name and the flow never started: 0 findings.
#[test]
fn go_parameter_is_a_source_by_its_type() {
    let src = r#"
package main

import (
	"net/http"
	"os/exec"
)

func handle(request *http.Request) {
	cmd := request.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd)
}
"#;
    assert!(vulnerable(&run("go", "app/h.go", src), "Command"));
}

/// Binding a parameter must not make it a source: a scalar has no type the
/// classifier accepts, so `literal` stays clean even though it now binds.
#[test]
fn go_scalar_parameter_is_not_a_source() {
    let src = r#"
package main

import "os/exec"

func handle(literal string) {
	exec.Command("sh", "-c", literal)
}
"#;
    assert!(!vulnerable(&run("go", "app/s.go", src), "Command"));
}

/// A destructured parameter names no variable of its own: `run({ h })` used to
/// push one parameter slot named `{ h }`, so the body's `h` was an undeclared
/// name and the caller's object never reached the sink (0 findings).
#[test]
fn destructured_parameter_carries_caller_taint() {
    let src = r#"
import { exec } from "child_process";
import express from "express";
const app = express();
function run({ h }: { h: string }) { exec("ping " + h); }
app.get("/a", async (req, res) => {
  const host = req.query.host as string;
  run({ h: host });
  res.send("ok");
});
"#;
    assert!(vulnerable(&run("ts", "app/d.ts", src), "exec"));
}

/// The nested shape recurses through the load of the outer part, so the inner
/// name reads that part instead of the whole parameter value.
#[test]
fn nested_destructured_parameter_carries_caller_taint() {
    let src = r#"
import { exec } from "child_process";
import express from "express";
const app = express();
function run({ body: { h } }: any) { exec("ping " + h); }
app.post("/a", async (req, res) => {
  run(req);
  res.send("ok");
});
"#;
    assert!(vulnerable(&run("ts", "app/n.ts", src), "exec"));
}

/// A nested pattern is the flat form written twice, so the intermediate part
/// is the variable that form would have named: `{ body: { name } }` means
/// `const { body } = x; const { name } = body`. Leaving the intermediate
/// anonymous hid a name the vocabulary knows (a variable named `body` is a
/// request body), so the reported shape stayed `Unknown`.
#[test]
fn nested_destructured_parameter_keeps_the_part_name() {
    let src = r#"
export function t({ body: { name } }: any) { eval(name); }
"#;
    assert!(vulnerable(&run("ts", "app/b.ts", src), "eval"));
}

/// Keeping the part name must not manufacture a source: a part whose name is
/// not vocabulary, with nothing tainted above it, stays silent.
#[test]
fn nested_destructured_parameter_of_an_unknown_object_stays_silent() {
    let src = r#"
export function t({ opts: { cmd } }: any) { eval(cmd); }
"#;
    assert!(!vulnerable(&run("ts", "app/u.ts", src), "eval"));
}

/// `...parts` wraps the name. Binding the parameter under the text `...parts`
/// left the body's `parts` an undeclared name, so a rest parameter's argument
/// never reached its uses (0 findings).
#[test]
fn rest_parameter_carries_caller_taint() {
    let src = r#"
import { exec } from "child_process";
import express from "express";
const app = express();
function run(...parts: string[]) { exec(parts.join(" ")); }
app.get("/a", async (req, res) => {
  const host = req.query.host as string;
  run(host);
  res.send("ok");
});
"#;
    assert!(vulnerable(&run("ts", "app/r.ts", src), "exec"));
}

/// The declaration form of the same pattern: `const { a: { b } } = ...` used to
/// bind a variable literally named `{ b }`, leaving `b` undefined.
#[test]
fn nested_destructuring_declaration_keeps_taint() {
    let src = r#"
export function test(req: any) {
    const { a: { b } } = { a: { b: req.body.payload } };
    eval(b);
}
"#;
    assert!(vulnerable(&run("ts", "app/n.ts", src), "eval"));
}

/// Binding a pattern must not invent a flow: a literal argument stays clean.
#[test]
fn destructured_parameter_of_a_literal_stays_silent() {
    let src = r#"
import { exec } from "child_process";
function run({ h }: { h: string }) { exec("ping " + h); }
export function main() { run({ h: "localhost" }); }
"#;
    assert!(!vulnerable(&run("ts", "app/s.ts", src), "exec"));
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
fn prepared_statement_suppression_is_pack_taught() {
    // The same program as `prepared_statement_arguments_are_bindings`: the
    // handle counts as a prepared statement only because the pack declares
    // the factory prefix. Remove the fact and the call is judged as SQL
    // again - which is what makes the factory name pack knowledge instead of
    // engine vocabulary.
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
    let (_, mut facts) = seeded_tables(["go"]);
    assert!(
        !facts.prepared_statement_prefixes.is_empty(),
        "the default pack teaches the prepared-statement factory prefix"
    );
    assert!(!vulnerable(
        &run_with("go", "app/g.go", src, &facts),
        "Exec"
    ));
    facts.prepared_statement_prefixes.clear();
    assert!(
        vulnerable(&run_with("go", "app/g.go", src, &facts), "Exec"),
        "without the fact the handle's arguments are not binding-typed"
    );
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
