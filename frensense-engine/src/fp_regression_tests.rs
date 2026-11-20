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

/// #133: a sink explored as "all args" must report the same slots as the same
/// sink with explicit slots. The receiver of a method call is not an argument,
/// so a clean `db` must not add a finding for slot `usize::MAX` per call (two
/// extra `Clean` findings in the issue's three-call repro).
#[test]
fn all_args_sink_does_not_report_a_clean_receiver() {
    use crate::analysis::taint::config::TaintConfig;
    use crate::analysis::taint::facts::{FactTable, SinkSignature};

    let src = r#"
declare const db: any
export function h(req: any) {
  const id = req.body.id
  db.query('SELECT ' + id)
}
export function lit() { db.query('SELECT 1') }
"#;
    let config = TaintConfig {
        sources: ["req.body".to_string()].into_iter().collect(),
        sinks: ["query".to_string()].into_iter().collect(),
        sanitizers: Default::default(),
    };
    let slots = |sig: SinkSignature| {
        let mut facts = FactTable::from_config(&config);
        facts.sink_signatures.insert("query".into(), sig);
        let mut s: Vec<usize> = scan(
            &[("a.ts".to_string(), src.to_string(), "ts".to_string())],
            &config,
            &facts,
        )
        .findings
        .iter()
        .map(|f| f.arg_slot)
        .collect();
        s.sort();
        s
    };

    let all = slots(SinkSignature::all_args("query"));
    let explicit = slots(SinkSignature::with_args("query", &[0]));
    assert_eq!(
        all, explicit,
        "an all-args sink must report exactly what an explicit one does"
    );
    assert!(
        !all.contains(&usize::MAX),
        "a clean receiver is not a finding: {all:?}"
    );
}

/// #100: a handler's own response object is not data. `res.write("hello")`
/// writes a constant, and walking `res` as an argument made the site
/// undecided because the handler parameter has no caller.
#[test]
fn method_sink_receiver_is_not_walked_as_an_argument() {
    let src = r#"
import express from "express";
const app = express();
app.get("/", (req, res) => { res.write("hello"); });
"#;
    let res = run("ts", "t.ts", src);

    assert!(!vulnerable(&res, "write"));
    assert!(
        res.findings
            .iter()
            .all(|f| f.verdict != BackwardVerdict::Unknown),
        "the receiver is not an argument, so nothing is undecided: {:?}",
        res.findings
            .iter()
            .map(|f| (f.sink.clone(), f.arg_slot, f.verdict.clone()))
            .collect::<Vec<_>>()
    );
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

/// An assignment to a pattern is the declaration form with the names already
/// bound: lowering read the pattern as an lvalue, found none, and dropped the
/// store, so the name stayed undefined and the value never reached the sink.
#[test]
fn destructuring_assignment_keeps_taint() {
    let src = r#"
export function test(req: any) {
  let a: any;
  ({ a } = req.body);
  eval(a);
}
"#;
    assert!(vulnerable(&run("ts", "app/o.ts", src), "eval"));
}

#[test]
fn array_destructuring_assignment_keeps_taint() {
    let src = r#"
export function test(req: any) {
  let h: any;
  [h] = req.body.parts;
  eval(h);
}
"#;
    assert!(vulnerable(&run("ts", "app/a.ts", src), "eval"));
}

/// Binding a pattern target must not invent a flow.
#[test]
fn destructuring_assignment_of_a_literal_stays_silent() {
    let src = r#"
export function test() {
  let a: any;
  ({ a } = { a: "safe" });
  eval(a);
}
"#;
    assert!(!vulnerable(&run("ts", "app/l.ts", src), "eval"));
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

/// #124: a property assignment is a DOM sink in its own right, and the
/// finding points at the write, not at where the value was defined.
#[test]
fn property_assignment_sink_reports_the_write() {
    let src = r#"
import express from "express";
const app = express();
app.get("/x", (req, res) => {
  const user = req.query.name;
  const el = document.getElementById("out") as any;
  el.innerHTML = user;
});
"#;
    let res = run("ts", "a.ts", src);
    assert!(vulnerable(&res, "innerHTML"), "innerHTML store is a sink");
    let located = res
        .located
        .iter()
        .find(|l| l.finding.sink.contains("innerHTML"))
        .expect("located innerHTML finding");
    assert_eq!(
        located.line, 7,
        "the store line, not the value's definition"
    );
}

#[test]
fn property_assignment_of_a_literal_is_clean() {
    let src = r#"
const el = document.getElementById("out") as any;
el.innerHTML = "<b>static</b>";
"#;
    let res = run("ts", "b.ts", src);
    assert!(!vulnerable(&res, "innerHTML"));
}

/// #123: JSX attributes are writes too. `dangerouslySetInnerHTML` carries
/// attacker-supplied markup exactly like `el.innerHTML = …` does.
#[test]
fn jsx_dangerously_set_inner_html_is_a_sink() {
    let src = r#"
import express from "express";
const app = express();
app.get("/x", (req, res) => {
  const user = req.query.name;
  const el = <div dangerouslySetInnerHTML={{ __html: user }} />;
  return el;
});
"#;
    let res = run("tsx", "c.tsx", src);
    assert!(vulnerable(&res, "dangerouslySetInnerHTML"), "JSX sink");
}

#[test]
fn jsx_static_attribute_value_is_clean() {
    let src = r#"
const el = <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;
"#;
    let res = run("tsx", "d.tsx", src);
    assert!(!vulnerable(&res, "dangerouslySetInnerHTML"));
}

/// #95: `obj['a']` is a static field read, so it must match the `a` an object
/// literal stored. The lowering kept the literal's quotes in the field name,
/// the store never matched, and the flow to `exec` was lost.
#[test]
fn quoted_subscript_matches_the_object_literal_field() {
    let src = r#"
import { exec } from "child_process";
import express from "express";
const app = express();
app.get("/a", async (req, res) => {
  const host = req.query.host as string;
  const cmds = { a: "ping " + host };
  exec(cmds['a']);
  res.send("ok");
});
"#;
    let res = run("ts", "obj.ts", src);
    assert!(
        vulnerable(&res, "exec"),
        "a quoted subscript must reach the field the literal stored: {:?}",
        res.findings
            .iter()
            .map(|f| (f.sink.clone(), f.verdict.clone()))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Python XPath: keyword bindings, inline delimiter escaping, and library state
// ---------------------------------------------------------------------------

/// `tree.xpath(expr, name=value)` binds `value` into the expression as an
/// XPath variable. A tainted *binding* is a parameter channel, not string
/// concatenation, so only slot 0 is dangerous.
#[test]
fn xpath_keyword_binding_is_clean() {
    let src = r#"
from flask import request
import lxml.etree

def h():
    param = request.args.get("p")
    root = lxml.etree.parse("x.xml")
    return root.xpath("/Employees/Employee[@emplid=$id]", id=param)
"#;
    let res = run("py", "xbind.py", src);
    assert!(
        !vulnerable(&res, "xpath"),
        "a keyword binding must not be reported as expression injection: {:?}",
        res.findings
            .iter()
            .map(|f| (f.sink.clone(), f.verdict.clone()))
            .collect::<Vec<_>>()
    );
}

/// The slot restriction must not silence a concatenated expression.
#[test]
fn xpath_concatenated_expression_is_vulnerable() {
    let src = r#"
from flask import request
import lxml.etree

def h():
    param = request.args.get("p")
    query = "/Employees/Employee[@emplid='" + param + "']"
    root = lxml.etree.parse("x.xml")
    return root.xpath(query)
"#;
    let res = run("py", "xexpr.py", src);
    assert!(vulnerable(&res, "xpath"), "concatenated XPath expression");
}

/// Escaping the quoting delimiter inline removes the only character an
/// injection could use to leave the string literal, so the flow is clean.
#[test]
fn replace_of_the_quote_delimiter_is_clean() {
    let src = r#"
from flask import request
import lxml.etree

def h():
    param = request.args.get("p")
    bar = param.replace("'", "&apos;")
    query = "/Employees/Employee[@emplid='" + bar + "']"
    root = lxml.etree.parse("x.xml")
    return root.xpath(query)
"#;
    let res = run("py", "xesc.py", src);
    assert!(
        !vulnerable(&res, "xpath"),
        "an inline `'` escape must be treated as a sanitizer: {:?}",
        res.findings
            .iter()
            .map(|f| (f.sink.clone(), f.verdict.clone()))
            .collect::<Vec<_>>()
    );
}

/// `ConfigParser.set(section, key, value)` then `get(section, key)` returns
/// the stored value: the state object must carry the flow.
#[test]
fn configparser_set_then_get_is_vulnerable() {
    let src = r#"
from flask import request
import configparser
import lxml.etree

def h():
    param = request.args.get("p")
    conf = configparser.ConfigParser()
    conf.add_section("s")
    conf.set("s", "k", param)
    bar = conf.get("s", "k")
    query = "/Employees/Employee[@emplid='" + bar + "']"
    root = lxml.etree.parse("x.xml")
    return root.xpath(query)
"#;
    let res = run("py", "cfg_same.py", src);
    assert!(
        vulnerable(&res, "xpath"),
        "ConfigParser state must carry the stored value: {:?}",
        res.findings
            .iter()
            .map(|f| (f.sink.clone(), f.verdict.clone()))
            .collect::<Vec<_>>()
    );
}

/// A read of a *different* key returns the value stored under that key, not
/// the tainted one, so the object's taint must not leak across keys.
#[test]
fn configparser_get_of_another_key_is_clean() {
    let src = r#"
from flask import request
import configparser
import lxml.etree

def h():
    param = request.args.get("p")
    conf = configparser.ConfigParser()
    conf.add_section("s")
    conf.set("s", "safe", "a-value")
    conf.set("s", "tainted", param)
    bar = conf.get("s", "safe")
    query = "/Employees/Employee[@emplid='" + bar + "']"
    root = lxml.etree.parse("x.xml")
    return root.xpath(query)
"#;
    let res = run("py", "cfg_other.py", src);
    assert!(
        !vulnerable(&res, "xpath"),
        "a read of another key must stay clean: {:?}",
        res.findings
            .iter()
            .map(|f| (f.sink.clone(), f.verdict.clone()))
            .collect::<Vec<_>>()
    );
}

/// `StringIO.write` accumulates state and `getvalue()` returns all of it, so
/// the buffer must carry the flow to the reader.
#[test]
fn stringio_write_then_getvalue_is_vulnerable() {
    let src = r#"
from flask import request
import io
import lxml.etree

def h():
    param = request.args.get("p")
    buf = io.StringIO()
    buf.write("/Employees/Employee[@emplid='")
    buf.write(param)
    buf.write("']")
    bar = buf.getvalue()
    root = lxml.etree.parse("x.xml")
    return root.xpath(bar)
"#;
    let res = run("py", "stringio.py", src);
    assert!(
        vulnerable(&res, "xpath"),
        "StringIO state must carry the written value: {:?}",
        res.findings
            .iter()
            .map(|f| (f.sink.clone(), f.verdict.clone()))
            .collect::<Vec<_>>()
    );
}

/// A list built by literal appends answers a literal index with the value
/// stored *at that index*: the read at 2 is the literal, the read at 1 is the
/// tainted element. The wildcard store every `append` writes made both reads
/// see both values.
#[test]
fn list_index_read_resolves_the_value_at_that_index() {
    let src = r#"
from flask import request
import lxml.etree

def literal_index():
    p = request.args.get("p")
    lst = []
    lst.append("safe")
    lst.append(p)
    lst.append("more")
    root = lxml.etree.parse("x.xml")
    return root.xpath(lst[2])

def tainted_index():
    p = request.args.get("p")
    lst = []
    lst.append("safe")
    lst.append(p)
    lst.append("more")
    root = lxml.etree.parse("x.xml")
    return root.xpath(lst[1])
"#;
    let res = run("py", "list_index.py", src);
    let functions = || {
        res.findings
            .iter()
            .map(|f| (f.function.clone(), f.verdict.clone()))
            .collect::<Vec<_>>()
    };
    assert!(
        !res.findings
            .iter()
            .any(|f| f.function == "literal_index" && f.verdict == BackwardVerdict::Vulnerable),
        "the literal element at index 2 must stay clean: {:?}",
        functions()
    );
    assert!(
        res.findings
            .iter()
            .any(|f| f.function == "tainted_index" && f.verdict == BackwardVerdict::Vulnerable),
        "the value appended at index 1 must still reach the sink: {:?}",
        functions()
    );
}

/// `pop(0)` shifts every later element down, so the following read at 0 sees
/// the previously second element.
#[test]
fn list_pop_shifts_the_read_position() {
    let src = r#"
from flask import request
import lxml.etree

def h():
    p = request.args.get("p")
    lst = []
    lst.append("safe")
    lst.append(p)
    lst.append("more")
    lst.pop(0)
    root = lxml.etree.parse("x.xml")
    return root.xpath(lst[0])
"#;
    let res = run("py", "list_pop.py", src);
    assert!(
        vulnerable(&res, "xpath"),
        "pop must shift the read position"
    );
}

/// A list filled inside a loop has no single-pass shape, so its element reads
/// keep the wildcard model and stay conservative.
#[test]
fn list_filled_in_a_loop_keeps_the_wildcard_model() {
    let src = r#"
from flask import request
import lxml.etree

def h():
    lst = []
    for item in request.args.get("p"):
        lst.append(item)
    root = lxml.etree.parse("x.xml")
    return root.xpath(lst[0])
"#;
    let res = run("py", "list_loop.py", src);
    assert!(
        vulnerable(&res, "xpath"),
        "a loop-built list must keep every stored value reachable"
    );
}

/// The raw query string is request input, like `request.args`: reading it and
/// slicing the parameter out of it must reach the sink.
#[test]
fn raw_query_string_is_a_source() {
    let src = r#"
import lxml.etree

def h(request):
    query_string = request.query_string.decode("utf-8")
    loc = query_string.find("p=")
    param = query_string[loc + 2:]
    root = lxml.etree.parse("x.xml")
    return root.xpath(param)
"#;
    let res = run("py", "query_string.py", src);
    assert!(
        vulnerable(&res, "xpath"),
        "request.query_string carries attacker input: {:?}",
        res.findings
            .iter()
            .map(|f| (f.sink.clone(), f.verdict.clone()))
            .collect::<Vec<_>>()
    );
}
