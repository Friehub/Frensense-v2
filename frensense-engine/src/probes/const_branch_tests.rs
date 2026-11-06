// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Compile-time-constant branch elimination.
//!
//! A condition or `match` subject whose value is fixed before the program runs
//! selects exactly one arm. Until lowering folded those, every arm executed in
//! the IR, so an assignment in an unreachable arm reached the join and the
//! backward walk reported taint no execution can produce. A table lookup that
//! selects a fixed label is the everyday shape:
//!
//! ```python
//! possible = "ABC"
//! guess = possible[1]          # 'B'
//! match guess:
//!     case 'A':        bar = param   # dead
//!     case 'B':        bar = 'bob'
//!     case 'C' | 'D':  bar = param   # dead
//!     case _:          bar = 'bob'
//! ```
//!
//! The probes below pin both directions: the unreachable arm must not taint,
//! and the arm that *does* execute must still be reported.

use super::*;

const MATCH_SAFE: &str = r#"
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/run')
def run_cmd():
    param = request.args.get('cmd')
    possible = "ABC"
    guess = possible[1]
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = "bob's your uncle"
    os.system("echo " + bar)
"#;

/// `guess` is `'B'`, so only the literal arm executes. The two tainted arms
/// cannot run.
#[test]
fn probe_python_constant_match_prunes_the_unreachable_tainted_arms() {
    assert_clean(&scan_py(MATCH_SAFE), "py_const_match_dead_arm");
}

/// The same shape with a subject selecting a tainted arm: folding must not
/// hide the real finding.
#[test]
fn probe_python_constant_match_keeps_the_taken_tainted_arm() {
    let src = MATCH_SAFE.replace("guess = possible[1]", "guess = possible[0]");
    assert_detected(&scan_py(&src), "py_const_match_live_arm", "system");
}

/// A constant `if` condition: `'yes' in bar` is false for `bar = "never"`,
/// so the tainted arm never runs.
#[test]
fn probe_python_dead_branch_does_not_taint_the_join() {
    let src = r#"
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/run')
def run_cmd():
    param = request.args.get('cmd')
    bar = "never"
    if 'yes' in bar:
        bar = param
    os.system("echo " + bar)
"#;
    assert_clean(&scan_py(src), "py_const_dead_branch");
}

/// Control: the same branch with a condition that is true keeps the finding.
#[test]
fn probe_python_taken_constant_branch_is_still_reported() {
    let src = r#"
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/run')
def run_cmd():
    param = request.args.get('cmd')
    bar = "yes indeed"
    if 'yes' in bar:
        bar = param
    os.system("echo " + bar)
"#;
    assert_detected(&scan_py(src), "py_const_taken_branch", "system");
}

/// Control: a condition that is not constant keeps both arms live, so the
/// tainted arm must stay reachable.
#[test]
fn probe_python_runtime_condition_keeps_both_arms() {
    let src = r#"
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/run')
def run_cmd():
    param = request.args.get('cmd')
    bar = "never"
    if param:
        bar = param
    os.system("echo " + bar)
"#;
    assert_detected(&scan_py(src), "py_runtime_condition", "system");
}

/// A variable assigned inside one arm is not constant after the merge; the
/// second `if` must not be folded away.
#[test]
fn probe_python_branch_assignment_invalidates_the_constant() {
    let src = r#"
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/run')
def run_cmd():
    param = request.args.get('cmd')
    flag = "no"
    if param:
        flag = "yes"
    if flag == "no":
        param = ""
    os.system("echo " + param)
"#;
    assert_detected(&scan_py(src), "py_branch_join_invalidation", "system");
}

/// Rust `match` is an expression, so its arms are not pruned; the existing
/// lowering must keep reporting the reachable tainted arm.
#[test]
fn probe_rust_match_expression_unchanged() {
    let src = r#"
use axum::extract::Query;

async fn h(Query(p): Query<P>) -> axum::response::Html<String> {
    let bar = match std::env::var("MODE").unwrap().as_str() {
        "a" => p.id.clone(),
        _ => String::new(),
    };
    axum::response::Html(format!("<h1>{}</h1>", bar))
}
"#;
    assert_detected(&scan_rust(src), "rust_match_expression", "Html");
}
