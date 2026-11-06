// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Module-scope (top-level) statement analysis.
//!
//! Dataflow used to run only over function bodies, so the same two statements
//! were a finding inside `def handler():` and silent at file scope. These
//! probes pin the module-level shapes an application actually ships: a script's
//! straight-line code, code under a top-level `if`, and a bare JS expression.

use super::*;

/// Straight-line module code: the canonical script shape.
#[test]
fn probe_module_scope_python_straight_line() {
    let src = r#"
from flask import Flask, request
import os

app = Flask(__name__)

cmd = request.args.get('c')
os.system("echo " + cmd)
"#;
    assert_detected(&scan_py(src), "py_module_straight_line", "system");
}

/// Code under a top-level `if` still runs at import time
/// (`if __name__ == "__main__": ...`, feature guards).
#[test]
fn probe_module_scope_python_inside_top_level_if() {
    let src = r#"
from flask import Flask, request
import os

app = Flask(__name__)

if True:
    cmd = request.args.get('c')
    os.system("echo " + cmd)
"#;
    assert_detected(&scan_py(src), "py_module_top_level_if", "system");
}

/// A JS top-level expression statement has no declaration to own it.
#[test]
fn probe_module_scope_js_expression_statement() {
    let src = r#"
import { execSync } from 'child_process';

execSync('ls ' + process.argv[2]);
"#;
    assert_detected(&scan_ts(src), "ts_module_expression", "execSync");
}

/// Control: the function form keeps working, and the module IR must not add a
/// second copy of the same finding.
#[test]
fn probe_module_scope_function_form_reported_once() {
    let src = r#"
from flask import Flask, request
import os

app = Flask(__name__)

def handler():
    cmd = request.args.get('c')
    os.system("echo " + cmd)
"#;
    let res = scan_py(src);
    assert_detected(&res, "py_module_function_control", "system");
    let vulnerable = res
        .located
        .iter()
        .filter(|l| l.finding.verdict == BackwardVerdict::Vulnerable)
        .count();
    assert_eq!(
        vulnerable,
        1,
        "the function body must be lowered once, not mirrored into the module IR: {:?}",
        res.located
            .iter()
            .map(|l| (&l.finding.function, &l.finding.sink))
            .collect::<Vec<_>>()
    );
}

/// Control: a top-level declaration is owned by the binding/static walk, not
/// the module IR. A sink in its initializer is reported once.
#[test]
fn probe_module_scope_declaration_not_double_lowered() {
    let src = r#"
import { execSync } from 'child_process';

const out = execSync('ls ' + process.argv[2]);
"#;
    let res = scan_ts(src);
    assert_detected(&res, "ts_module_declaration_control", "execSync");
    let vulnerable = res
        .located
        .iter()
        .filter(|l| l.finding.verdict == BackwardVerdict::Vulnerable)
        .count();
    assert_eq!(
        vulnerable,
        1,
        "a top-level declaration must be lowered once, got: {:?}",
        res.located
            .iter()
            .map(|l| (&l.finding.function, &l.finding.sink))
            .collect::<Vec<_>>()
    );
}
