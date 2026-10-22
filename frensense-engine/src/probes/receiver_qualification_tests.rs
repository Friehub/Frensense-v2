// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Receiver qualification: a sink declared under a module is a sink only
//! under that module.
//!
//! A dotted declaration publishes a bare shadow of its last segment (the
//! walker matches a virtual call by method name and cannot see the module
//! the method was reached through). Without the receiver-qualification
//! gate every object in the program inherited the library's semantics:
//! `json.loads` was reported as unsafe deserialization because
//! `pickle.loads` is, and any `.urlopen(...)` was reported as SSRF
//! because `urllib.request.urlopen` is.
//!
//! Each probe is a precision pair: the qualified call must still fire,
//! and the same method name on an unrelated receiver must stay silent.

use super::*;

#[test]
fn probe_qual_01_json_loads_is_not_unsafe_deserialization() {
    let src = r#"
        import json
        from flask import request

        def handler():
            payload = request.args.get('id')
            return json.loads(payload)
    "#;
    assert_clean(
        &scan_py(src),
        "qual_01_json_loads_is_not_unsafe_deserialization",
    );
}

#[test]
fn probe_qual_02_pickle_loads_is_unsafe_deserialization() {
    let src = r#"
        import pickle
        from flask import request

        def handler():
            payload = request.args.get('id')
            return pickle.loads(payload)
    "#;
    assert_detected(
        &scan_py(src),
        "qual_02_pickle_loads_is_unsafe_deserialization",
        "loads",
    );
}

#[test]
fn probe_qual_03_unrelated_receiver_urlopen_is_not_ssrf() {
    let src = r#"
        import urllib.request
        from flask import request

        class Client:
            def urlopen(self, url):
                return url

        def handler():
            target = request.args.get('url')
            client = Client()
            return client.urlopen(target)
    "#;
    assert_clean(
        &scan_py(src),
        "qual_03_unrelated_receiver_urlopen_is_not_ssrf",
    );
}

#[test]
fn probe_qual_04_urllib_urlopen_is_ssrf() {
    let src = r#"
        import urllib.request
        from flask import request

        def handler():
            target = request.args.get('url')
            return urllib.request.urlopen(target)
    "#;
    assert_detected(&scan_py(src), "qual_04_urllib_urlopen_is_ssrf", "urlopen");
}

#[test]
fn probe_qual_05_builtin_open_is_path_traversal() {
    let src = r#"
        from flask import request

        def handler():
            name = request.args.get('name')
            return open(name)
    "#;
    assert_detected(
        &scan_py(src),
        "qual_05_builtin_open_is_path_traversal",
        "open",
    );
}

#[test]
fn probe_qual_06_file_handle_read_is_not_path_traversal() {
    // `f.read(n)` reads FROM the handle. The tainted value is the handle
    // itself, not a path - a tainted handle is not path traversal.
    let src = r#"
        from flask import request

        def handler():
            handle = request.args.get('f')
            return handle.read(1000)
    "#;
    assert_clean(
        &scan_py(src),
        "qual_06_file_handle_read_is_not_path_traversal",
    );
}

#[test]
fn probe_qual_07_file_handle_write_is_not_path_traversal() {
    // `f.write(data)` writes data TO a file. It takes no path, so tainted
    // data flowing into it is not path traversal.
    let src = r#"
        import io
        from flask import request

        def handler():
            buf = io.StringIO()
            payload = request.args.get('data')
            buf.write(payload)
            return buf.getvalue()
    "#;
    assert_clean(
        &scan_py(src),
        "qual_07_file_handle_write_is_not_path_traversal",
    );
}

#[test]
fn probe_qual_08_subprocess_run_is_command_injection() {
    let src = r#"
        import subprocess
        from flask import request

        def handler():
            cmd = request.args.get('cmd')
            return subprocess.run(cmd, shell=True)
    "#;
    assert_detected(
        &scan_py(src),
        "qual_08_subprocess_run_is_command_injection",
        "run",
    );
}

#[test]
fn probe_qual_09_unrelated_run_method_is_not_command_injection() {
    let src = r#"
        from flask import request

        class Workflow:
            def run(self, step):
                return step

        def handler():
            step = request.args.get('step')
            workflow = Workflow()
            return workflow.run(step)
    "#;
    assert_clean(
        &scan_py(src),
        "qual_09_unrelated_run_method_is_not_command_injection",
    );
}

#[test]
fn probe_qual_10_from_import_pickle_loads_is_unsafe_deserialization() {
    // The qualified form reached through a `from` import resolves to the
    // import origin, which is the other way a qualified name can arm.
    let src = r#"
        from pickle import loads
        from flask import request

        def handler():
            payload = request.args.get('id')
            return loads(payload)
    "#;
    assert_detected(
        &scan_py(src),
        "qual_10_from_import_pickle_loads_is_unsafe_deserialization",
        "loads",
    );
}
