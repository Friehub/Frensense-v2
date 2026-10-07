// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Frontier 5: Concrete Historic CVE Minimal Reproductions.

use super::*;

#[test]
fn probe_cve_01_lodash_prototype_pollution() {
    let src = r#"
        const _ = require("lodash");

        export function test(req: any) {
            const obj = {};
            _.set(obj, req.body.path, req.body.value);
        }
    "#;
    assert_detected(&scan_ts(src), "cve_01_lodash_prototype_pollution", "set");
}

#[test]
fn probe_cve_02_axios_ssrf() {
    let src = r#"
        const axios = require("axios");

        export function test(req: any) {
            const targetUrl = req.body.url;
            axios.get(targetUrl);
        }
    "#;
    assert_detected(&scan_ts(src), "cve_02_axios_ssrf", "get");
}

#[test]
#[ignore = "Blind spot: Zip slip path traversal join propagation"]
fn probe_cve_03_zip_slip_path_traversal() {
    let src = r#"
        const fs = require("fs");
        const path = require("path");

        export function extractEntry(req: any) {
            const destPath = path.join("/var/data", req.body.filename);
            fs.writeFile(destPath, "content");
        }
    "#;
    assert_detected(&scan_ts(src), "cve_03_zip_slip_path_traversal", "writeFile");
}

#[test]
fn probe_cve_04_user_regexp_injection() {
    let src = r#"
        export function test(req: any) {
            const regex = new RegExp(req.body.pattern);
            eval(regex.source);
        }
    "#;
    assert_detected(&scan_ts(src), "cve_04_user_regexp_injection", "eval");
}
