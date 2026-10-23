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

#[test]
fn probe_cve_2025_27152_axios_instance_alias_ssrf() {
    // CVE-2025-27152 (mre01): `const client = axios.create(...)` then
    // `client.get(tainted)` must fire SSRF. The receiver resolves through
    // its own source name (`client`), which collides with a declared client
    // root and used to short-circuit before the factory fallback recovered
    // `axios` - the verb sink then stayed suppressed (instance-alias false
    // negative: positive silent, negative vacuous, family cannot separate).
    let src = r#"
        import axios from "axios";

        const client = axios.create({ baseURL: "http://directory.internal/api/v1/" });

        export function getUser(req: any) {
            return client.get(String(req.params.id));
        }
    "#;
    assert_detected(&scan_ts(src), "mre01_ssrf_instance_alias", "get");

    // Precision pair: an instance NOT built from a client factory must not
    // arm the verb sink just because its variable name collides with a
    // declared client root.
    let clean = r#"
        export function getUser(req: any) {
            const client = makeThing();
            return client.get(String(req.params.id));
        }
    "#;
    assert_clean(&scan_ts(clean), "mre01_non_factory_instance_not_ssrf");
}
