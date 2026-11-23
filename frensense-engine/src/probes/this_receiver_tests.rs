// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub

//! Receiver identity inside a method: `this` is the object the call was made
//! on, so a field written through it and read through it is one location.

use super::*;

/// `this` is the receiver the method was called on: a field the source
/// writes through it and reads through it is one location. Before the JS
/// family classified `this`, the write stored into nothing and the read
/// argument was dropped, so the sink was not even recognised.
#[test]
fn probe_07b_store_and_read_through_this_in_one_method() {
    let src = r#"
        import { exec } from "child_process";
        export function test(req: any) {
            const o = { h: "", go() { this.h = req.body.payload; exec(this.h); } };
            o.go();
        }
    "#;
    assert_detected(&scan_ts(src), "07b_this_in_one_method", "exec");
}
