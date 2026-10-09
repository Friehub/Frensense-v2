// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Frontier 2: Concurrency, EventEmitters, Timers, and Microtasks.

use super::*;

#[test]
#[ignore = "Blind spot: Node.js EventEmitter emit/on dataflow"]
fn probe_async_01_event_emitter() {
    let src = r#"
        export function test(req: any) {
            const EventEmitter = require("events");
            const bus = new EventEmitter();
            bus.on("dispatch", (data: any) => {
                eval(data);
            });
            bus.emit("dispatch", req.body.payload);
        }
    "#;
    assert_detected(&scan_ts(src), "async_01_event_emitter", "eval");
}

#[test]
fn probe_async_02_set_timeout() {
    let src = r#"
        export function test(req: any) {
            setTimeout(() => {
                eval(req.body.payload);
            }, 100);
        }
    "#;
    assert_detected(&scan_ts(src), "async_02_set_timeout", "eval");
}

#[test]
fn probe_async_03_queue_microtask() {
    let src = r#"
        export function test(req: any) {
            queueMicrotask(() => {
                eval(req.body.payload);
            });
        }
    "#;
    assert_detected(&scan_ts(src), "async_03_queue_microtask", "eval");
}

#[test]
#[ignore = "Blind spot: Promise.all array aggregation taint propagation"]
fn probe_async_04_promise_all_aggregate() {
    let src = r#"
        export function test(req: any) {
            Promise.all(["safe", req.body.payload]).then((results: any) => {
                eval(results[1]);
            });
        }
    "#;
    assert_detected(&scan_ts(src), "async_04_promise_all_aggregate", "eval");
}
