// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Frontier 4: Sanitizer Pipelines, Order-of-Operations, and Bypass Patterns.

use super::*;

#[test]
fn probe_sm_01_sequential_sanitizers() {
    let src = r#"
        export function test(req: any) {
            const step1 = escapeHtml(req.body.payload);
            const step2 = parseInt(step1, 10);
            eval(step2);
        }
    "#;
    // Sequential sanitization: numeric coercion kills taint
    assert_clean(&scan_ts(src), "sm_01_sequential_sanitizers");
}

#[test]
#[ignore = "Blind spot: Order inversion sanitizer smearing across pipeline"]
fn probe_sm_02_order_inversion_untaint_reversal() {
    let src = r#"
        export function test(req: any) {
            const encoded = encodeURIComponent(req.body.payload);
            const decoded = decodeURIComponent(encoded);
            eval(decoded);
        }
    "#;
    // Decoding undoes encoding: taint remains active
    assert_detected(
        &scan_ts(src),
        "sm_02_order_inversion_untaint_reversal",
        "eval",
    );
}

#[test]
fn probe_sm_03_single_replace_regex_bypass() {
    let src = r#"
        export function test(req: any) {
            const bypassed = req.body.payload.replace("../", "");
            eval(bypassed);
        }
    "#;
    // Non-global replace does not sanitize
    assert_detected(&scan_ts(src), "sm_03_single_replace_regex_bypass", "eval");
}

#[test]
fn probe_sm_04_html_escape_into_command_sink() {
    let src = r#"
        export function test(req: any) {
            const escaped = escapeHtml(req.body.payload);
            eval(escaped);
        }
    "#;
    // HTML escaping does not sanitize command/code execution sinks
    assert_detected(&scan_ts(src), "sm_04_html_escape_into_command_sink", "eval");
}
