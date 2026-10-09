// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Frontier 1: Path Sensitivity, Branch Guards, and Infeasible Paths.

use super::*;

#[test]
#[ignore = "Blind spot: Dominator path sensitivity on early return guards (false positive)"]
fn probe_ps_01_early_return_guard() {
    let src = r#"
        export function test(req: any) {
            if (!isValid(req.body.payload)) {
                return;
            }
            eval(req.body.payload);
        }
    "#;
    // When a guard returns early, downstream code is protected
    let res = scan_ts(src);
    assert_clean(&res, "ps_01_early_return_guard");
}

#[test]
fn probe_ps_02_correlated_boolean_flag() {
    let src = r#"
        export function test(req: any) {
            const isSafe = req.body.flag === "secure";
            if (!isSafe) {
                return;
            }
            eval(req.body.payload);
        }
    "#;
    // Even if branch is taken, payload is still untrusted payload unless sanitized
    let res = scan_ts(src);
    assert_detected(&res, "ps_02_correlated_boolean_flag", "eval");
}

#[test]
fn probe_ps_03_throw_dominates_sink() {
    let src = r#"
        export function test(req: any) {
            if (req.body.role !== "admin") {
                throw new Error("Forbidden");
            }
            eval(req.body.payload);
        }
    "#;
    // Authorization check does not sanitize dataflow payload
    let res = scan_ts(src);
    assert_detected(&res, "ps_03_throw_dominates_sink", "eval");
}

#[test]
#[ignore = "Blind spot: Infeasible branch constant folding pruning (false positive)"]
fn probe_ps_04_infeasible_contradictory_branch() {
    let src = r#"
        export function test(req: any) {
            const x = 5;
            if (x > 10) {
                eval(req.body.payload);
            }
        }
    "#;
    // Dead branch should be pruned by constant evaluation
    let res = scan_ts(src);
    assert_clean(&res, "ps_04_infeasible_contradictory_branch");
}
