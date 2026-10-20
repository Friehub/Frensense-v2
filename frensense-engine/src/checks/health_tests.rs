// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the structural-health (function complexity) check.

use super::*;
use crate::harness::lower_source;

fn branchy(n: usize) -> String {
    let mut s = String::from("def f(x):\n    t = 0\n");
    for i in 0..n {
        s.push_str("    if x == ");
        s.push_str(&i.to_string());
        s.push_str(":\n        t += 1\n");
    }
    s.push_str("    return t\n");
    s
}

fn complexity_of(src: &str, name: &str) -> usize {
    let fns = lower_source("t.py", src, "py").unwrap();
    let ir = fns.values().find(|f| f.name.ends_with(name)).unwrap();
    cyclomatic_complexity(ir)
}

#[test]
fn straight_line_code_has_complexity_one() {
    assert_eq!(
        complexity_of("def f(x):\n    y = x + 1\n    return y\n", "f"),
        1
    );
}

#[test]
fn each_decision_adds_one() {
    assert_eq!(complexity_of(&branchy(3), "f"), 4);
    assert_eq!(complexity_of(&branchy(10), "f"), 11);
}

#[test]
fn only_outliers_are_reported() {
    let small = lower_source("t.py", &branchy(5), "py").unwrap();
    let big = lower_source("t.py", &branchy(30), "py").unwrap();
    assert!(small.values().all(|ir| check(ir).is_empty()));
    let found: Vec<_> = big.values().flat_map(check).collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].rule, FUNCTION_COMPLEXITY);
    assert!(found[0].params.contains(&("complexity", "31".to_string())));
}

#[test]
fn limit_is_a_parameter_not_a_constant() {
    let fns = lower_source("t.py", &branchy(5), "py").unwrap();
    let ir = fns.values().find(|f| f.name.ends_with('f')).unwrap();
    assert!(check_with_limit(ir, 3).len() == 1);
    assert!(check_with_limit(ir, 6).is_empty());
}
