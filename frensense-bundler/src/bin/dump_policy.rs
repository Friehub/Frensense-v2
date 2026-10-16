// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Throwaway diagnostic: count learned-fact entry variants in a `.frc`
//! bundle and dump any fact (Policy or Check) whose trigger matches the
//! `when_call` argument, so the serialized requirement shape is visible.

use frensense_bundler::format::load_bundle;
use frensense_engine::analysis::taint::facts::LearnedFactEntry;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "bundle.frc".into());
    let needle = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "updateMany".into());
    let bytes = std::fs::read(&path).expect("bundle read");
    let bundle = load_bundle(&bytes).expect("bundle decode");

    println!("bundle: {path}  entries: {}", bundle.learned_facts.len());
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    for entry in &bundle.learned_facts {
        let kind = match entry {
            LearnedFactEntry::Policy { .. } => "Policy",
            LearnedFactEntry::Check { .. } => "Check",
            _ => "other",
        };
        *counts.entry(kind).or_insert(0) += 1;
        match entry {
            LearnedFactEntry::Policy {
                rule,
                when_call,
                require,
                scope,
                message,
                severity,
                ..
            } if when_call.contains(&needle) => {
                println!("rule: {rule}");
                println!("when_call: {when_call}");
                println!("scope: {scope:?}");
                println!("severity: {severity}");
                println!("message: {message}");
                println!("requirements ({}):", require.len());
                for r in require {
                    println!("  {r:?}");
                }
                println!("---");
            }
            LearnedFactEntry::Check {
                rule,
                call,
                message,
                severity,
                unless_guard,
                unless_range_check,
            } if call.contains(&needle) => {
                println!("(check) rule: {rule}");
                println!("(check) call: {call}");
                println!("(check) severity: {severity}");
                println!("(check) message: {message}");
                println!("(check) unless_guard: {unless_guard:?}");
                println!("(check) unless_range_check: {unless_range_check:?}");
                println!("---");
            }
            _ => {
                let dbg = format!("{entry:?}");
                if dbg.contains(&needle) {
                    let trimmed: Vec<&str> = dbg.lines().take(24).collect();
                    println!("[other entry containing target predicate]");
                    for l in trimmed {
                        println!("  {l}");
                    }
                    println!("---");
                }
            }
        }
    }
    if let Some(patterns) = Some(&bundle.patterns) {
        for p in patterns {
            if format!("{p:?}").contains(&needle) {
                println!("[bundle pattern containing target predicate]");
                let dbg = format!("{p:?}");
                for l in dbg.lines().take(30) {
                    println!("  {l}");
                }
                println!("---");
            }
        }
    }
    for (k, v) in counts {
        println!("variant counts: {k}: {v}");
    }
}
