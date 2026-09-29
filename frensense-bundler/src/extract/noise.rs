// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

/// Names that plausibly participate in taint boundaries. This is a *bundler*
/// heuristic (build-time, recall-oriented); the replay gate provides the
/// precision.
/// Decides whether a call name is worth proposing as a candidate fact.
///
/// The corpus, not a hardcoded list, is the source of truth: a call is
/// taint-relevant if the FAMILY ITSELF discriminates on it. We keep only a
/// minimal syntactic exclusion (property lookups / obviously pure names
/// that would explode the candidate space) and let the replay gate reject
/// wrong proposals, that is what the gate is for.
pub fn looks_taint_relevant(call: &str) -> bool {
    // Accessor/universal-method noise: these appear in nearly every
    // variant and are structurally not policy/sink calls.
    const NOISE: &[&str] = &[
        "get",
        "set",
        "has",
        "then",
        "catch",
        "finally",
        "toString",
        "valueOf",
        "push",
        "pop",
        "map",
        "filter",
        "reduce",
        "forEach",
        "join",
        "split",
        "len",
        "length",
        "keys",
        "values",
        "entries",
        "stringify",
        "parse",
    ];
    !NOISE.contains(&call) && !call.is_empty()
}

/// True when `name` looks like an error/exception constructor or class
/// rather than an enforcement guard function (e.g. `Error`, `PermissionError`,
/// `ValueError`, `Exception`).
pub fn is_exception_name(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    last.ends_with("Error")
        || last.ends_with("Exception")
        || last.ends_with("Err")
        || last == "Error"
        || last == "Exception"
}

/// Score how likely a function call name is an enforcement guard
/// (auth check, validation, permission test). Higher = more likely.
pub fn guard_priority(name: &str) -> i32 {
    if is_exception_name(name) {
        return -100;
    }
    let lower = name.to_ascii_lowercase();
    let mut score = 0;
    if lower.contains("verify")
        || lower.contains("check")
        || lower.contains("guard")
        || lower.contains("auth")
        || lower.contains("valid")
        || lower.contains("permit")
        || lower.contains("allow")
        || lower.contains("require")
    {
        score += 50;
    }
    if lower.starts_with("is_") || lower.starts_with("has_") || lower.starts_with("can_") {
        score += 30;
    }
    if lower.ends_with("_permission") || lower.ends_with("_access") || lower.ends_with("_role") {
        score += 20;
    }
    score
}
