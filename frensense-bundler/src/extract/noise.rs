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
