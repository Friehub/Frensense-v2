// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! C provider vocabulary, translated verbatim from
//! `frensense-lang`'s `providers/c_lang.rs` (Phase 6.3c; lang's copy deleted in
//! 6.3d - this static data is the sole source).

use super::call_last_segment;
use super::LanguageVocab;
use crate::role_map::{PropagatorRule, SanitizerKind};

pub(super) static C_SINK_NAMES: &[(&str, crate::role_map::SinkLabel)] = &[
    // Code Execution
    ("system", crate::role_map::SinkLabel::CommandInjection),
    ("popen", crate::role_map::SinkLabel::CommandInjection),
    ("exec", crate::role_map::SinkLabel::CommandInjection),
    ("execve", crate::role_map::SinkLabel::CommandInjection),
    ("execl", crate::role_map::SinkLabel::CommandInjection),
    ("execlp", crate::role_map::SinkLabel::CommandInjection),
    ("execvp", crate::role_map::SinkLabel::CommandInjection),
    ("execvpe", crate::role_map::SinkLabel::CommandInjection),
    // SQL Injection
    ("mysql_query", crate::role_map::SinkLabel::SqlInjection),
    ("sqlite3_exec", crate::role_map::SinkLabel::SqlInjection),
    // Path Traversal
    ("fopen", crate::role_map::SinkLabel::PathTraversal),
    ("open", crate::role_map::SinkLabel::PathTraversal),
    ("read", crate::role_map::SinkLabel::PathTraversal),
    ("write", crate::role_map::SinkLabel::PathTraversal),
    ("unlink", crate::role_map::SinkLabel::PathTraversal),
    ("stat", crate::role_map::SinkLabel::PathTraversal),
    ("access", crate::role_map::SinkLabel::PathTraversal),
    // Buffer Overflow / Memory Safety
    //
    // Unsized copies only: a tainted source into gets/strcpy/strcat is an
    // unbounded write. Sized copies (memcpy, memmove, memset, strncpy,
    // strncat) are deliberately NOT taint sinks - they carry an explicit
    // length, so boundedness is a spatial question for the capacity-based
    // checker, and every idiomatic `memcpy(buf, getenv_derived, n)` pattern
    // (config parsing, path building) alerted on normal input handling.
    ("gets", crate::role_map::SinkLabel::BufferOverflow),
    ("strcpy", crate::role_map::SinkLabel::BufferOverflow),
    ("strcat", crate::role_map::SinkLabel::BufferOverflow),
    ("sprintf", crate::role_map::SinkLabel::FormatString),
    ("vsprintf", crate::role_map::SinkLabel::FormatString),
    ("printf", crate::role_map::SinkLabel::FormatString),
    ("snprintf", crate::role_map::SinkLabel::FormatString),
    ("sscanf", crate::role_map::SinkLabel::FormatString),
    ("mktemp", crate::role_map::SinkLabel::PathTraversal),
    ("tmpnam", crate::role_map::SinkLabel::PathTraversal),
];

pub(super) static C_SINK_SIGNATURES: &[(&str, &[usize], bool)] = &[
    // (call, dangerous slots, binding slots safe)
    // sprintf/vsprintf(dst, fmt, ...), printf(fmt, ...),
    // snprintf(dst, n, fmt, ...), sscanf(input, fmt, ...).
    ("sprintf", &[1], false),
    ("vsprintf", &[1], false),
    ("printf", &[0], false),
    ("snprintf", &[2], false),
    ("sscanf", &[1], false),
];

pub(super) static C_SOURCE_PATTERNS: &[&str] = &["argv", "getenv", "fgets", "scanf", "stdin"];

pub(super) static C_PROPAGATORS: &[PropagatorRule] = &[
    PropagatorRule {
        call: "sprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "snprintf",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strcat",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strcpy",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "strdup",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
];

pub(super) static C_SANITIZER_NAMES: &[&str] = &["atoi", "atol", "atof", "strtol", "strtoul"];

pub(super) static C_ROUTE_PATTERNS: &[&str] = &[];

fn c_classify_sanitizer(call: &str) -> Option<SanitizerKind> {
    match call_last_segment(call) {
        "atoi" | "atol" | "atof" | "strtol" | "strtoul" => Some(SanitizerKind::Full),
        _ => None,
    }
}

pub(super) const C_VOCAB: LanguageVocab = LanguageVocab {
    language: "c",
    ambiguous_verbs: crate::data::BOOTSTRAP_AMBIGUOUS_VERBS,
    global_only_sinks: &[],
    package_scoped_sinks: &[],
    sink_names: C_SINK_NAMES,
    sink_signatures: C_SINK_SIGNATURES,
    idor_sinks: &[],
    source_patterns: C_SOURCE_PATTERNS,
    request_param_names: &[],
    sanitizer_names: C_SANITIZER_NAMES,
    classify_sanitizer: c_classify_sanitizer,
    propagators: C_PROPAGATORS,
    session_roots: &[],
    route_patterns: C_ROUTE_PATTERNS,
    policies: &[],
};

pub(crate) fn vocab() -> &'static LanguageVocab {
    &C_VOCAB
}
