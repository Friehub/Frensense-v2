// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Go database/transport sink signatures (slot + binding-safe) for the
//! framework-scope expansion. `Query/Exec`/`QueryRow` slot convention follows
//! the engine's `LanguageSinkSlots` emission: slot 0 = SQL text, args after it
//! are binding arguments.

/// Database sink signatures: (call, dangerous-arg-slots, binding_args_safe).
/// `binding_safe: true` means args are bound and not directly injectable.
/// Includes dense-driver name variants (sqlx-style) so `db.Query` (any
/// package) and `xx.Query` (sqlx export) arm the same fact under either
/// import origin.
pub(crate) static GO_SINK_SIGNATURES: &[(&str, &[usize], bool)] = &[
    // database/sql: Query/Exec(sql, args...)
    ("Query", &[0], true),
    ("QueryRow", &[0], true),
    ("QueryContext", &[0], true),
    ("Exec", &[0], true),
    ("ExecContext", &[0], true),
    ("Prepare", &[0], true),
    ("PrepareContext", &[0], true),
    // sqlx (dotted names match by last segment): dest slot 0 is an
    // out-param; a tainted dest injects only via the query, so slot 1 only.
    ("Get", &[1], true),
    ("Select", &[1], true),
    // D1 (Cloudflare Workers Go-style bindings)
    ("prepare", &[0], true),
];

/// Remaining Go sink names (transport + os + deserialization + log leak),
/// grouped for framework awareness.
pub(crate) static GO_SINK_NAMES: &[(&str, crate::role_map::SinkLabel)] = &[
    // Code Execution
    ("exec", crate::role_map::SinkLabel::CommandInjection),
    ("Exec", crate::role_map::SinkLabel::CommandInjection),
    ("Command", crate::role_map::SinkLabel::CommandInjection),
    ("Run", crate::role_map::SinkLabel::CommandInjection),
    ("Output", crate::role_map::SinkLabel::CommandInjection),
    (
        "CombinedOutput",
        crate::role_map::SinkLabel::CommandInjection,
    ),
    // SQL Injection
    ("Query", crate::role_map::SinkLabel::SqlInjection),
    ("QueryRow", crate::role_map::SinkLabel::SqlInjection),
    ("QueryContext", crate::role_map::SinkLabel::SqlInjection),
    ("ExecContext", crate::role_map::SinkLabel::SqlInjection),
    ("Prepare", crate::role_map::SinkLabel::SqlInjection),
    ("PrepareContext", crate::role_map::SinkLabel::SqlInjection),
    ("prepare", crate::role_map::SinkLabel::SqlInjection),
    // Path Traversal
    ("ReadFile", crate::role_map::SinkLabel::PathTraversal),
    ("Open", crate::role_map::SinkLabel::PathTraversal),
    ("Create", crate::role_map::SinkLabel::PathTraversal),
    ("WriteFile", crate::role_map::SinkLabel::PathTraversal),
    // SSRF
    ("http.Get", crate::role_map::SinkLabel::Ssrf),
    ("http.Post", crate::role_map::SinkLabel::Ssrf),
    ("http.Head", crate::role_map::SinkLabel::Ssrf),
    ("http.Do", crate::role_map::SinkLabel::Ssrf),
    ("Get", crate::role_map::SinkLabel::Ssrf),
    ("Post", crate::role_map::SinkLabel::Ssrf),
    ("Do", crate::role_map::SinkLabel::Ssrf),
    ("NewRequest", crate::role_map::SinkLabel::Ssrf),
    // Open Redirect
    ("Redirect", crate::role_map::SinkLabel::OpenRedirect),
    // SSTI
    ("ExecuteTemplate", crate::role_map::SinkLabel::TemplateSsti),
    // Insecure Deserialization
    (
        "msgpack.decode",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    // Log Leak
    ("log", crate::role_map::SinkLabel::LogLeak),
    ("error", crate::role_map::SinkLabel::LogLeak),
    ("info", crate::role_map::SinkLabel::LogLeak),
    ("debug", crate::role_map::SinkLabel::LogLeak),
];

/// Sanitizer classification for Go.
pub(crate) fn go_classify_sanitizer(call: &str) -> Option<crate::role_map::SanitizerKind> {
    use super::super::call_last_segment;
    match call_last_segment(call) {
        // Numeric coercion - kills injection risk
        "Atoi" | "ParseInt" | "ParseUint" | "ParseFloat" | "ParseBool" => {
            Some(crate::role_map::SanitizerKind::Full)
        }
        // HTML escaping
        "EscapeString" | "HTMLEscapeString" | "HTMLEscape" => {
            Some(crate::role_map::SanitizerKind::HtmlEscape)
        }
        // URL encoding
        "QueryEscape" | "PathEscape" | "PathUnescape" => {
            Some(crate::role_map::SanitizerKind::UrlEncode)
        }
        // Path cleaning - partial mitigation for path traversal
        "Clean" | "Abs" | "EvalSymlinks" => Some(crate::role_map::SanitizerKind::PathNormalize),
        _ => None,
    }
}

/// Go sanitizer names.
pub(crate) static GO_SANITIZER_NAMES: &[&str] = &[
    "EscapeString",
    "EscapeHTML",
    "QueryEscape",
    "PathEscape",
    "template.HTMLEscapeString",
    "url.QueryEscape",
    "strconv.Atoi",
    "Sanitize",
    "EscapeText",
];

/// Propagators: (call, tainted_arg-slot, tainted_receiver). Travels taint
/// from arguments/receiver to the return value, enabling downstream sinks.
pub(crate) static GO_PROPAGATORS: &[crate::role_map::PropagatorRule] = &[
    // fmt - format string propagates taint from args
    (crate::role_map::PropagatorRule {
        call: "Sprintf",
        tainted_arg: None,
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "Fprintf",
        tainted_arg: None,
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "Errorf",
        tainted_arg: None,
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "Stringer",
        tainted_arg: None,
        tainted_receiver: false,
    }),
    // strings - receiver taints return
    (crate::role_map::PropagatorRule {
        call: "Join",
        tainted_arg: None,
        tainted_receiver: true,
    }),
    (crate::role_map::PropagatorRule {
        call: "Replace",
        tainted_arg: None,
        tainted_receiver: true,
    }),
    (crate::role_map::PropagatorRule {
        call: "ReplaceAll",
        tainted_arg: None,
        tainted_receiver: true,
    }),
    (crate::role_map::PropagatorRule {
        call: "TrimSpace",
        tainted_arg: None,
        tainted_receiver: true,
    }),
    (crate::role_map::PropagatorRule {
        call: "Trim",
        tainted_arg: None,
        tainted_receiver: true,
    }),
    (crate::role_map::PropagatorRule {
        call: "ToLower",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "ToUpper",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "Split",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "SplitN",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "Contains",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "HasPrefix",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "HasSuffix",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    // strconv - propagates taint (type conversion, not sanitization)
    (crate::role_map::PropagatorRule {
        call: "Itoa",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "FormatInt",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    (crate::role_map::PropagatorRule {
        call: "AppendInt",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    // path/filepath - path building propagates traversal risk
    (crate::role_map::PropagatorRule {
        call: "Base",
        tainted_arg: Some(0),
        tainted_receiver: false,
    }),
    // bytes.Buffer / strings.Builder
    (crate::role_map::PropagatorRule {
        call: "WriteString",
        tainted_arg: Some(0),
        tainted_receiver: true,
    }),
    (crate::role_map::PropagatorRule {
        call: "Write",
        tainted_arg: Some(0),
        tainted_receiver: true,
    }),
    (crate::role_map::PropagatorRule {
        call: "String",
        tainted_arg: None,
        tainted_receiver: true,
    }),
];
