// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//!
//! Method names the languages' own builtin types carry.
//!
//! This is *language mechanism*, not detection knowledge: it says "this
//! name belongs to the language's containers, sequences and file handles",
//! never "this call is dangerous". That is the line between this crate and
//! `frensense-packgen` (which owns sink / source / sanitizer vocabulary):
//! neither the engine nor the pack may carry it.
//!
//! # Why the engine needs it
//!
//! When a call's receiver type cannot be resolved (`m.get(k)`,
//! `buf.write(s)`, `items.append(v)`), the call graph must not bind the site
//! to a program function that merely shares the bare method name. A local
//! `fn get()` is not `Map.prototype.get`, and the fabricated interprocedural
//! edge drags unrelated same-named functions into the taint walk - the
//! dominant false-positive class in the real-repo audit (tests/mre). A name
//! in this table is known to belong to a builtin type, so the site stays
//! external.
//!
//! # This is not a denylist of dangerous calls
//!
//! Membership carries no severity, CWE or label. A taint flow that reaches
//! `send` through a resolved receiver is still reported; only the
//! *unresolved* receiver's bare-name binding is refused.
//!
//! # Extending the table
//!
//! Add a name only when the language's standard library defines it on a
//! builtin type across the supported languages' shared vocabulary
//! (`Map.get`, `dict.get`, `Vec::get`, `sync.Map` aside). A name that is
//! only ever a user-defined method belongs in a corpus bundle, not here.

/// Is `name` a method the language's own containers, sequences, strings or
/// file handles define?
///
/// Deliberately language-agnostic: the languages Frensense lowers share
/// almost all of these method names, and the only consumer is a guard
/// against binding an unresolved receiver to a same-named program function,
/// where over-inclusion costs nothing but a missing (unlikely) internal
/// edge, and under-inclusion costs a fabricated edge and its taint.
#[must_use]
pub fn is_container_verb(name: &str) -> bool {
    matches!(
        name,
        // Maps, dictionaries and sets.
        "get"
            | "set"
            | "put"
            | "has"
            | "keys"
            | "values"
            | "items"
            | "clear"
            | "copy"
            | "update"
            // Sequences and strings.
            | "pop"
            | "push"
            | "append"
            | "extend"
            | "insert"
            | "add"
            // File and stream handles.
            | "read"
            | "write"
            | "close"
    )
}

#[cfg(test)]
mod tests {
    use super::is_container_verb;

    #[test]
    fn builtin_method_names_are_recognized() {
        for name in ["get", "set", "items", "append", "read", "write"] {
            assert!(is_container_verb(name), "{name} is a builtin method");
        }
    }

    #[test]
    fn application_and_framework_names_are_not() {
        // Project methods and provider APIs are not builtin methods; binding
        // them by name is the callgraph's job, not this table's.
        for name in ["execute", "query", "login", "render", "send", "handle"] {
            assert!(!is_container_verb(name), "{name} is not a builtin method");
        }
    }

    /// The table is mechanism, so it must never grow security vocabulary:
    /// a name that reads as a sink belongs in packgen's vocab or a bundle.
    #[test]
    fn table_holds_no_sink_vocabulary() {
        for name in ["eval", "exec", "system", "popen", "loads", "deserialize"] {
            assert!(!is_container_verb(name), "{name} is detection knowledge");
        }
    }
}
