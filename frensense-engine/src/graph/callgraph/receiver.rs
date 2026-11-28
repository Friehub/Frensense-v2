// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Which class a call receiver is written under, derived from the enclosing
//! function's lowered name.
//!
//! Lowered names are file-qualified (`app.ts::main`, `src/app.py::handler`),
//! so the file qualifier must never be read as a class: splitting
//! `app.ts::main` on `.` yields `("app", "ts::main")` and invents a class
//! named `app`. That fabricates a class for every top-level function in a
//! file whose name contains a dot, which makes the unknown-receiver arm of
//! dispatch resolution unreachable and re-opens the bare-name binding it
//! exists to prevent (#193).

/// If `fname` is a qualified method name (`Class.method`, or
/// `file.ts::Class.method`), return `Class`.
///
/// Only the part after the file qualifier is split, and a remainder that is
/// still dotted (`app.ts::main` -> `ts::main`) is a file extension rather
/// than a class, so a top-level function names no class at all.
pub(super) fn this_class_of(fname: &str) -> Option<String> {
    let name = fname.rsplit_once("::").map_or(fname, |(_, name)| name);
    let (class, _method) = name.rsplit_once('.')?;
    if class.is_empty() || class.contains(['.', '/', '\\']) {
        return None;
    }
    Some(class.to_string())
}

#[cfg(test)]
mod tests {
    use super::this_class_of;

    #[test]
    fn a_qualified_method_name_names_its_class() {
        assert_eq!(this_class_of("User.save").as_deref(), Some("User"));
    }

    #[test]
    fn a_file_qualified_function_names_no_class() {
        assert_eq!(this_class_of("app.ts::main"), None);
        assert_eq!(this_class_of("src/app.py::handler"), None);
        assert_eq!(this_class_of("src/nested/mod.ts::run"), None);
    }

    #[test]
    fn a_method_inside_a_file_keeps_its_class() {
        assert_eq!(this_class_of("app.ts::User.save").as_deref(), Some("User"));
    }

    #[test]
    fn a_dot_free_name_names_no_class() {
        assert_eq!(this_class_of("main"), None);
        assert_eq!(this_class_of(""), None);
    }
}
