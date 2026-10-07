// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//! Python [`LanguageSpec`] implementation.
//!
//! Key differences from JS/TS that broke the engine before this crate:
//! - Functions are `function_definition` / `async_function_definition`, not
//!   `function_declaration`. Both were silently skipped everywhere.
//! - Calls are `call` nodes, not `call_expression`.
//! - Member access is `attribute`, not `member_expression`.
//! - Assignments are `assignment`, not `variable_declarator`.
//! - `import_from_statement` (`from flask import Flask`) was never parsed.
//! - Route handlers are identified by decorators (`@app.route`), not param names.
//! - Python `with open(path) as f:` is a file-system sink that needs special handling.
//! - f-strings (`f"SELECT {user_input}"`) propagate taint through interpolation nodes.

use tree_sitter::Node;

use crate::spec::{
    call_last_segment, node_text, Import, LanguageSpec, NodeRole, PackageCategory, TaintOrigin,
};

// ── AST classification ────────────────────────────────────────────────────────

fn classify_python(kind: &str) -> NodeRole {
    match kind {
        // ── Functions ────────────────────────────────────────────────────
        // Both were missing from the engine's hardcoded match before this crate.
        "function_definition" | "async_function_definition" => NodeRole::Function {
            is_method: false, // determined by parent (class_definition body)
            name_field: Some("name".into()),
            params_field: "parameters".into(),
            body_field: "body".into(),
        },
        // `decorated_definition` wraps a `function_definition` with decorators.
        // Fingerprint extraction must descend into it to find the real function.
        // We classify it as a Function so the walker enters it.
        "decorated_definition" => NodeRole::Function {
            is_method: false,
            name_field: None, // name is on the inner function_definition
            params_field: "parameters".into(),
            body_field: "body".into(),
        },
        "lambda" => NodeRole::Function {
            is_method: false,
            name_field: None,
            params_field: "parameters".into(),
            body_field: "body".into(),
        },

        // ── Assignments ──────────────────────────────────────────────────
        // Python has no separate "declaration" concept - `x = expr` is both.
        "assignment" | "annotated_assignment" => NodeRole::Declaration {
            name_field: "left".into(),
            value_field: "right".into(),
        },
        "augmented_assignment" => NodeRole::Assignment {
            lhs_field: "left".into(),
            rhs_field: "right".into(),
        },
        // Walrus operator `:=` - e.g. `if (m := re.match(...))`
        "named_expression" => NodeRole::Declaration {
            name_field: "name".into(),
            value_field: "value".into(),
        },

        // ── Calls ────────────────────────────────────────────────────────
        // Python uses `call`, NOT `call_expression`
        "call" => NodeRole::Call {
            callee_field: "function".into(),
            args_field: "arguments".into(),
        },
        // Python member access is `attribute`, NOT `member_expression`
        "attribute" => NodeRole::MemberAccess {
            object_field: "object".into(),
            property_field: "attribute".into(),
        },
        "conditional_expression" => NodeRole::Conditional,
        "subscript" => NodeRole::MemberAccess {
            object_field: "value".into(),
            property_field: "subscript".into(),
        },

        // ── Control flow ─────────────────────────────────────────────────
        "if_statement" | "conditional_expression" | "match_statement" => NodeRole::Branch,
        "for_statement" | "while_statement" => NodeRole::Loop,
        "return_statement" => NodeRole::Return,
        "try_statement" => NodeRole::Try,
        // Python uses `except_clause`, NOT `catch_clause`
        "except_clause" | "except_group_clause" => NodeRole::Catch,
        "finally_clause" => NodeRole::Finally,
        "raise_statement" => NodeRole::Throw,
        "await" => NodeRole::Await,
        // `with` statement - needs special context_manager_call handling
        "with_statement" => NodeRole::ContextManager,

        // ── Structural ───────────────────────────────────────────────────
        "block" => NodeRole::Block,
        "import_statement" | "import_from_statement" => NodeRole::Import,
        "identifier" => NodeRole::Identifier,
        "string" | "integer" | "float" | "true" | "false" | "none" | "concatenated_string" => {
            NodeRole::Literal
        }

        // ── Supplementary structural roles ───────────────────────────────
        "parameters"
        | "parameter"
        | "default_parameter"
        | "typed_parameter"
        | "typed_default_parameter"
        | "positional_separator"
        | "tuple_pattern"
        | "list_pattern"
        | "dictionary_pattern"
        | "return_type" => NodeRole::Parameters,
        "argument_list" | "generator_expression" => NodeRole::Arguments,
        "class_definition" => NodeRole::ClassDef,
        "binary_operator" | "comparison_operator" | "boolean_operator" | "not_operator" => {
            NodeRole::BinaryOp
        }
        "unary_operator" => NodeRole::UnaryOp,
        "match_statement" => NodeRole::Match,
        "async_block" => NodeRole::AsyncBlock,

        _ => NodeRole::Other,
    }
}

// ── Context manager sink detection ───────────────────────────────────────────

/// For `with open(path, mode) as f:`, extracts the path argument text
/// so the engine can check if it's tainted.
///
/// Returns `Some(path_text)` when the context manager is a file open call.
fn python_context_manager_call<'s>(node: Node<'_>, source: &'s str) -> Option<&'s str> {
    if node.kind() != "with_statement" {
        return None;
    }

    // with_statement > with_clause > with_item > value (the expression)
    for i in 0..node.named_child_count() {
        let clause = node.named_child(i)?;
        for j in 0..clause.named_child_count() {
            let item = clause.named_child(j)?;
            if let Some(value) = item.child_by_field_name("value") {
                // Is it a call to `open`, `io.open`, `gzip.open`, etc.?
                if value.kind() == "call" {
                    if let Some(func) = value.child_by_field_name("function") {
                        let name = node_text(func, source);
                        let last = call_last_segment(name);
                        if matches!(last, "open" | "fopen" | "fdopen" | "gzip.open" | "bz2.open") {
                            // Return the first argument (the path)
                            if let Some(args) = value.child_by_field_name("arguments") {
                                if let Some(first_arg) = args.named_child(0) {
                                    return Some(node_text(first_arg, source));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// ── Import extraction ─────────────────────────────────────────────────────────

fn extract_python_imports(root: Node<'_>, source: &str) -> Vec<Import> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    'outer: loop {
        let node = cursor.node();

        match node.kind() {
            // `import flask`
            // `import sqlalchemy as sa`
            "import_statement" => {
                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        match child.kind() {
                            "dotted_name" => {
                                let pkg = node_text(child, source);
                                let local = pkg.split('.').next().unwrap_or(pkg);
                                imports.push(Import {
                                    local_name: local.to_owned(),
                                    package: pkg.to_owned(),
                                    symbol: None,
                                });
                            }
                            "aliased_import" => {
                                // `import sqlalchemy as sa`
                                let name = child
                                    .child_by_field_name("name")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or("");
                                let alias = child
                                    .child_by_field_name("alias")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or(name);
                                imports.push(Import {
                                    local_name: alias.to_owned(),
                                    package: name.to_owned(),
                                    symbol: None,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }

            // `from flask import Flask, request`
            // `from flask import Flask as F`
            // `from sqlalchemy.orm import Session`
            "import_from_statement" => {
                let module_name = node
                    .child_by_field_name("module_name")
                    .map(|n| node_text(n, source))
                    .unwrap_or("")
                    .to_owned();

                for i in 0..node.named_child_count() {
                    if let Some(child) = node.named_child(i) {
                        match child.kind() {
                            "dotted_name" | "identifier" => {
                                let sym = node_text(child, source);
                                if sym != module_name.as_str() {
                                    imports.push(Import {
                                        local_name: sym.to_owned(),
                                        package: module_name.clone(),
                                        symbol: Some(sym.to_owned()),
                                    });
                                }
                            }
                            "aliased_import" => {
                                let name = child
                                    .child_by_field_name("name")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or("");
                                let alias = child
                                    .child_by_field_name("alias")
                                    .map(|n| node_text(n, source))
                                    .unwrap_or(name);
                                imports.push(Import {
                                    local_name: alias.to_owned(),
                                    package: module_name.clone(),
                                    symbol: Some(name.to_owned()),
                                });
                            }
                            "wildcard_import" => {
                                // `from flask import *` - bind the module itself
                                imports.push(Import {
                                    local_name: module_name
                                        .split('.')
                                        .next()
                                        .unwrap_or(&module_name)
                                        .to_owned(),
                                    package: module_name.clone(),
                                    symbol: None,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }

        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                break 'outer;
            }
        }
    }

    imports
}

// ── Package catalogue ─────────────────────────────────────────────────────────

fn python_package_category(pkg: &str) -> Option<PackageCategory> {
    // Match the top-level package name (before any `.`)
    let base = pkg.split('.').next().unwrap_or(pkg);
    match base {
        // ── HTTP frameworks ───────────────────────────────────────────────
        "flask" | "django" | "fastapi" | "aiohttp" | "tornado" | "starlette" | "sanic"
        | "falcon" | "bottle" | "pyramid" | "cherrypy" | "uvicorn" | "litestar" | "blacksheep"
        | "robyn" => Some(PackageCategory::HttpFramework),

        // ── SQL databases ─────────────────────────────────────────────────
        "sqlalchemy" | "psycopg2" | "psycopg" | "pymysql" | "sqlite3" | "pymssql" | "cx_Oracle"
        | "aiomysql" | "asyncpg" | "databases" | "tortoise" | "peewee" | "pony" => {
            Some(PackageCategory::SqlDatabase)
        }

        // ── NoSQL ─────────────────────────────────────────────────────────
        "pymongo" | "motor" | "redis" | "aioredis" | "elasticsearch" | "cassandra" | "couchdb" => {
            Some(PackageCategory::NoSqlDatabase)
        }

        // ── Command execution ─────────────────────────────────────────────
        "subprocess" | "os" | "shlex" | "pty" | "popen2" | "commands" | "plumbum" | "sh" => {
            Some(PackageCategory::CommandExecution)
        }

        // ── File system ───────────────────────────────────────────────────
        "pathlib" | "shutil" | "glob" | "tempfile" | "io" | "fileinput" | "zipfile" | "tarfile" => {
            Some(PackageCategory::FileSystem)
        }

        // ── HTTP clients (SSRF) ───────────────────────────────────────────
        "requests" | "httpx" | "urllib" | "urllib3" | "httplib2" | "pycurl" | "grequests" => {
            Some(PackageCategory::HttpClient)
        }

        // ── Template engines (SSTI) ───────────────────────────────────────
        "jinja2" | "mako" | "chameleon" | "genshi" => Some(PackageCategory::TemplateEngine), // also framework

        // ── Unsafe deserialization ────────────────────────────────────────
        "pickle" | "cPickle" | "shelve" | "marshal" | "yaml" | "PyYAML" | "jsonpickle" | "dill" => {
            Some(PackageCategory::Deserialization)
        }

        // ── Crypto ───────────────────────────────────────────────────────
        "cryptography" | "Crypto" | "nacl" | "hashlib" | "hmac" | "secrets" => {
            Some(PackageCategory::Crypto)
        }

        // ── Testing ───────────────────────────────────────────────────────
        "pytest" | "unittest" | "nose" | "hypothesis" => Some(PackageCategory::Testing),

        _ => None,
    }
}

// ── Param taint ───────────────────────────────────────────────────────────────

fn python_classify_param(name: Option<&str>, ann: Option<&str>) -> Option<TaintOrigin> {
    // FastAPI: parameter type is a Pydantic model or an explicit annotation
    // like `request: Request`. The type annotation is the key signal.
    if let Some(a) = ann {
        let base = a.split('[').next().unwrap_or(a).trim();
        if matches!(base, "Request" | "HTTPRequest" | "HttpRequest") {
            return Some(TaintOrigin::UserInput);
        }
        // FastAPI dependencies annotated with `Query(...)`, `Path(...)`, `Body(...)`
        // These appear in function signatures as `param: str = Query(...)`.
        // We can't distinguish from annotation alone; handled by propagators.
    }

    // Flask / Django: `request` is always a global taint source - no param needed.
    // FastAPI: named params from URL path / query are taint sources by framework convention.
    match name? {
        "request" | "req" => Some(TaintOrigin::UserInput),
        _ => None,
    }
}

// ── Tree-sitter queries ───────────────────────────────────────────────────────

const PYTHON_SYMBOL_QUERY: &str = r#"
    (function_definition name: (identifier) @name)
    (async_function_definition name: (identifier) @name)
    (class_definition name: (identifier) @name)
"#;

// Covers both top-level functions and class methods.
const PYTHON_CALL_QUERY: &str = r#"
    (function_definition name: (identifier) @caller
        body: (block
            (expression_statement
                (call function: (identifier) @call))))

    (function_definition name: (identifier) @caller
        body: (block
            (expression_statement
                (call function:
                    (attribute attribute: (identifier) @call)))))

    (class_definition body: (block
        (function_definition name: (identifier) @caller
            body: (block
                (expression_statement
                    (call function: (identifier) @call))))))

    (class_definition body: (block
        (function_definition name: (identifier) @caller
            body: (block
                (expression_statement
                    (call function:
                        (attribute attribute: (identifier) @call)))))))

    (async_function_definition name: (identifier) @caller
        body: (block
            (expression_statement
                (call function: (identifier) @call))))

    (async_function_definition name: (identifier) @caller
        body: (block
            (expression_statement
                (call function:
                    (attribute attribute: (identifier) @call)))))
"#;

// ── PythonSpec ────────────────────────────────────────────────────────────────

pub struct PythonSpec;

impl LanguageSpec for PythonSpec {
    fn name(&self) -> &'static str {
        "python"
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["py", "pyi", "pyw"]
    }

    fn tree_sitter_language(&self) -> tree_sitter::Language {
        #[cfg(feature = "python")]
        return tree_sitter_python::LANGUAGE.into();
        #[cfg(not(feature = "python"))]
        panic!("frensense-lang: 'python' feature not enabled");
    }

    fn classify(&self, kind: &str) -> NodeRole {
        classify_python(kind)
    }

    // tree-sitter-python: `attribute` nodes hold the property name in a plain
    // `identifier` child. The default JS heuristic misclassifies it as a
    // computed index, turning `cursor.execute(...)` into CallPointer and
    // losing the sink name.
    fn is_property_kind(&self, kind: &str) -> bool {
        kind == "identifier"
    }

    fn is_declaration_assignment(&self, kind: &str) -> bool {
        matches!(kind, "subscript" | "attribute")
    }

    /// Python `with open(path) as f:` - extracts the path argument.
    fn context_manager_call<'s>(&self, node: Node<'_>, source: &'s str) -> Option<&'s str> {
        python_context_manager_call(node, source)
    }

    fn wrap_region(&self, code: &str) -> String {
        // Python requires indentation inside function bodies
        let indented: String = code.lines().map(|l| format!("    {}\n", l)).collect();
        format!("def _region():\n{}", indented)
    }

    fn import_node_kinds(&self) -> &'static [&'static str] {
        &["import_statement", "import_from_statement"]
    }

    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import> {
        extract_python_imports(root, source)
    }

    fn symbol_query(&self) -> Option<&'static str> {
        Some(PYTHON_SYMBOL_QUERY)
    }
    fn call_query(&self) -> Option<&'static str> {
        Some(PYTHON_CALL_QUERY)
    }

    fn package_category(&self, pkg: &str) -> Option<PackageCategory> {
        python_package_category(pkg)
    }

    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin> {
        python_classify_param(name, type_annotation)
    }

    fn is_http_route_decorator(&self, name: &str) -> bool {
        // Matches the decorator name regardless of which framework uses it
        matches!(
            name,
            "route" | "get" | "post" | "put" | "delete" | "patch" | "options" | "head"
            // Django
            | "login_required" | "require_http_methods" | "require_GET" | "require_POST"
            // FastAPI
            | "router" | "api_route"
        )
    }

    fn ternary_cond_index(&self) -> usize {
        // Python: `then if cond else else_arm` - the condition is the
        // middle named child, unlike JS/C where it comes first.
        1
    }
}
