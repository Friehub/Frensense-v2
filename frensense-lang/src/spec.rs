// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
//!
//! The [`LanguageSpec`] trait is the single contract every language must
//! satisfy. All engine subsystems (fingerprint, CFG, def-use, flow-fingerprint,
//! import resolver, semantic provider) call *this* trait instead of containing
//! their own hardcoded `match kind { "call_expression" | … }` arms.
//!
//! # Why one trait, not many?
//!
//! Previous analysis showed nine separate hardcoding sites. Splitting the fix
//! across nine small traits creates nine places a new language author can
//! forget to implement one. A single trait with good defaults makes the
//! "forgot to implement" case a compile error, not a silent empty result.

use std::borrow::Cow;

use tree_sitter::Node;

// ── Supporting types ─────────────────────────────────────────────────────────

/// What role does a tree-sitter node play in the language?
///
/// Variants carry the **field names** needed to walk child nodes so callers
/// never need a second lookup. All `*_field` values are `Cow<'static, str>`:
/// `Borrowed` for spec vocabulary (tree-sitter grammar constants, no
/// allocation), `Owned` for bundle-learned roles (allocated once per fact,
/// never leaked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRole {
    // ── Definitions ──────────────────────────────────────────────────────
    /// A named or anonymous function / method / closure.
    Function {
        /// True when the grammar distinguishes methods from top-level functions
        /// (TS `method_definition`, Go `method_declaration`).
        is_method: bool,
        /// Field holding the function's name identifier, if any.
        /// `None` for arrow functions, lambdas, anonymous closures.
        name_field: Option<Cow<'static, str>>,
        /// Field holding the parameter list node.
        params_field: Cow<'static, str>,
        /// Field holding the body block node.
        body_field: Cow<'static, str>,
    },

    // ── Assignments / declarations ────────────────────────────────────────
    /// A variable declaration with an initializer.
    /// `let x = expr` (JS/Rust), `x := expr` (Go).
    Declaration {
        name_field: Cow<'static, str>,
        value_field: Cow<'static, str>,
    },
    /// A mutation of an existing binding.
    /// `x = expr` (all languages), `x += expr`.
    Assignment {
        lhs_field: Cow<'static, str>,
        rhs_field: Cow<'static, str>,
    },

    // ── Calls ─────────────────────────────────────────────────────────────
    /// Any function / method invocation.
    Call {
        callee_field: Cow<'static, str>,
        args_field: Cow<'static, str>,
    },
    /// Member / field access producing a value (not a call).
    /// `obj.field`, `obj->field`, `obj.attribute`.
    MemberAccess {
        object_field: Cow<'static, str>,
        property_field: Cow<'static, str>,
    },

    // ── Control flow ──────────────────────────────────────────────────────
    Branch, // if / switch / match-arm
    /// Ternary conditional EXPRESSION (`a ? b : c`, Python `a if c else b`).
    /// Separate from Branch: both arms are expressions producing a value,
    /// lowered as branch + Phi, not as a statement-level fork.
    Conditional,
    Loop,    // for / while / do / loop
    Return,  // return statement / expression
    Try,     // try { … }
    Catch,   // catch / except clause
    Finally, // finally clause
    Throw,   // throw / raise

    // ── Special language patterns ─────────────────────────────────────────
    /// Go: `if err != nil { return … }` - structurally a Branch but semantically
    /// an error propagation guard; the engine needs to detect it for auth-guard
    /// dominator analysis.
    ErrorGuard,
    /// Python: `with expr as var:` - a context-manager entry; the callee
    /// may be a path/file sink.
    ContextManager,
    /// Rust: the `?` postfix operator - propagates errors, terminates the
    /// current scope if the value is `Err`.
    ErrorPropagation,
    /// Rust async block, JS/TS `await`, Python `await`.
    Await,

    // ── Structural ────────────────────────────────────────────────────────
    Block, // { … } / indented block
    /// Value-context composite literal: JS/TS `object` used as a value (not a
    /// statement block), `array`, `object_pattern` in expression position.
    /// Uniformly-keyed objects and arrays lower to an allocation with one
    /// store per property/element: field reads resolve through
    /// field-sensitive heap edges (taint in one property does not pollute
    /// reads of another), while whole-container consumers see every stored
    /// value. Objects with unkeyed children (spreads) keep the legacy
    /// may-analysis union - conservative for taint.
    Composite,
    Import,     // import / use / require
    Export,     // export (JS/TS only)
    Identifier, // bare name reference
    Literal,    // string / number / bool literal

    // ── Supplementary structural roles ────────────────────────────────────
    /// Parameter list: `formal_parameters` (JS/TS), `parameter_list` (Go),
    /// `parameters` (Python), `parameter_declaration` (C).
    Parameters,
    /// Argument list: `arguments` (JS/TS), `argument_list` (Python/Go/C),
    /// `token_tree` (Rust macros).
    Arguments,
    /// A named call argument (`f(secure=False)`): Python `keyword_argument`.
    /// Distinct from a plain expression so the IR can keep the argument's
    /// *name* alongside its value - a policy that constrains one flag cannot
    /// be expressed correctly by position when the caller may omit earlier
    /// optional arguments.
    KeywordArgument {
        /// Field holding the argument name.
        name_field: Cow<'static, str>,
        /// Field holding the argument value expression.
        value_field: Cow<'static, str>,
    },
    /// Class / struct / enum / interface / trait definition.
    ClassDef,
    /// Binary expression: `a + b`, `x && y`.
    BinaryOp,
    /// Unary expression: `!x`, `-x`, `*ptr`.
    UnaryOp,
    /// Pattern match: `match` (Rust), `switch` as type/value switch (Go),
    /// `match` statement (Python), `switch_expression` (JS/TS).
    Match,
    /// Rust: `unsafe { … }` block.
    Unsafe,
    /// Rust async block, JS/TS `async function`, Python `async def`.
    AsyncBlock,

    /// Anything the engine does not need to inspect.
    Other,
}

impl NodeRole {}

/// Broad category for what a package is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PackageCategory {
    HttpFramework,
    GraphQL,
    WebSocket,
    EmailService,
    SqlDatabase,
    NoSqlDatabase,
    CommandExecution,
    FileSystem,
    HttpClient,      // SSRF risk
    TemplateEngine,  // SSTI / XSS
    Deserialization, // unsafe deserialize
    Crypto,
    Logging,
    Testing,
}

/// Broad origin of tainted data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TaintOrigin {
    UserInput,   // HTTP request body/query/path/header
    Environment, // process.env / os.environ / std::env
    FileSystem,  // file read whose path came from user
    Database,    // query result that may contain injection
    Network,     // IPC / downstream API response
    Custom(String),
}

impl std::fmt::Display for TaintOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserInput => write!(f, "user_input"),
            Self::Environment => write!(f, "environment"),
            Self::Database => write!(f, "database"),
            Self::Network => write!(f, "network"),
            Self::FileSystem => write!(f, "file_system"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

impl From<&str> for TaintOrigin {
    fn from(s: &str) -> Self {
        match s {
            "user_input" | "user" => Self::UserInput,
            "environment" | "env" => Self::Environment,
            "database" | "db" => Self::Database,
            "network" | "net" => Self::Network,
            "file_system" | "fs" => Self::FileSystem,
            _ => Self::Custom(s.to_string()),
        }
    }
}

/// A parsed import as extracted by [`LanguageSpec::extract_imports`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The local binding name, e.g. `"cp"`, `"exec"`, `"Flask"`.
    pub local_name: String,
    /// The source package / module path, e.g. `"child_process"`, `"flask"`.
    pub package: String,
    /// The specific symbol imported, if the language supports named imports.
    /// e.g. `from flask import Flask` → `symbol = Some("Flask")`.
    pub symbol: Option<String>,
}

/// A parsed export or re-export as extracted by [`LanguageSpec::extract_exports`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Export {
    /// The exported symbol name (the name visible to importers).
    pub exported_name: String,
    /// The local / source symbol name being exported.
    pub local_name: String,
    /// If this is a re-export from another module (e.g. `export { x as y } from "./foo"`),
    /// the source module package / path. None for local exports.
    pub from_module: Option<String>,
    /// Written visibility of the export.
    pub visibility: Visibility,
    /// Declaration kind of the exported symbol.
    pub kind: ItemKind,
}

/// Written or inferred visibility of a declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Visibility {
    Public,
    Internal,
    Private,
}

/// The syntactic or semantic kind of a module-level declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ItemKind {
    Function,
    Constant,
    Variable,
    Class,
    Enum,
    Interface,
    Type,
    Module,
    Struct,
    Trait,
    Other,
}

/// A top-level item declared in a module.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ModuleItem {
    pub name: String,
    pub kind: ItemKind,
    pub visibility: Visibility,
}

// ── The trait ─────────────────────────────────────────────────────────────────

/// Everything the frensense engine needs to know about one source language.
///
/// Implement this once per language.  The engine never matches raw node-kind
/// strings anywhere else.
///
/// # Object safety
///
/// The trait is object-safe: it can be stored as `Arc<dyn LanguageSpec>` in
/// the [`LanguageRegistry`](crate::registry::LanguageRegistry).
pub trait LanguageSpec: Send + Sync + 'static {
    // ── Identity ─────────────────────────────────────────────────────────

    /// Canonical short name used in fingerprints and the FRC bundle.
    fn name(&self) -> &'static str;

    /// File extensions handled by this spec (lowercase, no dot).
    fn extensions(&self) -> &'static [&'static str];

    /// The tree-sitter `Language` object for parsing.
    fn tree_sitter_language(&self) -> tree_sitter::Language;

    // ── Node classification ───────────────────────────────────────────────

    /// Classify a tree-sitter node kind into a [`NodeRole`].
    ///
    /// This is the single hot-path entry point for all engine subsystems.
    /// The returned variant carries the field names needed by the caller so
    /// no second lookup is required.
    ///
    /// ```rust,ignore
    /// match spec.classify(node.kind()) {
    ///     NodeRole::Call { callee_field, args_field } => {
    ///         let callee = node.child_by_field_name(callee_field);
    ///         // …
    ///     }
    ///     NodeRole::Assignment { lhs_field, rhs_field } => { /* … */ }
    ///     _ => {}
    /// }
    /// ```
    fn classify(&self, kind: &str) -> NodeRole;

    /// Index of the condition among a ternary expression's named children.
    ///
    /// JS/TS `a ? b : c` → `[cond, then, else]`, condition at 0.
    /// Python `then if cond else else_arm` → `[then, cond, else]`,
    /// condition at 1 (middle). Defaults to 0.
    fn ternary_cond_index(&self) -> usize {
        0
    }

    /// Is this node kind a *property-name* (a named field access) rather
    /// than a computed index?
    ///
    /// Used by the lowering to distinguish `obj.field` (LoadField, the name
    /// matters for member-path source matching and sink method resolution)
    /// from `obj[expr]` (LoadElement). The default heuristic recognizes the
    /// common JS/TS kinds; languages whose attribute/selector property nodes
    /// have different grammar kinds MUST override this:
    ///
    /// - Python `attribute`: the property child is a plain `identifier`
    /// - Go `selector_expression` / Rust `field_expression`: `field_identifier`
    ///
    /// A wrong answer silently turns method calls into CallPointer sites and
    /// loses sink matching entirely.
    fn is_property_kind(&self, kind: &str) -> bool {
        kind.contains("property")
            || kind == "property_identifier"
            || kind == "shorthand_property_identifier"
            || kind == "private_property_identifier"
    }

    /// Returns `true` if this node is the entry node for a function definition.
    ///
    /// Convenience wrapper around [`classify`](Self::classify); the default
    /// implementation delegates.  Override only when a language has edge-cases
    /// (e.g. Python `decorated_definition` which wraps the real
    /// `function_definition`).
    fn is_function_node(&self, kind: &str) -> bool {
        matches!(self.classify(kind), NodeRole::Function { .. })
    }

    /// Returns `true` if this node kind represents a type cast or type assertion (e.g. `x as T`, `(T)x`).
    fn is_cast(&self, _kind: &str) -> bool {
        false
    }

    /// Decorator / attribute call names applied to this function-definition
    /// node (`@guard(...)`, `#[guard]`, `@app.route(...)`).
    ///
    /// Pure grammar mechanism: decorators are placed either as *direct
    /// children* of the definition (Python `decorated_definition`, JS/TS
    /// member decorators) or as *preceding sibling attribute nodes*
    /// (Rust `#[attr]` on `fn`). Their text reliably starts with `@`
    /// or `#[`, so placement and spelling are recognized structurally
    /// and no per-language node-kind table is needed. The name is
    /// stripped to its last `.` segment and cut at the call paren so
    /// `@group.require_role(user)` yields `require_role`.
    fn decorator_guard_calls<'a>(
        &self,
        node: tree_sitter::Node<'a>,
        source: &'a str,
    ) -> Vec<&'a str> {
        let mut out = Vec::new();
        let mut visit = |n: tree_sitter::Node<'a>| {
            if let Some(name) = decorator_call_name(node_text(n, source)) {
                out.push(name);
            }
        };
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            visit(child);
        }
        let mut prev = node;
        while let Some(sib) = prev.prev_sibling() {
            if is_attribute_text(node_text(sib, source)) {
                visit(sib);
            }
            prev = sib;
        }
        out
    }

    /// Returns `true` if this node kind represents a string template or interpolated string (e.g. `template_string`, `f_string`).
    fn is_template_string(&self, _kind: &str) -> bool {
        false
    }

    /// Returns `true` if this node kind represents an untainted literal fragment of a template string (e.g. `string_fragment`).
    fn is_template_literal_fragment(&self, _kind: &str) -> bool {
        false
    }

    /// Returns `true` if this node kind represents a destructuring pattern (e.g. `object_pattern`, `array_pattern`).
    fn is_destructuring_pattern(&self, _kind: &str) -> bool {
        false
    }

    /// Returns `true` if this node kind represents a pair pattern inside a destructuring pattern (e.g. `pair_pattern`).
    fn is_pair_pattern(&self, _kind: &str) -> bool {
        false
    }

    /// Returns `true` if this node kind represents a key-value pair inside an object literal (e.g. `pair`).
    fn is_pair_entry(&self, _kind: &str) -> bool {
        false
    }

    /// Returns `true` if this node kind represents a ternary conditional expression evaluated straight-line
    /// (e.g. `ternary_expression`, `conditional_expression`, `conditional_type`).
    fn is_ternary_straight_line(&self, _kind: &str) -> bool {
        false
    }

    /// Returns `true` if this node kind represents an assignment expression in declaration position
    /// (e.g. Python `subscript`, `attribute`).
    fn is_declaration_assignment(&self, _kind: &str) -> bool {
        false
    }

    /// If the function body has an implicit return expression (e.g. Rust trailing expression
    /// or JS arrow function expression), return the node producing that return value.
    fn implicit_return_node<'a>(&self, _fn_node: Node<'a>, _body: Node<'a>) -> Option<Node<'a>> {
        None
    }

    /// Unwraps declarator wrapper nodes (e.g. `pointer_declarator`, `expression_list`, etc.)
    /// to locate the leaf name binding node.
    fn unwrap_declarator_node<'a>(&self, node: Node<'a>) -> Node<'a> {
        let mut cur = node;
        if matches!(
            cur.kind(),
            "expression_list" | "identifier_list" | "expression_sequence"
        ) {
            let mut nc = cur.walk();
            let named: Vec<_> = cur.named_children(&mut nc).collect();
            if named.len() == 1 {
                cur = named[0];
            }
        }
        while let Some(inner) = match cur.kind() {
            "pointer_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "reference_declarator" => {
                let mut wc = cur.walk();
                let mut found = None;
                for c in cur.children(&mut wc) {
                    if c.is_named() && c.kind() != "comment" {
                        found = Some(c);
                        break;
                    }
                }
                found
            }
            _ => None,
        } {
            cur = inner;
        }
        cur
    }

    // ── Special structural patterns ───────────────────────────────────────

    /// Returns `true` when this node is a Go-style error guard:
    /// `if err != nil { return … }`.
    ///
    /// The default always returns `false`.  Override in the Go provider.
    fn is_error_guard<'tree>(&self, _node: Node<'tree>, _source: &str) -> bool {
        false
    }

    /// For Python `with_statement` nodes, return the text of the call inside
    /// the `as` clause if it looks like a file/resource sink.
    ///
    /// Returns `None` for all languages that don't have context managers.
    fn context_manager_call<'s>(&self, _node: Node<'_>, _source: &'s str) -> Option<&'s str> {
        None
    }

    // ── Region wrapping ───────────────────────────────────────────────────

    /// Wrap a snippet of source code so it can be re-parsed as a valid
    /// function body.  Used by region chunking in the fingerprinter.
    fn wrap_region(&self, code: &str) -> String;

    // ── Import extraction ─────────────────────────────────────────────────

    /// Tree-sitter node kinds that represent import declarations.
    fn import_node_kinds(&self) -> &'static [&'static str];

    /// Walk `root` and return all imports found in the file.
    ///
    /// The engine calls this once per file; the result is stored in the
    /// `ImportMap` and used by the semantic provider.
    fn extract_imports<'tree>(&self, root: Node<'tree>, source: &str) -> Vec<Import>;

    /// Walk `root` and return all exports and re-exports found in the file.
    fn extract_exports<'tree>(&self, _root: Node<'tree>, _source: &str) -> Vec<Export> {
        Vec::new()
    }

    /// Walk `root` and return all top-level module items (declarations) in the file.
    fn extract_module_items<'tree>(&self, _root: Node<'tree>, _source: &str) -> Vec<ModuleItem> {
        Vec::new()
    }

    // ── Tree-sitter queries ───────────────────────────────────────────────

    /// A tree-sitter query that captures symbol definitions.
    /// Capture names: `@name` (identifier), optionally `@kind`.
    /// Used to build the per-file symbol table.
    fn symbol_query(&self) -> Option<&'static str> {
        None
    }

    /// A tree-sitter query that captures call edges for the call graph.
    /// Capture names: `@caller`, `@call`.
    fn call_query(&self) -> Option<&'static str> {
        None
    }

    // ── Framework / semantic knowledge ────────────────────────────────────

    /// Map an import package path to its broad category.
    ///
    /// e.g. `"database/sql"` → `Some(PackageCategory::SqlDatabase)`
    ///
    /// Used by the semantic provider to classify sinks and sources without
    /// knowing every individual method name in every package.
    fn package_category(&self, package: &str) -> Option<PackageCategory>;

    /// Is this function parameter a taint source?
    ///
    /// Called with both the name (`"r"`) and the raw type annotation text
    /// (`"*http.Request"`).  Either may be `None`.
    fn classify_param_taint(
        &self,
        name: Option<&str>,
        type_annotation: Option<&str>,
    ) -> Option<TaintOrigin>;

    /// Is this decorator / attribute name an HTTP route decorator?
    ///
    /// e.g. Python `@app.route`, Rust `#[get("/")]`, NestJS `@Get("/")`.
    fn is_http_route_decorator(&self, decorator_name: &str) -> bool {
        let _ = decorator_name;
        false
    }

    /// Route-registration call suffixes (`.post`, `.get`, ...) whose
    /// function arguments the harness extracts as handlers. The entries
    /// are matched as suffixes of the callee text.
    fn known_route_verbs(&self) -> &'static [&'static str] {
        &[".post", ".get", ".put", ".delete", ".use", ".all"]
    }

    /// Rule ids this language declares with full advisory metadata
    /// (severity plus title/impact/improvement templates). Rules absent from
    /// the registry receive the engine's generic policy fallback. Each
    /// language owns the rules of its own domain. Empty by default.
    fn known_rule_registry(&self) -> &'static [crate::severity::RuleEntry] {
        &[]
    }
}

// ── Helper: extract the last segment of a dotted call ────────────────────────

/// `"fmt.Sprintf"` → `"Sprintf"`, `"exec"` → `"exec"`.
#[inline]
pub fn call_last_segment(call: &str) -> &str {
    call.rsplit('.').next().unwrap_or(call)
}

// ── Helper: node text ─────────────────────────────────────────────────────────

/// Extract the UTF-8 text for a node from the source slice.
#[inline]
pub fn node_text<'s>(node: Node<'_>, source: &'s str) -> &'s str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
}

/// Does a node's text look like a decorator or attribute definition
/// (`@...` or `#[...]`) rather than ordinary statements? Purely textual,
/// so placement styles differ per language without a kind table.
#[inline]
fn is_attribute_text(text: &str) -> bool {
    let t = text.trim();
    t.starts_with('@') || t.starts_with("#[")
}

/// Parse the call name out of decorator/attribute text:
/// `"@app.route("/x")"` → `route`, `"#[ensure_owner]"` → `ensure_owner`.
#[inline]
fn decorator_call_name(text: &str) -> Option<&str> {
    let t = text.trim();
    let inner = match (t.strip_prefix('@'), t.strip_prefix("#[")) {
        (Some(s), _) => s,
        (_, Some(s)) => s,
        (None, None) => return None,
    };
    let inner = inner.trim();
    // Rust `#[...]` closes with `]`; the name is everything before the
    // first paren or bracket.
    let end = inner.find(['(', '[', '{', ']']).unwrap_or(inner.len());
    let name = inner[..end].trim();
    if name.is_empty() {
        None
    } else {
        Some(call_last_segment(name))
    }
}
