// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing
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
//!
//! # The three layers of grammar knowledge
//!
//! A subsystem asks the spec at whichever layer matches its question, from
//! coarsest to finest:
//!
//! 1. **Roles** - [`LanguageSpec::classify`] answers "what is this node?" with a
//!    [`NodeRole`], field names included. Use it when one answer drives one
//!    branch (`Call`, `Return`, `Composite`, ...).
//! 2. **Predicates** - `is_*` queries answer a yes/no question the analysis
//!    asks about a node it already holds: [`LanguageSpec::is_statement_node`],
//!    [`LanguageSpec::is_block_node`], [`LanguageSpec::is_case_clause`],
//!    [`LanguageSpec::is_jump_target_name`],
//!    [`LanguageSpec::is_function_value`],
//!    [`LanguageSpec::is_discard_pattern`], and the rest. They exist because a
//!    role is sometimes too narrow (one grammar spells one concept several
//!    ways) or too broad, while a lowering site only needs the boolean. Every
//!    predicate defaults to the cross-language superset, so a provider overrides
//!    only what its grammar spells differently.
//! 3. **Tables** - [`LanguageSpec::jump_kind`],
//!    [`LanguageSpec::literal_shape`] and [`LanguageSpec::param_bindings`] map a
//!    kind to structured data (which jump, which literal shape, which binding),
//!    for walkers that dispatch on the answer instead of branching on a
//!    boolean.
//!
//! The rule for contributors: **the engine may not spell a node kind.** When a
//! decision needs one, add a layer-1/2/3 query here with a default that
//! reproduces today's behaviour, override it per grammar where the spelling
//! differs, and pin both in `providers/node_vocabulary_tests.rs`.

use std::borrow::Cow;

use tree_sitter::Node;

use crate::spec_params::param_bindings;

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
    /// A variable declaration with an initializer: `let x = expr` (JS/Rust),
    /// `x := expr` (Go), and Python's `x = expr`, which has no separate
    /// declaration form.
    Declaration {
        /// Field holding the declared name (or binding pattern).
        name_field: Cow<'static, str>,
        /// Field holding the initializer expression.
        value_field: Cow<'static, str>,
    },
    /// A mutation of an existing binding (`x = expr`, `x += expr`).
    ///
    /// Only the grammars that spell mutation as its own node kind use this;
    /// Python's plain `x = expr` is a [`NodeRole::Declaration`].
    Assignment {
        /// Field holding the assigned target.
        lhs_field: Cow<'static, str>,
        /// Field holding the assigned value expression.
        rhs_field: Cow<'static, str>,
    },

    // ── Calls ─────────────────────────────────────────────────────────────
    /// Any function / method invocation.
    Call {
        /// Field holding the callee expression.
        callee_field: Cow<'static, str>,
        /// Field holding the argument list node.
        args_field: Cow<'static, str>,
    },
    /// Member / field access producing a value (not a call).
    /// `obj.field`, `obj->field`, `obj.attribute`.
    MemberAccess {
        /// Field holding the accessed object.
        object_field: Cow<'static, str>,
        /// Field holding the accessed property name.
        property_field: Cow<'static, str>,
    },

    // ── Control flow ──────────────────────────────────────────────────────
    /// An `if` / `else if` / `else` chain, or a C-style `switch_statement`.
    ///
    /// Grammars whose switch/match dispatches on one subject are
    /// [`NodeRole::Match`] instead, and a ternary expression is
    /// [`NodeRole::Conditional`].
    Branch,
    /// Ternary conditional EXPRESSION (`a ? b : c`, Python `a if c else b`).
    /// Separate from Branch: both arms are expressions producing a value,
    /// lowered as branch + Phi, not as a statement-level fork.
    Conditional,
    /// A loop (`for`, `while`, `do`, `loop`): the CFG adds a back-edge.
    Loop,
    /// A `return` statement or expression.
    Return,
    /// A `try` block: the exception edge starts here.
    Try,
    /// An exception handler (`catch` clause, Python `except` clause).
    Catch,
    /// A `finally` block.
    Finally,
    /// A `throw` statement or expression (Python `raise`).
    Throw,

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
    /// An `await` expression (JS/TS, Python, Rust) or Go's `defer` / `go`
    /// statement, whose work runs outside the current evaluation.
    Await,

    // ── Structural ────────────────────────────────────────────────────────
    /// A block of statements (`{ … }`, an indented block).
    Block,
    /// Value-context composite literal: JS/TS `object` used as a value (not a
    /// statement block), `array`, `object_pattern` in expression position.
    /// Uniformly-keyed objects and arrays lower to an allocation with one
    /// store per property/element: field reads resolve through
    /// field-sensitive heap edges (taint in one property does not pollute
    /// reads of another), while whole-container consumers see every stored
    /// value. Objects with unkeyed children (spreads) keep the legacy
    /// may-analysis union - conservative for taint.
    Composite,
    /// An import declaration or call: `import`, `use`, `require`.
    Import,
    /// An export declaration (JS/TS only).
    Export,
    /// A bare name reference.
    Identifier,
    /// A literal value: string, number, boolean or null.
    Literal,

    // ── Supplementary structural roles ────────────────────────────────────
    /// A parameter list (`formal_parameters` in JS/TS, `parameters` in
    /// Python, `parameter_list` in Go/C) or one parameter node a grammar
    /// spells on its own (`parameter`, `parameter_declaration`,
    /// `typed_parameter`, `default_parameter`, `positional_separator`, ...).
    Parameters,
    /// An argument list: `arguments` (JS/TS/Rust), `argument_list`
    /// (Python/Go/C), Python's `generator_expression`, or a Rust macro's
    /// `token_tree`.
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
    /// An async block (`async { … }` in Rust, Python `async_block`).
    ///
    /// A JS/TS `async function` / Python `async def` is still a
    /// [`NodeRole::Function`]: only a block *without* a function of its own
    /// gets this role.
    AsyncBlock,

    /// Anything the engine does not need to inspect.
    Other,
}

impl NodeRole {}

/// A statement that transfers control to a labelled block or out of the
/// current loop/switch.
///
/// Named so the CFG lowering dispatches on the grammar's answer instead of
/// repeating a grammar's spellings: the default below is the C/JS pair the
/// lowering has always recognized, and a grammar whose jump nodes are spelled
/// differently overrides [`LanguageSpec::jump_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JumpKind {
    /// `goto label;`
    Goto,
    /// `label:` - the target of a `goto`.
    Label,
    /// `break;` / `break label;`
    Break,
    /// `continue;` / `continue label;`
    Continue,
}

/// The parts of JSX/TSX markup the lowering turns into prop stores.
///
/// Only the TypeScript/TSX grammar has these node kinds, so only the JavaScript
/// family overrides [`LanguageSpec::jsx_part`]; every other language answers
/// `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsxPart {
    /// `<div>…</div>` - holds an opening element and a children run.
    Element,
    /// `<div />` - attributes and no children.
    SelfClosingElement,
    /// `<>…</>` - children only.
    Fragment,
    /// `<div …>` inside an [`JsxPart::Element`].
    OpeningElement,
    /// The children run of an [`JsxPart::Element`].
    Children,
    /// `name={value}`.
    Attribute,
}

/// The literal a node spells, when the lowering can fold it at compile time.
///
/// Used by match-arm selection: only a pattern that spells one of these can
/// be compared against a constant subject without running the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LiteralShape {
    /// A quoted string or an implicit concatenation of them.
    String,
    /// An integer literal.
    Integer,
    /// A floating-point literal.
    Float,
    /// `true` / `false`.
    Boolean(bool),
    /// `none` / `null`.
    Null,
}

/// Broad category for what a package is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PackageCategory {
    /// Web framework (Express, Flask, Django, Actix).
    HttpFramework,
    /// GraphQL server or client library.
    GraphQL,
    /// WebSocket server or client library.
    WebSocket,
    /// Transactional or marketing email service.
    EmailService,
    /// Relational database driver or ORM (SQL injection risk).
    SqlDatabase,
    /// Document / key-value store driver (NoSQL injection risk).
    NoSqlDatabase,
    /// Process or shell command execution library.
    CommandExecution,
    /// File system API.
    FileSystem,
    /// HTTP client library (SSRF risk).
    HttpClient,
    /// Template engine (SSTI / XSS).
    TemplateEngine,
    /// Serializer or deserializer (unsafe deserialize).
    Deserialization,
    /// Cryptographic primitive.
    Crypto,
    /// Logging library.
    Logging,
    /// Test framework or assertion library.
    Testing,
}

/// Broad origin of tainted data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TaintOrigin {
    /// HTTP request body, query, path or header.
    UserInput,
    /// Process environment (`process.env`, `os.environ`, `std::env`).
    Environment,
    /// A file read whose path came from the user.
    FileSystem,
    /// A query result that may contain injected data.
    Database,
    /// An IPC or downstream API response.
    Network,
    /// A caller-defined origin, carried verbatim.
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
    /// Visible outside the declaring module.
    Public,
    /// Visible within the crate / package but not outside it.
    Internal,
    /// Visible only within the declaring item.
    Private,
}

/// The syntactic or semantic kind of a module-level declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ItemKind {
    /// Function or method.
    Function,
    /// Compile-time constant.
    Constant,
    /// Mutable or inferred variable binding.
    Variable,
    /// Class definition.
    Class,
    /// Enum definition.
    Enum,
    /// Interface definition.
    Interface,
    /// Type alias, `typedef` or associated type.
    Type,
    /// Module or namespace declaration.
    Module,
    /// Struct definition.
    Struct,
    /// Trait definition.
    Trait,
    /// Anything else the extractor found.
    Other,
}

/// A top-level item declared in a module.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ModuleItem {
    /// The declared name, as written in source.
    pub name: String,
    /// What kind of item it is.
    pub kind: ItemKind,
    /// Its written or inferred visibility.
    pub visibility: Visibility,
}

impl ModuleItem {
    /// Project the `public` items of `items` onto their [`Export`] view.
    ///
    /// A language without re-export syntax (C, Go, Python, and Rust's root
    /// surface) exports exactly its publicly visible declarations, so this
    /// projection belongs to the shared types rather than to each provider:
    /// every field of [`Export`] is already on [`ModuleItem`]. Languages that
    /// *do* have re-export statements (JS/TS `export { x as y } from "…"`)
    /// still derive exports from the AST, because a `ModuleItem` cannot say
    /// which module an export came from.
    ///
    /// A provider whose language has no re-export syntax returns exactly this
    /// projection from [`LanguageSpec::extract_exports`].
    pub(crate) fn public_exports(items: impl IntoIterator<Item = Self>) -> Vec<Export> {
        items
            .into_iter()
            .filter(|item| item.visibility == Visibility::Public)
            .map(|item| Export {
                exported_name: item.name.clone(),
                local_name: item.name,
                from_module: None,
                visibility: item.visibility,
                kind: item.kind,
            })
            .collect()
    }
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

    /// Rewrites the source into something the grammar can parse, run
    /// immediately before lowering. The default is the identity: the
    /// source is parsed as-is.
    ///
    /// **Position contract**: the rewrite MUST preserve every byte offset
    /// — same total length, same newline layout — so tree-sitter nodes and
    /// every line/column derived from them still point at the original
    /// file. Single-file-container formats (Vue SFCs, and later Svelte or
    /// Astro) use this to blank template markup into same-length runs of
    /// spaces instead of extracting script text to a separate buffer.
    fn preprocess<'a>(&self, source: &'a str) -> std::borrow::Cow<'a, str> {
        std::borrow::Cow::Borrowed(source)
    }

    /// The language key the FactTable and learned bundles key this spec's
    /// knowledge under. Defaults to [`name`](Self::name); a container
    /// format delegating to another spec's grammar also delegates its
    /// vocabulary (a Vue SFC's script is TypeScript, so its facts live in
    /// the `typescript` section). Registry identity still uses `name()`.
    fn fact_language(&self) -> &'static str {
        self.name()
    }

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

    // ── Node-kind vocabulary ──────────────────────────────────────────────

    // `classify` answers "what value does this node produce", but a few
    // grammar decisions are about *placement*: a comment among a statement's
    // children, the declarator inside a declaration, a JSX attribute, a jump
    // target. They are named here so no consumer keeps its own copy of a
    // grammar's spellings. Every default is `false`/`None` (or the one
    // language-agnostic spelling) so a provider states only what its grammar
    // actually has.

    /// A comment node. Every supported grammar spells it `comment`; a grammar
    /// that does not overrides this.
    fn is_comment(&self, kind: &str) -> bool {
        kind == "comment"
    }

    /// A statement that introduces variable declarators (`const x = 1`,
    /// `var x`). The engine binds the declarators it contains.
    fn is_variable_declaration_statement(&self, _kind: &str) -> bool {
        false
    }

    /// A single declarator inside a
    /// [`is_variable_declaration_statement`](Self::is_variable_declaration_statement).
    fn is_variable_declarator(&self, _kind: &str) -> bool {
        false
    }

    /// A function *value*: a function node that carries no name of its own
    /// (arrow function, function expression, lambda, closure, func literal).
    ///
    /// Distinct from [`is_function_node`](Self::is_function_node), which also
    /// matches declarations: binding a value to a name is not the same act as
    /// declaring the function that name refers to.
    fn is_function_value(&self, _kind: &str) -> bool {
        false
    }

    /// A composite literal that is array-shaped (`[a, b]`) rather than keyed
    /// (`{ a: 1 }`).
    fn is_array_composite(&self, _kind: &str) -> bool {
        false
    }

    /// A composite literal that is keyed (`{ a: 1 }`) rather than positional.
    ///
    /// The lowering allocates a keyed composite as an object and stores each
    /// entry under its field, keeping reads field-sensitive; one that is
    /// neither keyed nor positional (a parenthesized expression, a grammar's
    /// own composite wrapper) keeps the conservative union lowering. Answering
    /// `true` here for such a shape would silently make it field-sensitive.
    fn is_object_composite(&self, _kind: &str) -> bool {
        false
    }

    /// A destructuring pattern that binds by position (`[a, b]`) rather than
    /// by name (`{ a }`). Only meaningful when
    /// [`is_destructuring_pattern`](Self::is_destructuring_pattern) is true.
    fn is_array_pattern(&self, _kind: &str) -> bool {
        false
    }

    /// A destructured binding with a fallback value (`{ a = 1 }`): the name on
    /// the left of `=` reads the member of the same name, and the right side is
    /// only used when the member is absent.
    fn is_assignment_pattern(&self, _kind: &str) -> bool {
        false
    }

    /// A rest element in a pattern (`...rest`, `*rest`): it binds everything
    /// the pattern did not, and carries no name of its own.
    fn is_rest_pattern(&self, _kind: &str) -> bool {
        false
    }

    /// A match-arm pattern that binds one name (`case x:`, Rust's `x`).
    ///
    /// The default is the union the binder applies to every grammar: a plain
    /// `identifier` is a binding in Python, JS and Rust alike, and
    /// `identifier_pattern` is Rust's explicit spelling for the same thing.
    fn is_binding_pattern(&self, kind: &str) -> bool {
        matches!(kind, "identifier" | "identifier_pattern")
    }

    /// A match-arm pattern that destructures a value by type
    /// (`Point { x, y }`, `Some(v)`): the binding names are its children, so
    /// the binder recurses into it instead of using its text.
    fn is_structured_pattern(&self, kind: &str) -> bool {
        matches!(kind, "tuple_struct_pattern" | "struct_pattern")
    }

    /// A C-family storage-class specifier (`static`, `extern`).
    fn is_storage_class_specifier(&self, _kind: &str) -> bool {
        false
    }

    /// A pointer dereference expression (`*p`), which names the value `p`
    /// points at rather than the pointer itself.
    fn is_pointer_expression(&self, _kind: &str) -> bool {
        false
    }

    /// A preprocessor conditional branch (`#if`, `#ifdef`, `#elif`, `#else`),
    /// whose arms are alternative configurations rather than a runtime fork.
    fn is_preproc_conditional(&self, _kind: &str) -> bool {
        false
    }

    /// The `#else` branch of a preprocessor conditional - the false arm's
    /// body, not a fork of its own.
    fn is_preproc_else(&self, _kind: &str) -> bool {
        false
    }

    /// A statement-form `switch`, which the lowering turns into a condition
    /// chain (one comparison per case) rather than the coarse
    /// branch-with-sequential-body.
    fn is_switch_statement(&self, _kind: &str) -> bool {
        false
    }

    /// A clause of a `switch` (`case`, `default`).
    fn is_case_clause(&self, _kind: &str) -> bool {
        false
    }

    /// A statement-form `match` whose arms may be pruned when the subject is
    /// a compile-time constant. The expression form produces a value its
    /// caller consumes, which the pruned path does not synthesize.
    fn is_match_statement(&self, _kind: &str) -> bool {
        false
    }

    /// A guard on a match arm. It turns the arm into a runtime predicate, so
    /// the arm can never be selected statically.
    fn is_match_guard(&self, _kind: &str) -> bool {
        false
    }

    /// The jump statement `kind` is, if any.
    ///
    /// The default is the C/JS vocabulary the CFG lowering has always
    /// handled; a grammar that spells its jumps differently (`break_expression`
    /// in Rust, for example) overrides it.
    fn jump_kind(&self, kind: &str) -> Option<JumpKind> {
        match kind {
            "goto_statement" => Some(JumpKind::Goto),
            "labeled_statement" => Some(JumpKind::Label),
            "break_statement" => Some(JumpKind::Break),
            "continue_statement" => Some(JumpKind::Continue),
            _ => None,
        }
    }

    /// The JSX/TSX part `kind` is, if any.
    fn jsx_part(&self, _kind: &str) -> Option<JsxPart> {
        None
    }

    /// A node that can be the value half of a JSX attribute: `{expr}`, a
    /// literal string, or a nested element.
    fn is_jsx_attribute_value(&self, _kind: &str) -> bool {
        false
    }

    // ── Grammar shape ─────────────────────────────────────────────────────

    // The CFG builder discovers a loop's body and condition, a branch's
    // condition and consequence, and a switch's clauses by *shape* rather than
    // by field, because the grammars disagree about which fields they expose.
    // Those shape questions are answered here, so the builder does not spell
    // out `contains("statement")`-style vocabulary for every language.
    //
    // The defaults are the vocabulary the builder applies today to every
    // grammar. A provider narrows them when its grammar disagrees.

    /// A node that carries statements (`*_statement`).
    fn is_statement_node(&self, kind: &str) -> bool {
        kind.contains("statement")
    }

    /// A node that is a block of statements.
    fn is_block_node(&self, kind: &str) -> bool {
        kind == "block" || kind.contains("block")
    }

    /// A node that can stand in for a statement or a block - a body, a
    /// branch's consequence, a loop's body.
    fn is_block_or_statement(&self, kind: &str) -> bool {
        self.is_statement_node(kind) || self.is_block_node(kind)
    }

    /// A node that owns a nested body, including the grammars that name it
    /// `*_body` instead of `*_block`.
    fn is_body_node(&self, kind: &str) -> bool {
        self.is_block_or_statement(kind) || kind.ends_with("body")
    }

    /// A declarator wrapper (`*_declarator`).
    fn is_declarator_node(&self, kind: &str) -> bool {
        kind.contains("declarator")
    }

    /// The update or initializer clause of a `for` header.
    fn is_loop_update_or_initializer(&self, kind: &str) -> bool {
        kind.contains("update") || kind.contains("initializer")
    }

    /// A node that can be the condition operand of a loop: anything that is
    /// not the body, a declarator, an update or an initializer.
    fn is_loop_condition_node(&self, kind: &str) -> bool {
        !self.is_block_or_statement(kind)
            && !self.is_declarator_node(kind)
            && !self.is_loop_update_or_initializer(kind)
    }

    /// For a `for … in/of iterable` loop node, return the iterable child node
    /// (the expression being iterated over) and the loop variable binding node.
    ///
    /// Returns `None` for `while`, `do`, or C-style `for` loops that have no
    /// iterable child. The engine visits the iterable in the loop header block
    /// so that taint from the iterable reaches the loop variable.
    ///
    /// Python `for_statement`: `left` = binding, `right` = iterable.
    /// JS/TS `for_in_statement` / `for_of_statement`: `left` = binding,
    /// `right` = iterable.
    fn for_loop_iterable<'t>(
        &self,
        _node: tree_sitter::Node<'t>,
    ) -> Option<(tree_sitter::Node<'t>, tree_sitter::Node<'t>)> {
        None
    }

    /// A node that can be the condition operand of a branch.
    fn is_branch_condition_node(&self, kind: &str) -> bool {
        !self.is_statement_node(kind)
            && !self.is_block_node(kind)
            && !kind.contains("declaration")
            && !kind.contains("assignment")
    }

    /// A name that can be the target of `break`/`continue`/`goto`:
    /// `statement_identifier` in Go's labelled statements, a plain identifier
    /// elsewhere.
    fn is_jump_target_name(&self, kind: &str) -> bool {
        kind == "statement_identifier" || kind == "identifier"
    }

    /// A pattern node of a match arm.
    fn is_match_pattern_node(&self, kind: &str) -> bool {
        kind.contains("pattern")
    }

    /// The discard pattern (`_`), which matches anything and binds nothing.
    fn is_discard_pattern(&self, kind: &str) -> bool {
        kind == "_"
    }

    /// A wrapper a grammar puts around every arm pattern (Python's
    /// `case_pattern`), transparent for matching.
    fn is_pattern_wrapper(&self, kind: &str) -> bool {
        kind == "case_pattern"
    }

    /// A pattern that is an alternative of others (`case 'a' | 'b':`): the arm
    /// executes when any alternative matches.
    fn is_alternative_pattern(&self, kind: &str) -> bool {
        kind == "union_pattern"
    }

    /// A left-hand side that lists several assignment targets (`a, b = …`).
    ///
    /// The default is the union the lowering has always accepted across the
    /// grammars (Python's and C's expression lists, JS's pattern lists).
    fn is_multi_target_node(&self, kind: &str) -> bool {
        matches!(
            kind,
            "expression_list" | "identifier_list" | "pattern_list" | "tuple_pattern"
        )
    }

    /// A node that is, or wraps, a body of statements (`*_block`, `*_body`).
    /// Used where a grammar puts a loop's body behind neither a field nor a
    /// statement kind.
    fn is_containment_node(&self, kind: &str) -> bool {
        self.is_block_node(kind) || kind.contains("body")
    }

    /// The `else` clause of a conditional (`else_clause`, `else_statement`).
    fn is_else_clause(&self, kind: &str) -> bool {
        kind.contains("else")
    }

    /// A node whose `break` belongs to a `switch` rather than the enclosing
    /// loop, including the grammars that lower a Go switch as a branch.
    fn is_switch_like_node(&self, kind: &str) -> bool {
        kind.contains("switch")
    }

    /// A clause or arm of a `match`, including the grammars that spell it
    /// `*_arm` rather than `case`.
    fn is_case_alternative(&self, kind: &str) -> bool {
        kind.contains("arm") || kind.contains("case")
    }

    /// A node whose value may be a string built from literal and interpolated
    /// parts: a template string, a quoted string, an implicit concatenation,
    /// or a `+` chain the lowering folds part by part.
    fn is_string_expression(&self, kind: &str) -> bool {
        self.is_template_string(kind)
            || matches!(kind, "string" | "binary_expression" | "concatenated_string")
    }

    /// The literal `kind` spells, when the lowering can fold it at compile
    /// time. `None` for anything that needs the program to run.
    fn literal_shape(&self, kind: &str) -> Option<LiteralShape> {
        match kind {
            "string" | "concatenated_string" => Some(LiteralShape::String),
            "integer" => Some(LiteralShape::Integer),
            "float" => Some(LiteralShape::Float),
            "true" => Some(LiteralShape::Boolean(true)),
            "false" => Some(LiteralShape::Boolean(false)),
            "none" | "null" => Some(LiteralShape::Null),
            _ => None,
        }
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

    // ── Parameter binding ─────────────────────────────────────────────────

    /// The parameter-list node of a function definition, when the grammar
    /// exposes one.
    ///
    /// Follows the [`NodeRole::Function`]'s `params_field`, and keeps walking
    /// while the node it lands on is not a [`NodeRole::Parameters`] list. C
    /// needs that: its `function_definition` exposes `declarator`, and the
    /// list sits one hop further, inside `function_declarator`'s `parameters`
    /// field (`pointer_declarator` may wrap it again). Handling the hop here
    /// means no consumer carries a C-specific walk.
    fn function_params<'t>(&self, fn_node: Node<'t>) -> Option<Node<'t>> {
        let NodeRole::Function { params_field, .. } = self.classify(fn_node.kind()) else {
            return None;
        };
        let mut cur = fn_node.child_by_field_name(params_field.as_ref());
        while let Some(node) = cur {
            if matches!(self.classify(node.kind()), NodeRole::Parameters) {
                return Some(node);
            }
            cur = node
                .child_by_field_name("parameters")
                .or_else(|| node.child_by_field_name(params_field.as_ref()));
        }
        None
    }

    /// The node that names a function definition.
    ///
    /// Follows the [`NodeRole::Function`]'s `name_field` until it reaches an
    /// [`NodeRole::Identifier`]. A grammar that names the function inside a
    /// declarator chain (C: `function_definition → declarator →
    /// function_declarator → identifier`, with `pointer_declarator` in between
    /// for `void *f(void)`) says so by exposing that chain in `name_field`, so
    /// no consumer walks it.
    ///
    /// `None` for a function that binds no name (arrow function, lambda,
    /// closure, and a Python `decorated_definition`, whose name belongs to the
    /// wrapped definition).
    fn function_name_node<'t>(&self, fn_node: Node<'t>) -> Option<Node<'t>> {
        let NodeRole::Function { name_field, .. } = self.classify(fn_node.kind()) else {
            return None;
        };
        let field = name_field?;
        let mut cur = fn_node.child_by_field_name(field.as_ref());
        while let Some(node) = cur {
            if matches!(self.classify(node.kind()), NodeRole::Identifier) {
                return Some(node);
            }
            cur = node.child_by_field_name(field.as_ref());
        }
        None
    }

    /// A parameter that binds the receiver of a method (`&self`,
    /// `&mut self`). Its name is the language keyword, not its text.
    fn is_self_parameter(&self, _kind: &str) -> bool {
        false
    }

    /// The name a function form binds its receiver under when the grammar
    /// does not spell the receiver as a parameter.
    ///
    /// Python's `self` and Rust's `self_parameter` are ordinary parameters, so
    /// they need nothing here. JavaScript's `this` is implicit: the method's
    /// parameter list never mentions it, yet `this.h = v` and `exec(this.h)`
    /// address the same receiver the call site passes. Returns `None` for a
    /// function form with no receiver of its own.
    fn implicit_receiver_name(&self, _fn_kind: &str) -> Option<&'static str> {
        None
    }

    /// The binding identifiers of one parameter node, in declaration order.
    ///
    /// Grammars disagree about how many names one parameter node carries and
    /// where they sit, so this is the one place that knows:
    ///
    /// - JS/TS: `required_parameter`/`optional_parameter` with a `pattern`
    ///   field, and `...rest` as a `rest_pattern` around the name.
    /// - Python: a plain `identifier`, plus the annotated/defaulted wrappers
    ///   (`x: T`, `x=v`, `x: T = v`) and the splats (`*x`, `**x`).
    /// - Rust: a `parameter` node wrapping the name identifier.
    /// - C: `parameter_declaration` shaped `type declarator`, where the
    ///   declarator may be `pointer_declarator` → `identifier` (`char *p`).
    /// - Go: `parameter_declaration`/`variadic_parameter_declaration` shaped
    ///   `name ... type`, with one `name` field per grouped name (`a, b string`
    ///   is a single declaration and binds both names).
    fn param_bindings<'t>(&self, param: Node<'t>) -> Vec<Node<'t>> {
        param_bindings(param)
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

// ── Helper: tree walk ─────────────────────────────────────────────────────────

/// Visit every node of `root`, depth-first and in pre-order (a node before its
/// children).
///
/// Every provider's import/export extractor wants the same thing — "look at
/// each node, match on its kind" — and the cursor dance to do it
/// (`goto_first_child` / `goto_next_sibling` / `goto_parent` with a labelled
/// outer loop) is identical in all of them. Open-coding it once per grammar is
/// pure repetition and easy to get subtly wrong (a missing `break 'outer`
/// revisits the root forever).
///
/// It is `pub(crate)`, not `pub`: a provider implementation detail, not part of
/// the contract downstream crates consume.
pub(crate) fn walk_preorder<'tree>(root: Node<'tree>, mut visit: impl FnMut(Node<'tree>)) {
    let mut cursor = root.walk();
    'outer: loop {
        visit(cursor.node());
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
