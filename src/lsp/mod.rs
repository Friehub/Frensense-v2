// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! `frensense-lsp` — Language Server Protocol adapter.
//!
//! Delivery, not analysis. The server reuses the per-file scan path
//! (`Engine::run(file)`, the same path the CLI watch mode and the MCP
//! tools use) and maps advisories onto LSP `publishDiagnostics`
//! notifications on open/save. No `tower-lsp` dependency: the protocol
//! subset an editor needs for diagnostics is small (three lifecycle
//! methods, two document events, Base-64-free `Content-Length` framing),
//! and hand-rolling keeps the dependency tree at zero while every
//! interesting decision (severity mapping, stable IDs, URI handling)
//! stays testable as plain functions.
//!
//! Behavior:
//! - `initialize` advertises `textDocumentSync` (full sync, change=1)
//!   and nothing else — diagnostics-only servers should not claim
//!   hover/completion they can't serve.
//! - `textDocument/didOpen` and `didSave` scan the file on disk and
//!   publish one diagnostics array per version. Full sync: the client
//!   sends the whole document, but scanning the saved disk state keeps
//!   the engine the single source of truth (no in-memory AST fork).
//! - Diagnostics carry the stable finding ID in `code` and the
//!   observation in `message`, so editor inline display and the CLI
//!   refer to the same bug the same way.
//! - `didClose` clears diagnostics for that file (protocol hygiene:
//!   stale editor tabs must not show dead findings).

pub mod framing;
pub mod server;

pub use server::{DiagnosticItem, PublishParams, diagnostics_for_file, run_server};
