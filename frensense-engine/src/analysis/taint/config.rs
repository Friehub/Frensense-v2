// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Taint analysis configuration.
//!
//! [`TaintConfig`] declares the name sets that define a scan: source
//! functions, sink functions, and sanitizer functions. It is consumed by the
//! demand-driven engine (`BackwardTaintEngine`), by the summary pass that
//! suppresses the pass-through edges a known callee replaces, and is
//! serialized alongside scan policies.

use rustc_hash::FxHashSet;

/// Configuration defining the boundaries of the security analysis.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct TaintConfig {
    /// Source patterns: calls or member-access paths whose results carry attacker-controlled data, such as `req.body` or `getQuery()`.
    pub sources: FxHashSet<String>,
    /// Sink calls that are dangerous when tainted data reaches them, such as `db.execute` or `eval`.
    pub sinks: FxHashSet<String>,
    /// Sanitizer calls that neutralize taint, such as `escapeHtml` or `sanitize`.
    pub sanitizers: FxHashSet<String>,
}
