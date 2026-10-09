// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Taint analysis configuration.
//!
//! [`TaintConfig`] declares the name sets that define a scan: source
//! functions, sink functions, and sanitizer functions. It is consumed by the
//! demand-driven engines (`BackwardTaintEngine`, `InterproceduralTaintEngine`)
//! and serialized alongside scan policies.

use rustc_hash::FxHashSet;

/// Configuration defining the boundaries of the security analysis.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
pub struct TaintConfig {
    pub sources: FxHashSet<String>,    // e.g., "req.body", "getQuery()"
    pub sinks: FxHashSet<String>,      // e.g., "db.execute", "eval"
    pub sanitizers: FxHashSet<String>, // e.g., "escapeHtml", "sanitize"
}
