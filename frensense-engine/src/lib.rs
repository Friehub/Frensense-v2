// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Frensense engine: the dataflow compiler.
//!
//! The pipeline: parse (via `frensense-lang` specs) → lower → SSA → SVFG →
//! callgraph → demand-driven taint. Knowledge about sources, sinks, and
//! sanitizers lives in `frensense-lang` specs and `.frc`-bundle fact
//! tables, merged into a [`analysis::taint::config::TaintConfig`] +
//! [`analysis::taint::facts::FactTable`] at scan time.
//!
//! Crate layout (strict layering, each layer only depends on the ones
//! above it):
//! * [`ir`], the compiler frontend: `FunctionIR`, lowering, Memory SSA.
//!   Pure data; knows nothing about taint or checks.
//! * [`graph`], program-graph construction: SVFG, callgraph, heap
//!   points-to, serialization.
//! * [`analysis`], the engines: demand-driven backward taint (with its
//!   fact table and context sensitivity), the forward engine, summaries.
//! * [`checks`], non-dataflow policy rules (weak crypto, insecure JWT
//!   algorithms), one module per rule.
//! * [`harness`], the ONE implementation of "source text → analyzed
//!   program graph", shared by the scanner, e2e drivers, and the bundler.
//! * [`scan`], the stable query API: files + config + facts → findings.

/// The engine crate version as published. Bundles record this as
/// `built_by_engine`; the compatibility decision itself is made on
/// [`analysis::taint::facts::fact_vocabulary_fingerprint`], because the
/// serialized vocabulary (not the crate number) is what decides whether a
/// bundle can be decoded.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod analysis;
pub mod checks;
#[cfg(test)]
mod dataflow_probes_tests;
pub mod debug_flags;
#[cfg(test)]
mod fp_regression_tests;
pub mod graph;
pub mod harness;
pub mod ir;
#[cfg(test)]
mod language_scope_tests;
#[cfg(test)]
mod package_scoped_sanitizer_tests;
#[cfg(test)]
mod package_scoped_sink_tests;
#[cfg(test)]
mod probes;
#[cfg(test)]
mod regression_gate_tests;
pub mod scan;
pub mod telemetry;
#[cfg(test)]
mod type_source_tests;

/// Opaque identifier for a source file within a single analysis session.
#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub u32);

#[cfg_attr(feature = "serialize", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeId(pub u64);
