// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

pub(crate) mod runner;

use crate::{FileId, Severity};
use std::path::PathBuf;

/// The scan engine.
///
/// Configuration is minimal by design: the analysis knowledge lives in the
/// language specs (`frensense-lang`) and the `.frc` bundle's learned facts,
/// not in knobs on this struct.
pub struct Engine {
    /// Optional `.frc` bundle bytes (static) whose learned facts are merged
    /// over the built-in fact table.
    pub(crate) corpus_bundle: Option<&'static [u8]>,
    /// Optional `.frc` bundle loaded from disk at scan time.
    pub(crate) corpus_bundle_path: Option<PathBuf>,
    pub(crate) severity_filter: Option<Severity>,
    pub(crate) language_filter: Option<Vec<&'static str>>,
    pub(crate) min_confidence: f64,
    /// When `true`, the runner records every explored sink argument that
    /// did NOT become an advisory (see [`crate::explain::ExplainRecord`]),
    /// surfaced via [`Engine::take_explain`] under `--explain`.
    pub(crate) explain: bool,
    /// When `true` (`--show-flows`), taint advisories carry the full
    /// source→sink flow (observation embed + `taint_steps`/SARIF
    /// codeFlows). Off by default: the flow is debug-grade detail.
    pub(crate) show_flows: bool,
    /// Silent-finding records from the most recent `run` (when `explain`).
    pub(crate) explain_records: Vec<crate::explain::ExplainRecord>,
}

impl Engine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            corpus_bundle: None,
            corpus_bundle_path: None,
            severity_filter: None,
            language_filter: None,
            min_confidence: 0.0,
            explain: false,
            show_flows: false,
            explain_records: Vec::new(),
        }
    }

    /// Provide a `.frc` bundle (static bytes) whose learned facts teach the
    /// engine additional sinks/sanitizers/guards.
    pub fn set_corpus_bundle(&mut self, bundle: &'static [u8]) {
        self.corpus_bundle = Some(bundle);
    }

    /// Provide a `.frc` bundle loaded from disk (mut + scan workflow).
    pub fn set_corpus_bundle_path(&mut self, path: PathBuf) {
        self.corpus_bundle_path = Some(path);
    }

    pub fn set_severity_filter(&mut self, severity: Option<Severity>) {
        self.severity_filter = severity;
    }

    pub fn set_language_filter(&mut self, extensions: Vec<&'static str>) {
        self.language_filter = Some(extensions);
    }

    pub fn set_min_confidence(&mut self, min: f64) {
        self.min_confidence = min;
    }

    /// Enable `--explain`: record every silent sink argument (not reported)
    /// with the reason the engine stayed silent, for later retrieval via
    /// [`Engine::take_explain`].
    pub fn set_explain(&mut self, on: bool) {
        self.explain = on;
    }

    /// Enable `--show-flows`: taint advisories carry the full source→sink
    /// flow in the observation text and `taint_steps` (SARIF codeFlows).
    /// Off by default - the flow is debug-grade detail.
    pub fn set_show_flows(&mut self, on: bool) {
        self.show_flows = on;
    }

    /// Take the explain records collected by the most recent `run`.
    /// Returns an empty vec when `--explain` was not enabled.
    #[must_use]
    pub fn take_explain(&mut self) -> Vec<crate::explain::ExplainRecord> {
        std::mem::take(&mut self.explain_records)
    }

    /// Register a synthetic file id for a scanned path (used by the runner
    /// when converting findings to advisories).
    #[allow(dead_code)]
    pub(crate) fn next_file_id(seq: usize) -> FileId {
        FileId(u32::try_from(seq).unwrap_or(u32::MAX))
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "stable_id_tests.rs"]
mod stable_id_tests;
