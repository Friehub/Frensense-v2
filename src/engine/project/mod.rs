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
    /// When `true` (`--show-flows`), the taint advisory TEXT also embeds
    /// the full source→sink flow. `taint_steps`/SARIF `codeFlows` carry
    /// the path unconditionally now (WI-54); this knob only governs the
    /// text observation, the debug-grade detail of a clean text report.
    pub(crate) show_flows: bool,
    /// Precision profile governing reportable finding tiers.
    pub(crate) profile: crate::Profile,
    /// When `true` (`--hygiene`), hygiene findings (such as `function_complexity`)
    /// are reported even if not included in the active scan profile.
    pub(crate) enable_hygiene: bool,
    /// Optional cyclomatic complexity limit override (`--max-complexity`).
    pub(crate) max_complexity: Option<usize>,
    /// Silent-finding records from the most recent `run` (when `explain`).
    pub(crate) explain_records: Vec<crate::explain::ExplainRecord>,
    /// Functions the per-function work budget pushed into the degraded
    /// (flow-insensitive) form, accumulated across `run` calls and surfaced
    /// via [`Engine::take_incomplete`] so the report can list them under
    /// `analysis_incomplete` instead of silently weakening those results.
    pub(crate) analysis_incomplete: Vec<frensense_engine::scan::IncompleteFunction>,
    /// Source files skipped by the most recent `run` because the engine has
    /// no language spec for them. Surfaced via
    /// [`Engine::take_skipped_unsupported`] so the report can say which
    /// languages it did not analyze instead of describing a partial scan as
    /// complete.
    pub(crate) skipped_unsupported: Vec<crate::engine::files::UnsupportedSourceFile>,
    /// Hidden finding counts grouped by tier.
    pub(crate) hidden_by_tier: std::collections::BTreeMap<crate::RuleTier, usize>,
    /// Accumulated telemetry across scanned language groups.
    pub(crate) telemetry: frensense_engine::telemetry::ScanTelemetry,
    /// Optional progress callback for real-time progress updates.
    pub(crate) progress_callback: Option<
        std::sync::Arc<
            dyn Fn(&frensense_engine::scan::ScanProgress<'_>)
                + Send
                + Sync
                + std::panic::UnwindSafe
                + std::panic::RefUnwindSafe,
        >,
    >,
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
            profile: crate::Profile::Default,
            enable_hygiene: false,
            max_complexity: None,
            explain_records: Vec::new(),
            analysis_incomplete: Vec::new(),
            skipped_unsupported: Vec::new(),
            hidden_by_tier: std::collections::BTreeMap::new(),
            telemetry: frensense_engine::telemetry::ScanTelemetry::default(),
            progress_callback: None,
        }
    }

    /// Set an optional callback to receive scan progress updates.
    pub fn set_progress_callback(
        &mut self,
        callback: impl Fn(&frensense_engine::scan::ScanProgress<'_>)
            + Send
            + Sync
            + std::panic::UnwindSafe
            + std::panic::RefUnwindSafe
            + 'static,
    ) {
        self.progress_callback = Some(std::sync::Arc::new(callback));
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

    /// Enable `--show-flows`: taint advisories embed the full source→sink
    /// flow in the observation text as well. `taint_steps` (and SARIF
    /// codeFlows) are always populated since WI-54; this only widens the
    /// text observation.
    pub fn set_show_flows(&mut self, on: bool) {
        self.show_flows = on;
    }

    /// Take the explain records collected by the most recent `run`.
    /// Returns an empty vec when `--explain` was not enabled.
    #[must_use]
    pub fn take_explain(&mut self) -> Vec<crate::explain::ExplainRecord> {
        std::mem::take(&mut self.explain_records)
    }

    /// Take the functions analyzed in degraded form because their
    /// per-function work budget expired (accumulated across `run` calls).
    /// Empty when every function was analyzed fully.
    #[must_use]
    pub fn take_incomplete(&mut self) -> Vec<frensense_engine::scan::IncompleteFunction> {
        std::mem::take(&mut self.analysis_incomplete)
    }

    /// Take the source files the most recent `run` skipped because their
    /// language has no engine spec. A scan that reports findings while
    /// silently ignoring the Python half of a repo is not complete, and the
    /// caller is expected to say so.
    #[must_use]
    pub fn take_skipped_unsupported(&mut self) -> Vec<crate::engine::files::UnsupportedSourceFile> {
        std::mem::take(&mut self.skipped_unsupported)
    }

    /// Set the scan profile governing which rule tiers are reported.
    pub fn set_profile(&mut self, profile: crate::Profile) {
        self.profile = profile;
    }

    /// Enable hygiene findings (such as function_complexity) under any profile.
    pub fn set_enable_hygiene(&mut self, on: bool) {
        self.enable_hygiene = on;
    }

    /// Set a custom cyclomatic complexity ceiling for the function_complexity check.
    /// Setting this automatically enables hygiene rules.
    pub fn set_max_complexity(&mut self, max: Option<usize>) {
        self.max_complexity = max;
        if max.is_some() {
            self.enable_hygiene = true;
        }
    }

    /// The active scan profile.
    #[must_use]
    pub fn profile(&self) -> crate::Profile {
        self.profile
    }

    /// Take the counts of hidden findings by tier collected by the most recent `run`.
    #[must_use]
    pub fn take_hidden_by_tier(&mut self) -> std::collections::BTreeMap<crate::RuleTier, usize> {
        std::mem::take(&mut self.hidden_by_tier)
    }

    /// Take the scan telemetry collected by the most recent `run`.
    #[must_use]
    pub fn take_telemetry(&mut self) -> frensense_engine::telemetry::ScanTelemetry {
        std::mem::take(&mut self.telemetry)
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
