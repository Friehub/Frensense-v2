// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Engine configuration shared by the full scan and the per-file diff scan.

use crate::cli::CliOptions;
use crate::engine::Engine;

/// Apply the run-wide options to `engine`.
///
/// `--diff-only` builds one engine per changed file, so this keeps that setup
/// identical to the full scan's instead of drifting from it.
pub fn configure_engine(engine: &mut Engine, options: &CliOptions) {
    if let Some(path) = options.corpus_bundle_path.clone() {
        engine.set_corpus_bundle_path(path);
    }
    engine.set_severity_filter(options.severity_filter);
    engine.set_profile(options.profile);
    engine.set_enable_hygiene(options.enable_hygiene);
    engine.set_max_complexity(options.max_complexity);
    engine.set_explain(options.explain);
    engine.set_show_suppressed(options.show_suppressed);
    engine.set_rule_filters(options.disable_rules.clone(), options.only_rules.clone());
    engine.set_collect_options(options.include_dirs.clone(), options.no_default_excludes);
    engine.set_show_flows(options.show_flows);
}
