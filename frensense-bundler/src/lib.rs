// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

#![allow(clippy::all)]
#![allow(dead_code, unreachable_patterns, unreachable_code)]

//! Frensense bundler: builds `.frc` bundles from positive/negative corpus
//! pairs. The learning pipeline is: group families → scan both variants
//! through the engine's compiler → delta → replay gate → publish facts.

pub mod builder;
pub mod extract;
pub mod fact_extract;
pub mod format;
pub mod lint;
mod parallel;
pub mod pipeline;
mod sanitizer_qualification;

pub use pipeline::{run_facts_pipeline, run_facts_pipeline_with_trust};
