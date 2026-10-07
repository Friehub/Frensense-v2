// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Sink-role model: what a sink *does* with the data it receives.
//!
//! The type itself lives in `frensense-lang` ([`SinkRole`]): the
//! `SinkLabel` -> role mapping, the default role->tier ladder and the
//! stable reporting tag are classification/reporting knowledge, and both
//! the bundler's replay gate and the CLI need the ladder without going
//! through the engine (ENGINE_PURITY_REFACTOR 1.3 / D4). The engine keeps
//! only the type on its findings - zero tier strings.

pub use frensense_lang::severity::SinkRole;

/// Parse the snake_case [`SinkRole`] name the default-pack generator
/// serializes on [`crate::analysis::taint::facts::LearnedFactEntry::LanguageSink`]
/// (the serde wire form). Unknown names keep the conservative default.
#[must_use]
pub fn sink_role_from_name(name: &str) -> SinkRole {
    let role_part = name.split_once(':').map(|(r, _)| r).unwrap_or(name);
    match role_part {
        "execution" => SinkRole::Execution,
        "resource" => SinkRole::Resource,
        "storage" => SinkRole::Storage,
        "crypto" => SinkRole::Crypto,
        "response" => SinkRole::Response,
        "xss" => SinkRole::Xss,
        "validation" => SinkRole::Validation,
        _ => SinkRole::Other,
    }
}

/// Extract the optional label slug serialized after the colon in a role string
/// (e.g. `"execution:prototype"` -> `Some("prototype")`).
#[must_use]
pub fn sink_label_slug_from_role_str(name: &str) -> Option<&str> {
    name.split_once(':').map(|(_, slug)| slug)
}

/// The snake_case wire name of a [`SinkRole`] - the inverse of
/// [`sink_role_from_name`]. The default-pack generator serializes this
/// onto [`crate::analysis::taint::facts::LearnedFactEntry::LanguageSink`],
/// so the pack stores role names instead of serde enum indices (bundle
/// stability across enum reorders).
#[must_use]
pub fn sink_role_name(role: SinkRole) -> &'static str {
    match role {
        SinkRole::Execution => "execution",
        SinkRole::Resource => "resource",
        SinkRole::Storage => "storage",
        SinkRole::Crypto => "crypto",
        SinkRole::Response => "response",
        SinkRole::Xss => "xss",
        SinkRole::Validation => "validation",
        SinkRole::Other => "other",
    }
}
