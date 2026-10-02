// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::FactTable;
use serde::Deserialize;

/// File schema. Only fields present are applied; unknown fields are
/// ignored so older engines load newer files without failing.
#[derive(Debug, Deserialize, Default)]
pub struct SeedFacts {
    /// Receiver roots of trusted session stores
    /// (`security.authenticatedUsers` -> root `authenticatedUsers`).
    #[serde(default)]
    pub session_roots: Vec<String>,
}

impl SeedFacts {
    /// Parse a seed-facts JSON document.
    pub fn parse(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("seed facts: {e}"))
    }

    /// Load from disk.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("seed facts {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    /// Merge into a fact table (self wins on collision).
    pub fn apply_to(&self, t: &mut FactTable) {
        for r in &self.session_roots {
            t.session_roots.insert(r.clone());
        }
    }

    /// Load a seed file (if it exists) and merge over `t`.
    pub fn load_and_apply(path: &std::path::Path, t: &mut FactTable) -> Result<(), String> {
        if !path.exists() {
            return Ok(());
        }
        Self::load(path)?.apply_to(t);
        Ok(())
    }
}
