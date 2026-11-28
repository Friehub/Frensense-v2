// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Cross-build cache of replay-gate trial verdicts.
//!
//! A trial scans one family's positive/negative pair under one fact table.
//! That answer is a pure function of the family sources, the family's
//! language tables, the facts published so far in the pass, the candidate
//! fact, and the build itself - so it is safe to memoise across runs. An
//! unchanged family never needs re-scanning, which is what makes an
//! incremental corpus build possible: editing one family costs its own
//! trials, not the whole corpus's.
//!
//! The cache lives in the JSON file named by `FRENSENSE_BUNDLE_CACHE`
//! (the corpus `build_all.sh` points it at `dist/.cache/<lang>.json`). Every
//! entry is keyed under a salt covering the crate version, the bundle format
//! version and the embedded default pack, so an engine or vocabulary change
//! invalidates the whole file instead of serving stale verdicts. A missing,
//! unreadable or salt-mismatched file starts empty: that costs a rebuild,
//! never a wrong bundle.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    salt: String,
    entries: BTreeMap<String, (bool, bool)>,
}

/// Memo of `(positive alerts, negative alerts)` per trial key.
pub(crate) struct TrialCache {
    salt: String,
    path: Option<PathBuf>,
    entries: BTreeMap<String, (bool, bool)>,
    hits: usize,
    misses: usize,
}

impl TrialCache {
    /// Open the cache named by `FRENSENSE_BUNDLE_CACHE`, if any.
    pub(crate) fn from_env() -> Self {
        let salt = salt();
        let path = match std::env::var("FRENSENSE_BUNDLE_CACHE") {
            Ok(p) if !p.is_empty() && p != "0" => Some(PathBuf::from(p)),
            _ => None,
        };
        let mut cache = Self {
            salt,
            path,
            entries: BTreeMap::new(),
            hits: 0,
            misses: 0,
        };
        if let Some(path) = cache.path.clone() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(stored) = serde_json::from_str::<Stored>(&text) {
                    if stored.salt == cache.salt {
                        cache.entries = stored.entries;
                    }
                }
            }
        }
        cache
    }

    /// Cached verdict for `key`, counting the lookup for the run summary.
    pub(crate) fn get(&mut self, key: &str) -> Option<(bool, bool)> {
        let hit = self.entries.get(key).copied();
        if hit.is_some() {
            self.hits += 1;
        } else {
            self.misses += 1;
        }
        hit
    }

    pub(crate) fn put(&mut self, key: String, value: (bool, bool)) {
        self.entries.insert(key, value);
    }

    /// Write the cache back, atomically, if one was configured.
    pub(crate) fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let stored = Stored {
            salt: self.salt.clone(),
            entries: self.entries.clone(),
        };
        let Ok(text) = serde_json::to_string(&stored) else {
            return;
        };
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// Short stable hash of a key fragment (published-fact sets can be long).
pub(crate) fn hash_str(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()
}

/// What invalidates every entry: engine/bundler build, bundle format, pack.
fn salt() -> String {
    format!(
        "{}|{}|{}",
        env!("CARGO_PKG_VERSION"),
        crate::format::BUNDLE_VERSION,
        crate::format::default_pack_blake3_hex()
    )
}
