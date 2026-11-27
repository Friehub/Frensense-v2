// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The committed default pack, assembled into the `.frc` envelope.

use frensense_bundler::format::{write_bundle, BundlePayload};

use crate::{default_pack_entries, store_hints};

/// Serialize [`default_pack_entries`] into the `.frc` envelope: zero patterns,
/// empty `policy_pack`, no sanitizer or policy scopes; the only side table is
/// the store-sink base-kind table from [`store_hints`]. Used by the drift
/// tests and by `--out`.
pub fn build_default_bundle() -> Vec<u8> {
    let payload = BundlePayload::new(
        Vec::new(),
        default_pack_entries(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        store_hints::scopes(),
    );
    write_bundle(&payload, 0).unwrap_or_else(|e| panic!("default pack serialization failed: {e}"))
}
