// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! # FRC - Frensense Reference Corpus Bundle Format
//!
//! A pre-compiled binary format that embeds corpus fingerprints.
//! This crate handles the `.frc` file envelope (header, versioning, checksum)
//! while remaining generic over the payload data structure.

#![allow(clippy::module_name_repetitions)]

pub const BUNDLE_MAGIC: &[u8; 4] = b"FRC1";
pub const BUNDLE_VERSION: u32 = 5;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BundleHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub pattern_count: u32,
    pub checksum: [u8; 32],
}

/// Serialize a payload into the .frc binary format.
pub fn write_bundle<T: serde::Serialize>(
    payload: &T,
    pattern_count: u32,
) -> Result<Vec<u8>, String> {
    let data = bincode::serialize(payload).map_err(|e| e.to_string())?;

    let checksum = blake3::hash(&data);
    let header = BundleHeader {
        magic: *BUNDLE_MAGIC,
        version: BUNDLE_VERSION,
        pattern_count,
        checksum: *checksum.as_bytes(),
    };

    let mut output = Vec::new();
    let header_bytes = bincode::serialize(&header).map_err(|e| e.to_string())?;

    // Write header length as 4-byte LE
    output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(&data);

    Ok(output)
}

/// Split the `.frc` envelope: verify magic, gate the version against
/// [`BUNDLE_VERSION`], verify the checksum, and return the header with the
/// payload bytes (not yet deserialized).
///
/// The version gate rejects *newer* bundles with a clean error; which
/// payload shape the bytes hold is the caller's decision (see the
/// version-branched load in `format::load_bundle`).
pub fn read_bundle_parts(bytes: &[u8]) -> Result<(BundleHeader, &[u8]), String> {
    if bytes.len() < 4 {
        return Err("Bundle too small (missing header length)".to_string());
    }

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&bytes[0..4]);
    let header_len = u32::from_le_bytes(len_bytes) as usize;

    if bytes.len() < 4 + header_len {
        return Err("Bundle truncated (header incomplete)".to_string());
    }

    let header_data = &bytes[4..4 + header_len];
    let header: BundleHeader = bincode::deserialize(header_data).map_err(|e| e.to_string())?;

    if header.magic != *BUNDLE_MAGIC {
        return Err("Invalid magic bytes, expected FRC1".to_string());
    }

    if header.version > BUNDLE_VERSION {
        return Err(format!(
            "Unsupported bundle version {} (engine supports {})",
            header.version, BUNDLE_VERSION
        ));
    }

    let payload_data = &bytes[4 + header_len..];
    let actual_checksum = blake3::hash(payload_data);
    if actual_checksum.as_bytes() != &header.checksum {
        return Err("Bundle checksum mismatch (corrupted data)".to_string());
    }

    Ok((header, payload_data))
}

/// Deserialize a payload from the .frc binary format.
pub fn read_bundle<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<(BundleHeader, T), String> {
    let (header, payload_data) = read_bundle_parts(bytes)?;
    let payload: T = bincode::deserialize(payload_data).map_err(|e| e.to_string())?;
    Ok((header, payload))
}
