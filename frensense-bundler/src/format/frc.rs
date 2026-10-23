// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! # FRC - Frensense Reference Corpus Bundle Format
//!
//! A pre-compiled binary format that embeds corpus fingerprints.
//! This crate handles the `.frc` file envelope (header, versioning, checksum)
//! while remaining generic over the payload data structure.
//!
//! ## Compatibility (Phase 6)
//!
//! A bundle outlives the binary that built it, and it stores `LearnedFactEntry`
//! and `HintKind` values by *variant position*. So a bundle is only decodable
//! by an engine that speaks the same vocabulary, and the envelope now says so
//! explicitly instead of leaving the reader to discover it as a serde error:
//!
//! * [`BundleHeader::vocabulary`] - the
//!   [`fact_vocabulary_fingerprint`](frensense_engine::analysis::taint::facts::fact_vocabulary_fingerprint)
//!   of the engine that wrote it. Checked strictly on load: a mismatch is
//!   refused with both values named.
//! * [`BundleHeader::requires_engine`] - an optional coarse range, for
//!   corpus authors who want a policy bound ("this pack targets 0.9") on top
//!   of the strict vocabulary check.
//! * [`BundleHeader::built_by_engine`] - diagnostics only.
//!
//! Version 6 bundles carry none of this and still load: the fingerprint field
//! is absent, so there is nothing to compare, and the reader treats them as
//! pre-Phase-6 (see [`BundleHeader::is_legacy`]). `docs/FORMATS.md` carries
//! the table of every artifact and its bump rule.

#![allow(clippy::module_name_repetitions)]

use std::fmt;

/// Envelope version. Bumped whenever the header or the payload gains a field
/// or a variant, because bincode is positional and cannot self-describe.
///
/// ## Bump rule
///
/// Adding *any* serialized field or enum variant to the header, the payload,
/// or the fact-entry vocabulary requires a bump here. The engine's
/// `FACT_VOCABULARY_FINGERPRINT` ratchet catches vocabulary movement; this
/// number catches layout movement. `docs/FORMATS.md` records both.
pub const BUNDLE_VERSION: u32 = 7;

pub const BUNDLE_MAGIC: &[u8; 4] = b"FRC1";

/// The oldest bundle version this reader can still decode. Older envelopes
/// are rejected with an actionable message rather than a parse error.
pub const MIN_SUPPORTED_VERSION: u32 = 4;

/// A semver-ish bound on the engine a bundle may be loaded by.
///
/// Expressed as `[major, minor, patch]` triples rather than parsed semver
/// strings, because this type is on the wire: fixed-width arrays bincode
/// encodes without allocation, and there is no string to parse (or to get
/// wrong) at load time. Pre-release/build metadata is deliberately ignored -
/// `0.9.0-beta` and `0.9.0` are the same series for compatibility purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EngineRequirement {
    /// Inclusive lower bound on the engine version.
    pub min: [u32; 3],
    /// Exclusive upper bound. `None` = unbounded above.
    pub max_exclusive: Option<[u32; 3]>,
}

impl EngineRequirement {
    /// The requirement satisfied by every engine in the same minor series as
    /// `version`: `[major, minor, 0] <= v < [major, minor + 1, 0]`.
    ///
    /// A minor bump in 0.x may add fact variants, which invalidates bundles;
    /// a patch bump may not. So "same series" is the conservative default a
    /// corpus author reaches for.
    #[must_use]
    pub fn same_series(version: [u32; 3]) -> Self {
        Self {
            min: [version[0], version[1], 0],
            max_exclusive: Some([version[0], version[1] + 1, 0]),
        }
    }

    /// Whether an engine version satisfies this bound.
    #[must_use]
    pub fn accepts(&self, engine: [u32; 3]) -> bool {
        let above_min = engine >= self.min;
        let below_max = self.max_exclusive.is_none_or(|max| engine < max);
        above_min && below_max
    }

    /// Parse `major.minor.patch`, ignoring any `-pre` / `+build` suffix.
    /// Returns `None` when the string is not a version, so a caller can fall
    /// back to the strict vocabulary check rather than guessing.
    #[must_use]
    pub fn parse_triple(version: &str) -> Option<[u32; 3]> {
        let numeric = version.split(['-', '+']).next().unwrap_or(version);
        let mut parts = numeric.split('.');
        let next = |parts: &mut core::str::Split<'_, char>| parts.next()?.parse::<u32>().ok();
        let major = next(&mut parts)?;
        let minor = next(&mut parts)?;
        let patch = next(&mut parts).unwrap_or(0);
        Some([major, minor, patch])
    }
}

impl fmt::Display for EngineRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, ">={}.{}.0", self.min[0], self.min[1])?;
        if let Some(max) = self.max_exclusive {
            write!(f, ",<{}.{}.0", max[0], max[1])?;
        }
        Ok(())
    }
}

/// The `.frc` envelope header.
///
/// Fields 0..4 are the version-6 layout and are unchanged; the trailing three
/// are version 7. `read_bundle_parts` branches on `version` before decoding so
/// that a v6 header is never handed to the v7 shape.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BundleHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub pattern_count: u32,
    pub checksum: [u8; 32],
    /// Fact-vocabulary fingerprint of the engine that wrote this bundle.
    /// `None` on a v6 (pre-Phase-6) bundle.
    #[serde(default)]
    pub vocabulary: Option<u64>,
    /// Coarse engine range this bundle targets. Optional: the vocabulary
    /// fingerprint is the strict check; this is policy for corpus authors.
    #[serde(default)]
    pub requires_engine: Option<EngineRequirement>,
    /// Engine version string at write time. Diagnostics only.
    #[serde(default)]
    pub built_by_engine: Option<String>,
}

/// The v6 header, kept only so old bundles keep loading. Do not use for new
/// writes.
///
/// `Serialize` is derived (not just `Deserialize`) so a test can fabricate a
/// genuine pre-v7 envelope: hand-writing the four-field bytes is how we
/// exercise the version branch without depending on a real v6 corpus file.
#[derive(serde::Serialize, serde::Deserialize)]
struct BundleHeaderV6 {
    #[allow(dead_code)]
    magic: [u8; 4],
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    pattern_count: u32,
    #[allow(dead_code)]
    checksum: [u8; 32],
}

impl BundleHeader {
    /// Header for a v7 write, recording the current vocabulary fingerprint and
    /// the engine that built it.
    #[must_use]
    pub fn current(pattern_count: u32, checksum: [u8; 32]) -> Self {
        Self {
            magic: *BUNDLE_MAGIC,
            version: BUNDLE_VERSION,
            pattern_count,
            checksum,
            vocabulary: Some(frensense_engine::analysis::taint::facts::FACT_VOCABULARY_FINGERPRINT),
            requires_engine: None,
            built_by_engine: Some(frensense_engine::VERSION.to_string()),
        }
    }

    /// A v6-shaped header, for tests and for round-tripping an existing
    /// bundle's metadata through a rewrite.
    #[must_use]
    pub fn legacy(pattern_count: u32, checksum: [u8; 32]) -> Self {
        Self {
            magic: *BUNDLE_MAGIC,
            version: 6,
            pattern_count,
            checksum,
            vocabulary: None,
            requires_engine: None,
            built_by_engine: None,
        }
    }

    /// Whether this header predates the vocabulary fingerprint. Such a bundle
    /// loads (nothing to compare) but is not pinned to an engine.
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.vocabulary.is_none()
    }
}

/// Serialize a payload into the .frc binary format, recording the current
/// engine's fact-vocabulary fingerprint.
///
/// Use [`write_bundle_pinned`] when the bundle should also carry a coarse
/// engine range for distribution.
pub fn write_bundle<T: serde::Serialize>(
    payload: &T,
    pattern_count: u32,
) -> Result<Vec<u8>, String> {
    write_bundle_with_header(payload, BundleHeader::current(pattern_count, [0; 32]))
}

/// Like [`write_bundle`], but stamps an engine range so a consumer can refuse
/// the bundle before decoding it. This is what corpus-repo publishing should
/// use: the range names the engine the families were replay-gated against.
pub fn write_bundle_pinned<T: serde::Serialize>(
    payload: &T,
    pattern_count: u32,
    requires_engine: EngineRequirement,
) -> Result<Vec<u8>, String> {
    let mut header = BundleHeader::current(pattern_count, [0; 32]);
    header.requires_engine = Some(requires_engine);
    write_bundle_with_header(payload, header)
}

fn write_bundle_with_header<T: serde::Serialize>(
    payload: &T,
    mut header: BundleHeader,
) -> Result<Vec<u8>, String> {
    let data = bincode::serialize(payload).map_err(|e| e.to_string())?;
    let checksum = blake3::hash(&data);
    header.checksum = *checksum.as_bytes();

    let mut output = Vec::new();
    let header_bytes = bincode::serialize(&header).map_err(|e| e.to_string())?;

    // Write header length as 4-byte LE
    output.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(&data);

    Ok(output)
}

/// Hand-write an envelope in the *pre-v7* header shape.
///
/// Test-only, for exercising the reader's version branching against a header
/// that really is 4 fields wide - patching the version inside a v7 header
/// would leave the extra fields on the wire and prove nothing.
#[cfg(test)]
pub(crate) fn write_legacy_envelope(version: u32, payload: &[u8]) -> Vec<u8> {
    let header = BundleHeaderV6 {
        magic: *BUNDLE_MAGIC,
        version,
        pattern_count: 0,
        checksum: *blake3::hash(payload).as_bytes(),
    };
    let header_bytes = bincode::serialize(&header).expect("legacy header serializes");
    let mut bytes = (header_bytes.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(payload);
    bytes
}

/// Split the `.frc` envelope: verify magic, gate the version against
/// [`BUNDLE_VERSION`], verify the checksum, and return the header with the
/// payload bytes (not yet deserialized).
///
/// Compatibility is checked here, before any payload decode, so a bundle that
/// cannot be understood is refused with a message naming both sides rather
/// than surfacing as a serde error halfway through a scan.
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

    // Peek magic + version without committing to a header shape: they are the
    // first two fields of every version, so the prefix decodes identically.
    let (magic, version) = peek_header_prefix(header_data)?;
    if magic != *BUNDLE_MAGIC {
        return Err("Invalid magic bytes, expected FRC1".to_string());
    }
    if version > BUNDLE_VERSION {
        return Err(format!(
            "Unsupported bundle version {} (this engine supports up to {})",
            version, BUNDLE_VERSION
        ));
    }
    if version < MIN_SUPPORTED_VERSION {
        return Err(format!(
            "Bundle version {version} is no longer supported (oldest readable is \
             {MIN_SUPPORTED_VERSION}); rebuild it with a current `frensense bundle`"
        ));
    }

    let header: BundleHeader = if version < BUNDLE_VERSION {
        // v6-and-earlier layout: decode the frozen shape, then widen it.
        let legacy: BundleHeaderV6 =
            bincode::deserialize(header_data).map_err(|e| e.to_string())?;
        BundleHeader {
            magic: legacy.magic,
            version: legacy.version,
            pattern_count: legacy.pattern_count,
            checksum: legacy.checksum,
            vocabulary: None,
            requires_engine: None,
            built_by_engine: None,
        }
    } else {
        bincode::deserialize(header_data).map_err(|e| e.to_string())?
    };

    let payload_data = &bytes[4 + header_len..];
    let actual_checksum = blake3::hash(payload_data);
    if actual_checksum.as_bytes() != &header.checksum {
        return Err("Bundle checksum mismatch (corrupted data)".to_string());
    }

    check_engine_compatibility(&header)?;

    Ok((header, payload_data))
}

/// Enforce the header's engine compatibility claims against this binary.
///
/// The vocabulary fingerprint is the strict check: it is derived from the
/// serialized fact vocabulary itself, so it moves exactly when a bundle's
/// bytes would stop decoding. The engine range is a coarser, author-declared
/// policy bound on top of it.
///
/// # Errors
/// Returns a message naming both sides whenever the bundle cannot be loaded
/// by this engine.
pub fn check_engine_compatibility(header: &BundleHeader) -> Result<(), String> {
    let engine_version = frensense_engine::VERSION;
    let engine_triple = EngineRequirement::parse_triple(engine_version);

    if let Some(required) = header.requires_engine {
        match engine_triple {
            Some(triple) if required.accepts(triple) => {}
            Some(triple) => {
                return Err(format!(
                    "Bundle requires frensense {required} but this engine is \
                     {engine_version} ({}.{}.{}). Rebuild the bundle with a \
                     matching engine, or upgrade.",
                    triple[0], triple[1], triple[2]
                ));
            }
            None => {
                return Err(format!(
                    "Bundle declares an engine requirement ({required}) but this \
                     engine's version {engine_version} is not a parseable version; \
                     refusing rather than guessing"
                ));
            }
        }
    }

    // `built_by_engine` is diagnostics only: a bundle written by an older
    // patch of the same series carries the same vocabulary fingerprint and is
    // perfectly loadable, so nothing is checked against it here.
    if let Some(recorded) = header.vocabulary {
        let current = frensense_engine::analysis::taint::facts::FACT_VOCABULARY_FINGERPRINT;
        if recorded != current {
            return Err(format!(
                "Bundle was built for fact vocabulary {recorded:#018x} but this \
                 engine speaks {current:#018x}. The engine's fact vocabulary has \
                 changed since it was written; rebuild the bundle with this engine \
                 (`frensense bundle <corpus> <out>.frc`)."
            ));
        }
    }

    Ok(())
}

/// Decode magic and version from a header without knowing its full shape.
///
/// Both are the first fields of every version of [`BundleHeader`], and bincode
/// 1.x encodes them fixed-width little-endian, so the prefix is stable.
fn peek_header_prefix(header_data: &[u8]) -> Result<([u8; 4], u32), String> {
    if header_data.len() < 8 {
        return Err(format!(
            "Bundle header truncated ({} bytes, need at least 8)",
            header_data.len()
        ));
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&header_data[0..4]);
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&header_data[4..8]);
    Ok((magic, u32::from_le_bytes(version_bytes)))
}

/// Deserialize a payload from the .frc binary format.
pub fn read_bundle<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<(BundleHeader, T), String> {
    let (header, payload_data) = read_bundle_parts(bytes)?;
    let payload: T = bincode::deserialize(payload_data).map_err(|e| e.to_string())?;
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-write an envelope at a chosen version, bypassing the writer so
    /// the *reader* is what is under test.
    fn raw_envelope(header_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = (header_bytes.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(header_bytes);
        bytes.extend_from_slice(payload);
        bytes
    }

    /// A v7 bundle records the fingerprint and the writing engine, and loads.
    #[test]
    fn v7_write_records_vocabulary_and_engine() {
        let bytes = write_bundle(&vec![1u32, 2, 3], 0).expect("write");
        let (header, payload) = read_bundle::<Vec<u32>>(&bytes).expect("v7 round-trips");
        assert_eq!(header.version, BUNDLE_VERSION);
        assert_eq!(
            header.vocabulary,
            Some(frensense_engine::analysis::taint::facts::FACT_VOCABULARY_FINGERPRINT)
        );
        assert_eq!(
            header.built_by_engine.as_deref(),
            Some(frensense_engine::VERSION)
        );
        assert_eq!(payload, vec![1, 2, 3]);
    }

    /// A v6 header (no vocabulary fields) still loads, marked legacy.
    #[test]
    fn v6_envelope_still_loads() {
        let payload = bincode::serialize(&vec![7u8]).expect("payload");
        let legacy = BundleHeaderV6 {
            magic: *BUNDLE_MAGIC,
            version: 6,
            pattern_count: 0,
            checksum: *blake3::hash(&payload).as_bytes(),
        };
        let header_bytes = bincode::serialize(&legacy).expect("header");
        let bytes = raw_envelope(&header_bytes, &payload);

        let (header, loaded) = read_bundle::<Vec<u8>>(&bytes).expect("v6 loads");
        assert_eq!(header.version, 6);
        assert!(header.is_legacy(), "v6 bundles predate the fingerprint");
        assert_eq!(header.vocabulary, None);
        assert_eq!(loaded, vec![7u8]);
    }

    /// The prefix peek agrees with the decoded header for every shape.
    #[test]
    fn version_prefix_matches_decoded_header() {
        for version in [6u32, 7] {
            let header = if version == 6 {
                BundleHeader::legacy(3, [0; 32])
            } else {
                BundleHeader::current(3, [0; 32])
            };
            let bytes = bincode::serialize(&header).expect("serialize");
            let (magic, peeked) = peek_header_prefix(&bytes).expect("peek");
            assert_eq!(magic, *BUNDLE_MAGIC);
            assert_eq!(peeked, version, "byte offsets differ from bincode layout");
        }
    }

    /// A newer-than-known envelope is refused by version, before decoding.
    #[test]
    fn newer_bundle_version_rejected_with_clean_error() {
        let mut header = BundleHeader::current(0, [0; 32]);
        header.version = BUNDLE_VERSION + 1;
        let header_bytes = bincode::serialize(&header).expect("serialize");
        let bytes = raw_envelope(&header_bytes, &[]);

        let err = read_bundle_parts(&bytes).expect_err("newer version must fail");
        assert!(err.contains("Unsupported bundle version"), "{err}");
        assert!(err.contains(&BUNDLE_VERSION.to_string()), "{err}");
    }

    /// A too-old envelope is refused with a rebuild instruction rather than a
    /// parse error.
    #[test]
    fn pre_min_supported_version_rejected() {
        let header = BundleHeader::legacy(0, [0; 32]);
        let mut bytes_header = bincode::serialize(&header).expect("serialize");
        // Rewrite the version field to 3 (prefix bytes 4..8).
        bytes_header[4..8].copy_from_slice(&3u32.to_le_bytes());
        let bytes = raw_envelope(&bytes_header, &[]);

        let err = read_bundle_parts(&bytes).expect_err("must fail");
        assert!(err.contains("no longer supported"), "{err}");
    }

    /// A bundle built for a different vocabulary is refused with both values
    /// named - the check that makes corpus distribution safe.
    #[test]
    fn vocabulary_mismatch_rejected() {
        let mut header = BundleHeader::current(0, [0; 32]);
        header.vocabulary = Some(0xdead_beef_dead_beef);
        let checksum = blake3::hash(b"payload");
        header.checksum = *checksum.as_bytes();
        let header_bytes = bincode::serialize(&header).expect("serialize");
        let bytes = raw_envelope(&header_bytes, b"payload");

        let err = read_bundle_parts(&bytes).expect_err("must fail");
        assert!(err.contains("fact vocabulary"), "{err}");
        assert!(err.contains("rebuild the bundle"), "{err}");
    }

    /// An out-of-range engine requirement is refused with both sides named.
    #[test]
    fn engine_requirement_rejected_when_out_of_range() {
        let mut header = BundleHeader::current(0, [0; 32]);
        let checksum = blake3::hash(b"payload");
        header.checksum = *checksum.as_bytes();
        // A series far in the future.
        header.requires_engine = Some(EngineRequirement {
            min: [99, 0, 0],
            max_exclusive: None,
        });
        let header_bytes = bincode::serialize(&header).expect("serialize");
        let bytes = raw_envelope(&header_bytes, b"payload");

        let err = read_bundle_parts(&bytes).expect_err("must fail");
        assert!(err.contains("requires frensense >="), "{err}");
        assert!(err.contains(frensense_engine::VERSION), "{err}");
    }

    /// `write_bundle_pinned` stamps the range, and a bundle for this engine's
    /// own series loads.
    #[test]
    fn pinned_bundle_for_current_series_loads() {
        let current = EngineRequirement::parse_triple(frensense_engine::VERSION)
            .expect("engine version parses");
        let bytes = write_bundle_pinned(&vec![1u8], 0, EngineRequirement::same_series(current))
            .expect("write");
        let (header, _) = read_bundle::<Vec<u8>>(&bytes).expect("loads");
        assert!(header.requires_engine.is_some());
        assert!(header.requires_engine.expect("range").accepts(current));
    }

    /// Version parsing ignores pre-release and build suffixes.
    #[test]
    fn engine_version_parsing() {
        assert_eq!(
            EngineRequirement::parse_triple("0.8.0-beta"),
            Some([0, 8, 0])
        );
        assert_eq!(
            EngineRequirement::parse_triple("1.2.3+build"),
            Some([1, 2, 3])
        );
        assert_eq!(EngineRequirement::parse_triple("0.9"), Some([0, 9, 0]));
        assert_eq!(EngineRequirement::parse_triple("nonsense"), None);
    }

    /// The same-series range includes the current patch and excludes the next
    /// minor.
    #[test]
    fn same_series_bounds() {
        let req = EngineRequirement::same_series([0, 8, 0]);
        assert!(req.accepts([0, 8, 0]));
        assert!(req.accepts([0, 8, 5]));
        assert!(!req.accepts([0, 7, 9]));
        assert!(!req.accepts([0, 9, 0]));
        assert_eq!(req.to_string(), ">=0.8.0,<0.9.0");
    }
}
