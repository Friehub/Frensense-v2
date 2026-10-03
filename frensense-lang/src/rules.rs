// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Stable rule identifiers emitted by engine checkers.
//!
//! Rule ids are declarations, not engine behavior: they live here so the
//! per-language severity registries ([`crate::severity::RuleEntry`]) and the
//! engine's finding emitters share one source of truth. The engine references
//! these constants; it never owns the strings.

/// Temporal memory-safety violation (use after free).
pub const USE_AFTER_FREE: &str = "use_after_free";
/// Temporal memory-safety violation (double free / uninitialized free).
pub const DOUBLE_FREE: &str = "double_free";
/// Spatial memory-safety violation (buffer overflow write).
pub const BUFFER_OVERFLOW: &str = "buffer_overflow";
/// Spatial memory-safety violation (out-of-bounds read).
pub const OUT_OF_BOUNDS_READ: &str = "out_of_bounds_read";
/// Spatial memory-safety violation (out-of-bounds access).
pub const OUT_OF_BOUNDS_ACCESS: &str = "out_of_bounds_access";
/// Integer wrap in an allocation size expression (undersized buffer).
pub const INTEGER_OVERFLOW_ALLOC: &str = "integer_overflow_alloc";
/// Memory still owned at function exit (missing release / leak).
pub const MEMORY_LEAK: &str = "memory_leak";

/// Allowlist guard built on substring containment (bypassable).
pub const SUBSTRING_ALLOWLIST_GUARD: &str = "substring_allowlist_guard";
/// Plaintext password routed to a fast digest instead of a memory-hard KDF.
pub const CREDENTIAL_KDF_POLICY: &str = "credential_kdf_policy";
/// Allowlist definition enforced elsewhere by substring containment.
pub const ALLOWLIST_DEFINITION_BYPASSABLE: &str = "allowlist_definition_bypassable";
/// Password hashing routed through an opaque hash wrapper.
pub const WEAK_HASH_WRAPPER: &str = "weak_hash_wrapper";
/// Numeric bound declared in prose but not enforced by the schema builder.
pub const UNBOUNDED_NUMBER_SCHEMA: &str = "unbounded_number_schema";
