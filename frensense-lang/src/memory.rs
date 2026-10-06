// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Memory-function vocabulary: allocators, deallocators, and their
//! capacity contracts.
//!
//! The engine's memory-summary inference, UAF discovery, and spatial
//! (OOB) checker all need to know *which calls allocate, which free, and
//! how capacity flows from arguments*. That knowledge is language
//! vocabulary - it lives here, never in `frensense-engine`. Specs override
//! [`LanguageSpec::known_memory_functions`](crate::spec::LanguageSpec::known_memory_functions);
//! the engine reads the table through the fact table
//! (`FactTable::memory_functions`) and falls back to
//! [`bootstrap_memory_functions`] when no spec is available.

/// Capacity of a fresh allocation, derived from the call's arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocCapacity {
    /// Fresh, but capacity is dynamic or unconstrained (`strdup(s)`).
    Unknown,
    /// Capacity is the argument at this index (`malloc(n)`).
    Param(usize),
    /// Capacity is the product of two arguments (`calloc(n, size)`).
    ParamProduct(usize, usize),
}

/// One memory-function contract: what the call returns and which slots
/// it consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFuncSpec {
    /// Callee name (bare or dotted; the engine matches exact-or-last).
    pub name: &'static str,
    /// Does the call return freshly allocated memory?
    pub returns_fresh: bool,
    /// Capacity of the returned allocation (meaningful when fresh).
    pub capacity: AllocCapacity,
    /// Parameter indices the call consumes (deallocates / takes ownership).
    pub consumes_params: &'static [usize],
}

const fn fresh(name: &'static str, capacity: AllocCapacity) -> MemoryFuncSpec {
    MemoryFuncSpec {
        name,
        returns_fresh: true,
        capacity,
        consumes_params: &[],
    }
}

const fn fresh_consuming(
    name: &'static str,
    capacity: AllocCapacity,
    consumes_params: &'static [usize],
) -> MemoryFuncSpec {
    MemoryFuncSpec {
        name,
        returns_fresh: true,
        capacity,
        consumes_params,
    }
}

const fn dealloc(name: &'static str) -> MemoryFuncSpec {
    MemoryFuncSpec {
        name,
        returns_fresh: false,
        capacity: AllocCapacity::Unknown,
        consumes_params: &[0],
    }
}

/// The bootstrap memory vocabulary: the C family plus the common bindings
/// (GLib, kernel, sqlite, OpenSSL, Apache, libxml, cJSON) that server
/// code links against. This is the default for every spec - providers
/// whose language has a different memory model (Go GC, JVM, JS) may
/// override with a narrower table.
pub static BOOTSTRAP_MEMORY_FUNCS: &[MemoryFuncSpec] = &[
    // Deallocators: consume parameter 0, return nothing fresh.
    dealloc("free"),
    dealloc("g_free"),
    dealloc("kfree"),
    dealloc("cJSON_Delete"),
    dealloc("apr_palloc"), // pool-allocated, ownership passes to the pool
    dealloc("CRYPTO_free"),
    dealloc("xmlFree"),
    dealloc("sqlite3_free"),
    // Sized allocators: capacity = argument 0.
    fresh("malloc", AllocCapacity::Param(0)),
    fresh("valloc", AllocCapacity::Param(0)),
    fresh("alloca", AllocCapacity::Param(0)),
    fresh("g_malloc", AllocCapacity::Param(0)),
    fresh("g_malloc0", AllocCapacity::Param(0)),
    fresh("kmalloc", AllocCapacity::Param(0)),
    fresh("kzalloc", AllocCapacity::Param(0)),
    fresh("sqlite3_malloc", AllocCapacity::Param(0)),
    // Count × size allocators.
    fresh("calloc", AllocCapacity::ParamProduct(0, 1)),
    fresh("sqlite3_malloc64", AllocCapacity::ParamProduct(0, 1)),
    fresh("kcalloc", AllocCapacity::ParamProduct(0, 1)),
    // Realloc-style: capacity = argument 1, consumes the old pointer.
    fresh_consuming("realloc", AllocCapacity::Param(1), &[0]),
    fresh_consuming("g_realloc", AllocCapacity::Param(1), &[0]),
    fresh_consuming("sqlite3_realloc", AllocCapacity::Param(1), &[0]),
    // Aligned allocator: capacity = argument 1 (size), arg 0 is alignment.
    fresh("aligned_alloc", AllocCapacity::Param(1)),
    // String duplicators: fresh, capacity unknown.
    fresh("strdup", AllocCapacity::Unknown),
    fresh("strndup", AllocCapacity::Unknown),
    fresh("g_strdup", AllocCapacity::Unknown),
];

/// The default vocabulary (see [`BOOTSTRAP_MEMORY_FUNCS`]).
pub fn bootstrap_memory_functions() -> &'static [MemoryFuncSpec] {
    BOOTSTRAP_MEMORY_FUNCS
}

/// Is `name` one of the bootstrap memory functions?
///
/// Used by the bundler to avoid re-emitting built-in contracts into a
/// `.frc` bundle (they already ship with the engine's vocabulary).
/// Exact-name match, mirroring the registry's bootstrap keys.
pub fn is_bootstrap_memory_func(name: &str) -> bool {
    BOOTSTRAP_MEMORY_FUNCS.iter().any(|m| m.name == name)
}

/// Calls whose results live on the current stack frame, not the heap.
/// Declared here because the vocabulary owner is lang: their lifetime
/// ends with the frame by definition, so leak-style checkers must never
/// treat them as leakable allocations (spatial checks still track their
/// capacity like any other buffer).
pub static BOOTSTRAP_STACK_ALLOCATORS: &[&str] = &["alloca", "_alloca", "__builtin_alloca"];

/// Is `name` (bare, dotted, or `::`-qualified) a lang-declared stack
/// allocator?
pub fn is_stack_allocator(name: &str) -> bool {
    let s = name.rsplit('.').next().unwrap_or(name);
    let s = s.rsplit("::").next().unwrap_or(s);
    BOOTSTRAP_STACK_ALLOCATORS.iter().any(|a| *a == s)
}

/// One buffer-manipulation builtin: which arguments are the destination
/// buffer, the source data, and the length, so the spatial checker can
/// verify write/read bounds against the tracked capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferBuiltinSpec {
    /// Callee last-segment name.
    pub name: String,
    /// Argument index of the destination buffer (`None` = none).
    pub dst_arg: Option<usize>,
    /// Argument index of the source data (`None` = none).
    pub src_arg: Option<usize>,
    /// Argument index of the length.
    pub len_arg: usize,
}

/// The bootstrap buffer vocabulary: C's copy/fill/read primitives.
///
/// Owned names (Phase 6): bundle-loaded builtins carry corpus text, so the
/// shared spec type may not be `&'static str`.
pub static BOOTSTRAP_BUFFER_BUILTINS: std::sync::LazyLock<Vec<BufferBuiltinSpec>> =
    std::sync::LazyLock::new(|| {
        fn bi(name: &str, dst: Option<usize>, src: Option<usize>, len: usize) -> BufferBuiltinSpec {
            BufferBuiltinSpec {
                name: name.to_string(),
                dst_arg: dst,
                src_arg: src,
                len_arg: len,
            }
        }
        vec![
            bi("memset", Some(0), None, 2),
            bi("bzero", Some(0), None, 1),
            bi("memcpy", Some(0), Some(1), 2),
            bi("memmove", Some(0), Some(1), 2),
            bi("strncpy", Some(0), None, 2),
            bi("snprintf", Some(0), None, 1),
            bi("fgets", Some(0), None, 1),
            bi("read", Some(1), None, 2),
        ]
    });

/// The default buffer vocabulary (see [`BOOTSTRAP_BUFFER_BUILTINS`]).
pub fn bootstrap_buffer_builtins() -> &'static [BufferBuiltinSpec] {
    &BOOTSTRAP_BUFFER_BUILTINS
}
