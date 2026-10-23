// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
pub mod c_lang;
pub mod go;
pub mod javascript;
pub mod python;
pub mod rust_lang;

#[cfg(test)]
#[path = "module_surface_tests.rs"]
mod module_surface_tests;
