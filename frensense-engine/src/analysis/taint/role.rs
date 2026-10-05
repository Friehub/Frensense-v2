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
