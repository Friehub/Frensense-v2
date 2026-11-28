// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! What a [`PackageCategory`] implies about a call into that package.
//!
//! Split out of `spec.rs`: the category table classifies packages, and this
//! is the one consumer that turns a classification into an analysis fact.

use super::PackageCategory;
use crate::severity::SinkRole;

impl PackageCategory {
    /// The sink role a package of this category implies, when the caller has
    /// no role of its own for the call.
    ///
    /// Every provider classifies the packages it knows into one of these
    /// categories, and the classification had no consumer: a call into a
    /// package the fact layer carried no role for reported as `Other` even
    /// though the language already knew it was a SQL driver or a template
    /// engine. Categories whose risk is carried by a *label* rather than a
    /// role (`HttpClient` -> SSRF) and libraries that interpret nothing
    /// (`Logging`, `Testing`, frameworks) answer `None`.
    #[must_use]
    pub fn sink_role(&self) -> Option<SinkRole> {
        match self {
            // The input is interpreted: it becomes a query, a command, a
            // template, or an object graph.
            PackageCategory::SqlDatabase
            | PackageCategory::NoSqlDatabase
            | PackageCategory::CommandExecution
            | PackageCategory::TemplateEngine
            | PackageCategory::Deserialization => Some(SinkRole::Execution),
            // The input selects a path on disk.
            PackageCategory::FileSystem => Some(SinkRole::Resource),
            // The input enters a cryptographic primitive.
            PackageCategory::Crypto => Some(SinkRole::Crypto),
            // SSRF is ranked by its own label; a framework, mailbox,
            // websocket, logger or test helper interprets nothing here.
            PackageCategory::HttpClient
            | PackageCategory::HttpFramework
            | PackageCategory::GraphQL
            | PackageCategory::WebSocket
            | PackageCategory::EmailService
            | PackageCategory::Logging
            | PackageCategory::Testing => None,
        }
    }
}
