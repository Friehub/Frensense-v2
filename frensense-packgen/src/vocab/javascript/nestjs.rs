// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! NestJS provider vocabulary: package-scoped database and ORM sinks.
//!
//! Covers:
//! - `@nestjs/typeorm`: raw query execution on `EntityManager` / `Repository`
//! - `@nestjs/mongoose`: model query finders and updaters
//!
//! NOTE: `@nestjs/config` `ConfigService.get` is intentionally EXCLUDED from
//! sources because it returns developer-controlled application configuration.

use crate::role_map::SinkLabel;

/// Package-scoped sinks for NestJS integrations (`call`, `package`, `label`).
pub(super) static NESTJS_PACKAGE_SCOPED_SINKS: &[(&str, &str, SinkLabel)] = &[
    // @nestjs/typeorm raw query execution
    ("query", "@nestjs/typeorm", SinkLabel::SqlInjection),
    (
        "createQueryBuilder",
        "@nestjs/typeorm",
        SinkLabel::SqlInjection,
    ),
    ("execute", "@nestjs/typeorm", SinkLabel::SqlInjection),
    // @nestjs/mongoose NoSQL operations
    ("find", "@nestjs/mongoose", SinkLabel::NoSqlInjection),
    ("findOne", "@nestjs/mongoose", SinkLabel::NoSqlInjection),
    ("findById", "@nestjs/mongoose", SinkLabel::NoSqlInjection),
    ("updateOne", "@nestjs/mongoose", SinkLabel::NoSqlInjection),
    ("updateMany", "@nestjs/mongoose", SinkLabel::NoSqlInjection),
    ("deleteOne", "@nestjs/mongoose", SinkLabel::NoSqlInjection),
    ("deleteMany", "@nestjs/mongoose", SinkLabel::NoSqlInjection),
];

/// Route registration patterns for NestJS controller decorators.
pub(super) static NESTJS_ROUTE_PATTERNS: &[&str] =
    &["@Get(", "@Post(", "@Put(", "@Delete(", "@Patch(", "@All("];
