// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! npm package → [`PackageCategory`](crate::spec::PackageCategory) knowledge.

use crate::spec::PackageCategory;

// ── Package knowledge ─────────────────────────────────────────────────────────

pub(super) fn js_package_category(pkg: &str) -> Option<PackageCategory> {
    // Normalize: strip @scope prefix for lookup, handle sub-paths
    let base = pkg.split('/').next().unwrap_or(pkg);
    match base {
        // HTTP frameworks
        "express" | "fastify" | "koa" | "hapi" | "@hono" | "hono" | "polka" | "h3" | "elysia"
        | "next" | "nuxt" | "@nestjs" | "nest" | "@adonisjs" | "bun" | "deno" | "@remix-run"
        | "astro" | "sveltekit" | "@sveltejs" | "trpc" | "@trpc" => {
            Some(PackageCategory::HttpFramework)
        }

        // GraphQL
        "graphql" | "apollo-server" | "@apollo" | "type-graphql" | "nexus" | "pothos-graphql"
        | "mercurius" => Some(PackageCategory::GraphQL),

        // WebSocket
        "ws" | "socket.io" | "uws" | "@fastify" => Some(PackageCategory::WebSocket),

        // Email Service
        "nodemailer" | "sendgrid" | "@sendgrid" | "mailgun" => Some(PackageCategory::EmailService),

        // SQL
        "pg" | "postgres" | "mysql" | "mysql2" | "mariadb" | "sqlite3" | "better-sqlite3"
        | "mssql" | "oracledb" | "sequelize" | "knex" | "typeorm" | "@prisma" | "prisma"
        | "slonik" | "drizzle-orm" => Some(PackageCategory::SqlDatabase),

        // NoSQL
        "mongodb" | "mongoose" | "redis" | "ioredis" | "cassandra-driver" | "couchdb"
        | "@elastic" => Some(PackageCategory::NoSqlDatabase),

        // Command execution
        "child_process" | "shelljs" | "execa" | "cross-spawn" | "node-pty" | "spawn-command" => {
            Some(PackageCategory::CommandExecution)
        }

        // HTTP clients (SSRF)
        "node-fetch" | "axios" | "got" | "superagent" | "undici" | "request" | "node:http"
        | "node:https" | "puppeteer" | "playwright" | "@playwright" => {
            Some(PackageCategory::HttpClient)
        }

        // File system (path traversal)
        "fs" | "node:fs" | "fs-extra" | "graceful-fs" | "recursive-readdir" | "glob" | "rimraf" => {
            Some(PackageCategory::FileSystem)
        }

        // Template engines (SSTI / XSS)
        "ejs" | "pug" | "handlebars" | "nunjucks" | "mustache" | "dot" | "art-template"
        | "consolidate" => Some(PackageCategory::TemplateEngine),

        // Unsafe deserialization
        "node-serialize"
        | "serialize-javascript"
        | "js-yaml"
        | "yaml"
        | "xml2js"
        | "fast-xml-parser"
        | "xml-js"
        | "libxmljs"
        | "saxjs" => Some(PackageCategory::Deserialization),

        // Testing and Validation
        "validator" | "joi" | "zod" | "yup" | "ajv" => Some(PackageCategory::Testing),

        // Crypto
        "crypto" | "node:crypto" | "bcrypt" | "bcryptjs" | "argon2" => {
            Some(PackageCategory::Crypto)
        }

        _ => None,
    }
}
