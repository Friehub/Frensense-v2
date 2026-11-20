// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Next.js provider vocabulary: package-scoped sinks, signatures, and sources.
//!
//! Covers Next.js App Router and Pages Router:
//! - `next/server`: `NextResponse.redirect`, `NextResponse.rewrite`, `NextResponse.json`
//! - `next/navigation`: `redirect`, `permanentRedirect`, `useSearchParams`, `useParams`, `usePathname`
//! - `next/headers`: `cookies()`, `headers()`
//! - `next/cache`: `revalidatePath`, `revalidateTag`

use crate::role_map::SinkLabel;

/// Package-scoped sinks for Next.js (`call`, `package`, `label`).
pub(super) static NEXTJS_PACKAGE_SCOPED_SINKS: &[(&str, &str, SinkLabel)] = &[
    (
        "NextResponse.redirect",
        "next/server",
        SinkLabel::OpenRedirect,
    ),
    (
        "NextResponse.rewrite",
        "next/server",
        SinkLabel::OpenRedirect,
    ),
    ("NextResponse.json", "next/server", SinkLabel::ResponseLeak),
    ("redirect", "next/navigation", SinkLabel::OpenRedirect),
    (
        "permanentRedirect",
        "next/navigation",
        SinkLabel::OpenRedirect,
    ),
    ("revalidatePath", "next/cache", SinkLabel::StorageWrite),
    ("revalidateTag", "next/cache", SinkLabel::StorageWrite),
];

/// Source patterns for Next.js request extractors, navigation hooks, and URL accessors.
pub(super) static NEXTJS_SOURCE_PATTERNS: &[&str] = &[
    // next/headers function call sources
    "cookies",
    "headers",
    // next/navigation hooks
    "useSearchParams",
    "useParams",
    "usePathname",
    // NextRequest URL accessors
    "request.nextUrl.searchParams",
    "request.nextUrl.pathname",
    "req.nextUrl.searchParams",
    "req.nextUrl.pathname",
    // Next.js App Router PageProps / parameter destructuring
    "searchParams",
];
