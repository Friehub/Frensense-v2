// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Shared JS/TS parameter → [`TaintOrigin`](crate::spec::TaintOrigin) classification.

use crate::spec::TaintOrigin;

// ── Shared JS/TS param classification ─────────────────────────────────────────

pub(super) fn classify_js_param(name: Option<&str>, ann: Option<&str>) -> Option<TaintOrigin> {
    // Type annotation from an HTTP framework package → confirmed user input
    if let Some(a) = ann {
        let base = a
            .trim_start_matches(':')
            .trim()
            .split(['<', '[', ' '])
            .next()
            .unwrap_or(a);
        let base = base.rsplit('.').next().unwrap_or(base);
        if matches!(
            base,
            "Request"
                | "IncomingMessage"
                | "FastifyRequest"
                | "Context"
                | "HonoContext"
                | "KoaContext"
                | "APIGatewayProxyEvent"
                | "HttpRequest"
                | "NextApiRequest"
                | "NextRequest"
                | "ServerRequest"
                | "H3Event"
                | "ElysiaContext"
                | "AdonisRequest"
                | "ExpressRequest"
                | "SocketStream"
                | "CloudFrontRequest"
                | "APIGatewayProxyEventV2"
        ) {
            return Some(TaintOrigin::UserInput);
        }
    }
    // Name-based fallback for untyped code
    match name? {
        "req" | "request" | "ctx" | "context" | "event" | "c" | "e" | "socket" | "ws"
        | "incomingMsg" | "httpReq" => Some(TaintOrigin::UserInput),
        "env" | "config" | "settings" => Some(TaintOrigin::Environment),
        "filePath" | "filepath" | "filename" | "fileName" | "dir" | "directory" => {
            Some(TaintOrigin::FileSystem)
        }
        "response" | "reply" => Some(TaintOrigin::Network),
        _ => None,
    }
}
