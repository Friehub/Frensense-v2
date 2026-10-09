// MRE-02a - reflected XSS whose only sink is a Response-tier API.
// Shape of CVE-2025-59057 (react-router meta()/script:ld+json <= 7.8.2):
// untrusted query content is serialized into a <script type="application/
// ld+json"> block without neutralizing `</script>` / `<`.
//
// EXPECTED (corpus contract): >= 1 advisory, identity token "xss".
// ACTUAL   (release binary, 2026-10-03):
//   default scan            -> 0 advisories.
//   --severity info         -> 1 advisory, tags ["taint","response"],
//     title "User data reaches `send` as a value (review: role=response)".
//     Neither tags nor title contain "xss" -> identity would still fail.
//
// Root cause (layered):
//  1. Lang declares `res.send`/`res.json` -> SinkLabel::ResponseLeak
//     (frensense-lang/src/providers/javascript/tables.rs:243) ->
//     SinkRole::Response -> default_level "info"
//     (frensense-engine/src/analysis/taint/role.rs:92).
//  2. ScanResult::has_alert() ignores info-tier findings (frensense-engine/
//     src/scan.rs:289) so the bundler baseline sees positive_alerts=false,
//     and the CLI default severity floor is warning (src/cli/options.rs:35),
//     so users see nothing at all.
//  3. Even surfaced, role tag is "response", never "xss": SinkLabel is
//     collapsed into SinkRole before reporting (role.rs:50 from_label).
//
// Design question for the engine agent: an HTML document echoed with
// attacker script inside is XSS regardless of which response method wrote
// it. Content-type/context (is the payload HTML? does it reach a script
// context?) is the missing signal - role alone cannot distinguish
// `res.json(echo)` (noise) from `res.send(htmlPage)` (CWE-79).

import type { Request, Response } from "express";

export function searchMeta(req: Request, res: Response): void {
    const query = String(req.query.q);

    const jsonLd = JSON.stringify({
        "@context": "https://schema.org",
        "@type": "SearchResultsPage",
        name: query,
        description: `Results for ${query}`,
    });

    res.send(
        `<!doctype html><html><head>` +
            `<script type="application/ld+json">${jsonLd}</script>` +
            `</head><body></body></html>`,
    );
}
