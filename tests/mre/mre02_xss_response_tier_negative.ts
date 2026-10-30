// MRE-02b - paired negative for mre02_xss_response_tier (SAFE).
// The serialized JSON-LD neutralizes `<`, so a reflected value cannot close
// the script element (the CVE-2025-59057 remediation, react-router 7.9.0).
//
// EXPECTED: 0 advisories. ACTUAL today: 0 advisories.
// NOTE: because the POSITIVE is silent too (info-tier), the family never
// separates at baseline - the bundler cannot learn `sanitizer:replace` from
// this pair alone (it only published thanks to a second family, py_file_
// traversal, voting for the same key). See README.md learn defect L1.

import type { Request, Response } from "express";

export function searchMeta(req: Request, res: Response): void {
    const query = String(req.query.q);

    const jsonLd = JSON.stringify({
        "@context": "https://schema.org",
        "@type": "SearchResultsPage",
        name: query,
        description: `Results for ${query}`,
    })
        .replace(/</g, "\\u003c")
        .replace(/\u2028/g, "\\u2028")
        .replace(/\u2029/g, "\\u2029");

    res.send(
        `<!doctype html><html><head>` +
            `<script type="application/ld+json">${jsonLd}</script>` +
            `</head><body></body></html>`,
    );
}
