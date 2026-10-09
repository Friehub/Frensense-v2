// MRE-01a - SSRF false negative through a factory-made client instance.
// Shape of CVE-2025-27152 (axios >= 1.0.0 < 1.8.2): an absolute URL in the
// path overrides baseURL, so the request (with the X-API-KEY header) leaves
// for an attacker-chosen host.
//
// EXPECTED (corpus contract): >= 1 advisory whose tags/title contain "ssrf".
// ACTUAL   (release binary, 2026-10-03): 0 advisories.
//
// Root cause: the receiver variable `client` is bound to axios.create(...).
// FactTable::receiver_root() resolves it to its own source name ("client"),
// which is not in client_roots, so the verb sink `get` is suppressed by
// is_sink_call() (frensense-engine/src/analysis/taint/facts/signatures.rs:120
// and :136). The unresolvable-receiver overapproximation only applies when
// receiver_root is None - here it resolves to the WRONG name, a worse case
// than being unknown.
// Control: mre01_ssrf_direct_control.ts (axios.get(...) as a member chain)
// DOES fire, proving verb gating itself works when the root is literal.
//
// Second, independent gap: even when it fires, the advisory carries
// tags ["taint","resource"] and a title naming the sink "get" - neither
// contains the gate identity token "ssrf". SinkLabel::Ssrf is collapsed to
// SinkRole::Resource at fact-table build time (frensense-engine/src/
// analysis/taint/role.rs:50) and never reaches the advisory
// (src/engine/project/runner.rs:271 with_tags(["taint", class_tag])).

import axios from "axios";

const client = axios.create({
    baseURL: "http://directory.internal/api/v1/users/",
    headers: { "X-API-KEY": process.env.DIRECTORY_API_KEY ?? "" },
});

export async function getUser(req: any, res: any): Promise<void> {
    const userId = String(req.params.id);
    // "http://169.254.169.254/latest/meta-data/" overrides baseURL.
    const resp = await client.get(userId);
    res.json(resp.data);
}
