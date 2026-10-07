// MRE-01c - control for MRE-01a (NOT a bundler family: no _positive/_negative
// suffix, so group_families() ignores it).
//
// EXPECTED (corpus contract): >= 1 advisory containing identity token "ssrf".
// ACTUAL: 1 advisory, but tags ["taint","resource"], title
//   "Unsanitized data from `req.params.id` reaches sink `get`".
//   The identity check (tags + title, case-sensitive substring) finds no
//   "ssrf" -> the gate would report Wrong Identity, not a pass.
//
// Proves two things in isolation:
//  1. Verb gating works when the receiver root is the literal package name
//     (dotted entry `axios.get` -> client_roots contains "axios").
//  2. Detection and identity are SEPARATE contract layers: fixing the
//     instance-alias FN alone still fails the gate until SinkLabel (or a
//     CWE-class slug) is threaded into advisory tags/title.

import axios from "axios";

export function getUser(req: any, res: any) {
    return axios.get(String(req.params.id));
}
