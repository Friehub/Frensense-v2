// MRE-04a - ReDoS driven by a constructor option, not a call-shape delta.
// Shape of CVE-2025-69873 (ajv <= 8.17.1, fixed 8.18.0 / 6.14.0):
// `new Ajv({ $data: true })` lets a schema keyword reference a regex
// carried in the payload; ajv compiles it with new RegExp before matching.
//
// EXPECTED (corpus contract): >= 1 advisory, identity token "regex".
// ACTUAL   (release binary, 2026-10-03): 0 advisories. And with a plain
//   `new RegExp(String(req.body.pattern))` (see redos control below) the
//   engine also reports 0 - there is NO ReDoS/regex-compilation sink
//   anywhere in frensense-lang (no SinkLabel, no sink table entry).
//
// Bundler learn trace (FXREPORT): baseline positive_alerts=false,
// negative_alerts=false. The only difference between the pair is the
// constructor OPTION (`$data: true` vs nothing) and the schema literal
// (`pattern: {$data: ...}` vs a fixed string). propose() diffs CALLS, not
// object properties, so it proposes sink:validate / sink:Ajv / sink:status,
// all rejected because the identical call shape exists in both variants
// ("positive_alerts=true, negative_alerts=true" for sink:validate).
// This is learn defect L3: no candidate type can express
// "policy: this constructor/option shape is dangerous" from a pos/neg delta.

import Ajv from "ajv";
import type { Request, Response } from "express";

const ajv = new Ajv({ $data: true } as any);

const orderSchema = {
    type: "object",
    properties: {
        code: { type: "string" },
        check: { type: "string", pattern: { $data: "1/code" } },
    },
} as any;

const validate = ajv.compile(orderSchema);

export function submitOrder(req: Request, res: Response): void {
    const ok = validate(req.body);
    res.status(ok ? 200 : 422).json({ ok });
}
