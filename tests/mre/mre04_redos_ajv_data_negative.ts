// MRE-04b - paired negative for mre04_redos_ajv_data (SAFE).
// $data is not enabled, so payload values never become regular
// expressions, and the pattern is a fixed literal (the CVE-2025-69873
// remediation, ajv 8.18.0).
//
// EXPECTED: 0 advisories. ACTUAL today: 0 advisories (vacuously).

import Ajv from "ajv";
import type { Request, Response } from "express";

const ajv = new Ajv();

const orderSchema = {
    type: "object",
    properties: {
        code: { type: "string" },
        check: { type: "string", pattern: "^[A-Z]{3}-\\d{4}$" },
    },
} as any;

const validate = ajv.compile(orderSchema);

export function submitOrder(req: Request, res: Response): void {
    const ok = validate(req.body);
    res.status(ok ? 200 : 422).json({ ok });
}
