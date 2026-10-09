// MRE-03b - paired negative for mre03_proto_unset (SAFE).
// Path segments are rejected before lodash parses them, so no path can
// resolve through Object.prototype (the CVE-2025-13465 remediation,
// lodash 4.18.0).
//
// EXPECTED: 0 advisories. ACTUAL today: 0 advisories (vacuously - the
// positive is silent too). The interesting behavior appears only once
// `sink:unset` exists: the negative then ALERTS (the isSafePath guard is
// unknown), which is exactly why the gate rejects sink:unset today.

import unset from "lodash/unset";
import omit from "lodash/omit";
import type { Request } from "express";

const FORBIDDEN_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

function isSafePath(path: string | readonly string[]): boolean {
    const segments = Array.isArray(path) ? path : String(path).split(".");
    return segments.every((segment) => !FORBIDDEN_SEGMENTS.has(segment));
}

export function updatePreferences(req: Request, profile: Record<string, unknown>) {
    const field = String(req.body.field);
    const drop = String(req.body.drop);

    if (!isSafePath(field) || !isSafePath(drop)) {
        return { profile, visible: profile };
    }

    unset(profile, field);
    const visible = omit(profile, drop);

    return { profile, visible };
}
