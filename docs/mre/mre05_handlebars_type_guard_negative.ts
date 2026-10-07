// MRE-05a - false positive on a type-narrowing guard (part 1 of the
// handlebars negative failure, CVE-2026-33937 remediation shape).
//
// EXPECTED: 0 advisories - after `typeof t !== "string"` returns early,
//   only a string template reaches Handlebars.compile(), which is the
//   documented fix (reject the deserialized AST object).
// ACTUAL (release binary, 2026-10-03): 1 advisory -
//   "Unsanitized data from `req.body.t` reaches sink `compile`".
//
// Root cause: the taint engine has no notion of type narrowing. The guard
// is an early-return branch on a typeof comparison; `frensense-engine/src`
// contains zero references to "typeof" and frensense-lang's
// is_predicate_guard() only classifies CALL names (is*/every/includes/
// .test()). A value whose type has been proven `string` on the fall-through
// path is treated exactly like the raw request value.
//
// Control: truthy_guard.ts (`if (!t) return;`) produces the SAME advisory -
// so this is not typeof-specific: ANY early-return validation on the value
// itself is invisible; the engine only honors guards expressed as recognized
// sanitizer/predicate CALLS on the tainted variable.

import Handlebars from "handlebars";
import type { Request, Response } from "express";

export function previewTemplate(req: Request, res: Response): void {
    const t = req.body.t;

    if (typeof t !== "string") {
        res.status(400).send("template must be a string");
        return;
    }

    const fn = Handlebars.compile(t);
    res.send(fn({}));
}
