// MRE-05b - control for mre05a: a plain truthy early-return guard.
// NOT a bundler family (no _positive/_negative suffix).
//
// EXPECTED: 0 advisories (guard rejects empty/falsy input before compile).
// ACTUAL: 1 advisory - "Unsanitized data from `req.body.t` reaches sink
//   `compile`" - identical to the typeof variant.
//
// Proves the FP is not about typeof syntax specifically: early-return
// validation that does not call a recognized sanitizer/predicate function
// leaves the taint set untouched. Together with mre05a this brackets the
// needed engine work: path-sensitive taint killing for dominance-based
// guards, OR teachability of local guard functions (isSafePath-style) so
// the BUNDLER can learn them (it currently cannot: the guard exists only
// in the negative, is proposed as a sanitizer candidate, and is then
// rejected because the family does not separate while sink:compile is a
// built-in that also fires on the negative - conjunction problem, L2).

import Handlebars from "handlebars";
import type { Request, Response } from "express";

export function previewTemplate(req: Request, res: Response): void {
    const t = req.body.t;

    if (!t) {
        res.status(400).send("template must be a string");
        return;
    }

    const fn = Handlebars.compile(t);
    res.send(fn({}));
}
