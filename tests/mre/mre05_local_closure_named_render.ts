// MRE-05c - name-collision false positive (part 2 of the handlebars
// negative failure).
//
// EXPECTED: 0 advisories - `render` here is a LOCAL const (the result of
//   Handlebars.compile(template) / any local closure), not the framework
//   res.render/view-render sink.
// ACTUAL: 1 advisory when the local is named `render`:
//   "Unsanitized data from `req.body.name` reaches sink `render`".
//   Rename the local to `fn` -> 0 advisories (same AST shape otherwise).
//
// Root cause: sink matching is by bare last-segment name
// (FactTable::is_sink_call -> sink_signatures.contains_key("render"),
// frensense-engine/src/analysis/taint/facts/signatures.rs:120) and the
// renderer's slot convention ("render", &[0]) flags slot 0. A call through
// a local variable that HAPPENS to be named `render` is indistinguishable
// from `res.render(view, locals)` without value-origin tracking: the engine
// knows the callee name but not that the callee is a local binding.
//
// This is what keeps the corpus family ts_cve_2026_33937_handlebars_ast
// negative at 2 findings; renaming alone drops it to 1 (the compile FP from
// mre05a remains).

import Handlebars from "handlebars";
import type { Request, Response } from "express";

export function previewTemplate(req: Request, res: Response): void {
    const template = req.body.template;
    const render = Handlebars.compile(template);
    res.send(render({ user: req.body.name }));
}
