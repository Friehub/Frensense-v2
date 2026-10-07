// MRE-03c - control: _.set IS a declared PrototypePollution sink.
// NOT a bundler family (no _positive/_negative suffix).
//
// EXPECTED (corpus contract): >= 1 advisory, identity token "prototype".
// ACTUAL: 1 advisory - tags ["taint","execution"],
//   title "Unsanitized data from `req.body.field` reaches sink `set`".
//   Identity check fails: no "prototype" substring in tags or title.
//
// Isolates defect 2 of MRE-03: detection exists, identity does not.
// SinkLabel::PrototypePollution is mapped to SinkRole::Execution in
// role.rs from_label() and the label itself never reaches the advisory.

import _ from "lodash";
import type { Request } from "express";

export function setPath(req: Request, obj: Record<string, unknown>) {
    _.set(obj, String(req.body.field), "x");
    return obj;
}
