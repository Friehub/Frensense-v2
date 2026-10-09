// MRE-03a - prototype pollution via lodash path APIs that are NOT sinks.
// Shape of CVE-2025-13465 (lodash 4.0.0-4.17.22, fixed 4.18.0): a
// request-controlled path string passed to _.unset/_.omit resolves through
// Object.prototype and mutates/poisons the prototype.
//
// EXPECTED (corpus contract): >= 1 advisory, identity token "prototype".
// ACTUAL   (release binary, 2026-10-03): 0 advisories.
//
// Root cause (layered):
//  1. Lang sink table declares PrototypePollution for set/merge/extend/
//     assign/defaults/deepExtend/mixin/cloneDeep/setPrototypeOf/_.set/
//     $.extend/... (frensense-lang/src/providers/javascript/tables.rs:91-98,
//     :223-231) - `unset` is declared NOWHERE, and `omit` is declared as a
//     PROPAGATOR (javascript/propagators.rs:398), i.e. the engine treats
//     omit() as taint-preserving, not as a path-mutation sink.
//  2. Even _.set (which IS a sink, see mre03_control_underscore_set.ts)
//     reports tags ["taint","execution"] + "reaches sink `set`" - no
//     "prototype" token anywhere. SinkLabel::PrototypePollution ->
//     SinkRole::Execution (role.rs:66) and the label is dropped.
//
// Bundler learn trace (FXREPORT): the delta DOES propose `sink:unset` and
// `sink:omit`, but both are rejected - "no voting family separates under
// this fact (positive_alerts=true, negative_alerts=true)". With sink:unset
// applied, the NEGATIVE also alerts, because its guard is a hand-rolled
// isSafePath()/Set.has() validator the engine does not recognize as a
// sanitizer, and the gate trials candidates ONE AT A TIME (bundler/src/
// extract/mod.rs:274 trial = f_builtin.clone() + ONE candidate): the pair
// {sink:unset, sanitizer:isSafePath} would separate, but neither half does
// alone, and the gate never tries conjunctions. See README.md L2.

import unset from "lodash/unset";
import omit from "lodash/omit";
import type { Request } from "express";

export function updatePreferences(req: Request, profile: Record<string, unknown>) {
    const field = String(req.body.field);
    const drop = String(req.body.drop);

    unset(profile, field); // `__proto__.toString` walks onto the prototype
    const visible = omit(profile, drop);

    return { profile, visible };
}
