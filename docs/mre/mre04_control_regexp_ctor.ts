// MRE-04c - control: direct regex compilation from user input.
// NOT a bundler family (no _positive/_negative suffix).
//
// EXPECTED (corpus contract for a ReDoS-capable engine):
//   >= 1 advisory, identity token "regex".
// ACTUAL: 0 advisories - no sink, no role, no label for regex
//   compilation exists in frensense-lang or frensense-engine.
//
// Note `new Function(...)` with the same flow DOES fire (sink `Function`,
// tags ["taint","execution"]) - the engine has a code-compilation sink but
// no regex-compilation sink. This is the smallest possible repro of the
// detection gap behind the corpus family ts_cve_2025_69873_ajv_data_redos.

export function search(req: any, res: any) {
    const re = new RegExp(String(req.body.pattern), "u");
    res.json({ ok: re.test(String(req.body.value)) });
}
