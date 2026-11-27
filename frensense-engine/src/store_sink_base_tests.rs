// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Store sinks honour their base-kind hint: a property write fires only when
//! the receiver was produced by a call the fact names (`querySelector`,
//! `createElement`, ...), never because the field happens to be spelled
//! `innerHTML`. The second case below is the reported false positive class.
//! The hint reaches the installed signature through the bundle payload's
//! `sink_base_kinds` table, joined by `FactTable::qualify_sink_base_kinds`.

#[cfg(test)]
pub(crate) mod tests {
    use crate::analysis::taint::engine::SinkFinding;
    use crate::analysis::taint::facts::{SinkSignature, seeded_tables};
    use crate::scan::{prepare, scan_prepared};

    /// The DOM write: the base comes from `querySelector`, so the hint matches.
    const DOM_WRITE: &str = r#"
export function render(host: HTMLElement, q: string) {
  const el = host.querySelector('.out')
  el.innerHTML = q
}
"#;

    /// Same field, unrelated object: the base comes from `load`, which no
    /// base-kind names. A bare-name sink would fire here; the hint stops it.
    const ROW_WRITE: &str = r#"
export function render(row: any, q: string) {
  const el = row.load()
  el.innerHTML = q
}
"#;

    fn run(src: &str, hint: Option<&[&str]>) -> Vec<SinkFinding> {
        let files = vec![("test.ts".to_string(), src.to_string(), "ts".to_string())];
        let (config, mut facts) = seeded_tables(["ts"]);
        // Install the bare signature where a pack's language table lands, then
        // join the hint exactly as the runner joins a payload table.
        facts
            .lang_sink_signatures
            .entry("typescript".to_string())
            .or_default()
            .insert(
                "innerHTML".to_string(),
                SinkSignature::with_args("innerHTML", &[0]),
            );
        if let Some(kinds) = hint {
            let kinds: Vec<String> = kinds.iter().map(|k| (*k).to_string()).collect();
            assert!(
                facts.qualify_sink_base_kinds("innerHTML", None, &kinds),
                "the hint must reach the installed language signature"
            );
        }
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts).findings
    }

    /// A JSX attribute write. The props object is synthesized by lowering, so
    /// its base is the type lowering gives it, not a call.
    const JSX_WRITE: &str = r#"
export function render(req: any) {
  const q = req.query.q
  return <div dangerouslySetInnerHTML={{ __html: q }} />
}
"#;

    /// Same attribute name on an unrelated object: not a React write.
    const JSX_NAME_LOOKALIKE: &str = r#"
export function fill(row: any, q: string) {
  const el = row.load()
  el.dangerouslySetInnerHTML = q
}
"#;

    fn jsx_findings(src: &str, hint: Option<&[&str]>) -> Vec<SinkFinding> {
        let files = vec![("test.tsx".to_string(), src.to_string(), "tsx".to_string())];
        let (config, mut facts) = seeded_tables(["tsx"]);
        let signature = SinkSignature::with_args("dangerouslySetInnerHTML", &[0]);
        for language in crate::analysis::taint::facts::languages_for_exts(["tsx"]) {
            facts
                .lang_sink_signatures
                .entry(language.to_string())
                .or_default()
                .insert("dangerouslySetInnerHTML".to_string(), signature.clone());
        }
        if let Some(kinds) = hint {
            let kinds: Vec<String> = kinds.iter().map(|k| (*k).to_string()).collect();
            assert!(
                facts.qualify_sink_base_kinds("dangerouslySetInnerHTML", None, &kinds),
                "the hint must reach the installed language signature"
            );
        }
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts).findings
    }

    fn writes(findings: &[SinkFinding]) -> usize {
        findings.iter().filter(|f| f.sink == "innerHTML").count()
    }

    #[test]
    fn store_sink_fires_on_a_matching_base() {
        let findings = run(DOM_WRITE, Some(&["querySelector"]));
        assert!(
            writes(&findings) > 0,
            "an innerHTML write on a querySelector base must fire; got {findings:?}"
        );
    }

    #[test]
    fn store_sink_is_silent_on_a_bare_field_name_match() {
        let findings = run(ROW_WRITE, Some(&["querySelector"]));
        assert_eq!(
            writes(&findings),
            0,
            "innerHTML on an unrelated receiver must stay silent; got {findings:?}"
        );
    }

    #[test]
    fn jsx_attribute_fires_when_the_base_is_a_jsx_props_object() {
        let findings = jsx_findings(JSX_WRITE, Some(&[crate::ir::JSX_PROPS_BASE_KIND]));
        assert!(
            findings.iter().any(|f| f.sink == "dangerouslySetInnerHTML"),
            "a JSX attribute write must still fire; got {findings:?}"
        );
    }

    #[test]
    fn jsx_attribute_name_on_a_plain_object_stays_silent() {
        let findings = jsx_findings(JSX_NAME_LOOKALIKE, Some(&[crate::ir::JSX_PROPS_BASE_KIND]));
        assert!(
            !findings.iter().any(|f| f.sink == "dangerouslySetInnerHTML"),
            "a lookalike property on a non-JSX object must stay silent; got {findings:?}"
        );
    }

    #[test]
    fn unhinted_signature_keeps_the_legacy_bare_name_match() {
        let findings = run(ROW_WRITE, None);
        assert!(
            writes(&findings) > 0,
            "without a hint the field name alone still arms the sink; got {findings:?}"
        );
    }
}
