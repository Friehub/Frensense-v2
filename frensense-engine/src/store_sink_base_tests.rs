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
    fn unhinted_signature_keeps_the_legacy_bare_name_match() {
        let findings = run(ROW_WRITE, None);
        assert!(
            writes(&findings) > 0,
            "without a hint the field name alone still arms the sink; got {findings:?}"
        );
    }
}
