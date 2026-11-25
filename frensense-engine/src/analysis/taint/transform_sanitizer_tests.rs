// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Transform (non-guard) sanitizer facts and their argument slots.
//!
//! A transform sanitizer's cut used to be its whole result node, so the call
//! read as neutralising everything it was handed and `sanitizes_args` had
//! nothing to say. Declared slots move the cut onto the incoming argument
//! edges: the call neutralises the values that enter through the slots it
//! names, and taint arriving through any other argument still reaches the
//! sink. An empty set keeps the legacy result-node cut.

#[cfg(test)]
pub(crate) mod tests {
    use crate::analysis::taint::config::TaintConfig;
    use crate::analysis::taint::engine::BackwardVerdict;
    use crate::analysis::taint::facts::{FactTable, SanitizerFact, seeded_tables};
    use crate::scan::{prepare, scan_prepared};

    /// The tainted value is the call's argument 0.
    const TAINT_IN_SLOT_0: &str = r#"
export async function bad(req: any, res: any) {
  const name = req.body.name
  const safe = escape(name, 'json')
  exec(safe)
}
"#;

    /// The same call shape with the tainted value in argument 1.
    const TAINT_IN_SLOT_1: &str = r#"
export async function bad(req: any, res: any) {
  const name = req.body.name
  const safe = escape('json', name)
  exec(safe)
}
"#;

    /// Production tables plus a transform `escape` fact whose slots are exactly
    /// `slots` (installed the way an embedder installs one).
    fn tables(slots: &[usize]) -> (TaintConfig, FactTable) {
        let (config, mut facts) = seeded_tables(["ts"]);
        facts.sanitizer_facts.insert(
            "escape".to_string(),
            SanitizerFact {
                call: "escape".to_string(),
                package: None,
                kind: "full".to_string(),
                sanitizes_args: slots.iter().copied().collect(),
                guard_style: false,
            },
        );
        (config, facts)
    }

    fn exec_finding(src: &str, slots: &[usize]) -> crate::analysis::taint::engine::SinkFinding {
        let files = vec![("test.ts".to_string(), src.to_string(), "ts".to_string())];
        let (config, facts) = tables(slots);
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts)
            .findings
            .into_iter()
            .find(|f| f.sink == "exec")
            .expect("exec sink must be reached")
    }

    /// The declared slot is the value the call neutralises: taint that entered
    /// there is cut, so the sink stays clean.
    #[test]
    fn a_declared_slot_cuts_the_value_that_entered_through_it() {
        let f = exec_finding(TAINT_IN_SLOT_0, &[0]);
        assert_eq!(
            f.verdict,
            BackwardVerdict::Sanitized,
            "the tainted value entered through the declared slot; got {f:?}"
        );
    }

    /// The recall-safe half: taint arriving through an argument the fact does
    /// not name is untouched by the call, so the finding stays live. Under the
    /// legacy reading this same program was silenced.
    #[test]
    fn an_unlisted_argument_still_reaches_the_sink() {
        let f = exec_finding(TAINT_IN_SLOT_1, &[0]);
        assert_eq!(
            f.verdict,
            BackwardVerdict::Vulnerable,
            "the tainted value did not enter through a declared slot; got {f:?}"
        );
        assert!(f.alert.is_some(), "an unvalidated argument must alert");
    }

    /// The set is honoured by membership, not merely by being non-empty:
    /// declaring slot 1 flips both fixtures.
    #[test]
    fn the_declared_slot_is_matched_not_assumed() {
        assert_eq!(
            exec_finding(TAINT_IN_SLOT_1, &[1]).verdict,
            BackwardVerdict::Sanitized
        );
        assert_eq!(
            exec_finding(TAINT_IN_SLOT_0, &[1]).verdict,
            BackwardVerdict::Vulnerable
        );
    }

    /// An empty set keeps the documented legacy reading: the call neutralises
    /// its result whatever it was handed, so both fixtures are clean.
    #[test]
    fn a_transform_fact_without_slots_keeps_the_result_cut() {
        for src in [TAINT_IN_SLOT_0, TAINT_IN_SLOT_1] {
            let f = exec_finding(src, &[]);
            assert_eq!(
                f.verdict,
                BackwardVerdict::Sanitized,
                "an empty `sanitizes_args` means every argument; got {f:?}"
            );
        }
    }
}
