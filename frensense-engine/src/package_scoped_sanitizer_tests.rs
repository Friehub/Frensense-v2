// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Package-scoped sanitizer facts: a sanitizer installed under a package
//! (`@acme/sanitize`) must only cut taint when the caller's import origin
//! resolves to that package.
//!
//! Scoping a sanitizer is the **mirror image** of scoping a sink, and the
//! asymmetry is the whole point:
//!
//! * A sink that fires when it should not is a false positive — annoying
//!   but visible.
//! * A sanitizer that cuts when it should not **silences a true finding** —
//!   a false negative, the failure mode a scanner exists to prevent.
//!
//! So the fallback on unknown origin is *recall-safe*: a scoped sanitizer
//! stays inert unless import resolution positively confirms its package. A
//! genuine package sanitizer whose origin does not resolve surfaces an
//! advisory (a precision cost), it never quietly drops a real one (a
//! recall cost). Universal (unpackage-qualified) sanitizers are unaffected —
//! they were proven against the bare name and keep cutting everywhere.
//!
//! Triplets:
//! 1. import origin matches the package — the scoped sanitizer cuts
//!    (Sanitized verdict, no alert). Scoping must not break the legitimate
//!    shape.
//! 2. no import, unrelated receiver object (`helper.scrub(...)`) — inert,
//!    taint flows on to the sink (Vulnerable). The false-negative class
//!    package scoping exists to close.
//! 3. wrong-package import (`some-other-package` lookalike) — inert, the
//!    origin mismatch must not inherit another package's sanitizer.
//!
//! Plus the recall-safety fallback:
//! 4. a universal sanitizer keeps cutting with no origin at all — the
//!    fallback must not cost universal recall.

#[cfg(test)]
#[allow(clippy::module_inception)] // test file convention: module name repeats parent path segment
pub mod package_scoped_sanitizer_tests {
    use crate::analysis::taint::config::TaintConfig;
    use crate::analysis::taint::engine::BackwardVerdict;
    use crate::analysis::taint::facts::{
        FactTable, LearnedFactEntry, apply_language_entries, languages_for_exts, seeded_tables,
    };
    use crate::scan::{prepare, scan_prepared};

    /// The package the scoped sanitizer is installed under.
    const PKG: &str = "@acme/sanitize";

    /// Production tables for the TS spec, plus one package-scoped sanitizer
    /// (`scrub` from `@acme/sanitize`) installed exactly the way a `.frc`
    /// bundle installs it (language-keyed `LanguageSanitizer` entry with a
    /// `package`). This exercises the real install path, not a hand-built
    /// table, so the fixture cannot drift from production wiring.
    fn tables() -> (TaintConfig, FactTable) {
        let (mut config, mut facts) = seeded_tables(["ts"]);
        let entry = LearnedFactEntry::LanguageSanitizer {
            language: "*".to_string(),
            call: "scrub".to_string(),
            package: Some(PKG.to_string()),
            kind: "full".to_string(),
            guard_style: false,
        };
        let langs = languages_for_exts(["ts"]);
        apply_language_entries(&mut config, &mut facts, &[entry], &langs);
        (config, facts)
    }

    fn run(src: &str) -> Vec<crate::analysis::taint::engine::SinkFinding> {
        let files = vec![("test.ts".to_string(), src.to_string(), "ts".to_string())];
        let (config, facts) = tables();
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts).findings
    }

    /// The `exec(...)` finding (the sink every fixture drives taint into).
    fn exec_finding(
        findings: &[crate::analysis::taint::engine::SinkFinding],
    ) -> Option<&crate::analysis::taint::engine::SinkFinding> {
        findings.iter().find(|f| f.sink == "exec")
    }

    /// Legitimate shape: `@acme/sanitize` imported, `scrub` applied to the
    /// source, the result fed to the sink. The scoped sanitizer must cut —
    /// Sanitized verdict, no alert.
    const MATCHING_ORIGIN: &str = r#"
import { scrub } from '@acme/sanitize'
export async function bad(req: any, res: any) {
  const safe = scrub(req.body.name)
  exec(safe)
}
"#;

    /// Same method name, but the receiver is an unrelated local object and
    /// no `@acme/sanitize` import exists. The scoped sanitizer must stay
    /// inert: taint flows on to the sink and the finding fires.
    const UNRELATED_RECEIVER: &str = r#"
declare const helper: any
export async function bad(req: any, res: any) {
  const safe = helper.scrub(req.body.name)
  exec(safe)
}
"#;

    /// An import from a DIFFERENT package with the same local name. The
    /// origin mismatch must not inherit `@acme/sanitize`'s sanitizer: the
    /// finding fires.
    const WRONG_PACKAGE: &str = r#"
import { scrub } from 'some-other-package'
export async function bad(req: any, res: any) {
  const safe = scrub(req.body.name)
  exec(safe)
}
"#;

    /// Production tables with `scrub` installed as a UNIVERSAL sanitizer
    /// (no package). The recall-safe fallback must keep universal facts
    /// cutting with no origin at all — scoping a package fact must not
    /// cost universal recall.
    fn universal_tables() -> (TaintConfig, FactTable) {
        let (mut config, mut facts) = seeded_tables(["ts"]);
        let entry = LearnedFactEntry::LanguageSanitizer {
            language: "*".to_string(),
            call: "scrub".to_string(),
            package: None,
            kind: "full".to_string(),
            guard_style: false,
        };
        let langs = languages_for_exts(["ts"]);
        apply_language_entries(&mut config, &mut facts, &[entry], &langs);
        (config, facts)
    }

    #[test]
    fn scoped_sanitizer_cuts_with_matching_import_origin() {
        let findings = run(MATCHING_ORIGIN);
        let f = exec_finding(&findings).expect("exec sink must be reached");
        assert_eq!(
            f.verdict,
            BackwardVerdict::Sanitized,
            "matching origin must let the scoped sanitizer cut; got {findings:?}"
        );
        assert!(
            f.alert.is_none(),
            "a sanitized flow must not alert; got {findings:?}"
        );
        assert!(
            f.cut_reasons.contains(&"sanitizer"),
            "the cut must be attributed to the sanitizer; got {:?}",
            f.cut_reasons
        );
    }

    #[test]
    fn scoped_sanitizer_is_inert_on_unrelated_receiver() {
        let findings = run(UNRELATED_RECEIVER);
        let f = exec_finding(&findings).expect("exec sink must be reached");
        assert_eq!(
            f.verdict,
            BackwardVerdict::Vulnerable,
            "an unrelated receiver's same-named method must NOT sanitize (that would \\
             silence a true finding); got {findings:?}"
        );
        assert!(
            !f.cut_reasons.contains(&"sanitizer"),
            "no sanitizer cut may fire without a confirmed origin; got {:?}",
            f.cut_reasons
        );
    }

    #[test]
    fn scoped_sanitizer_is_inert_on_wrong_package_origin() {
        let findings = run(WRONG_PACKAGE);
        let f = exec_finding(&findings).expect("exec sink must be reached");
        assert_eq!(
            f.verdict,
            BackwardVerdict::Vulnerable,
            "an origin from a different package must not inherit the scoped sanitizer \\
             (that would silence a true finding); got {findings:?}"
        );
        assert!(
            !f.cut_reasons.contains(&"sanitizer"),
            "no sanitizer cut may fire on an origin mismatch; got {:?}",
            f.cut_reasons
        );
    }

    #[test]
    fn universal_sanitizer_still_cuts_with_no_origin() {
        // The exact source that stays Vulnerable under the SCOPED table
        // (no import, unrelated receiver) — under a UNIVERSAL table the
        // identical call name cuts. This isolates the package
        // qualification as the only difference, and proves the
        // unknown-origin fallback keeps universal sanitizers live.
        let files = vec![(
            "test.ts".to_string(),
            UNRELATED_RECEIVER.to_string(),
            "ts".to_string(),
        )];
        let (config, facts) = universal_tables();
        let prepared = prepare(&files).expect("prepare");
        let findings = scan_prepared(&prepared, &config, &facts).findings;
        let f = exec_finding(&findings).expect("exec sink must be reached");
        assert_eq!(
            f.verdict,
            BackwardVerdict::Sanitized,
            "a universal sanitizer must keep cutting regardless of origin (the \\
             recall-safe fallback); got {findings:?}"
        );
        assert!(
            f.cut_reasons.contains(&"sanitizer"),
            "the universal cut must be attributed to the sanitizer; got {:?}",
            f.cut_reasons
        );
    }
}
