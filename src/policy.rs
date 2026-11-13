// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Reporting policy: which engine findings become advisories, which survive
//! the severity/confidence floor (ENGINE_PURITY_REFACTOR 1.3), and what the
//! report may claim the scan actually covered ([`Coverage`]).
//!
//! The engine emits verdicts; what becomes a *reported* advisory is
//! consumer policy. This module is the only place that answers
//!
//! 1. which engine findings become advisories ([`reports_finding`]),
//! 2. which advisories survive the severity/confidence floor ([`apply`]), and
//! 3. how much of the input the scan really inspected ([`Coverage`]).
//!
//! [`crate::reporter`] renders what survives; nothing else filters.
//! The `--explain` "why the engine stayed silent" map lives in
//! [`crate::explain`].

use crate::{Advisory, Profile, RuleTier, Severity};
use frensense_engine::analysis::taint::engine::{BackwardVerdict, FindingClass, SinkFinding};
use frensense_engine::scan::ScanResult;
use frensense_lang::rule_card;
use std::collections::{BTreeMap, BTreeSet};

/// Engine output that becomes an advisory: a vulnerable verdict on a
/// dangerous sink slot (sink-signature aware), whose sink names a
/// vulnerability class.
///
/// `alert` is `None` exactly when the slot is a safe channel - the engine
/// already evaluated per-slot danger (`jwt.verify(token, secret)` slot 1 =
/// secret, `query(sql, params)` slot 1+ = binding channel). A
/// [`BackwardVerdict::Vulnerable`] verdict on a non-dangerous slot must
/// not become an advisory.
///
/// The class comes from the rule card the finding reports under (see
/// [`frensense_lang::rule_card`]). A sink whose label is unknown and whose
/// role pins no class resolves to a fallback card ("untrusted data reaches
/// a sensitive operation"), which tells the reader only that tainted data
/// went somewhere: nothing to fix, suppress or trend. Those findings are
/// dropped here, so no surface (CLI, MCP, LSP, SARIF) reports them and
/// `--explain` lists the sink as silent instead.
#[must_use]
pub fn reports_finding(f: &SinkFinding) -> bool {
    if f.verdict != BackwardVerdict::Vulnerable || f.alert.is_none() {
        return false;
    }
    !rule_card::taint_card(
        f.label.as_deref(),
        f.role,
        matches!(f.finding_class, FindingClass::Idor),
    )
    .is_generic()
}

/// Apply the reporting floor: drop advisories below `min_confidence` or
/// under the severity floor (`None` = every tier; `Some(Severity::Info)`
/// is the no-op floor, so tool surfaces that default to `"info"` pass
/// everything through). Uses [`Profile::Default`].
#[must_use]
pub fn apply(
    advisories: Vec<Advisory>,
    min_confidence: f64,
    severity_floor: Option<Severity>,
) -> Vec<Advisory> {
    apply_with_profile(advisories, min_confidence, severity_floor, Profile::Default).0
}

/// Apply the reporting floor, active scan profile, and optional hygiene flag:
/// drop advisories below `min_confidence`, under `severity_floor`, or excluded
/// by `profile` (unless `enable_hygiene` is true and `a.tier == RuleTier::Hygiene`).
/// Returns the surviving advisories and the count of hidden findings by tier.
#[must_use]
pub fn apply_with_profile_and_hygiene(
    advisories: Vec<Advisory>,
    min_confidence: f64,
    severity_floor: Option<Severity>,
    profile: Profile,
    enable_hygiene: bool,
) -> (Vec<Advisory>, BTreeMap<RuleTier, usize>) {
    let (kept, hidden_by_tier, _, _) = apply_with_profile_and_hygiene_counted(
        advisories,
        min_confidence,
        severity_floor,
        profile,
        enable_hygiene,
    );
    (kept, hidden_by_tier)
}

/// Apply the reporting policy and also count findings dropped by confidence
/// and severity floors. A finding is assigned to the first gate that drops it.
#[must_use]
pub fn apply_with_profile_and_hygiene_counted(
    advisories: Vec<Advisory>,
    min_confidence: f64,
    severity_floor: Option<Severity>,
    profile: Profile,
    enable_hygiene: bool,
) -> (Vec<Advisory>, BTreeMap<RuleTier, usize>, usize, usize) {
    let mut kept = Vec::new();
    let mut hidden_by_tier = BTreeMap::new();
    let mut below_confidence = 0;
    let mut below_severity = 0;

    for a in advisories {
        let tier_allowed =
            profile.includes_tier(a.tier) || (enable_hygiene && a.tier == RuleTier::Hygiene);
        if !tier_allowed {
            *hidden_by_tier.entry(a.tier).or_insert(0) += 1;
            continue;
        }
        if a.confidence < min_confidence {
            below_confidence += 1;
            continue;
        }
        if !severity_floor.is_none_or(|floor| a.severity.meets_threshold(floor)) {
            below_severity += 1;
            continue;
        }
        kept.push(a);
    }

    (kept, hidden_by_tier, below_confidence, below_severity)
}

/// Apply the reporting floor and active scan profile: drop advisories below
/// `min_confidence`, under `severity_floor`, or excluded by `profile`.
/// Returns the surviving advisories and the count of hidden findings by tier.
#[must_use]
pub fn apply_with_profile(
    advisories: Vec<Advisory>,
    min_confidence: f64,
    severity_floor: Option<Severity>,
    profile: Profile,
) -> (Vec<Advisory>, BTreeMap<RuleTier, usize>) {
    apply_with_profile_and_hygiene(advisories, min_confidence, severity_floor, profile, false)
}

/// How many file names / unresolved sites a report keeps. Matches the
/// engine's telemetry sample cap (`telemetry::PARTIAL_SAMPLE`) so a
/// whole-tree scan cannot inflate the report envelope.
pub const COVERAGE_SAMPLE: usize = 25;

/// One sink argument the backward walk reached but could not decide.
///
/// A taint walk that meets a value it cannot resolve (dynamic dispatch,
/// reflection, an unmodeled callee) ends `Unknown` rather than `Clean`. The
/// engine has always counted those; this names them so "we could not decide"
/// stops looking like "there was nothing to decide".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnresolvedSite {
    /// Path exactly as the scan submitted it.
    pub file: String,
    /// 1-based line of the sink call (`0` when lowering recorded no span).
    pub line: u32,
    /// Sink name the engine recognized.
    pub sink: String,
}

/// What a scan *covered*, as distinct from what it *concluded*.
///
/// "No findings" has two meanings the report used to collapse into one word:
///
/// 1. the engine inspected the dangerous operations in this code and no
///    attacker source reached them, or
/// 2. the engine never looked at the code at all - a file in a language with
///    no spec, a file that failed to lower, or a file where nothing it models
///    as dangerous appeared.
///
/// The second is a statement about the engine, not about the code, and
/// printing "Clean" for it makes a clean scan unfalsifiable. Both are true at
/// once on a large corpus: on the OWASP Benchmark for Python, 622 of 1,230
/// files yield no recognized sink site.
///
/// Every count is derived from data the scan already produces (findings plus
/// `ScanTelemetry`), so this costs one pass over values the consumer already
/// receives and works on any language. No engine change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coverage {
    /// Source files the walk found: every supported file submitted for
    /// analysis plus every source file whose language has no engine spec.
    /// The denominator of "N of M files scanned".
    pub files_found: usize,
    /// Files successfully read, parsed, and lowered.
    pub files_analyzed: usize,
    /// Supported files that could not be read, parsed, or lowered.
    pub files_failed: usize,
    /// Source files dropped without analysis because the engine has no spec
    /// for their language.
    pub files_unsupported: usize,
    /// Distinct sink call sites the engine recognized (`file`, `line`, sink).
    /// Every verdict counts: a recognized site is one the engine reasoned
    /// about, whether or not it produced an advisory.
    pub sink_sites: usize,
    /// Analyzed files that yielded at least one recognized sink site.
    pub files_with_sink_sites: usize,
    /// Analyzed files that yielded none. For these, "no findings" describes
    /// the engine's vocabulary, not the code.
    pub files_without_sink_sites: usize,
    /// First [`COVERAGE_SAMPLE`] such files, sorted.
    pub no_sink_files: Vec<String>,
    /// Distinct sink sites whose walk ended `Unknown`.
    pub unresolved_sites: usize,
    /// First [`COVERAGE_SAMPLE`] unresolved sites, sorted by file/line/sink.
    pub unresolved_sample: Vec<UnresolvedSite>,
}

impl Coverage {
    /// Derive coverage from one scan's findings and input accounting.
    ///
    /// `considered` is the set of paths the runner submitted for lowering;
    /// it is only used to name files for the sample, never to count them
    /// (the scan's own `scanned` count is authoritative).
    /// `files_unsupported` is the number of source files the walk skipped
    /// because their language has no spec - the runner knows it from its
    /// collected-file list, the engine telemetry does not.
    #[must_use]
    pub fn from_scan(result: &ScanResult, considered: &[String], files_unsupported: usize) -> Self {
        let mut sites: BTreeSet<(&str, u32, &str)> = BTreeSet::new();
        let mut recognized: BTreeSet<&str> = BTreeSet::new();
        let mut unresolved: BTreeSet<UnresolvedSite> = BTreeSet::new();
        for located in &result.located {
            sites.insert((
                located.file.as_str(),
                located.line,
                located.finding.sink.as_str(),
            ));
            recognized.insert(located.file.as_str());
            if located.finding.verdict == BackwardVerdict::Unknown {
                unresolved.insert(UnresolvedSite {
                    file: located.file.clone(),
                    line: located.line,
                    sink: located.finding.sink.clone(),
                });
            }
        }
        // A non-dataflow checker finding (weak hash, insecure cookie) is also
        // recognition: the engine understood an operation in that file.
        for located in &result.located_checker {
            recognized.insert(located.file.as_str());
        }

        let input = &result.telemetry.input;
        let files_analyzed = input.scanned;
        let files_with_sink_sites = recognized.len();
        // A file that failed to lower is not evidence about the engine's
        // vocabulary, and it is already counted (and named) as a failure.
        let failed: BTreeSet<&str> = input.failed_files.iter().map(String::as_str).collect();
        let mut no_sink_files: Vec<String> = considered
            .iter()
            .filter(|path| !recognized.contains(path.as_str()))
            .filter(|path| !failed.contains(path.as_str()))
            .cloned()
            .collect();
        no_sink_files.sort();
        no_sink_files.dedup();
        no_sink_files.truncate(COVERAGE_SAMPLE);

        Coverage {
            files_found: input.submitted + files_unsupported,
            files_analyzed,
            files_failed: input.failed,
            files_unsupported,
            sink_sites: sites.len(),
            files_with_sink_sites,
            files_without_sink_sites: files_analyzed.saturating_sub(files_with_sink_sites),
            no_sink_files,
            unresolved_sites: unresolved.len(),
            unresolved_sample: unresolved.into_iter().take(COVERAGE_SAMPLE).collect(),
        }
    }

    /// Source files the scan found but did not analyze: unsupported languages
    /// plus read/parse/lower failures. The "M - N" in "N of M files scanned".
    #[must_use]
    pub fn files_not_analyzed(&self) -> usize {
        self.files_failed + self.files_unsupported
    }

    /// Fold one scan's coverage into a running total. Multi-path and
    /// `--diff-only` runs scan one file at a time, so their report is the
    /// union, not the last run's numbers.
    pub fn merge(&mut self, other: Coverage) {
        self.files_found += other.files_found;
        self.files_analyzed += other.files_analyzed;
        self.files_failed += other.files_failed;
        self.files_unsupported += other.files_unsupported;
        self.sink_sites += other.sink_sites;
        self.files_with_sink_sites += other.files_with_sink_sites;
        self.files_without_sink_sites += other.files_without_sink_sites;
        self.unresolved_sites += other.unresolved_sites;
        self.no_sink_files.extend(other.no_sink_files);
        self.no_sink_files.sort();
        self.no_sink_files.dedup();
        self.no_sink_files.truncate(COVERAGE_SAMPLE);
        self.unresolved_sample.extend(other.unresolved_sample);
        self.unresolved_sample.sort();
        self.unresolved_sample.dedup();
        self.unresolved_sample.truncate(COVERAGE_SAMPLE);
    }

    /// True when the scan recognized at least one sink site somewhere. A
    /// scan that recognized nothing has no basis to call anything clean.
    #[must_use]
    pub fn recognized_anything(&self) -> bool {
        self.files_with_sink_sites > 0
    }

    /// True when every sink site the scan recognized was decided.
    #[must_use]
    pub fn fully_resolved(&self) -> bool {
        self.unresolved_sites == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frensense_engine::analysis::forward::predicates::SinkAlert;
    use frensense_lang::severity::SinkRole;
    use std::path::Path;

    fn finding(
        label: Option<&str>,
        role: SinkRole,
        class: FindingClass,
        verdict: BackwardVerdict,
    ) -> SinkFinding {
        SinkFinding::builder()
            .function("handler")
            .sink("count")
            .verdict(verdict)
            .finding_class(class)
            .role(role)
            .label(label.map(str::to_string))
            .alert(Some(SinkAlert {
                sink: "count".to_string(),
                slot: 0,
                function: "handler".to_string(),
                class,
            }))
            .build()
    }

    #[test]
    fn unclassified_sink_class_is_not_reported() {
        // No label, no role that pins a class: the report would only say
        // "untrusted data reaches a sensitive operation".
        assert!(!reports_finding(&finding(
            None,
            SinkRole::Other,
            FindingClass::Injection,
            BackwardVerdict::Vulnerable,
        )));
        assert!(!reports_finding(&finding(
            Some("other"),
            SinkRole::Other,
            FindingClass::Injection,
            BackwardVerdict::Vulnerable,
        )));
        // Bare Execution spans command/SQL/code: generic "injection".
        assert!(!reports_finding(&finding(
            None,
            SinkRole::Execution,
            FindingClass::Injection,
            BackwardVerdict::Vulnerable,
        )));
    }

    #[test]
    fn classified_sinks_still_report() {
        for (label, role) in [
            (Some("ssrf"), SinkRole::Execution),
            (Some("traversal"), SinkRole::Resource),
            (None, SinkRole::Xss),
        ] {
            assert!(
                reports_finding(&finding(
                    label,
                    role,
                    FindingClass::Injection,
                    BackwardVerdict::Vulnerable,
                )),
                "{label:?}/{role:?} names a class and must report"
            );
        }
        // Idor is its own class (CWE-639) even without a sink label.
        assert!(reports_finding(&finding(
            None,
            SinkRole::Other,
            FindingClass::Idor,
            BackwardVerdict::Vulnerable,
        )));
    }

    #[test]
    fn verdict_and_alert_still_gate_first() {
        assert!(!reports_finding(&finding(
            Some("sql"),
            SinkRole::Execution,
            FindingClass::Injection,
            BackwardVerdict::Unknown,
        )));
    }

    fn mock_advisory(tier: RuleTier, severity: Severity) -> Advisory {
        Advisory::bare(
            "test_finding",
            severity,
            crate::FileId(1),
            Path::new("test.py"),
            "test observation",
        )
        .with_tier(tier)
        .with_confidence(1.0)
    }

    #[test]
    fn default_profile_hides_hygiene_and_tracks_count() {
        let advisories = vec![
            mock_advisory(RuleTier::Stable, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
        ];

        let (reported, hidden) = apply_with_profile(advisories, 0.0, None, Profile::Default);
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].tier, RuleTier::Stable);
        assert_eq!(hidden.get(&RuleTier::Hygiene), Some(&2));
        assert_eq!(hidden.get(&RuleTier::Stable), None);
    }

    #[test]
    fn strict_profile_includes_hygiene() {
        let advisories = vec![
            mock_advisory(RuleTier::Stable, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
        ];

        let (reported, hidden) = apply_with_profile(advisories, 0.0, None, Profile::Strict);
        assert_eq!(reported.len(), 2);
        assert!(hidden.is_empty());
    }

    #[test]
    fn recommended_profile_includes_beta_only() {
        let advisories = vec![
            mock_advisory(RuleTier::Stable, Severity::Warning),
            mock_advisory(RuleTier::Beta, Severity::Warning),
            mock_advisory(RuleTier::Experimental, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
        ];

        let (reported, hidden) = apply_with_profile(advisories, 0.0, None, Profile::Recommended);
        assert_eq!(reported.len(), 2);
        assert_eq!(hidden.get(&RuleTier::Experimental), Some(&1));
        assert_eq!(hidden.get(&RuleTier::Hygiene), Some(&1));
    }

    #[test]
    fn hygiene_flag_enables_hygiene_without_experimental() {
        let advisories = vec![
            mock_advisory(RuleTier::Stable, Severity::Warning),
            mock_advisory(RuleTier::Beta, Severity::Warning),
            mock_advisory(RuleTier::Experimental, Severity::Warning),
            mock_advisory(RuleTier::Hygiene, Severity::Warning),
        ];

        let (reported, hidden) =
            apply_with_profile_and_hygiene(advisories, 0.0, None, Profile::Default, true);
        assert_eq!(reported.len(), 2);
        assert_eq!(reported[0].tier, RuleTier::Stable);
        assert_eq!(reported[1].tier, RuleTier::Hygiene);
        assert_eq!(hidden.get(&RuleTier::Beta), Some(&1));
        assert_eq!(hidden.get(&RuleTier::Experimental), Some(&1));
        assert_eq!(hidden.get(&RuleTier::Hygiene), None);
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

    /// Scan a throwaway directory through the real `Engine`, so the fixture
    /// exercises the same fact tables the product does.
    fn coverage_for(files: &[(&str, &str)]) -> Coverage {
        let n = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("frensense-coverage-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        for (name, source) in files {
            std::fs::write(dir.join(name), source).expect("write fixture");
        }
        let mut engine = crate::Engine::new();
        engine.run(&dir).expect("scan");
        let coverage = engine.take_coverage();
        let _ = std::fs::remove_dir_all(&dir);
        coverage
    }

    const SINK: &str = "from flask import request\nimport os\n\n\ndef handler():\n    os.system(request.args.get(\"cmd\"))\n";

    #[test]
    fn a_file_with_a_sink_is_recognized() {
        let coverage = coverage_for(&[("sink.py", SINK)]);
        assert!(coverage.recognized_anything(), "{coverage:?}");
        assert_eq!(coverage.files_found, 1);
        assert_eq!(coverage.files_analyzed, 1);
        assert_eq!(coverage.files_with_sink_sites, 1);
        assert_eq!(coverage.files_without_sink_sites, 0);
        assert!(coverage.no_sink_files.is_empty());
        assert!(coverage.sink_sites >= 1);
    }

    #[test]
    fn a_file_without_a_sink_is_named_as_unrecognized() {
        let coverage = coverage_for(&[
            ("sink.py", SINK),
            ("models.py", "class User:\n    name: str = \"\"\n"),
        ]);
        assert_eq!(coverage.files_found, 2);
        assert_eq!(coverage.files_analyzed, 2);
        assert_eq!(coverage.files_with_sink_sites, 1);
        assert_eq!(coverage.files_without_sink_sites, 1);
        assert!(
            coverage
                .no_sink_files
                .iter()
                .all(|p| p.ends_with("models.py")),
            "{coverage:?}"
        );
    }

    #[test]
    fn a_sanitized_sink_still_counts_as_recognized() {
        // Recognition is not detection: the engine inspected this sink and
        // decided no attacker source reaches it. That is a conclusion, and
        // the file must not be reported as blind.
        let coverage = coverage_for(&[(
            "sanitized.py",
            "import os\n\n\ndef handler():\n    os.system(\"echo hi\")\n",
        )]);
        assert!(coverage.recognized_anything(), "{coverage:?}");
        assert_eq!(coverage.files_without_sink_sites, 0);
    }

    #[test]
    fn an_unsupported_language_is_counted_but_not_scanned() {
        // The denominator: a 1-of-2 scan must not report itself as 1/1.
        let coverage = coverage_for(&[("sink.py", SINK), ("worker.rb", "puts 'hello'\n")]);
        assert_eq!(coverage.files_found, 2, "{coverage:?}");
        assert_eq!(coverage.files_analyzed, 1);
        assert_eq!(coverage.files_unsupported, 1);
        assert_eq!(coverage.files_not_analyzed(), 1);
    }

    #[test]
    fn merge_unions_samples_and_sums_counts() {
        let mut a = Coverage {
            files_found: 1,
            files_analyzed: 1,
            files_with_sink_sites: 1,
            sink_sites: 2,
            ..Coverage::default()
        };
        let b = Coverage {
            files_found: 2,
            files_analyzed: 1,
            files_failed: 1,
            files_without_sink_sites: 1,
            no_sink_files: vec!["b.py".into()],
            unresolved_sites: 1,
            unresolved_sample: vec![UnresolvedSite {
                file: "b.py".into(),
                line: 3,
                sink: "eval".into(),
            }],
            ..Coverage::default()
        };
        a.merge(b);
        assert_eq!(a.files_found, 3);
        assert_eq!(a.files_analyzed, 2);
        assert_eq!(a.files_not_analyzed(), 1);
        assert_eq!(a.sink_sites, 2);
        assert_eq!(a.files_without_sink_sites, 1);
        assert_eq!(a.no_sink_files, vec!["b.py".to_string()]);
        assert!(!a.fully_resolved());
    }
}
