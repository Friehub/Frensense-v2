// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! The scan runner: collect files → `data_flow::scan` → advisories.
//!
//! This is the whole consumer pipeline. Advisory text renders from the
//! lang rule registry or, for flows, from the flow itself (source access
//! path, sink name, exact sink line/column); fact-authored prose wins over
//! both, and a bundle pattern whose `rules` match the finding overlays
//! severity, impact, and tags (plus observation on the checker path).

use super::Engine;
use crate::engine::files::collect_files;
use crate::{Advisory, Result};
use std::path::Path;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{
    FactTable, fact_table_from_entries, tables_from_exts,
};
use frensense_engine::scan;
use frensense_engine::scan::LocatedFinding;

impl Engine {
    /// Scan a directory tree or a single file. Returns advisories.
    ///
    /// # Errors
    /// Returns an error if the path does not exist or a bundle cannot be
    /// loaded.
    pub fn run(&mut self, root: &Path) -> Result<Vec<Advisory>> {
        let paths = collect_files(root, self.language_filter.as_ref());

        // Read all scannable sources.
        let mut files: Vec<(String, String, String)> = Vec::new();
        let mut id_by_path: rustc_hash::FxHashMap<String, usize> = rustc_hash::FxHashMap::default();
        for (seq, p) in paths.iter().enumerate() {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_lowercase)
                .unwrap_or_default();
            if frensense_lang::spec_for_ext(&ext).is_none() {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(p) else {
                continue;
            };
            id_by_path.insert(p.to_string_lossy().into_owned(), seq);
            files.push((p.to_string_lossy().into_owned(), content, ext));
        }

        // Built-in config + fact table from the language specs present.
        let (mut config, mut facts) = build_spec_tables(&files);

        // Merge learned facts from the .frc bundle, if any, and index the
        // bundle's per-family advisory patterns by the finding identities
        // they apply to (`BundlePattern::rules`) for the advisory path.
        let mut bundle_advisories: rustc_hash::FxHashMap<
            String,
            frensense_bundler::format::BundlePattern,
        > = rustc_hash::FxHashMap::default();
        if let Some(bundle_bytes) = self.load_bundle_bytes(root)? {
            match frensense_bundler::format::load_bundle(bundle_bytes) {
                Ok(loaded) => {
                    facts.merge(&fact_table_from_entries(&loaded.learned_facts));
                    for pattern in &loaded.patterns {
                        for rule in &pattern.rules {
                            bundle_advisories
                                .entry(rule.clone())
                                .or_insert_with(|| pattern.clone());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to load corpus bundle: {e}");
                }
            }
        }

        // Bundle-learned source patterns widen the taint config: the bundle
        // teaches new framework sources without touching the built-in tables.
        for pattern in facts.source_patterns() {
            config.sources.insert(pattern.to_string());
        }

        let result = scan::scan(&files, &config, &facts);
        for err in &result.errors {
            tracing::warn!("scan error: {err}");
        }

        let mut advisories = Vec::new();
        // Non-dataflow policy findings (weak crypto, insecure config):
        // these are assertions about API/constant choices, no taint path
        // exists, so they bypass the flow machinery entirely.
        for lc in &result.located_checker {
            let (c, path, line, col) = (&lc.finding, &lc.file, lc.line, lc.column);
            let Some(&seq) = id_by_path.get(path) else {
                continue;
            };
            advisories.push(
                advisory_from_checker(
                    c,
                    path,
                    line,
                    col,
                    crate::engine::project::Engine::next_file_id(seq),
                    &bundle_advisories,
                )
                .with_end_line(lc.end_line),
            );
        }
        // Dedup gate, two layers:
        //
        // 1. Exact gate, the same (file, line, sink, source) emitted for
        //    several sink arguments collapses to one finding.
        // 2. Shape gate, SSA variants of one flow (same path shape: same
        //    functions, same hops, same field names, different SSA numbering)
        //    collapse to the variant with the most steps (the richest
        //    path). Grouping includes the sink location so the same helper
        //    called from two different sites still reports both.
        let mut exact: std::collections::HashSet<(String, u32, String, String)> =
            std::collections::HashSet::new();
        let mut candidates: Vec<&_> = Vec::new();
        for loc in &result.located {
            let f = &loc.finding;
            if !crate::reporting::reports_finding(f) {
                continue;
            }
            let key = (
                loc.file.clone(),
                loc.line,
                f.sink.clone(),
                f.source_desc.clone().unwrap_or_default(),
            );
            if !exact.insert(key) {
                continue;
            }
            candidates.push(loc);
        }
        // Shape gate: keep the richest path per (shape, sink location).
        let kept = dedup_keep_richest(&candidates);
        for i in kept {
            let loc = candidates[i];
            let Some(&seq) = id_by_path.get(&loc.file) else {
                continue;
            };
            advisories.push(advisory_from_finding(
                &loc.finding,
                &loc.file,
                loc.line,
                loc.column,
                crate::engine::project::Engine::next_file_id(seq),
                &bundle_advisories,
            ));
        }

        Ok(crate::reporting::apply(
            advisories,
            self.min_confidence,
            self.severity_filter,
        ))
    }

    fn load_bundle_bytes(&self, root: &Path) -> Result<Option<&'static [u8]>> {
        if let Some(static_bytes) = self.corpus_bundle {
            return Ok(Some(static_bytes));
        }
        if let Some(ref path) = self.corpus_bundle_path {
            let bytes = std::fs::read(path).map_err(crate::FrensenseError::Io)?;
            let leaked: &'static [u8] = Box::leak(bytes.into_boxed_slice());
            return Ok(Some(leaked));
        }
        let default_path = root.join("frensense-corpus.frc");
        if default_path.exists() {
            let bytes = std::fs::read(&default_path).map_err(crate::FrensenseError::Io)?;
            let leaked: &'static [u8] = Box::leak(bytes.into_boxed_slice());
            return Ok(Some(leaked));
        }
        Ok(None)
    }
}

/// Build the merged `TaintConfig` and `FactTable` from the language specs of
/// the files being scanned.
///
/// Delegates to [`tables_from_exts`], the shared assembly the fact bundler
/// also uses, so the harness can never learn under tables the CLI would not
/// scan with (harness/CLI parity).
fn build_spec_tables(files: &[(String, String, String)]) -> (TaintConfig, FactTable) {
    tables_from_exts(files.iter().map(|(_, _, ext)| ext.as_str()))
}

/// Corpus `[frensense] severity:` labels -> CLI tier. CVSS-style labels;
/// tier mapping is consumer policy (D4). Unknown labels return `None` so
/// the finding keeps the registry's severity.
fn corpus_severity(raw: &str) -> Option<crate::Severity> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" | "high" => Some(crate::Severity::Critical),
        "medium" => Some(crate::Severity::Warning),
        "low" => Some(crate::Severity::Info),
        _ => None,
    }
}

/// Overlay a matched bundle pattern's advisory on a finding's advisory:
/// declared severity, impact, improvement, and cwe/cvss/owasp tags
/// override the registry. Observation is handled by the caller - only the
/// checker path lets pattern prose replace the template; a flow's
/// observation is the finding's own description and stays.
fn apply_bundle_pattern(
    advisory: &mut Advisory,
    pattern: &frensense_bundler::format::BundlePattern,
) {
    if let Some(raw) = pattern.severity.as_deref()
        && let Some(tier) = corpus_severity(raw)
    {
        advisory.severity = tier;
    }
    if let Some(impact) = &pattern.impact {
        advisory.impact = impact.clone();
    }
    if let Some(improvement) = &pattern.improvement {
        advisory.improvement = improvement.clone();
    }
    if let Some(cwe) = &pattern.cwe {
        advisory.tags.push(cwe.clone());
    }
    if let Some(cvss) = pattern.cvss {
        advisory.tags.push(format!("CVSS:{cvss}"));
    }
    if let Some(owasp) = &pattern.owasp {
        advisory.tags.push(owasp.clone());
    }
}

/// Build the compiler-style advisory for one non-dataflow policy finding.
fn advisory_from_checker(
    c: &frensense_engine::checks::CheckerFinding,
    file: &str,
    line: u32,
    column: u32,
    file_id: crate::FileId,
    bundle_advisories: &rustc_hash::FxHashMap<String, frensense_bundler::format::BundlePattern>,
) -> Advisory {
    let path = Path::new(file);
    // Severity, title, and message templates are declared per-language in
    // frensense-lang (`LanguageSpec::known_rule_registry`); rules no
    // language declares fall back to the generic policy shape. Spec checks
    // emit an empty `message` plus structured `params` - the observation
    // body then renders from the lang template; bundle/policy findings
    // carry their own prose in `message` and win over the template, and a
    // bundle pattern whose `rules` contain this finding's rule overlays
    // registry severity/impact/tags (and the observation when no fact
    // prose exists).
    let (severity, title, impact, improvement, tag, observation) =
        frensense_lang::severity::checker_advisory(
            frensense_lang::spec_for_path(path),
            &c.rule,
            &c.function,
            file,
            line,
            &c.params,
        );
    let pattern = bundle_advisories.get(&c.rule);
    // Prose precedence: fact-authored `message` > matched bundle pattern's
    // observation > lang template.
    let observation = if !c.message.is_empty() {
        c.message.clone()
    } else if let Some(p) = pattern
        && let Some(o) = &p.observation
    {
        o.clone()
    } else {
        observation
    };
    let mut advisory = Advisory::bare(title, severity, file_id, path, observation)
        .with_confidence(1.0)
        .with_line(line)
        .with_column(column)
        .with_content(c.function.clone())
        .with_enclosing_symbol(c.function.clone())
        .with_impact(impact)
        .with_improvement(improvement)
        .with_tags(["checker", &c.rule, tag]);
    if let Some(p) = pattern {
        apply_bundle_pattern(&mut advisory, p);
    }
    advisory.requires_human = false;
    advisory.fingerprint = stable_fingerprint(&[file, &c.rule, &c.function]);
    advisory
}

/// Build the compiler-style advisory for one vulnerable flow.
fn advisory_from_finding(
    f: &frensense_engine::analysis::taint::engine::SinkFinding,
    file: &str,
    line: u32,
    column: u32,
    file_id: crate::FileId,
    bundle_advisories: &rustc_hash::FxHashMap<String, frensense_bundler::format::BundlePattern>,
) -> Advisory {
    let src = f.source_desc.as_deref().unwrap_or("user input");
    let path = Path::new(file);
    // Role-first ranking lives in frensense-lang's cross-cutting taint
    // policy: what the sink DOES with the data decides the default level;
    // the shape class (Idor) can only lower it further.
    let class_tag = f.role.tag();
    let class = match f.finding_class {
        frensense_engine::analysis::taint::engine::FindingClass::Idor => {
            frensense_lang::severity::TaintClass::Idor
        }
        frensense_engine::analysis::taint::engine::FindingClass::Injection => {
            frensense_lang::severity::TaintClass::Injection
        }
    };
    let (severity, title) = frensense_lang::severity::taint_advisory(
        class,
        f.role.default_level(),
        class_tag,
        &f.sink,
        src,
    );
    let flow = crate::reporter::render_taint_path(&f.path);
    let observation = format!(
        "Tainted value from `{src}` flows to sink `{}` (argument {}) in function `{}`.\nTaint path:\n{}",
        f.sink,
        f.arg_slot,
        f.function,
        flow.trim_end()
    );
    let mut advisory = Advisory::bare(title, severity, file_id, path, observation)
        .with_confidence(1.0)
        .with_line(line)
        .with_column(column)
        .with_content(f.function.clone())
        .with_enclosing_symbol(f.function.clone())
        .with_impact(format!(
            "Unsanitized data from `{src}` reaches the `{}` sink at {}:{}.",
            f.sink, file, line
        ))
        .with_improvement(format!(
            "Sanitize `{src}` before it reaches `{}` in `{}`.",
            f.sink, f.function
        ))
        .with_tags(["taint", class_tag]);
    // A learned sink's family pattern joins on the sink name; the flow
    // observation stays (it is the finding's own description).
    if let Some(pattern) = bundle_advisories.get(&f.sink) {
        apply_bundle_pattern(&mut advisory, pattern);
    }
    advisory.requires_human = false;
    // Taint path steps (source→sink) for SARIF codeFlows / rich clients.
    advisory.taint_steps = f
        .path
        .steps
        .iter()
        .zip(&f.path.spans)
        .map(|(step, span)| {
            (
                crate::reporter::describe_path_step(step),
                span.as_ref()
                    .map(|(file, (start, _))| (file.clone(), *start)),
            )
        })
        .collect();
    advisory.fingerprint = stable_fingerprint(&[file, f.sink.as_str(), f.function.as_str(), src]);
    advisory
}

/// Stable finding ID: an FNV-1a hash over the finding's semantic
/// coordinates (file, rule/sink, enclosing function, source). Deliberately
/// EXCLUDES line/column so the ID survives line shifts - adding 10 lines
/// above a finding must not make it look new to baselines and diff gates.
/// What re-identifies a finding as "the same bug": the same dangerous API
/// or rule, in the same function, in the same file. Edit the function
/// itself (rename, remove the call) and the ID legitimately changes -
/// that IS a different code state.
///
/// FNV-1a rather than DefaultHasher: DefaultHasher's seed is stable only
/// within one process for SipHash with fixed keys - actually fixed keys
/// make it cross-process stable too, but FNV-1a is deterministic by spec,
/// cheap, and dependency-free. Two components joined with `\u{1f}` so
/// ("ab","c") and ("a","bc") hash differently.
pub fn stable_fingerprint(components: &[&str]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, part) in components.iter().enumerate() {
        if i > 0 {
            hash ^= 0x1f_u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("{hash:016x}")
}

/// Shape-based dedup over located findings: group by (path shape, sink file,
/// sink line) and keep one representative per group, the finding with the
/// most path steps (the richest path). Returns indices into `candidates`.
///
/// The engine's per-root BFS can emit several SSA variants of one flow at a
/// single sink call (different roots reaching the same argument through
/// equivalent hops). They are the same bug: same functions, same field
/// accesses, same call structure, only SSA numbering differs, which
/// `TaintPath::shape_id` ignores. Printing each variant wastes triage time
/// and buries distinct findings under noise.
fn dedup_keep_richest(candidates: &[&LocatedFinding]) -> Vec<usize> {
    // Number of steps whose span resolved to a real file position, the
    // "richest" representative is the one a consumer can annotate most.
    fn resolved(loc: &LocatedFinding) -> usize {
        loc.finding
            .path
            .spans
            .iter()
            .filter(|s| s.is_some())
            .count()
    }
    let mut best_by_shape: std::collections::HashMap<(String, String, u32), usize> =
        std::collections::HashMap::new();
    for (i, loc) in candidates.iter().enumerate() {
        let key = (loc.finding.path.shape_id(), loc.file.clone(), loc.line);
        match best_by_shape.get(&key).copied() {
            Some(j) if resolved(candidates[j]) >= resolved(loc) => {}
            _ => {
                best_by_shape.insert(key, i);
            }
        }
    }
    let mut kept: Vec<usize> = best_by_shape.into_values().collect();
    kept.sort_unstable();
    kept
}

#[cfg(test)]
mod shape_dedup_tests {
    use super::dedup_keep_richest;
    use frensense_engine::analysis::forward::SinkAlert;
    use frensense_engine::analysis::taint::engine::{BackwardVerdict, FindingClass, SinkFinding};
    use frensense_engine::analysis::taint::path::{PathStep, TaintPath};
    use frensense_engine::analysis::taint::role::SinkRole;
    use frensense_engine::scan::LocatedFinding;

    /// Build a finding whose path is `steps` assignments; the first
    /// `resolved` of them carry spans. Identical step sequence + tag
    /// produces an identical shape_id (variable numbers are ignored).
    fn located(file: &str, line: u32, steps: usize, resolved: usize, tag: &str) -> LocatedFinding {
        let finding = SinkFinding {
            function: "handler".to_string(),
            sink: "exec".to_string(),
            arg_slot: 0,
            alert: Some(SinkAlert {
                sink: "exec".to_string(),
                slot: 0,
                function: "handler".to_string(),
                class: FindingClass::Injection,
            }),
            verdict: BackwardVerdict::Vulnerable,
            finding_class: FindingClass::Injection,
            role: SinkRole::Execution,
            source_desc: Some(format!("source-{tag}")),
            sink_span: None,
            path: TaintPath {
                steps: (0..steps)
                    .map(|i| PathStep::Assignment {
                        function: format!("f{tag}"),
                        variable: i as u32,
                    })
                    .collect(),
                spans: (0..steps)
                    .map(|i| {
                        if i < resolved {
                            Some((file.to_string(), (0, 1)))
                        } else {
                            None
                        }
                    })
                    .collect(),
            },
        };
        LocatedFinding {
            finding,
            file: file.to_string(),
            line,
            column: 1,
        }
    }

    #[test]
    fn same_shape_same_location_keeps_richest() {
        let a = located("t.ts", 3, 5, 0, "a");
        let b = located("t.ts", 3, 5, 5, "a");
        let kept = dedup_keep_richest(&[&a, &b]);
        assert_eq!(kept, vec![1], "the fully-spanned variant must win");
    }

    #[test]
    fn same_shape_different_lines_keeps_both() {
        let a = located("t.ts", 3, 5, 5, "a");
        let b = located("t.ts", 9, 5, 5, "a");
        let kept = dedup_keep_richest(&[&a, &b]);
        assert_eq!(kept.len(), 2, "distinct sink sites must both report");
    }

    #[test]
    fn same_shape_different_files_keeps_both() {
        let a = located("a.ts", 3, 5, 5, "a");
        let b = located("b.ts", 3, 5, 5, "a");
        let kept = dedup_keep_richest(&[&a, &b]);
        assert_eq!(kept.len(), 2, "cross-file same-shape flows are distinct");
    }

    #[test]
    fn first_wins_on_equal_richness() {
        let a = located("t.ts", 3, 5, 2, "a");
        let b = located("t.ts", 3, 5, 2, "a");
        let kept = dedup_keep_richest(&[&a, &b]);
        assert_eq!(kept, vec![0], "stable: the earlier candidate survives");
    }

    #[test]
    fn different_step_sequences_are_different_shapes() {
        let a = located("t.ts", 3, 3, 3, "a");
        let b = located("t.ts", 3, 5, 5, "a");
        let kept = dedup_keep_richest(&[&a, &b]);
        assert_eq!(kept.len(), 2, "longer walk = different flow = both report");
    }
}

#[cfg(test)]
mod checker_observation_tests {
    use crate::engine::Engine;

    fn scan_temp(name: &str, file: &str, source: &str) -> Vec<crate::Advisory> {
        let dir = std::env::temp_dir().join(format!("frensense-obs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(file), source).expect("write");
        Engine::new().run(&dir.join(file)).expect("scan")
    }

    #[test]
    fn bare_weak_hash_renders_lang_observation() {
        let advisories = scan_temp(
            "bare",
            "app.py",
            "import hashlib\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
        );
        assert_eq!(advisories.len(), 1, "{advisories:?}");
        assert_eq!(
            advisories[0].observation,
            "Weak hash function `md5`, not acceptable for passwords or security-sensitive \
             digests (use bcrypt/argon2/scrypt or SHA-256+)"
        );
        assert_eq!(advisories[0].title, "Policy violation: weak_hash (digest)");
        assert_eq!(advisories[0].tags, ["checker", "weak_hash", "policy"]);
    }

    #[test]
    fn selector_weak_hash_renders_selected_primitive() {
        let advisories = scan_temp(
            "selector",
            "app.ts",
            "import { createHash } from \"crypto\";\n\n\
             export function hashPassword(pw: string) {\n  \
             return createHash(\"md5\").update(pw).digest(\"hex\");\n}\n",
        );
        let finding = advisories
            .iter()
            .find(|a| a.tags.iter().any(|t| t == "weak_hash"))
            .expect("weak_hash finding");
        assert_eq!(
            finding.observation,
            "Weak hash primitive 'md5' selected by `createHash`, not acceptable \
             for passwords or security-sensitive digests (use bcrypt/argon2/scrypt \
             or SHA-256+)"
        );
    }

    #[test]
    fn credential_kdf_renders_lang_observation() {
        let advisories = scan_temp(
            "kdf",
            "app.ts",
            "export function storePassword (clearTextPassword: string) {\n  \
             return security.hash(clearTextPassword)\n}\n",
        );
        let finding = advisories
            .iter()
            .find(|a| a.tags.iter().any(|t| t == "credential_kdf_policy"))
            .expect("credential_kdf_policy finding");
        assert_eq!(
            finding.observation,
            "Credential `hash` call receives a plaintext password, password storage \
             must use a memory-hard KDF (bcrypt/argon2/scrypt), not a fast digest \
             wrapper."
        );
    }
}

#[cfg(test)]
mod bundle_pattern_tests {
    //! Phase 2.3: bundle patterns join to findings through
    //! `BundlePattern::rules` and overlay the consumer advisory path.

    use super::{advisory_from_checker, apply_bundle_pattern, corpus_severity};
    use crate::Severity;
    use crate::engine::Engine;
    use frensense_bundler::format::{BundlePattern, BundlePayloadV5, write_bundle};
    use frensense_engine::analysis::taint::facts::Provenance;
    use frensense_engine::checks::CheckerFinding;

    fn checker(rule: &str, message: &str) -> CheckerFinding {
        CheckerFinding {
            function: "handler".to_string(),
            rule: rule.to_string(),
            message: message.to_string(),
            params: vec![],
            span: None,
            severity: String::new(),
            provenance: Provenance::Spec,
        }
    }

    fn pattern(rules: &[&str]) -> BundlePattern {
        BundlePattern {
            id: "family-a".to_string(),
            observation: Some("family observation".to_string()),
            impact: Some("family impact".to_string()),
            improvement: Some("family fix".to_string()),
            cwe: Some("CWE-79".to_string()),
            cvss: Some(7.5),
            owasp: Some("A03:2021".to_string()),
            severity: Some("High".to_string()),
            rules: rules.iter().map(|r| r.to_string()).collect(),
        }
    }

    fn pattern_map(rules: &[&str]) -> rustc_hash::FxHashMap<String, BundlePattern> {
        let mut map = rustc_hash::FxHashMap::default();
        for r in rules {
            map.insert(r.to_string(), pattern(rules));
        }
        map
    }

    #[test]
    fn corpus_severity_maps_cvss_labels_to_tiers() {
        assert_eq!(corpus_severity("critical"), Some(Severity::Critical));
        assert_eq!(corpus_severity("High"), Some(Severity::Critical));
        assert_eq!(corpus_severity("medium"), Some(Severity::Warning));
        assert_eq!(corpus_severity("Low"), Some(Severity::Info));
        assert_eq!(corpus_severity("Bogus"), None);
        assert_eq!(corpus_severity(""), None);
    }

    #[test]
    fn pattern_overlays_registry_when_rules_match() {
        let advisories = super::advisory_from_checker(
            &checker("policy_custom_rule", ""),
            "src/app.ts",
            3,
            1,
            Engine::next_file_id(0),
            &pattern_map(&["policy_custom_rule"]),
        );
        assert_eq!(advisories.severity, Severity::Critical);
        assert_eq!(advisories.observation, "family observation");
        assert_eq!(advisories.impact, "family impact");
        assert_eq!(advisories.improvement, "family fix");
        assert_eq!(
            advisories.tags,
            [
                "checker",
                "policy_custom_rule",
                "policy",
                "CWE-79",
                "CVSS:7.5",
                "A03:2021"
            ]
        );
    }

    #[test]
    fn fact_prose_wins_over_pattern_observation() {
        let advisories = advisory_from_checker(
            &checker("policy_custom_rule", "fact-authored prose"),
            "src/app.ts",
            3,
            1,
            Engine::next_file_id(0),
            &pattern_map(&["policy_custom_rule"]),
        );
        assert_eq!(advisories.observation, "fact-authored prose");
        assert_eq!(
            advisories.severity,
            Severity::Critical,
            "severity overlay is independent of prose precedence"
        );
    }

    #[test]
    fn unknown_pattern_severity_keeps_registry_tier() {
        let mut p = pattern(&["policy_custom_rule"]);
        p.severity = Some("Bogus".to_string());
        let mut advisories = advisory_from_checker(
            &checker("policy_custom_rule", ""),
            "src/app.ts",
            3,
            1,
            Engine::next_file_id(0),
            &rustc_hash::FxHashMap::default(),
        );
        let registry_tier = advisories.severity;
        apply_bundle_pattern(&mut advisories, &p);
        assert_eq!(advisories.severity, registry_tier);
    }

    #[test]
    fn unmatched_rule_keeps_registry_behavior() {
        let advisories = advisory_from_checker(
            &checker("policy_custom_rule", ""),
            "src/app.ts",
            3,
            1,
            Engine::next_file_id(0),
            &pattern_map(&["some_other_rule"]),
        );
        assert_eq!(advisories.severity, Severity::Warning);
        assert!(
            !advisories.tags.iter().any(|t| t.starts_with("CWE-")),
            "no pattern overlay without a rules match: {:?}",
            advisories.tags
        );
    }

    /// End-to-end: a loaded bundle's pattern reaches a real scan through
    /// the load -> index -> advisory path.
    #[test]
    fn bundle_loaded_pattern_reaches_scan_advisories() {
        let payload = BundlePayloadV5 {
            patterns: vec![pattern(&["weak_hash"])],
            learned_facts: vec![],
            policy_pack: vec![],
        };
        let bytes: &'static [u8] = Box::leak(
            write_bundle(&payload, 1)
                .expect("bundle writes")
                .into_boxed_slice(),
        );

        let dir =
            std::env::temp_dir().join(format!("frensense-bundle-pattern-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let source =
            "import hashlib\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n";
        std::fs::write(dir.join("app.py"), source).expect("write");
        let mut engine = Engine::new();
        engine.set_corpus_bundle(bytes);
        let advisories = engine.run(&dir.join("app.py")).expect("scan");
        let finding = advisories
            .iter()
            .find(|a| a.tags.iter().any(|t| t == "weak_hash"))
            .expect("weak_hash finding");
        assert_eq!(finding.severity, Severity::Critical, "{finding:?}");
        assert_eq!(finding.observation, "family observation", "{finding:?}");
        assert!(
            finding.tags.iter().any(|t| t == "CWE-79"),
            "{:?}",
            finding.tags
        );
    }
}
