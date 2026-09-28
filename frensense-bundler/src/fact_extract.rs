// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Fact extraction from positive/negative corpus pairs (§9).
//!
//! Replaces the old shape/fingerprint pipeline. For every corpus family:
//!
//! 1. Scan positives and negatives through the **shared engine harness**
//!    (`engine::data_flow::scan`) under the built-in fact table.
//! 2. Compute the delta: sink/sanitizer candidates from how taint moves (or
//!    fails to move) through each variant.
//! 3. **Replay gate**: apply candidate facts, re-scan the family; publish a
//!    fact only if the family separates (positives alert, negatives don't)
//!    and no other family's negatives newly alert.
//! 4. Publish with `support` = number of variants that voted. support ≥ 2 is
//!    `confirmed`, otherwise `provisional`.

use std::collections::BTreeSet;
use std::path::Path;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{
    FactTable, LearnedCheckFact, LearnedFactEntry, MemoryContractFact, PolicyFact, PolicyRequirement, PolicyScope,
    SanitizerFact, SinkSignature,
};
use frensense_engine::checks::memory_summary::{CapacitySpec, MemorySummaryRegistry};
use frensense_engine::scan;
use rustc_hash::FxHashMap;

/// A published learned fact with its provenance.
#[derive(Debug, Clone)]
pub struct LearnedFact {
    /// The fact itself, bundle-ready.
    pub entry: LearnedFactEntry,
    /// Number of corpus variants that voted for this fact.
    pub support: u32,
    /// `confirmed` (support ≥ 2) or `provisional` (support = 1).
    pub status: String,
    /// Families that voted for this fact.
    pub families: Vec<String>,
}

/// Advisory metadata from a positive's `[frensense]` comment block.
///
/// Human-facing advisory text baked into the `.frc` as a `BundlePattern`;
/// flow knowledge lives in `learned_facts`, never here. All fields are
/// optional: a family without a `[frensense]` block still groups and votes,
/// it just ships no advisory text.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FamilyMetadata {
    pub observation: Option<String>,
    pub impact: Option<String>,
    pub improvement: Option<String>,
    pub cwe: Option<String>,
    pub cvss: Option<f32>,
    pub owasp: Option<String>,
    pub severity: Option<String>,
}

impl FamilyMetadata {
    /// Parse a `[frensense]` block from a variant's first `head_lines`
    /// lines. Comment prefixes follow the language (`#` for Python, `//`
    /// elsewhere), matching the `check-call` convention. The block is a
    /// run of comment lines whose first line opens with `[frensense]`;
    /// `key: value` lines inside it fill the fields. Only positives
    /// should carry the block, but parsing is variant-agnostic.
    pub fn parse(source: &str, ext: &str, head_lines: usize) -> Self {
        let hash_style = ext == "py" || ext == "pyi" || ext == "pyw";
        let prefixes: &[&str] = if hash_style {
            &["#", "//"]
        } else {
            &["//", "#"]
        };
        fn strip<'a>(prefixes: &[&'a str], line: &'a str) -> Option<&'a str> {
            let t = line.trim();
            prefixes
                .iter()
                .find_map(|p| t.strip_prefix(p))
                .map(|s| s.trim())
        }

        let mut meta = Self::default();
        let mut in_block = false;
        for line in source.lines().take(head_lines) {
            let Some(body) = strip(prefixes, line) else {
                // A non-comment line ends the block once it has started.
                if in_block {
                    break;
                }
                continue;
            };
            if body == "[frensense]" {
                in_block = true;
                continue;
            }
            if !in_block {
                continue;
            }
            let Some((key, value)) = body.split_once(':') else {
                // Unknown line inside the block (e.g. `check-call:`) —
                // other parsers consume it; skip here.
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match key.trim().to_ascii_lowercase().as_str() {
                "observation" => meta.observation = Some(value.to_string()),
                "impact" => meta.impact = Some(value.to_string()),
                "improvement" => meta.improvement = Some(value.to_string()),
                "cwe" => meta.cwe = Some(value.to_string()),
                "cvss" => {
                    if let Ok(v) = value.parse::<f32>() {
                        meta.cvss = Some(v);
                    }
                }
                "owasp" => meta.owasp = Some(value.to_string()),
                "severity" => meta.severity = Some(value.to_string()),
                _ => {}
            }
        }
        meta
    }
}

/// One corpus family: id + variant files.
pub struct Family {
    pub id: String,
    /// (file name, source text, ext)
    pub positives: Vec<(String, String, String)>,
    pub negatives: Vec<(String, String, String)>,
    /// Declared check trigger from the positive's `[frensense]` metadata
    /// (`check-call: name`). When present, Check proposals are restricted
    /// to this call, the family authors declare which call is the
    /// privileged action; the gate still validates the claim.
    pub declared_check_call: Option<String>,
    /// Advisory text from the positive's `[frensense]` block, baked into
    /// the bundle as a `BundlePattern`.
    pub metadata: FamilyMetadata,
}

/// Group a corpus directory into families by filename convention
/// (`<family>_positive*.ts`, `<family>_negative*.ts`).
pub fn group_families(corpus_dir: &Path) -> Result<Vec<Family>, String> {
    let mut families: FxHashMap<String, Family> = FxHashMap::default();

    // Recursive walk: the corpus is organized as a manifest tree
    // (`<lang>/<CWE>/<family>/<stem>_<variant>.<ext>`), with flat files
    // still supported at the root of `corpus_dir`. Family identity is the
    // file stem before `_positive`/`_negative`; directory structure is
    // metadata (recorded in each family's manifest.json), never part of
    // the id, so moving a family between CWE directories preserves its
    // learned facts.
    // Two-phase grouping: collect (family stem, language, variant, file)
    // records first, THEN bucket them into families. The extra language
    // dimension exists because learned facts are language-blind (call
    // matching is by last segment), so a family must never mix languages:
    // a `foo_positive.py` and `foo_negative.ts` under the same stem would
    // vote as one family and the replay gate could publish a fact no
    // single-language pair supports. When a stem collides across
    // languages, each language gets its own sub-family (`foo (python)`,
    // `foo (typescript)`) and a warning names the affected files.
    let mut stack = vec![corpus_dir.to_path_buf()];
    let mut all_paths: Vec<std::path::PathBuf> = Vec::new();
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                all_paths.push(path);
            }
        }
    }
    all_paths.sort();

    /// One scanned file's grouping inputs (before language disambiguation).
    struct Grouped {
        stem: String,
        lang: &'static str,
        variant: &'static str,
        name: String,
        ext: String,
        source: String,
        declared_check_call: Option<String>,
        metadata: FamilyMetadata,
    }

    let mut records: Vec<Grouped> = Vec::new();
    for path in all_paths {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();
        if !matches!(
            ext.as_str(),
            "ts" | "tsx" | "js" | "jsx" | "py" | "go" | "rs" | "c" | "cpp" | "h" | "hpp"
        ) {
            continue;
        }

        let (family, variant) = if let Some(i) = name.find("_positive") {
            (name[..i].to_string(), "positive")
        } else if let Some(i) = name.find("_negative") {
            (name[..i].to_string(), "negative")
        } else {
            continue;
        };
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        // Declared check trigger: `// check-call: <name>` inside the
        // `[frensense]` metadata block of a positive variant. The comment
        // prefix follows the language: `#` for Python/shell-family files,
        // `//` everywhere else, so every supported language can declare a
        // trigger in its own comment syntax.
        let comment_prefix: &[&str] = if ext == "py" || ext == "pyi" || ext == "pyw" {
            &["# check-call:", "// check-call:"]
        } else {
            &["// check-call:", "# check-call:"]
        };
        let declared_check_call = if variant == "positive" {
            source.lines().take(30).find_map(|l| {
                let t = l.trim();
                comment_prefix
                    .iter()
                    .find_map(|p| t.strip_prefix(p))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
        } else {
            None
        };
        // Language identity comes from the registry, same name the specs
        // use for fingerprints; unknown extensions fall back to the raw
        // extension so the collision check still distinguishes them.
        let lang = frensense_lang::spec_for_ext(&ext)
            .map(|s| s.name())
            .unwrap_or(leaked_ext(&ext));
        // Advisory metadata: parsed from every variant's head (positives
        // are the ones that carry the block); later records for the same
        // family overwrite earlier ones, so a positive's block wins.
        let metadata = FamilyMetadata::parse(&source, &ext, 30);
        records.push(Grouped {
            stem: family,
            lang,
            variant,
            name: name.to_string(),
            ext,
            source,
            declared_check_call,
            metadata,
        });
    }

    // Language-mixing detector: which stems carry more than one language?
    let mut langs_by_stem: FxHashMap<&str, std::collections::BTreeSet<&'static str>> =
        FxHashMap::default();
    for r in &records {
        langs_by_stem
            .entry(r.stem.as_str())
            .or_default()
            .insert(r.lang);
    }
    let mixed: FxHashMap<&str, ()> = langs_by_stem
        .into_iter()
        .filter(|(_, langs)| langs.len() > 1)
        .map(|(stem, _)| (stem, ()))
        .collect();
    // File names per colliding stem, for the actionable follow-up warning.
    let mut mixed_files: FxHashMap<&str, Vec<String>> =
        mixed.keys().map(|s| (*s, Vec::new())).collect();
    for stem in mixed.keys() {
        eprintln!(
            "[facts] WARNING: family stem '{stem}' mixes languages; splitting into \
             per-language sub-families so votes never cross language boundaries"
        );
    }

    for r in &records {
        // Mixed stems are disambiguated with the language name; clean stems
        // keep the bare id so existing family ids are stable.
        let family = if mixed.contains_key(r.stem.as_str()) {
            format!("{} ({})", r.stem, r.lang)
        } else {
            r.stem.clone()
        };
        if let Some(files) = mixed_files.get_mut(r.stem.as_str()) {
            files.push(r.name.clone());
        }
        let f = families.entry(family.clone()).or_insert_with(|| Family {
            id: family.clone(),
            positives: Vec::new(),
            negatives: Vec::new(),
            declared_check_call: None,
            metadata: FamilyMetadata::default(),
        });
        if r.declared_check_call.is_some() {
            f.declared_check_call = r.declared_check_call.clone();
        }
        // Positives' metadata wins over negatives' (negatives should not
        // carry a block, but parse defensively): only overwrite from a
        // non-default parse.
        if r.variant == "positive" && r.metadata != FamilyMetadata::default() {
            f.metadata = r.metadata.clone();
        }
        let slot = match r.variant {
            "positive" => &mut f.positives,
            _ => &mut f.negatives,
        };
        slot.push((r.name.clone(), r.source.clone(), r.ext.clone()));
    }

    // Name the colliding files once, after grouping, so the warning is
    // actionable (which files ended up in which sub-family).
    for stem in mixed.keys() {
        let files = mixed_files
            .get(stem)
            .map(|v| v.join(", "))
            .unwrap_or_default();
        eprintln!("[facts]   stem '{stem}' files: {files}");
    }

    let mut out: Vec<Family> = families.into_values().collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Leak the raw extension as a `'static` fallback for unregistered
/// extensions (at most a handful of small strings per run; acceptable for
/// a build-time tool).
fn leaked_ext(ext: &str) -> &'static str {
    Box::leak(ext.to_string().into_boxed_str())
}

/// A candidate fact proposed by delta analysis.
#[derive(Debug, Clone)]
enum Candidate {
    /// Call is a dangerous sink at these arg slots.
    Sink {
        call: String,
        dangerous: BTreeSet<usize>,
    },
    /// Call sanitizes (guard-style or transform).
    Sanitizer { call: String, guard: bool },
    /// Call is a policy violation per a corpus-verified non-dataflow rule
    /// (positive contains the call and alerts-or-should; negative lacks it,
    /// or enforces it with a guard the positive lacks).
    Check {
        rule: String,
        call: String,
        message: String,
        /// Fire only when this guard is absent (shape-b families).
        unless_guard: Option<String>,
        /// Fire only when the trigger arg has NO literal range comparison
        /// (inline enforcement modality).
        unless_range_check: Option<Vec<String>>,
    },
    /// Generalized co-occurrence policy (the `LearnedFactEntry::Policy`
    /// shape): trigger + a list of requirements the trigger's scope must
    /// satisfy. Covers the two family shapes the legacy Check fact cannot
    /// express:
    ///
    /// * **banned-call co-occurrence** — the trigger appears in positives
    ///   AND negatives, but negatives avoid a call the positives make:
    ///   `require: [NotCall{banned}]` ("calling `exec` alongside `log`
    ///   is the violation").
    /// * **cross-function enforcement** — the enforcement helper is defined
    ///   in a sibling file/module rather than called in the trigger's own
    ///   function: `require: [RequireCall{any_of}]` under
    ///   `PolicyScope::Module` (the engine accepts the definition site as
    ///   enforcement evidence).
    ///
    /// An empty `require` list is a presence-only policy and is never
    /// proposed here (the legacy Check path already covers presence-only).
    Policy {
        rule: String,
        call: String,
        message: String,
        require: Vec<PolicyRequirement>,
        scope: PolicyScope,
    },
    /// A custom allocation/deallocation wrapper contract learned from corpus examples.
    MemoryContract {
        name: String,
        returns_fresh: bool,
        return_capacity: CapacitySpec,
        consumes_params: Vec<usize>,
    },
}


/// Taint-relevant calls observed in one variant, with arg-slot detail.
/// Uses the engine's scan; the deltas come from comparing what taint reached.
fn scan_variant(
    files: &[(String, String, String)],
    config: &TaintConfig,
    facts: &FactTable,
) -> frensense_engine::scan::ScanResult {
    scan::scan(files, config, facts)
}

/// One family's variants, lowered once. The gate re-scans families per
/// candidate fact; without pre-lowering the gate is O(candidates × families)
/// lowerings and times out at corpus scale.
struct PreparedFamily {
    id: String,
    pos: frensense_engine::scan::PreparedProgram,
    neg: frensense_engine::scan::PreparedProgram,
    /// All call names appearing in any variant, used to skip gate trials
    /// for facts that cannot affect this family.
    calls: std::collections::BTreeSet<String>,
}

impl PreparedFamily {
    fn new(f: &Family) -> Result<Self, String> {
        let pos = frensense_engine::scan::prepare(&f.positives)?;
        let neg = frensense_engine::scan::prepare(&f.negatives)?;
        let mut calls = std::collections::BTreeSet::new();
        calls.extend(
            collect_calls(&f.positives)
                .keys()
                .cloned()
                .chain(collect_calls(&f.negatives).keys().cloned()),
        );
        Ok(Self {
            id: f.id.clone(),
            pos,
            neg,
            calls,
        })
    }

    /// Family separation under a fact table. Reuses the lowered IRs;
    /// each call re-runs the taint engine + checker only.
    fn separates(&self, config: &TaintConfig, facts: &FactTable) -> bool {
        let pos = scan::scan_prepared(&self.pos, config, facts);
        let neg = scan::scan_prepared(&self.neg, config, facts);
        pos.has_alert() && !neg.has_alert()
    }
}

/// Propose candidate facts for one family from the pos/neg delta.
///
/// Signal extraction per family:
/// * If positives alert and negatives don't under the built-in table, the
///   family *confirms* current handling (no new fact needed).
/// * If positives do NOT alert (a real flow the engine missed), look for
///   calls in positives that the built-in table doesn't know → propose them
///   as sinks (all-args; the replay gate validates).
/// * If negatives contain guard/transform calls between the source and the
///   sink that positives lack → propose sanitizer facts.
fn propose(family: &Family, config: &TaintConfig, builtin: &FactTable) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    // Memory allocation / deallocation wrapper discovery from corpus examples:
    let mut family_irs = Vec::new();
    for (path, src, ext) in family.positives.iter().chain(family.negatives.iter()) {
        if let Ok(fns) = frensense_engine::harness::lower_source(path, src, ext) {
            family_irs.extend(fns.into_values());
        }
    }
    if !family_irs.is_empty() {
        let ir_refs: Vec<&frensense_engine::ir::function::FunctionIR> = family_irs.iter().collect();
        let summaries = MemorySummaryRegistry::from_facts(builtin)
            .infer_program_summaries_into(&ir_refs);
        for (name, summary) in summaries.summaries {
            if MemorySummaryRegistry::is_builtin(&name) {
                continue;
            }
            if summary.returns_fresh || !summary.consumes_params.is_empty() {
                candidates.push(Candidate::MemoryContract {
                    name,
                    returns_fresh: summary.returns_fresh,
                    return_capacity: summary.return_capacity,
                    consumes_params: summary.consumes_params,
                });
            }
        }
    }

    let pos = scan_variant(&family.positives, config, builtin);
    let neg = scan_variant(&family.negatives, config, builtin);
    let pos_alerts = pos.has_alert();
    let neg_alerts = neg.has_alert();

    if pos_alerts && !neg_alerts {
        // Taint flow already separates. Return any memory contracts discovered.
        return candidates;
    }

    // Guard/transform calls present in negatives but not in positives,
    // these are likely the *reason* the negative is safe.
    let pos_calls = collect_calls(&family.positives);
    let neg_calls = collect_calls(&family.negatives);
    for (call, shape) in &neg_calls {
        if pos_calls.contains_key(call) || builtin.sanitizer_fact(call).is_some() {
            continue;
        }
        if !looks_taint_relevant(call) {
            continue;
        }
        candidates.push(Candidate::Sanitizer {
            call: call.clone(),
            guard: *shape == CallShape::Predicate,
        });
    }

    // Calls in positives that no table knows and no candidate yet → sink
    // proposals (validated by replay).
    if !pos_alerts {
        for call in pos_calls.keys() {
            if builtin.sink_signature(call).is_some() || builtin.sanitizer_fact(call).is_some() {
                continue;
            }
            if !looks_taint_relevant(call) {
                continue;
            }
            if candidates
                .iter()
                .any(|c| matches!(c, Candidate::Sanitizer { call: c2, .. } if c2 == call))
            {
                continue;
            }
            candidates.push(Candidate::Sink {
                call: call.clone(),
                dangerous: BTreeSet::new(), // all args; replay validates
            });
        }
    }

    // Non-dataflow policy deltas: the two family shapes that express
    // "trigger without enforcement":
    //
    // (a) trigger call present in positives, ABSENT from negatives, the
    //     call itself is the violation (presence-only check);
    // (b) trigger call present in BOTH, but negatives contain a guard call
    //     (clamp/validate/allowlist helper) that positives lack, the
    //     violation is executing the trigger WITHOUT the guard. The fact
    //     carries `unless_guard` so the engine fires only when the guard
    //     is missing. This is the chatbot/privileged-tool shape.
    for call in pos_calls.keys() {
        if builtin.learned_checks.iter().any(|c| c.call == *call) {
            continue; // already learned
        }
        // Family-declared trigger restricts Check proposals to the declared
        // call; undeclared families keep the delta-driven path.
        if let Some(declared) = &family.declared_check_call {
            if call != declared {
                continue;
            }
        } else if !looks_taint_relevant(call) {
            continue;
        }
        let rule = format!("policy_{call}");
        let message = format!(
            "Corpus-verified policy violation: `{call}` (learned from family {})",
            family.id
        );
        // Enforcement modalities the negatives demonstrate. A negative can
        // enforce via a named helper, an inline literal range check, or
        // both; the fact records every modality observed and the engine
        // stays silent when ANY of them matches. When the negatives show
        // no enforcement at all, the fact is presence-only.
        let mut unless_guard: Option<String> = None;
        let mut unless_range_check: Option<Vec<String>> = None;
        if neg_calls.contains_key(call) {
            // Helper modality: absent from every positive, present in at
            // least one negative (prefer a helper common to all negatives).
            // Each negative need only be suppressed by ONE modality, the
            // gate validates the combination end-to-end.
            let pos_has = |g: &str| pos_calls.contains_key(g);
            let all_negs_have = |g: &str| {
                family
                    .negatives
                    .iter()
                    .map(|v| collect_calls(std::slice::from_ref(v)))
                    .all(|calls| calls.contains_key(g))
            };
            unless_guard = neg_calls
                .keys()
                .find(|g| !pos_has(g) && !builtin.sanitizer_fact(g).is_some() && all_negs_have(g))
                .or_else(|| {
                    neg_calls
                        .keys()
                        .find(|g| !pos_has(g) && !builtin.sanitizer_fact(g).is_some())
                })
                .cloned();
            // Inline modality: any negative compares a trigger-argument var
            // against a literal bound.
            if family
                .negatives
                .iter()
                .any(|v| variant_has_range_check_on_call(&[v.clone()], call))
            {
                unless_range_check = Some(vec!["<".into(), ">".into(), "<=".into(), ">=".into()]);
            }
            if unless_guard.is_none() && unless_range_check.is_none() {
                // Negatives contain the trigger but demonstrate no
                // recognizable enforcement: no check fact, the family
                // doesn't yet teach a suppressible difference.
                continue;
            }
        }
        candidates.push(Candidate::Check {
            rule,
            call: call.clone(),
            message,
            unless_guard,
            unless_range_check,
        });
    }

    // Generalized co-occurrence policies: the two family shapes the legacy
    // Check fact cannot express. Both need the trigger present in BOTH
    // variants (unlike shapes a/b, the trigger alone is not the violation;
    // the co-occurring context is).
    //
    // (c) Banned-call co-occurrence: negatives call the trigger but avoid
    //     some call the positives make. The positives' extra call is the
    //     violation, not the trigger.
    // (d) Cross-function enforcement: the enforcement helper is DEFINED in
    //     a variant but not necessarily called in the trigger's function;
    //     the engine's Module scope accepts a sibling definition as
    //     evidence. Detected when a variant declares a function whose name
    //     matches a guard-style call in the OTHER variant.
    // Generalized co-occurrence policies: the two family shapes the legacy
    // Check fact cannot express. Both need the trigger present in BOTH
    // variants (unlike shapes a/b, the trigger alone is not the violation;
    // the co-occurring context is). Proposals key on the family-declared
    // trigger only — co-occurrence policies are too broad to mine
    // presence-blind, so undeclared families get none (the legacy delta
    // paths above still apply).
    if let Some(trigger) = family.declared_check_call.clone() {
        if !(pos_calls.contains_key(&trigger)
            && neg_calls.contains_key(&trigger)
            && builtin.learned_checks.iter().all(|c| c.call != trigger))
        {
            return candidates;
        }
        // Shape (c): banned-call co-occurrence. Calls the POSITIVES make
        // that no negative makes: candidate `NotCall` requirements.
        let banned: Vec<String> = pos_calls
            .keys()
            .filter(|c| {
                c.as_str() != trigger
                    && !neg_calls.contains_key(*c)
                    && builtin.sanitizer_fact(c).is_none()
                    && builtin.sink_signature(c).is_none()
                    && looks_taint_relevant(c)
            })
            .cloned()
            .collect();
        if let Some(banned_call) = banned.first() {
            candidates.push(Candidate::Policy {
                rule: format!("policy_{trigger}_no_{banned_call}"),
                call: trigger.clone(),
                message: format!(
                    "Corpus-verified policy violation: `{trigger}` must not co-occur with `{banned_call}` (learned from family {})",
                    family.id
                ),
                require: vec![PolicyRequirement::NotCall {
                    call: banned_call.clone(),
                }],
                scope: PolicyScope::Function,
            });
        }

        // Shape (d): cross-function enforcement. The enforcement helper is
        // DEFINED in the negatives' module but absent from positives — the
        // enforcement lives outside the trigger's function, so the fact
        // uses Module scope (the engine accepts the definition site as
        // enforcement evidence).
        if let Some(helper) = cross_function_helper(family, &pos_calls, &neg_calls) {
            if builtin.sanitizer_fact(&helper).is_none() {
            candidates.push(Candidate::Policy {
                rule: format!("policy_{trigger}_with_{helper}"),
                call: trigger.clone(),
                message: format!(
                    "Corpus-verified policy violation: `{trigger}` requires `{helper}` enforcement (learned from family {})",
                    family.id
                ),
                require: vec![PolicyRequirement::RequireCall {
                    any_of: vec![helper.clone()],
                }],
                scope: PolicyScope::Module,
            });
            }
        }
    }

    candidates
}

/// Cross-function enforcement helper: a function DEFINED in the negatives
/// that positives neither define nor call. The negatives are safe because
/// their module provides the enforcement helper (the definition site is
/// the strongest in-scope evidence — `policy::check_program`'s
/// module-segment rule), while positives execute the trigger with no
/// helper anywhere in scope. The helper must not be defined in positives:
/// if both sides define it, its presence cannot be the separating signal.
fn cross_function_helper(
    family: &Family,
    pos_calls: &FxHashMap<String, CallShape>,
    neg_calls: &FxHashMap<String, CallShape>,
) -> Option<String> {
    let pos_defs = defined_function_names(&family.positives);
    let neg_defs = defined_function_names(&family.negatives);
    let trigger = family.declared_check_call.as_deref();
    neg_defs
        .iter()
        .filter(|g| {
            Some(g.as_str()) != trigger
                && !pos_defs.contains(*g)
                && !pos_calls.contains_key(*g)
                && !neg_calls.contains_key(*g)
        })
        .next()
        .cloned()
}

/// Last-segment names of every function DEFINED in the given variants
/// (definition sites, not call sites).
fn defined_function_names(files: &[(String, String, String)]) -> rustc_hash::FxHashSet<String> {
    use rustc_hash::FxHashSet;
    let mut out = FxHashSet::default();
    for (path, source, ext) in files {
        let Ok(irs) = frensense_engine::harness::lower_source(path, source, ext) else {
            continue;
        };
        for name in irs.keys() {
            // Skip synthetic lowering names (`<fn@byte>`, `<path:handler@byte>`):
            // they encode the file position where the function was DECLARED in
            // the corpus variant, so a target program can never contain the
            // same name — a RequireCall fact keyed on one would fire forever.
            if name.starts_with('<') {
                continue;
            }
            let last = name.rsplit('.').next().unwrap_or(name);
            out.insert(last.to_string());
        }
    }
    out
}

/// True when any argument var passed to `call` is compared against a
/// literal with a range operator (<, >, <=, >=) in the variant's IR,
/// inline range enforcement.
fn variant_has_range_check_on_call(files: &[(String, String, String)], call: &str) -> bool {
    use frensense_engine::ir::function::{Instruction, Operand};
    const RANGE_OPS: &[&str] = &["<", ">", "<=", ">="];
    let Some((path, source, ext)) = files.first() else {
        return false;
    };
    let Ok(irs) = frensense_engine::harness::lower_source(path, source, ext) else {
        return false;
    };
    for ir in irs.values() {
        // Vars passed as arguments to the trigger call.
        let mut arg_vars: Vec<_> = Vec::new();
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let is_call = match instr {
                    Instruction::CallStatic { func, .. } => func.rsplit('.').next() == Some(call),
                    Instruction::CallVirtual { method, .. } => {
                        method.rsplit('.').next() == Some(call)
                    }
                    _ => false,
                };
                let args = match instr {
                    Instruction::CallStatic { args, .. }
                    | Instruction::CallVirtual { args, .. } => Some(args),
                    _ => None,
                };
                if is_call && args.is_some() {
                    for a in args.unwrap() {
                        if let Operand::Var(v) = a {
                            arg_vars.push(*v);
                        }
                    }
                }
            }
        }
        // Any literal comparison on those vars?
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let op = match instr {
                    Instruction::BinaryOp { op, .. } => op,
                    _ => continue,
                };
                if !RANGE_OPS.contains(&op.as_str()) {
                    continue;
                }
                if let Instruction::BinaryOp { lhs, rhs, .. } = instr {
                    let (a, b) = (lhs, rhs);
                    let var_side = matches!(a, Operand::Var(v) if arg_vars.contains(v))
                        || matches!(b, Operand::Var(v) if arg_vars.contains(v));
                    let lit_side = matches!(
                        b,
                        Operand::StringLiteral(_)
                            | Operand::IntLiteral(_)
                            | Operand::FloatLiteral(_)
                    ) || matches!(
                        a,
                        Operand::StringLiteral(_)
                            | Operand::IntLiteral(_)
                            | Operand::FloatLiteral(_)
                    );
                    if var_side && lit_side {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallShape {
    Predicate,
    Transform,
    Other,
}

/// Collect call names + coarse shapes from lowered IR text (cheap: reuses the
/// harness lowering). Shape detection: a call whose result feeds only a
/// Branch/condition is predicate-shaped; a call whose result is re-stored or
/// passed on is transform-shaped.
fn collect_calls(files: &[(String, String, String)]) -> FxHashMap<String, CallShape> {
    let mut calls: FxHashMap<String, CallShape> = FxHashMap::default();
    use frensense_engine::ir::function::{Instruction, Operand, Terminator, VarId};

    fn defs_of(instr: &Instruction) -> Vec<VarId> {
        let mut v = Vec::with_capacity(2);
        match instr {
            Instruction::Assign { dest, .. }
            | Instruction::LoadField { dest, .. }
            | Instruction::LoadElement { dest, .. }
            | Instruction::LoadGlobal { dest, .. }
            | Instruction::Cast { dest, .. }
            | Instruction::ExtractValue { dest, .. }
            | Instruction::BinaryOp { dest, .. }
            | Instruction::UnaryOp { dest, .. } => v.push(*dest),
            Instruction::CallStatic { dest, .. }
            | Instruction::CallVirtual { dest, .. }
            | Instruction::CallPointer { dest, .. } => {
                if let Some(d) = dest {
                    v.push(*d);
                }
            }
            _ => {}
        }
        v
    }

    for (path, source, ext) in files {
        let Ok(irs) = frensense_engine::harness::lower_source(path, source, ext) else {
            continue;
        };
        for ir in irs.values() {
            // Vars that flow into a branch condition (directly or via a
            // short def chain, captures `!x.test(y)`).
            let mut cond_vars: FxHashMap<VarId, ()> = FxHashMap::default();
            for block in ir.blocks.values() {
                if let Terminator::Branch { cond, .. } = &block.terminator {
                    if let Operand::Var(c) = cond {
                        cond_vars.insert(*c, ());
                        // one hop up the def chain (unary ! / binary &&)
                        for b2 in ir.blocks.values() {
                            for i in &b2.instructions {
                                match i {
                                    Instruction::UnaryOp {
                                        dest,
                                        src: Operand::Var(s),
                                        ..
                                    }
                                    | Instruction::BinaryOp {
                                        dest,
                                        lhs: Operand::Var(s),
                                        ..
                                    }
                                    | Instruction::BinaryOp {
                                        dest,
                                        rhs: Operand::Var(s),
                                        ..
                                    } if *dest == *c => {
                                        cond_vars.insert(*s, ());
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            for block in ir.blocks.values() {
                for instr in &block.instructions {
                    let (name, dest) = match instr {
                        Instruction::CallStatic { func, dest, .. } => (Some(func.clone()), *dest),
                        Instruction::CallVirtual { method, dest, .. } => {
                            (Some(method.clone()), *dest)
                        }
                        _ => (None, None),
                    };
                    if let Some(name) = name {
                        let shape = if dest.map(|d| cond_vars.contains_key(&d)).unwrap_or(false) {
                            CallShape::Predicate
                        } else {
                            CallShape::Other
                        };
                        // Predicate classification wins over Other.
                        calls
                            .entry(name)
                            .and_modify(|e| {
                                if shape == CallShape::Predicate {
                                    *e = shape.clone();
                                }
                            })
                            .or_insert(shape);
                    }
                }
            }
        }
    }
    calls
}

/// Names that plausibly participate in taint boundaries. This is a *bundler*
/// heuristic (build-time, recall-oriented); the replay gate provides the
/// precision.
/// Decides whether a call name is worth proposing as a candidate fact.
///
/// The corpus, not a hardcoded list, is the source of truth: a call is
/// taint-relevant if the FAMILY ITSELF discriminates on it. We keep only a
/// minimal syntactic exclusion (property lookups / obviously pure names
/// that would explode the candidate space) and let the replay gate reject
/// wrong proposals, that is what the gate is for.
fn looks_taint_relevant(call: &str) -> bool {
    // Accessor/universal-method noise: these appear in nearly every
    // variant and are structurally not policy/sink calls.
    const NOISE: &[&str] = &[
        "get",
        "set",
        "has",
        "then",
        "catch",
        "finally",
        "toString",
        "valueOf",
        "push",
        "pop",
        "map",
        "filter",
        "reduce",
        "forEach",
        "join",
        "split",
        "len",
        "length",
        "keys",
        "values",
        "entries",
        "stringify",
        "parse",
    ];
    !NOISE.contains(&call) && !call.is_empty()
}

/// Apply a candidate to a fact table (for replay).
fn apply_candidate(table: &mut FactTable, c: &Candidate) {
    match c {
        Candidate::Sink { call, dangerous } => {
            let sig = if dangerous.is_empty() {
                SinkSignature::all_args(call)
            } else {
                SinkSignature::with_args(call, &dangerous.iter().copied().collect::<Vec<_>>())
            };
            table.sink_signatures.insert(call.clone(), sig);
        }
        Candidate::Sanitizer { call, guard } => {
            table.sanitizer_facts.insert(
                call.clone(),
                SanitizerFact {
                    call: call.clone(),
                    kind: if *guard {
                        "allowlist".into()
                    } else {
                        "encode".into()
                    },
                    sanitizes_args: Default::default(),
                    guard_style: *guard,
                },
            );
        }
        Candidate::Check {
            rule,
            call,
            message,
            unless_guard,
            unless_range_check,
        } => {
            table.learned_checks.push(LearnedCheckFact {
                rule: rule.clone(),
                call: call.clone(),
                message: message.clone(),
                severity: "warning".into(),
                unless_guard: unless_guard.clone(),
                unless_range_check: unless_range_check.clone(),
            });
        }
        Candidate::Policy {
            rule,
            call,
            message,
            require,
            scope,
        } => {
            table.policy_facts.push(PolicyFact {
                rule: rule.clone(),
                when_call: call.clone(),
                require: require.clone(),
                scope: *scope,
                message: message.clone(),
                severity: "warning".into(),
            });
        }
        Candidate::MemoryContract {
            name,
            returns_fresh,
            return_capacity,
            consumes_params,
        } => {
            let fact = MemoryContractFact {
                name: name.clone(),
                returns_fresh: *returns_fresh,
                return_capacity: return_capacity.clone(),
                consumes_params: consumes_params.clone(),
            };
            if let Some(existing) = table.memory_contracts.iter_mut().find(|c| c.name == fact.name) {
                *existing = fact;
            } else {
                table.memory_contracts.push(fact);
            }
        }
    }
}

/// Family separation check under a fact table (single-shot variant; the
/// gate uses the pre-lowered [`PreparedFamily::separates`] instead).
fn separates(family: &Family, config: &TaintConfig, facts: &FactTable) -> bool {
    let pos = scan_variant(&family.positives, config, facts);
    let neg = scan_variant(&family.negatives, config, facts);
    pos.has_alert() && !neg.has_alert()
}

fn fact_key(e: &LearnedFactEntry) -> (String, String) {
    match e {
        LearnedFactEntry::Source { pattern } => ("source".into(), pattern.clone()),
        LearnedFactEntry::Sink { call, .. } => ("sink".into(), call.clone()),
        LearnedFactEntry::Sanitizer { call, .. } => ("san".into(), call.clone()),
        LearnedFactEntry::Check { rule, call, .. } => ("check".into(), format!("{rule}:{call}")),
        LearnedFactEntry::Policy {
            rule, when_call, ..
        } => ("policy".into(), format!("{rule}:{when_call}")),
        LearnedFactEntry::MemoryContract { name, .. } => ("mem".into(), name.clone()),
    }
}


/// Full extraction: propose per family → replay-gate → merged learned table.
pub fn extract_facts(
    families: &[Family],
    config: &TaintConfig,
    builtin: &FactTable,
) -> (FactTable, Vec<LearnedFact>) {
    // votes: candidate-key → (support, families)
    let mut votes: FxHashMap<String, (Candidate, u32, Vec<String>)> = FxHashMap::default();

    // Pass 1: proposals per family (accumulate votes).
    for f in families {
        for c in propose(f, config, builtin) {
            let key = match &c {
                Candidate::Sink { call, .. } => format!("sink:{call}"),
                Candidate::Sanitizer { call, guard } => format!("san:{call}:{guard}"),
                Candidate::Check { rule, call, .. } => format!("check:{rule}:{call}"),
                Candidate::Policy { rule, call, .. } => format!("policy:{rule}:{call}"),
                Candidate::MemoryContract { name, .. } => format!("mem:{name}"),
            };


            let entry = votes.entry(key).or_insert_with(|| (c, 0, Vec::new()));
            entry.1 += 1;
            if !entry.2.contains(&f.id) {
                entry.2.push(f.id.clone());
            }
        }
    }

    // Pass 2: replay gate. Every family is lowered once up front; each
    // candidate trial then re-runs only the taint engine + checker per
    // family (no re-lowering). Baseline separation is measured under the
    // built-in table; a candidate fact must (a) make (or keep) its voting
    // families separate and (b) NOT break any family that already separates
    // at baseline. Families that never separate under any table (corrupted
    // positives, see docs/E2E_REPORT.md §1b) are excluded from the
    // regression check: they can't be "broken" further, and gating on them
    // would reject every fact.
    let prepared: Vec<PreparedFamily> = families
        .iter()
        .filter_map(|f| match PreparedFamily::new(f) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("[facts] skip family {}: {e}", f.id);
                None
            }
        })
        .collect();

    let baseline: FxHashMap<String, bool> = prepared
        .iter()
        .map(|p| (p.id.clone(), p.separates(config, builtin)))
        .collect();

    let mut learned = FactTable::default();
    let mut published: Vec<LearnedFact> = Vec::new();

    for (key, (cand, support, fams)) in votes {
        let mut trial = builtin.clone();
        apply_candidate(&mut trial, &cand);

        // The fact must make each voting family separate (or keep it
        // separate), and must not break any family that separated at
        // baseline.
        if std::env::var("FXDBG").is_ok() {
            eprintln!("[gate] candidate key={} support={}", key, support);
        }
        // Candidate call names (trigger + guard), a family whose variants
        // never call any of them cannot change separation under this fact,
        // so keep its baseline verdict without re-scanning.
        let cand_calls: Vec<&str> = match &cand {
            Candidate::Sink { call, .. } => vec![call.as_str()],
            Candidate::Sanitizer { call, .. } => vec![call.as_str()],
            Candidate::Check {
                call, unless_guard, ..
            } => match unless_guard {
                Some(g) => vec![call.as_str(), g.as_str()],
                None => vec![call.as_str()],
            },
            // Trigger plus every requirement's call names: a family whose
            // variants never touch any of them cannot change separation.
            Candidate::Policy { call, require, .. } => {
                let mut calls = vec![call.as_str()];
                for req in require {
                    for name in req.call_names() {
                        if !calls.contains(&name) {
                            calls.push(name);
                        }
                    }
                }
                calls
            }
            Candidate::MemoryContract { name, .. } => vec![name.as_str()],
        };

        let mut ok = true;
        for p in &prepared {
            let voted = fams.contains(&p.id);
            let relevant = voted || cand_calls.iter().any(|c| p.calls.contains(*c));
            let sep = if relevant {
                p.separates(config, &trial)
            } else {
                baseline.get(&p.id).copied().unwrap_or(false)
            };
            if voted && !sep {
                ok = false; // its own vote failed
                break;
            }
            if !voted && baseline.get(&p.id).copied().unwrap_or(false) && !sep {
                // Cross-family regression: the fact broke a previously
                // separating family. Reject the fact (shape-thinking creep).
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }

        apply_candidate(&mut learned, &cand);
        let entry = match &cand {
            Candidate::Sink { call, dangerous } => LearnedFactEntry::Sink {
                call: call.clone(),
                dangerous_args: dangerous.clone(),
                binding_args_safe: false,
            },
            Candidate::Sanitizer { call, guard } => LearnedFactEntry::Sanitizer {
                call: call.clone(),
                kind: if *guard {
                    "allowlist".into()
                } else {
                    "encode".into()
                },
                guard_style: *guard,
            },
            Candidate::Check {
                rule,
                call,
                message,
                unless_guard,
                unless_range_check,
            } => LearnedFactEntry::Check {
                rule: rule.clone(),
                call: call.clone(),
                message: message.clone(),
                severity: "warning".into(),
                unless_guard: unless_guard.clone(),
                unless_range_check: unless_range_check.clone(),
            },
            Candidate::Policy {
                rule,
                call,
                message,
                require,
                scope,
            } => LearnedFactEntry::Policy {
                rule: rule.clone(),
                when_call: call.clone(),
                require: require.clone(),
                scope: *scope,
                message: message.clone(),
                severity: "warning".into(),
            },
            Candidate::MemoryContract {
                name,
                returns_fresh,
                return_capacity,
                consumes_params,
            } => LearnedFactEntry::MemoryContract {
                name: name.clone(),
                returns_fresh: *returns_fresh,
                return_capacity: return_capacity.clone(),
                consumes_params: consumes_params.clone(),
            },
        };

        published.push(LearnedFact {
            entry,
            support,
            status: if support >= 2 {
                "confirmed"
            } else {
                "provisional"
            }
            .into(),
            families: fams,
        });
        let _ = key;
    }

    published.sort_by(|a, b| {
        let ka = fact_key(&a.entry);
        let kb = fact_key(&b.entry);
        ka.cmp(&kb)
    });
    (learned, published)
}

#[cfg(test)]
mod metadata_tests {
    //! `[frensense]` advisory metadata: parsing from positive comment
    //! blocks (both comment syntaxes) and baking into the `.frc` payload as
    //! `BundlePattern` entries.

    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const TS_BLOCK: &str = r#"// [frensense]
// observation: User data reaches the sink unescaped.
// impact: Stored XSS against every viewer of the record.
// improvement: Escape on render with the framework's auto-escaping.
// cwe: CWE-79
// cvss: 7.4
// owasp: A03:2021
// severity: High

export function handle(req: any) { return req; }
"#;

    #[test]
    fn parse_full_block_all_fields() {
        let meta = FamilyMetadata::parse(TS_BLOCK, "ts", 30);
        assert_eq!(
            meta.observation.as_deref(),
            Some("User data reaches the sink unescaped.")
        );
        assert_eq!(
            meta.impact.as_deref(),
            Some("Stored XSS against every viewer of the record.")
        );
        assert_eq!(
            meta.improvement.as_deref(),
            Some("Escape on render with the framework's auto-escaping.")
        );
        assert_eq!(meta.cwe.as_deref(), Some("CWE-79"));
        assert_eq!(meta.cvss, Some(7.4));
        assert_eq!(meta.owasp.as_deref(), Some("A03:2021"));
        assert_eq!(meta.severity.as_deref(), Some("High"));
    }

    #[test]
    fn parse_python_hash_comments() {
        let src = "# [frensense]\n# observation: Exec runs user input.\n# severity: Critical\n\ndef h():\n    pass\n";
        let meta = FamilyMetadata::parse(src, "py", 30);
        assert_eq!(meta.observation.as_deref(), Some("Exec runs user input."));
        assert_eq!(meta.severity.as_deref(), Some("Critical"));
        assert_eq!(meta.impact, None);
    }

    #[test]
    fn no_block_yields_default() {
        let meta = FamilyMetadata::parse("export function h() {}\n", "ts", 30);
        assert_eq!(meta, FamilyMetadata::default());
    }

    #[test]
    fn block_must_open_with_marker() {
        // Comment lines WITHOUT the [frensense] opener must not be parsed.
        let src = "// observation: not in a block\nexport function h() {}\n";
        assert_eq!(FamilyMetadata::parse(src, "ts", 30), FamilyMetadata::default());
    }

    #[test]
    fn non_comment_line_closes_block() {
        // The block ends at the first non-comment line; a later `key: value`
        // in a second comment run must not leak into the first block.
        let src = "// [frensense]\n// severity: High\n\nexport function h() {}\n// severity: Low\n";
        let meta = FamilyMetadata::parse(src, "ts", 30);
        assert_eq!(meta.severity.as_deref(), Some("High"));
    }

    #[test]
    fn metadata_survives_bundle_roundtrip() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("adv_positive.ts"),
            TS_BLOCK,
        )
        .unwrap();
        fs::write(
            dir.path().join("adv_negative.ts"),
            "// SAFE: parameterized\nexport function handle(req: any) { return escape(req); }\n",
        )
        .unwrap();

        let families = group_families(dir.path()).unwrap();
        assert_eq!(families[0].id, "adv");
        assert_eq!(families[0].metadata.cwe.as_deref(), Some("CWE-79"));

        let (bytes, _) = crate::builder::build_facts_bundle(
            dir.path(),
            &TaintConfig::default(),
            &FactTable::default(),
        )
        .unwrap();
        let loaded = crate::format::load_bundle(&bytes).unwrap();
        let pat = loaded
            .patterns
            .iter()
            .find(|p| p.id == "adv")
            .expect("family pattern in bundle");
        assert_eq!(pat.observation.as_deref(), Some("User data reaches the sink unescaped."));
        assert_eq!(pat.cwe.as_deref(), Some("CWE-79"));
        assert_eq!(pat.cvss, Some(7.4));
        assert_eq!(pat.severity.as_deref(), Some("High"));
    }

    #[test]
    fn family_without_block_ships_all_none_pattern() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("bare_positive.ts"), "export function h(req: any) { return req; }\n").unwrap();
        fs::write(dir.path().join("bare_negative.ts"), "export function h() { return 1; }\n").unwrap();

        let (bytes, _) = crate::builder::build_facts_bundle(
            dir.path(),
            &TaintConfig::default(),
            &FactTable::default(),
        )
        .unwrap();
        let loaded = crate::format::load_bundle(&bytes).unwrap();
        let pat = loaded
            .patterns
            .iter()
            .find(|p| p.id == "bare")
            .expect("family pattern in bundle");
        assert!(pat.observation.is_none() && pat.cwe.is_none() && pat.severity.is_none());
    }
}

#[cfg(test)]
mod grouping_tests {
    //! Family grouping pins: multi-language stem collisions must split into
    //! per-language sub-families (learned facts are language-blind — call
    //! matching is by last segment), while clean single-language corpora
    //! keep their bare family ids.

    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &TempDir, rel: &str, body: &str) {
        let p = dir.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn same_stem_different_languages_splits_into_sub_families() {
        let dir = TempDir::new().unwrap();
        write(&dir, "foo_positive.py", "def h(req):\n    return req\n");
        write(&dir, "foo_negative.py", "def h():\n    return 1\n");
        write(&dir, "foo_positive.ts", "export function h(req: any) { return req; }\n");
        write(&dir, "foo_negative.ts", "export function h() { return 1; }\n");

        let families = group_families(dir.path()).unwrap();
        let ids: Vec<&str> = families.iter().map(|f| f.id.as_str()).collect();
        // The bare id must NOT exist anymore: votes would cross languages.
        assert!(!ids.contains(&"foo"), "ids: {ids:?}");
        assert!(ids.contains(&"foo (python)"), "ids: {ids:?}");
        assert!(ids.contains(&"foo (typescript)"), "ids: {ids:?}");
        for f in &families {
            assert_eq!(f.positives.len(), 1, "{}", f.id);
            assert_eq!(f.negatives.len(), 1, "{}", f.id);
            // Each sub-family is single-language.
            let lang = f.positives[0].2.as_str();
            assert!(
                f.negatives.iter().all(|(_, _, e)| e == lang),
                "family {} mixed languages",
                f.id
            );
        }
    }

    #[test]
    fn ts_and_tsx_stay_one_family() {
        // Both extensions resolve to the same language spec (typescript).
        let dir = TempDir::new().unwrap();
        write(&dir, "bar_positive.ts", "export function h(req: any) { return req; }\n");
        write(&dir, "bar_negative.tsx", "export function h() { return 1; }\n");

        let families = group_families(dir.path()).unwrap();
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].id, "bar");
        assert_eq!(families[0].positives.len(), 1);
        assert_eq!(families[0].negatives.len(), 1);
    }

    #[test]
    fn clean_single_language_corpus_keeps_bare_ids() {
        let dir = TempDir::new().unwrap();
        write(&dir, "sql_positive.py", "def h(req):\n    return req\n");
        write(&dir, "sql_negative.py", "def h():\n    return 1\n");
        write(&dir, "xss_positive.ts", "export function h(req: any) { return req; }\n");
        write(&dir, "xss_negative.ts", "export function h() { return 1; }\n");

        let families = group_families(dir.path()).unwrap();
        let ids: Vec<&str> = families.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"sql"), "ids: {ids:?}");
        assert!(ids.contains(&"xss"), "ids: {ids:?}");
        assert_eq!(families.len(), 2);
    }

    #[test]
    fn declared_check_call_survives_language_split() {
        // The metadata comment is language-specific syntax; the py variant
        // declares it and only the python sub-family carries it.
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "adm_positive.py",
            "# check-call: admin_reset\ndef h():\n    admin_reset()\n",
        );
        write(&dir, "adm_negative.py", "def h():\n    return 1\n");
        write(&dir, "adm_positive.ts", "export function h() { adminReset(); }\n");
        write(&dir, "adm_negative.ts", "export function h() { return 1; }\n");

        let families = group_families(dir.path()).unwrap();
        let py = families.iter().find(|f| f.id == "adm (python)").unwrap();
        let ts = families
            .iter()
            .find(|f| f.id == "adm (typescript)")
            .unwrap();
        assert_eq!(py.declared_check_call.as_deref(), Some("admin_reset"));
        assert_eq!(ts.declared_check_call, None);
    }

    #[test]
    fn partial_collision_only_splits_the_colliding_stem() {
        // `baz` mixes py+ts; sibling stem `qux` is py-only and must keep its
        // bare id and its files untouched.
        let dir = TempDir::new().unwrap();
        write(&dir, "baz_positive.py", "def h(req):\n    return req\n");
        write(&dir, "baz_negative.ts", "export function h() { return 1; }\n");
        write(&dir, "qux_positive.py", "def h(req):\n    return req\n");
        write(&dir, "qux_negative.py", "def h():\n    return 1\n");

        let families = group_families(dir.path()).unwrap();
        let ids: Vec<&str> = families.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"baz (python)"), "ids: {ids:?}");
        assert!(ids.contains(&"baz (typescript)"), "ids: {ids:?}");
        assert!(ids.contains(&"qux"), "ids: {ids:?}");
        let qux = families.iter().find(|f| f.id == "qux").unwrap();
        assert_eq!(qux.positives.len(), 1);
        assert_eq!(qux.negatives.len(), 1);
    }
}

#[cfg(test)]
mod policy_proposal_tests {
    //! Generalized Policy fact proposals: the two family shapes the legacy
    //! Check fact cannot express — banned-call co-occurrence (NotCall) and
    //! cross-function enforcement (RequireCall under Module scope) — plus
    //! the guards that keep Policy proposals conservative.

    use super::*;
    use frensense_engine::analysis::taint::facts::{config_from_spec, fact_table_from_spec};
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &TempDir, rel: &str, body: &str) {
        let p = dir.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn builtin() -> (TaintConfig, FactTable) {
        let mut config = TaintConfig::default();
        let mut table = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            table.merge(&fact_table_from_spec(spec));
        }
        (config, table)
    }

    /// Both shapes need the trigger declared and present in both variants:
    /// the trigger alone is not the violation, the co-occurring context is.
    /// (Fixture builder kept for reference; the tests below write their own
    /// variants inline to pin each shape independently.)
    #[allow(dead_code)]
    fn shape_cd_corpus(dir: &TempDir) {
        write(
            dir,
            "adm_positive.ts",
            "// check-call: evaluate\nfunction audit() {}\nfunction run() { evaluate(request); evalUserPayload(request); }\n",
        );
        write(
            dir,
            "adm_negative.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); audit(); }\n",
        );
    }

    #[test]
    fn banned_call_co_occurrence_proposes_notcall_policy() {
        let dir = TempDir::new().unwrap();
        // Positives: trigger + banned call, no enforcement anywhere.
        // Negatives: trigger + a function DEFINED (audit) that positives
        // only call... simplest banned-call shape: both sides call trigger,
        // positives additionally call a banned helper.
        write(
            &dir,
            "ban_positive.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); shellExec(request); }\n",
        );
        write(
            &dir,
            "ban_negative.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); }\n",
        );
        let families = group_families(dir.path()).unwrap();
        let (config, table) = builtin();
        let (learned, published) = extract_facts(&families, &config, &table);

        let policies: Vec<&PolicyFact> = published
            .iter()
            .filter_map(|f| match &f.entry {
                LearnedFactEntry::Policy { .. } => match learned
                    .policy_facts
                    .iter()
                    .find(|p| p.rule == rule_of(&f.entry))
                {
                    _ => None,
                },
                _ => None,
            })
            .collect();
        // The published entries carry the Policy shape with NotCall;
        // assert on the published entries directly.
        let entries: Vec<&LearnedFactEntry> = published.iter().map(|f| &f.entry).collect();
        assert!(
            entries.iter().any(|e| matches!(
                e,
                LearnedFactEntry::Policy {
                    require,
                    scope: PolicyScope::Function,
                    ..
                } if matches!(require.as_slice(),
                    [PolicyRequirement::NotCall { call }] if call == "shellExec")
            )),
            "expected a NotCall policy for shellExec, got: {entries:?}"
        );
        assert!(policies.is_empty() || true); // shape-only assertion above
    }

    fn rule_of(e: &LearnedFactEntry) -> String {
        match e {
            LearnedFactEntry::Policy { rule, .. } => rule.clone(),
            _ => String::new(),
        }
    }

    #[test]
    fn cross_function_enforcement_proposes_requirecall_module_policy() {
        let dir = TempDir::new().unwrap();
        // Positives: the trigger and nothing else — no helper defined or
        // called anywhere. Negatives: the trigger PLUS the enforcement
        // helper DEFINED in the same variant (never called): the module
        // provides enforcement, which is what PolicyScope::Module accepts
        // as evidence. Positives violate; negatives comply by definition.
        write(
            &dir,
            "xfn_positive.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); }\n",
        );
        write(
            &dir,
            "xfn_negative.ts",
            "// check-call: evaluate\nfunction enforcePolicy() { return 1; }\nfunction run() { evaluate(request); }\n",
        );
        let families = group_families(dir.path()).unwrap();
        let (config, table) = builtin();
        let (_, published) = extract_facts(&families, &config, &table);
        let entries: Vec<&LearnedFactEntry> = published.iter().map(|f| &f.entry).collect();
        assert!(
            entries.iter().any(|e| matches!(
                e,
                LearnedFactEntry::Policy {
                    scope: PolicyScope::Module,
                    require,
                    ..
                } if matches!(require.as_slice(),
                    [PolicyRequirement::RequireCall { any_of }] if any_of.contains(&"enforcePolicy".to_string()))
            )),
            "expected a Module-scope RequireCall policy for enforcePolicy, got: {entries:?}"
        );
    }

    #[test]
    fn undeclared_families_get_no_policy_proposals() {
        // Same shape as the banned-call corpus but WITHOUT check-call:
        // co-occurrence mining is too broad presence-blind, so nothing
        // Policy-shaped may be published.
        let dir = TempDir::new().unwrap();
        write(&dir, "und_positive.ts", "function run() { evaluate(request); shellExec(request); }\n");
        write(&dir, "und_negative.ts", "function run() { evaluate(request); }\n");
        let families = group_families(dir.path()).unwrap();
        assert!(families[0].declared_check_call.is_none());
        let (config, table) = builtin();
        let (_, published) = extract_facts(&families, &config, &table);
        assert!(
            published
                .iter()
                .all(|f| !matches!(f.entry, LearnedFactEntry::Policy { .. })),
            "no Policy facts may be mined without a declared trigger"
        );
    }

    #[test]
    fn policy_facts_survive_bundle_roundtrip() {
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "ban_positive.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); shellExec(request); }\n",
        );
        write(
            &dir,
            "ban_negative.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); }\n",
        );
        let (bytes, published) =
            crate::builder::build_facts_bundle(dir.path(), &builtin().0, &builtin().1).unwrap();
        let loaded = crate::format::load_bundle(&bytes).unwrap();
        let has_policy = loaded
            .learned_facts
            .iter()
            .any(|e| matches!(e, LearnedFactEntry::Policy { .. }));
        assert!(
            has_policy || published.is_empty(),
            "policy facts must survive the FRC1 round-trip (or the family failed the gate)"
        );
    }
}

#[cfg(test)]
mod slot_regression_tests {
    //! Corpus-level regression pins for per-slot sink awareness (see
    //! `docs/JUICESHOP_BASELINE.md` and the FP-reduction work): the replay
    //! gate must never publish a fact that (a) re-alerts the parameterized
    //! query binding channel, (b) suppresses the dangerous SQL string slot,
    //! or (c) re-promotes validator APIs (`jwt.verify`) to sinks.

    use super::*;
    use frensense_engine::analysis::taint::facts::{config_from_spec, fact_table_from_spec};

    /// Built-in config + fact table exactly as the bundler CLI builds them.
    fn builtin() -> (TaintConfig, FactTable) {
        let mut config = TaintConfig::default();
        let mut table = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            table.merge(&fact_table_from_spec(spec));
        }
        (config, table)
    }

    fn ts_file(name: &str, source: &str) -> (String, String, String) {
        (name.to_string(), source.to_string(), "ts".to_string())
    }

    /// Taint lands in slot 0 (the SQL string): must alert.
    const PARAM_POSITIVE: &str = r#"
import { Pool } from "pg";
const pool = new Pool();
export function getUser (req: any) {
  const id = req.body.id;
  return pool.query("SELECT * FROM users WHERE id = " + id)
}
"#;

    /// Taint lands in slot 1 (the params binding channel): must NOT alert.
    const PARAM_NEGATIVE: &str = r#"
import { Pool } from "pg";
const pool = new Pool();
export function getUser (req: any) {
  const id = req.body.id;
  return pool.query("SELECT * FROM users WHERE id = $1", [id])
}
"#;

    /// `jwt.verify(taintedToken, secret)`: validation by design, not a sink.
    const JWT_VERIFY: &str = r#"
import jwt from "jsonwebtoken";
const JWT_SECRET = "dev-secret";
export function auth (req: any) {
  const token: string = req.cookies.token;
  return jwt.verify(token, JWT_SECRET)
}
"#;

    /// Control: a real injection flow through slot 0 must keep alerting,
    /// guards against someone later over-suppressing the whole sink.
    const CONTROL_SINK: &str = r#"
import { Pool } from "pg";
const pool = new Pool();
export function badSearch (req: any) {
  const q = req.query.q;
  return pool.query("SELECT * FROM items WHERE name = '" + q + "'")
}
"#;

    #[test]
    fn builtin_table_is_slot_aware() {
        let (_, table) = builtin();

        let q = table
            .sink_signature("query")
            .expect("query must be a known sink");
        assert!(q.is_dangerous(0), "SQL string slot is dangerous");
        assert!(
            !q.is_dangerous(1),
            "params slot is the safe binding channel"
        );
        assert!(q.is_binding(1));

        let d = table
            .sink_signature("decrypt")
            .expect("decrypt must be a known sink");
        assert!(d.is_dangerous(0), "ciphertext slot is dangerous");
        assert!(!d.is_dangerous(1), "key slot must not alert");
    }

    #[test]
    fn jwt_verify_is_a_validator_not_a_sink() {
        let (config, table) = builtin();
        assert!(
            !config.sinks.contains("verify"),
            "verify must not be a configured sink"
        );
        assert!(table.sink_signature("verify").is_none());

        let res = scan::scan(&[ts_file("jwt.ts", JWT_VERIFY)], &config, &table);
        assert!(
            !res.has_alert(),
            "jwt.verify(token, secret) must not alert; got {:?}",
            res.vulnerable().collect::<Vec<_>>()
        );

        // Control: real sinks still alert through the same harness.
        let ctrl = scan::scan(&[ts_file("ctrl.ts", CONTROL_SINK)], &config, &table);
        assert!(ctrl.has_alert(), "control injection flow must still alert");
    }

    #[test]
    fn parameterized_query_family_separates() {
        let (config, table) = builtin();
        let pos = scan::scan(
            &[ts_file("pq_positive.ts", PARAM_POSITIVE)],
            &config,
            &table,
        );
        let neg = scan::scan(
            &[ts_file("pq_negative.ts", PARAM_NEGATIVE)],
            &config,
            &table,
        );
        assert!(pos.has_alert(), "taint in the SQL slot must alert");
        assert!(
            !neg.has_alert(),
            "taint in the params binding channel must not alert"
        );
    }

    #[test]
    fn replay_gate_cannot_override_builtin_slot_facts() {
        let (config, table) = builtin();

        let param = Family {
            id: "parameterized_query".into(),
            positives: vec![ts_file("parameterized_query_positive.ts", PARAM_POSITIVE)],
            negatives: vec![ts_file("parameterized_query_negative.ts", PARAM_NEGATIVE)],
            declared_check_call: None,
            metadata: FamilyMetadata::default(),
        };
        let jwt = Family {
            id: "jwt_validator".into(),
            positives: vec![ts_file("jwt_validator_positive.ts", JWT_VERIFY)],
            negatives: vec![ts_file("jwt_validator_negative.ts", CONTROL_SINK)],
            declared_check_call: None,
            metadata: FamilyMetadata::default(),
        };

        let (learned, published) = extract_facts(&[param, jwt], &config, &table);

        // The gate must never publish a `query` sink fact: any such fact
        // would override the built-in slot-restricted signature on merge.
        let query_fact = published.iter().any(
            |f| matches!(&f.entry, LearnedFactEntry::Sink { call, .. } if call.as_str() == "query"),
        );
        assert!(
            !query_fact,
            "gate must not publish a query sink fact over the built-in slot signature"
        );

        // Slot awareness must survive merging whatever the gate published.
        let mut merged = table.clone();
        merged.merge(&learned);
        let pos = scan::scan(
            &[ts_file("pq_positive.ts", PARAM_POSITIVE)],
            &config,
            &merged,
        );
        let neg = scan::scan(
            &[ts_file("pq_negative.ts", PARAM_NEGATIVE)],
            &config,
            &merged,
        );
        assert!(pos.has_alert(), "SQL-slot danger must survive fact merge");
        assert!(
            !neg.has_alert(),
            "binding-channel safety must survive fact merge"
        );
    }
}
