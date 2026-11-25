// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Sanitizer qualification: which classes and which argument slots a learned
//! sanitizer fact ships with.
//!
//! Both qualifications ride in payload side tables rather than in a wire fact
//! variant (the engine's `SanitizerFact` keeps its shape), and both are proven
//! before they ship: the class scope by the cross-class canary, the slots by
//! the replay probe in [`probe_sanitizer_args`]. A fact is qualified exactly as
//! the consumer installs it, with `FactTable::qualify_sanitizer`.

use crate::format::{SanitizerArgScope, SanitizerScope};
use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{
    apply_language_entries, languages_for_exts, FactTable, LearnedFactEntry,
};
use frensense_engine::scan;
use std::collections::BTreeMap;

/// The per-fact cross-class canary gate.
///
/// A learned sanitizer is proven for the classes it names. For every other
/// class in which the same call is applied by a corpus family, the fact must
/// leave that family's vulnerable negative alerting: if it silences it, the
/// fact is cross-class and the build fails. This is the probe that would have
/// caught both sanitizer-collapse incidents automatically.
pub(crate) fn verify_sanitizer_class_scope(
    families: &[crate::fact_extract::Family],
    published: &[crate::fact_extract::LearnedFact],
    evidence: &BTreeMap<(String, Option<String>), Vec<usize>>,
) -> Result<(), String> {
    for fact in published {
        let (entry, call, package) = match &fact.entry {
            LearnedFactEntry::Sanitizer { call, package, .. }
            | LearnedFactEntry::LanguageSanitizer { call, package, .. } => {
                (&fact.entry, call, package)
            }
            _ => continue,
        };
        let classes = &fact.classes;
        if classes.is_empty() {
            return Err(format!(
                "sanitizer `{call}` has no class scope; refusing to publish a cross-class fact"
            ));
        }
        for family in families {
            let Some(class) = family.metadata.class.as_deref() else {
                continue;
            };
            if classes.iter().any(|c| c == class || c == "*") {
                continue;
            }
            // Only families in which the sanitizer is actually applied can
            // be a counter-probe, and only when the vulnerable twin would
            // alert without the fact.
            let applies = family
                .negatives
                .iter()
                .any(|(_, src, _)| src.contains(call.as_str()));
            if !applies {
                continue;
            }
            let (base_config, base_facts) = crate::fact_extract::family_tables(family);
            let baseline = scan::scan(&family.negatives, &base_config, &base_facts);
            if !crate::extract::gate::alerts(&baseline) {
                continue;
            }
            // The trial table must apply the same qualification a consumer
            // installs - class scope and the fact's argument slots - or the
            // probe would approve a fact that cuts more than the shipped one.
            let args = evidence
                .get(&(call.clone(), package.clone()))
                .cloned()
                .unwrap_or_default();
            let (config, facts) =
                family_probe_tables(family, entry, call, package.as_deref(), classes, &args);
            let probed = scan::scan(&family.negatives, &config, &facts);
            if !crate::extract::gate::alerts(&probed) {
                return Err(format!(
                    "cross-class sanitizer `{call}` (class(es): {}) silenced family `{}` \
                     (class {class}); a class-scoped fact must leave every other class alerting",
                    classes.join(", "),
                    family.id
                ));
            }
        }
    }
    Ok(())
}

/// The payload's sanitizer qualification tables: one class-scope entry and
/// one declared-slot entry per published sanitizer fact.
///
/// Both ride in side tables rather than in a wire fact variant, so the
/// engine's published `SanitizerFact` keeps its shape; the consumer applies
/// them with `FactTable::qualify_sanitizer`.
pub(crate) fn sanitizer_tables(
    published: &[crate::fact_extract::LearnedFact],
    evidence: &BTreeMap<(String, Option<String>), Vec<usize>>,
) -> (Vec<SanitizerScope>, Vec<SanitizerArgScope>) {
    let mut scopes = Vec::new();
    let mut arg_scopes = Vec::new();
    for fact in published {
        let (LearnedFactEntry::Sanitizer { call, package, .. }
        | LearnedFactEntry::LanguageSanitizer { call, package, .. }) = &fact.entry
        else {
            continue;
        };
        if !fact.classes.is_empty() || fact.family.is_some() {
            scopes.push(SanitizerScope {
                call: call.clone(),
                package: package.clone(),
                classes: fact.classes.clone(),
                family: fact.family.clone(),
            });
        }
        let args = evidence
            .get(&(call.clone(), package.clone()))
            .cloned()
            .unwrap_or_default();
        if !args.is_empty() {
            arg_scopes.push(SanitizerArgScope {
                call: call.clone(),
                package: package.clone(),
                args,
            });
        }
    }
    (scopes, arg_scopes)
}

/// The argument slots the families that taught `fact` declare for `call`
/// (`[frensense] sanitized-args:`), unioned and sorted.
///
/// A `sanitized-args` line describes its whole `[frensense]` block, so it
/// applies to the sanitizer calls that block names (`sanitizer:`); a block
/// that declares slots without naming a call speaks for every sanitizer the
/// family taught. Slots declared for a call the fact table did not publish are
/// dropped, not widened onto some other call.
fn declared_sanitizer_args(
    families: &[crate::fact_extract::Family],
    fact: &crate::fact_extract::LearnedFact,
    call: &str,
) -> Vec<usize> {
    let mut args: Vec<usize> = fact
        .families
        .iter()
        .filter_map(|id| families.iter().find(|fam| &fam.id == id))
        .filter(|fam| {
            fam.metadata.sanitizers.is_empty()
                || fam.metadata.sanitizers.iter().any(|name| name == call)
        })
        .flat_map(|fam| fam.metadata.sanitized_args.iter().copied())
        .collect();
    args.sort_unstable();
    args.dedup();
    args
}

/// The argument slots each published sanitizer fact ships, keyed by
/// `(call, package)`.
///
/// Authored `[frensense] sanitized-args:` lines are the primary evidence. A
/// fact whose families author none is **probed, not guessed**: the published
/// fact, narrowed to one slot, is replayed against the families that taught it,
/// and a slot that still silences their negatives is a slot the corpus itself
/// proves. A fact no probe pins keeps the legacy all-arguments reading, which is
/// the recall-safe direction - an unproven guard must never validate less than
/// it was shown to.
pub(crate) fn sanitizer_arg_evidence(
    families: &[crate::fact_extract::Family],
    published: &[crate::fact_extract::LearnedFact],
) -> BTreeMap<(String, Option<String>), Vec<usize>> {
    let mut out = BTreeMap::new();
    for fact in published {
        let (LearnedFactEntry::Sanitizer { call, package, .. }
        | LearnedFactEntry::LanguageSanitizer { call, package, .. }) = &fact.entry
        else {
            continue;
        };
        let mut args = declared_sanitizer_args(families, fact, call);
        if args.is_empty() {
            args = probe_sanitizer_args(families, fact, call, package.as_deref());
        }
        if !args.is_empty() {
            out.insert((call.clone(), package.clone()), args);
        }
    }
    out
}

/// The slots the families that taught `fact` prove for `call`.
///
/// The fact was published because, un-narrowed, it silences those families'
/// negatives while their positives still alert. Narrowed to one slot it must
/// keep doing so: that slot then carries the flow the guard suppresses, which
/// is exactly what `SanitizerFact::sanitizes_args` states. Three guards keep the
/// probe honest:
///
/// * only sanitizer entries are probed, and both styles narrow the same way:
///   a guard-style fact through the guard map, a transform fact through the
///   argument edges its cut covers;
/// * a family with no negatives proves nothing, and is skipped rather than
///   credited by a scan with nothing to alert on;
/// * a family whose negatives alert with **no** fact at all proves nothing
///   either, so its silence cannot be mistaken for the guard's doing.
///
/// The probe is exhaustive over the evidence, so its bound is the call's own
/// observed arity (see [`probe_bound`]) rather than a fixed number of slots.
fn probe_sanitizer_args(
    families: &[crate::fact_extract::Family],
    fact: &crate::fact_extract::LearnedFact,
    call: &str,
    package: Option<&str>,
) -> Vec<usize> {
    if !matches!(
        fact.entry,
        LearnedFactEntry::Sanitizer { .. } | LearnedFactEntry::LanguageSanitizer { .. }
    ) {
        return Vec::new();
    }
    let teaching: Vec<&crate::fact_extract::Family> = families
        .iter()
        .filter(|family| {
            !family.negatives.is_empty() && fact.families.iter().any(|id| id == &family.id)
        })
        .collect();
    if teaching.is_empty() {
        return Vec::new();
    }
    let Some(arity) = probe_bound(&teaching, call) else {
        return Vec::new();
    };
    // A family whose negatives alert with no fact at all proves nothing: its
    // silence later would not be the guard's doing. Resolve once per family,
    // not once per probed slot.
    let alerting: Vec<&crate::fact_extract::Family> = teaching
        .into_iter()
        .filter(|family| {
            let (config, facts) = crate::fact_extract::family_tables(family);
            crate::extract::gate::alerts(&scan::scan(&family.negatives, &config, &facts))
        })
        .collect();
    if alerting.is_empty() {
        return Vec::new();
    }
    (0..arity)
        .filter(|slot| {
            alerting.iter().all(|family| {
                let (config, facts) = family_probe_tables(
                    family,
                    &fact.entry,
                    call,
                    package,
                    &fact.classes,
                    &[*slot],
                );
                !crate::extract::gate::alerts(&scan::scan(&family.negatives, &config, &facts))
            })
        })
        .collect()
}

/// The slots worth probing for `call`: one per argument position the teaching
/// families are seen to pass.
///
/// A probe has to be exhaustive over its evidence. A slot it never tries is a
/// slot the shipped fact keeps validating - the probe's absence reads as the
/// legacy "all arguments" - so the walk must stop exactly where the observed
/// call sites stop passing arguments, not at a number chosen in advance: a
/// guard on a later argument of a wide call would otherwise be narrowed
/// silently to the first few. `None` means no sample calls `call` at all, and
/// then nothing is probed: arity the corpus never shows is not evidence.
fn probe_bound(families: &[&crate::fact_extract::Family], call: &str) -> Option<usize> {
    let files: Vec<(String, String, String)> = families
        .iter()
        .flat_map(|family| {
            family
                .negatives
                .iter()
                .chain(family.positives.iter())
                .cloned()
        })
        .collect();
    crate::extract::call_analysis::max_call_arity(&files, call)
}

/// A family's own tables (language spec + embedded pack) with `entry`
/// installed and the sanitizer qualified the way a consumer installs it: class
/// scope first, then the argument slots under test.
///
/// Extraction gates a fact under [`crate::fact_extract::family_tables`], so the
/// canary and the probe replay under the same tables; a trial under different
/// ones would approve a fact the corpus never saw.
fn family_probe_tables(
    family: &crate::fact_extract::Family,
    entry: &LearnedFactEntry,
    call: &str,
    package: Option<&str>,
    classes: &[String],
    args: &[usize],
) -> (TaintConfig, FactTable) {
    let (mut config, mut facts) = crate::fact_extract::family_tables(family);
    let exts: Vec<&str> = family
        .negatives
        .iter()
        .map(|(_, _, ext)| ext.as_str())
        .chain(family.positives.iter().map(|(_, _, ext)| ext.as_str()))
        .collect();
    let langs = languages_for_exts(exts);
    apply_language_entries(&mut config, &mut facts, std::slice::from_ref(entry), &langs);
    facts.qualify_sanitizer(call, package, classes, args);
    (config, facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_extract::{Family, FamilyMetadata, LearnedFact};
    use frensense_engine::analysis::taint::facts::LearnedFactEntry;

    fn family(id: &str, sanitizers: &[&str], args: &[usize]) -> Family {
        Family {
            id: id.to_string(),
            positives: Vec::new(),
            negatives: Vec::new(),
            declared_check_call: None,
            metadata: FamilyMetadata {
                sanitizers: sanitizers.iter().map(|s| (*s).to_string()).collect(),
                sanitized_args: args.to_vec(),
                ..FamilyMetadata::default()
            },
        }
    }

    fn fact(call: &str, families: &[&str]) -> LearnedFact {
        LearnedFact {
            entry: LearnedFactEntry::LanguageSanitizer {
                language: frensense_engine::analysis::taint::facts::languages_for_exts(["ts"])[0]
                    .to_string(),
                call: call.to_string(),
                package: None,
                kind: "allowlist".to_string(),
                guard_style: true,
            },
            classes: Vec::new(),
            family: families.first().map(|f| (*f).to_string()),
            support: 2,
            status: "confirmed".to_string(),
            families: families.iter().map(|f| (*f).to_string()).collect(),
        }
    }

    /// A `sanitized-args:` line describes its block, so it applies to the call
    /// that block names - and to nothing else.
    #[test]
    fn declared_slots_attach_to_the_calls_the_block_names() {
        let families = vec![family("f", &["check"], &[1])];
        assert_eq!(
            declared_sanitizer_args(&families, &fact("check", &["f"]), "check"),
            vec![1]
        );
        assert!(
            declared_sanitizer_args(&families, &fact("other", &["f"]), "other").is_empty(),
            "a block naming `check` says nothing about `other`"
        );
    }

    /// A family with real samples: a guard that validates the tainted value.
    fn sampled(id: &str, positive: &str, negative: &str) -> Family {
        Family {
            id: id.to_string(),
            positives: vec![("pos.ts".to_string(), positive.to_string(), "ts".to_string())],
            negatives: vec![("neg.ts".to_string(), negative.to_string(), "ts".to_string())],
            declared_check_call: None,
            metadata: FamilyMetadata {
                class: Some("inj.sql".to_string()),
                ..FamilyMetadata::default()
            },
        }
    }

    const UNGUARDED: &str =
        "export async function bad(req: any) {\n  const name = req.body.name\n  exec(name)\n}\n";

    /// `check(name)` validates the value it is handed: the family proves slot
    /// 0, so the producer publishes that instead of leaving the legacy
    /// all-arguments reading the engine used to assume.
    #[test]
    fn a_guard_family_proves_the_slot_it_checks() {
        let families = vec![sampled(
            "f",
            UNGUARDED,
            "export async function bad(req: any) {\n  const name = req.body.name\n  if (check(name)) {\n    exec(name)\n  }\n}\n",
        )];
        assert_eq!(
            probe_sanitizer_args(&families, &fact("check", &["f"]), "check", None),
            vec![0]
        );
    }

    /// The tainted value arrives in slot 1 and the guard is applied there: the
    /// probe follows the slot instead of assuming argument 0, which is the
    /// fabrication this evidence replaces.
    #[test]
    fn the_probe_follows_the_tainted_slot() {
        let families = vec![sampled(
            "f",
            UNGUARDED,
            "export async function bad(req: any) {\n  const name = req.body.name\n  if (check('literal', name)) {\n    exec(name)\n  }\n}\n",
        )];
        assert_eq!(
            probe_sanitizer_args(&families, &fact("check", &["f"]), "check", None),
            vec![1]
        );
    }

    /// A transform sanitizer's slots are proven too: `scrub(name, 'json')`
    /// neutralises the argument it is given, the family's negative is silent
    /// because of that, and the probe reports the slot it consumed rather than
    /// the whole call.
    #[test]
    fn a_transform_family_proves_the_argument_it_consumes() {
        let families = vec![sampled(
            "f",
            UNGUARDED,
            "export async function bad(req: any) {\n  const name = req.body.name\n  const safe = scrub(name, 'json')\n  exec(safe)\n}\n",
        )];
        let mut transform = fact("scrub", &["f"]);
        transform.entry = LearnedFactEntry::LanguageSanitizer {
            call: "scrub".to_string(),
            package: None,
            language: frensense_engine::analysis::taint::facts::languages_for_exts(["ts"])[0]
                .to_string(),
            kind: "encode".to_string(),
            guard_style: false,
        };
        assert_eq!(
            probe_sanitizer_args(&families, &transform, "scrub", None),
            vec![0],
            "the tainted value enters through argument 0, so that is the slot\n             the family proves"
        );
    }

    /// The probe bound is the call's observed arity, so a guard on a later
    /// argument of a wide call is still found instead of being left on the
    /// legacy reading by a fixed cap.
    #[test]
    fn a_slot_past_the_first_few_arguments_is_probed() {
        let families = vec![sampled(
            "f",
            UNGUARDED,
            "export async function bad(req: any) {\n  const name = req.body.name\n  if (check('a', 'b', 'c', 'd', name, 'e')) {\n    exec(name)\n  }\n}\n",
        )];
        assert_eq!(
            probe_sanitizer_args(&families, &fact("check", &["f"]), "check", None),
            vec![4]
        );
    }

    /// No sample calls the guard, so the corpus shows no arity and no slot is
    /// claimed: the fact keeps the legacy all-arguments reading.
    #[test]
    fn a_guard_no_sample_calls_proves_no_slot() {
        let families = vec![sampled("f", UNGUARDED, UNGUARDED)];
        assert!(probe_sanitizer_args(&families, &fact("check", &["f"]), "check", None).is_empty());
    }

    /// A block that declares slots without a `sanitizer:` name speaks for
    /// every sanitizer its family taught.
    #[test]
    fn a_block_without_a_sanitizer_name_speaks_for_its_family() {
        let families = vec![family("f", &[], &[2, 0, 2])];
        assert_eq!(
            declared_sanitizer_args(&families, &fact("scrub", &["f"]), "scrub"),
            vec![0, 2],
            "declared slots are unioned, sorted and deduplicated"
        );
    }
}
