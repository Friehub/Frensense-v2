// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Bundle construction: corpus pairs → replay-verified facts → `.frc` bytes.

use crate::fact_extract::{extract_facts, group_families};
use crate::format::{
    write_bundle_pinned_with_trust, BundlePattern, BundlePayloadV8, BundleTrust, EngineRequirement,
};
use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{
    apply_language_entries, languages_for_exts, FactTable, LearnedFactEntry,
};
use frensense_engine::scan;

/// The per-fact cross-class canary gate.
///
/// A learned sanitizer is proven for the classes it names. For every other
/// class in which the same call is applied by a corpus family, the fact must
/// leave that family's vulnerable negative alerting: if it silences it, the
/// fact is cross-class and the build fails. This is the probe that would have
/// caught both sanitizer-collapse incidents automatically.
fn verify_sanitizer_class_scope(
    families: &[crate::fact_extract::Family],
    published: &[crate::fact_extract::LearnedFact],
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
            let exts: Vec<&str> = family
                .negatives
                .iter()
                .map(|(_, _, ext)| ext.as_str())
                .chain(family.positives.iter().map(|(_, _, ext)| ext.as_str()))
                .collect();
            let langs = languages_for_exts(exts);
            let mut config = TaintConfig::default();
            let mut facts = FactTable::default();
            apply_language_entries(
                &mut config,
                &mut facts,
                &crate::format::default_pack().learned_facts,
                &langs,
            );
            let baseline = scan::scan(&family.negatives, &config, &facts);
            if !crate::extract::gate::alerts(&baseline) {
                continue;
            }
            apply_language_entries(&mut config, &mut facts, &[entry.clone()], &langs);
            // The trial table must apply the same class scope a consumer
            // installs, or the probe would approve a fact that cuts another
            // class once loaded.
            facts.scope_sanitizer(call, package.as_deref(), classes);
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

/// §9 pipeline: corpus pairs → replay-verified learned facts → bundle bytes.
///
/// Returns the bundle plus a summary of the published facts for reporting.
pub fn build_facts_bundle(
    corpus_dir: &std::path::Path,
) -> Result<(Vec<u8>, Vec<crate::fact_extract::LearnedFact>), String> {
    build_facts_bundle_with_trust(corpus_dir, BundleTrust::Certified)
}

/// [`build_facts_bundle`] with an explicit trust tier. `Community` bundles
/// are filtered by [`crate::format::LoadedBundle::effective_learned_facts`]
/// on load exactly like any third-party bundle.
pub fn build_facts_bundle_with_trust(
    corpus_dir: &std::path::Path,
    trust: BundleTrust,
) -> Result<(Vec<u8>, Vec<crate::fact_extract::LearnedFact>), String> {
    let families = group_families(corpus_dir)?;
    eprintln!(
        "[facts] {} families grouped from {}",
        families.len(),
        corpus_dir.display()
    );

    let (learned_table, published) = extract_facts(&families);
    verify_sanitizer_class_scope(&families, &published)?;

    // Payload: one metadata pattern per family + the published facts.
    let mut entries: Vec<frensense_engine::analysis::taint::facts::LearnedFactEntry> =
        Vec::with_capacity(published.len());
    let mut policy_meta: Vec<crate::format::PolicyMeta> = Vec::new();
    let mut sanitizer_scopes: Vec<crate::format::SanitizerScope> = Vec::new();
    for f in &published {
        entries.push(f.entry.clone());
        // A policy's tier/lifecycle are authored family metadata. They ride in
        // the payload's `policy_meta` table rather than in a wire variant, so
        // the engine's `PolicyFact` keeps its published shape.
        if let LearnedFactEntry::Policy { rule, .. } | LearnedFactEntry::PolicyScoped { rule, .. } =
            &f.entry
        {
            let meta = f
                .families
                .iter()
                .filter_map(|id| families.iter().find(|fam| &fam.id == id))
                .map(|fam| &fam.metadata)
                .find(|m| m.tier.is_some() || m.status.is_some());
            if let Some(meta) = meta {
                policy_meta.push(crate::format::PolicyMeta {
                    rule: rule.clone(),
                    tier: meta.tier.clone().unwrap_or_default(),
                    status: meta.status.clone().unwrap_or_default(),
                });
            }
        }
        // A sanitizer's class scope and teaching family ride in the payload's
        // `sanitizer_scopes` table: the consumer applies the scope with
        // `FactTable::scope_sanitizer`, so the fact itself keeps the engine's
        // published shape.
        if let LearnedFactEntry::Sanitizer { call, package, .. }
        | LearnedFactEntry::LanguageSanitizer { call, package, .. } = &f.entry
        {
            if !f.classes.is_empty() || f.family.is_some() {
                sanitizer_scopes.push(crate::format::SanitizerScope {
                    call: call.clone(),
                    package: package.clone(),
                    classes: f.classes.clone(),
                    family: f.family.clone(),
                });
            }
        }
    }

    // Tier transparency: a non-certified bundle is filtered on load, so warn
    // at build time when facts it just verified will not ship.
    if !matches!(trust, BundleTrust::Certified) {
        let mut sanitizers = 0usize;
        let mut shippable = 0usize;
        for f in &published {
            let package = match &f.entry {
                LearnedFactEntry::Sanitizer { package, .. }
                | LearnedFactEntry::LanguageSanitizer { package, .. } => package,
                _ => continue,
            };
            sanitizers += 1;
            if trust.may_ship_sanitizer(&f.classes, package.as_deref()) {
                shippable += 1;
            }
        }
        if shippable < sanitizers {
            eprintln!(
                "[facts] trust {trust:?}: {shippable}/{sanitizers} sanitizer facts ship; the rest lack a \
                 package/receiver scope the tier requires",
            );
        }
    }

    // One advisory pattern per family, sorted by id for a deterministic
    // payload. Metadata comes from the family's `[frensense]` comment block
    // (parsed during grouping); families without a block ship all-None.
    // `rules` joins the pattern to the findings the family's published
    // facts cause (checker rule ids + learned sink names), so the consumer
    // can attach this metadata when one of those findings fires.
    let mut family_ids: Vec<String> = families.iter().map(|f| f.id.clone()).collect();
    family_ids.sort();
    let mut patterns: Vec<BundlePattern> = Vec::with_capacity(family_ids.len());
    let empty = crate::fact_extract::FamilyMetadata::default();
    for id in &family_ids {
        let family = families.iter().find(|f| f.id == *id);
        let meta = family.map(|f| &f.metadata).unwrap_or(&empty);
        let mut rules: Vec<String> = published
            .iter()
            .filter(|f| f.families.iter().any(|fam| fam == id))
            .flat_map(|f| f.entry.finding_identities())
            .collect();
        rules.sort();
        rules.dedup();
        patterns.push(BundlePattern {
            id: id.clone(),
            observation: meta.observation.clone(),
            impact: meta.impact.clone(),
            improvement: meta.improvement.clone(),
            cwe: meta.cwe.clone(),
            cvss: meta.cvss,
            owasp: meta.owasp.clone(),
            severity: meta.severity.clone(),
            rules,
        });
    }

    let count = entries.len().max(patterns.len()) as u32;
    // v6 payload; package-qualified provenance facts for LTS 0.7.0.
    let payload = BundlePayloadV8 {
        patterns,
        learned_facts: entries,
        policy_pack: Vec::new(),
        sanitizer_scopes,
        policy_meta,
    };
    let _ = learned_table;

    // A corpus bundle is meant to be handed to other people's scanners, so it
    // declares the engine series its families were replay-gated against.
    // Bundles without the range still load (the strict vocabulary fingerprint
    // is always checked), but a distribution that can say "this targets 0.9"
    // should.
    let engine = EngineRequirement::parse_triple(frensense_engine::VERSION).unwrap_or([0, 0, 0]);
    let bytes = write_bundle_pinned_with_trust(
        &payload,
        count,
        EngineRequirement::same_series(engine),
        trust,
    )?;
    Ok((bytes, published))
}
