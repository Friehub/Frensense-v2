// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! `frensense capabilities`: what the engine can model, as data.
//!
//! Corpus curation is faster when the engine decides first. This module
//! answers, without scanning anything, "which sinks, sources, sanitizers and
//! check rules exist in language X, and can the engine express CWE Y at all?"
//! It reads two shipped truths and invents nothing:
//!
//! * the embedded default pack
//!   ([`frensense_bundler::format::default_pack`]) - the same 1.7k learned
//!   facts the engine seeds every scan with, grouped by language and role;
//! * the built-in rule cards ([`frensense_lang::rule_card`]) - the class
//!   catalogue and its CWE ids, plus [`taint_class_for_cwe`], which says
//!   whether a CWE resolves to a taint class at all.
//!
//! Sink entries carry a role, not a class (the pack stores roles and
//! guard styles, never families), so per-class availability is the join
//! "sinks in the role this class consumes, in this language", materialised on
//! every class row as `sinks_by_language`. That is exactly the quantity a
//! corpus author needs ("what can this class see in Python?"): a family whose
//! sink role has zero entries in its language cannot teach anything, and a
//! reader no longer has to join the class row to the language block. Nothing
//! here scans, writes, or mutates.

use std::collections::{BTreeMap, BTreeSet};

use frensense_bundler::format::{default_pack, default_pack_blake3_hex};
use frensense_engine::analysis::taint::facts::LearnedFactEntry;
use frensense_lang::rule_card::{all_cards, cwe_url, taint_card, taint_class_for_cwe, taint_slugs};
use frensense_lang::severity::SinkRole;
use serde_json::{Value, json};

#[path = "capabilities_render.rs"]
mod render_report;
pub use render_report::render;

/// The snake_case role of a pack entry's role string, dropping any legacy
/// `role:label` suffix.
fn role_of(raw: &str) -> String {
    raw.split_once(':')
        .map_or(raw, |(role, _)| role)
        .to_string()
}

/// The wire name of a [`SinkRole`].
fn role_name(role: SinkRole) -> &'static str {
    match role {
        SinkRole::Execution => "execution",
        SinkRole::Resource => "resource",
        SinkRole::Storage => "storage",
        SinkRole::Crypto => "crypto",
        SinkRole::Response => "response",
        SinkRole::Xss => "xss",
        SinkRole::Validation => "validation",
        SinkRole::Other => "other",
    }
}

/// A sink entry's dangerous argument slots: `(call, package, slots, binding-safe)`.
type SinkSlotRow = (String, Option<String>, Vec<usize>, bool);

/// A source pattern with its package qualification.
type SourceRow = (String, Option<String>);

/// A sanitizing call: `(call, package, guard-style)`.
type SanitizerRow = (String, Option<String>, bool);

/// One language's slice of the pack.
#[derive(Debug, Default)]
struct LangVocab {
    /// Role name -> sink call names, sorted and deduplicated.
    sinks: BTreeMap<String, BTreeSet<String>>,
    /// Per-slot sink rules (`LanguageSinkSlots`), which refine a sink's
    /// dangerous argument positions.
    sink_slots: Vec<SinkSlotRow>,
    /// Sink calls the pack marks global-only (the call name is too generic
    /// to fire without a package qualifier).
    global_only_sinks: usize,
    /// Source patterns, with their package qualification.
    sources: Vec<SourceRow>,
    /// Sanitizer kind -> sanitizing calls (with guard style).
    sanitizers: BTreeMap<String, Vec<SanitizerRow>>,
    /// Propagator calls.
    propagators: BTreeSet<String>,
    /// IDOR finder sinks.
    idor_sinks: BTreeSet<String>,
    /// Route-registration patterns.
    routes: usize,
    /// Session-root accessors.
    session_roots: usize,
    /// Entries of a kind this report does not break out.
    other: usize,
}

impl LangVocab {
    fn push_sink(&mut self, role: &str, call: &str) {
        self.sinks
            .entry(role_of(role))
            .or_default()
            .insert(call.to_string());
    }

    fn sink_count(&self) -> usize {
        self.sinks.values().map(BTreeSet::len).sum()
    }

    fn sanitizer_count(&self) -> usize {
        self.sanitizers.values().map(Vec::len).sum()
    }
}

/// Fold one pack entry into a language bucket. Returns `false` when the entry
/// is not language-keyed (the language-agnostic variants are counted in the
/// global block instead).
fn apply_language_entry(vocab: &mut LangVocab, entry: &LearnedFactEntry) -> bool {
    match entry {
        LearnedFactEntry::LanguageSink { call, role, .. } => {
            vocab.push_sink(role, call);
            true
        }
        LearnedFactEntry::LanguageSinkSlots {
            call,
            package,
            dangerous_args,
            binding_args_safe,
            ..
        } => {
            vocab.sink_slots.push((
                call.clone(),
                package.clone(),
                dangerous_args.iter().copied().collect(),
                *binding_args_safe,
            ));
            true
        }
        LearnedFactEntry::LanguageSinkGlobalOnly { call, .. } => {
            vocab.global_only_sinks += 1;
            let _ = call;
            true
        }
        LearnedFactEntry::LanguageSource {
            pattern, package, ..
        } => {
            vocab.sources.push((pattern.clone(), package.clone()));
            true
        }
        LearnedFactEntry::LanguageSanitizer {
            call,
            package,
            kind,
            guard_style,
            ..
        } => {
            vocab.sanitizers.entry(kind.clone()).or_default().push((
                call.clone(),
                package.clone(),
                *guard_style,
            ));
            true
        }
        LearnedFactEntry::LanguagePropagator { call, .. } => {
            vocab.propagators.insert(call.clone());
            true
        }
        LearnedFactEntry::LanguageIdorSink { call, .. } => {
            vocab.idor_sinks.insert(call.clone());
            true
        }
        LearnedFactEntry::LanguageRoutePattern { .. } => {
            vocab.routes += 1;
            true
        }
        LearnedFactEntry::LanguageSessionRoot { .. } => {
            vocab.session_roots += 1;
            true
        }
        _ => false,
    }
}

/// The language key an entry is filed under, if it is language-keyed.
fn entry_language(entry: &LearnedFactEntry) -> Option<&str> {
    match entry {
        LearnedFactEntry::LanguageSink { language, .. }
        | LearnedFactEntry::LanguageSinkSlots { language, .. }
        | LearnedFactEntry::LanguageSinkGlobalOnly { language, .. }
        | LearnedFactEntry::LanguageSource { language, .. }
        | LearnedFactEntry::LanguageSanitizer { language, .. }
        | LearnedFactEntry::LanguagePropagator { language, .. }
        | LearnedFactEntry::LanguageIdorSink { language, .. }
        | LearnedFactEntry::LanguageRoutePattern { language, .. }
        | LearnedFactEntry::LanguageSessionRoot { language, .. } => Some(language),
        _ => None,
    }
}

/// How many facts of each kind the pack carries, for the identity block.
#[derive(Debug, Default)]
struct PackCounts {
    sources: usize,
    sinks: usize,
    sanitizers: usize,
    policies: usize,
    checks: usize,
    memory_contracts: usize,
    propagators: usize,
    other: usize,
}

impl PackCounts {
    fn total(&self) -> usize {
        self.sources
            + self.sinks
            + self.sanitizers
            + self.policies
            + self.checks
            + self.memory_contracts
            + self.propagators
            + self.other
    }
}

fn count_global(counts: &mut PackCounts, entry: &LearnedFactEntry) {
    match entry {
        LearnedFactEntry::Source { .. } => counts.sources += 1,
        LearnedFactEntry::Sink { .. } => counts.sinks += 1,
        LearnedFactEntry::Sanitizer { .. } => counts.sanitizers += 1,
        LearnedFactEntry::Policy { .. } | LearnedFactEntry::PolicyScoped { .. } => {
            counts.policies += 1;
        }
        LearnedFactEntry::Check { .. } => counts.checks += 1,
        LearnedFactEntry::MemoryContract { .. }
        | LearnedFactEntry::Allocator { .. }
        | LearnedFactEntry::Deallocator { .. } => counts.memory_contracts += 1,
        LearnedFactEntry::Propagator { .. } | LearnedFactEntry::LanguagePropagator { .. } => {
            counts.propagators += 1;
        }
        LearnedFactEntry::LanguageSource { .. } => counts.sources += 1,
        LearnedFactEntry::LanguageSink { .. }
        | LearnedFactEntry::LanguageSinkSlots { .. }
        | LearnedFactEntry::LanguageSinkGlobalOnly { .. } => counts.sinks += 1,
        LearnedFactEntry::LanguageSanitizer { .. } => counts.sanitizers += 1,
        _ => counts.other += 1,
    }
}

/// One row of the class catalogue: a built-in rule card, its kind, the CWE
/// ids it names, and (for dataflow classes) the sink role it consumes.
#[derive(Debug, Clone)]
struct ClassRow {
    id: &'static str,
    slug: String,
    kind: &'static str,
    title: &'static str,
    role: Option<SinkRole>,
    cwe: Vec<&'static str>,
}

fn class_rows() -> Vec<ClassRow> {
    let mut rows = Vec::new();
    for slug in taint_slugs() {
        let card = taint_card(Some(slug), SinkRole::Other, false);
        // The two fallback cards name no vulnerability class.
        if card.is_generic() {
            continue;
        }
        let cwe: Vec<&'static str> = card.cwe.to_vec();
        let role = cwe
            .first()
            .and_then(|id| taint_class_for_cwe(id))
            .map(|(role, _)| role);
        rows.push(ClassRow {
            id: card.id,
            slug: slug.to_string(),
            kind: "taint",
            title: card.title,
            role,
            cwe,
        });
    }
    for card in all_cards().filter(|c| c.id.starts_with("check.")) {
        rows.push(ClassRow {
            id: card.id,
            slug: card.id.trim_start_matches("check.").to_string(),
            kind: "check",
            title: card.title,
            role: None,
            cwe: card.cwe.to_vec(),
        });
    }
    rows
}

/// The `cwe` block: every CWE a built-in card names, with how it is
/// expressible.
fn cwe_table(rows: &[ClassRow]) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for row in rows {
        for id in &row.cwe {
            out.entry((*id).to_string()).or_insert_with(|| {
                json!({
                    "cwe": id,
                    "expressible": true,
                    "via": row.kind,
                    "class": row.id,
                    "role": row.role.map(role_name),
                    "url": cwe_url(id),
                })
            });
        }
    }
    out
}

/// The join a caller would otherwise do: for one class row, how many sink
/// calls of its role's vocabulary exist in each language (empty for check
/// rules, which consume no sink role).
fn sinks_by_language(row: &ClassRow, langs: &BTreeMap<String, LangVocab>) -> Value {
    let Some(role) = row.role.map(role_name) else {
        return json!({});
    };
    langs
        .iter()
        .map(|(name, vocab)| {
            (
                name.clone(),
                json!(vocab.sinks.get(role).map_or(0, BTreeSet::len)),
            )
        })
        .collect()
}

/// One language's JSON block: sinks by role, sources, sanitizers by kind,
/// propagators and the remaining vocabularies.
fn language_report(vocab: &LangVocab) -> Value {
    let mut by_role = serde_json::Map::new();
    // `sinks` is a BTreeMap, so this is already one row per wire role name in
    // a stable order; no separate role list to keep in step with the pack.
    for (role, calls) in &vocab.sinks {
        by_role.insert(
            role.clone(),
            json!({
                "total": calls.len(),
                "calls": calls.iter().collect::<Vec<_>>(),
            }),
        );
    }
    let mut sanitizer_kinds = serde_json::Map::new();
    for (kind, entries) in &vocab.sanitizers {
        sanitizer_kinds.insert(
            kind.clone(),
            json!({
                "total": entries.len(),
                "calls": entries
                    .iter()
                    .map(|(call, package, guard_style)| json!({
                        "call": call,
                        "package": package,
                        "guard_style": guard_style,
                    }))
                    .collect::<Vec<_>>(),
            }),
        );
    }
    let sink_slots: Vec<Value> = vocab
        .sink_slots
        .iter()
        .map(|(call, package, args, safe)| {
            json!({
                "call": call,
                "package": package,
                "dangerous_args": args,
                "binding_args_safe": safe,
            })
        })
        .collect();
    let sources: Vec<Value> = vocab
        .sources
        .iter()
        .map(|(pattern, package)| json!({"pattern": pattern, "package": package}))
        .collect();
    json!({
        "sinks": {
            "total": vocab.sink_count(),
            "by_role": by_role,
            "slots": sink_slots,
            "global_only": vocab.global_only_sinks,
        },
        "sources": {"total": vocab.sources.len(), "patterns": sources},
        "sanitizers": {
            "total": vocab.sanitizer_count(),
            "by_kind": sanitizer_kinds,
        },
        "propagators": {
            "total": vocab.propagators.len(),
            "calls": vocab.propagators.iter().collect::<Vec<_>>(),
        },
        "idor_sinks": vocab.idor_sinks.iter().collect::<Vec<_>>(),
        "routes": vocab.routes,
        "session_roots": vocab.session_roots,
        "other": vocab.other,
    })
}

/// Build the whole capabilities report.
#[must_use]
pub fn report() -> Value {
    let pack = default_pack();
    let mut counts = PackCounts::default();
    let mut langs: BTreeMap<String, LangVocab> = BTreeMap::new();

    for entry in &pack.learned_facts {
        count_global(&mut counts, entry);
        if let Some(language) = entry_language(entry) {
            let vocab = langs.entry(language.to_string()).or_default();
            if !apply_language_entry(vocab, entry) {
                vocab.other += 1;
            }
        }
    }

    // Languages the engine has a parser for, even with no pack vocabulary:
    // a zero row is the answer a corpus author needs ("rust: 0 sinks").
    for spec in frensense_lang::all_specs() {
        langs.entry(spec.fact_language().to_string()).or_default();
    }

    let rows = class_rows();
    let cwes = cwe_table(&rows);

    let classes: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "slug": row.slug,
                "kind": row.kind,
                "title": row.title,
                "role": row.role.map(role_name),
                "sinks_by_language": sinks_by_language(row, &langs),
                "cwe": row.cwe,
            })
        })
        .collect();

    let languages: BTreeMap<String, Value> = langs
        .iter()
        .map(|(name, vocab)| (name.clone(), language_report(vocab)))
        .collect();

    json!({
        "schema_version": "1",
        "engine": {
            "version": crate::FRENSENSE_VERSION,
            "default_pack": {
                "blake3": default_pack_blake3_hex(),
                "facts": counts.total(),
                "sinks": counts.sinks,
                "sources": counts.sources,
                "sanitizers": counts.sanitizers,
                "policies": counts.policies,
                "checks": counts.checks,
                "memory_contracts": counts.memory_contracts,
                "propagators": counts.propagators,
                "other": counts.other,
            },
        },
        "languages": languages,
        "classes": classes,
        "cwe": cwes,
    })
}

/// The expressibility of one CWE id: the `cwe` entry when a built-in card
/// names it, otherwise the reason it cannot be authored against today.
#[must_use]
pub fn cwe_entry(report: &Value, cwe: &str) -> Value {
    let want = cwe.trim().to_ascii_uppercase();
    if let Some(entry) = report.get("cwe").and_then(|m| m.get(&want)) {
        return entry.clone();
    }
    json!({
        "expressible": false,
        "reason": "no built-in rule card names this CWE, so no family can report it yet",
        "cwe": want,
    })
}
