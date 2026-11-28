// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! `frensense bundle info`: the bundle inspector.
//!
//! Owns the rendering so the binary's dispatch module stays a dispatcher;
//! the facts it reads come from `frensense_bundler::format::load_bundle`.

use frensense_engine::analysis::taint::facts::LearnedFactEntry;

/// Fact-category counts for the bundle-info display.
struct FactCounts {
    sources: usize,
    sinks: usize,
    sanitizers: usize,
    policies: usize,
    checks: usize,
    memory_contracts: usize,
    other: usize,
}

pub(crate) fn print_bundle_info(
    bundle_path: &std::path::Path,
    json: bool,
) -> std::result::Result<(), String> {
    let bytes = std::fs::read(bundle_path)
        .map_err(|e| format!("failed to read bundle {}: {e}", bundle_path.display()))?;
    let loaded = frensense_bundler::format::load_bundle(&bytes)
        .map_err(|e| format!("failed to deserialize bundle: {e}"))?;

    let magic_str = std::str::from_utf8(&loaded.header.magic).unwrap_or("????");
    let checksum_hex: String = loaded
        .header
        .checksum
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let mut counts = FactCounts {
        sources: 0,
        sinks: 0,
        sanitizers: 0,
        policies: 0,
        checks: 0,
        memory_contracts: 0,
        other: 0,
    };

    for fact in &loaded.learned_facts {
        match fact {
            LearnedFactEntry::Source { .. } | LearnedFactEntry::LanguageSource { .. } => {
                counts.sources += 1
            }
            LearnedFactEntry::Sink { .. }
            | LearnedFactEntry::LanguageSink { .. }
            | LearnedFactEntry::LanguageSinkSlots { .. } => counts.sinks += 1,
            LearnedFactEntry::Sanitizer { .. } | LearnedFactEntry::LanguageSanitizer { .. } => {
                counts.sanitizers += 1
            }
            LearnedFactEntry::Policy { .. } | LearnedFactEntry::PolicyScoped { .. } => {
                counts.policies += 1
            }
            LearnedFactEntry::Check { .. } => counts.checks += 1,
            LearnedFactEntry::MemoryContract { .. }
            | LearnedFactEntry::Allocator { .. }
            | LearnedFactEntry::Deallocator { .. } => counts.memory_contracts += 1,
            _ => counts.other += 1,
        }
    }

    if json {
        // The `--json` envelope mirrors the header's compatibility fields so
        // corpus tooling can assert on them without parsing prose. The
        // `engine` block names what *this* binary would check the bundle
        // against, so a diff between the two is a stale-bundle signal.
        let obj = serde_json::json!({
            "schema_version": frensense::REPORT_SCHEMA_VERSION,
            "path": bundle_path.display().to_string(),
            "magic": magic_str,
            "format_version": loaded.header.version,
            "legacy": loaded.header.is_legacy(),
            "payload_bytes": bytes.len(),
            "blake3_checksum": checksum_hex,
            "pattern_count": loaded.patterns.len(),
            "learned_facts": {
                "total": loaded.learned_facts.len(),
                "taint_sources": counts.sources,
                "taint_sinks": counts.sinks,
                "sanitizers": counts.sanitizers,
                "co_occurrence": counts.policies,
                "checks": counts.checks,
                "memory_contracts": counts.memory_contracts,
                "other": counts.other,
            },
            "authored_policies": loaded.policy_pack.len(),
            "sanitizers_withheld": loaded.withheld_sanitizers(),
            "vocabulary": loaded.header.vocabulary.map(|v| format!("{v:#018x}")),
            "requires_engine": loaded.header.requires_engine.map(|r| r.to_string()),
            "built_by_engine": loaded.header.built_by_engine,
            "engine": {
                "version": frensense::FRENSENSE_VERSION,
                "bundle_format": frensense_bundler::format::BUNDLE_VERSION,
                "fact_vocabulary": format!(
                    "{:#018x}",
                    frensense_engine::analysis::taint::facts::FACT_VOCABULARY_FINGERPRINT
                ),
            },
            "patterns": loaded.patterns.iter().map(|pat| serde_json::json!({
                "id": pat.id,
                "cwe": pat.cwe,
                "severity": pat.severity,
                "rules": pat.rules,
            })).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&obj).map_err(|e| format!("JSON error: {e}"))?
        );
        return Ok(());
    }

    println!("============================= Bundle Details =============================");
    println!("Path:               {}", bundle_path.display());
    println!("Magic:              {magic_str}");
    println!("Format Version:     v{}", loaded.header.version);
    println!("Payload Size:       {} bytes", bytes.len());
    println!("BLAKE3 Checksum:    {checksum_hex}");
    if let Some(vocab) = loaded.header.vocabulary {
        println!("Fact Vocabulary:    {vocab:#018x}");
    }
    if let Some(req) = loaded.header.requires_engine {
        println!("Requires Engine:    frensense {req}");
    }
    if let Some(built) = &loaded.header.built_by_engine {
        println!("Built By Engine:    frensense {built}");
    }
    println!("Pattern Count:      {}", loaded.patterns.len());
    println!("Learned Facts:      {}", loaded.learned_facts.len());
    println!("  - Taint Sources:  {}", counts.sources);
    println!("  - Taint Sinks:    {}", counts.sinks);
    println!("  - Sanitizers:     {}", counts.sanitizers);
    println!("  - Co-occurrence:  {}", counts.policies);
    println!("  - Checks:         {}", counts.checks);
    if counts.memory_contracts > 0 {
        println!("  - Memory Facts:   {}", counts.memory_contracts);
    }
    if counts.other > 0 {
        println!("  - Other Facts:    {}", counts.other);
    }
    if !loaded.policy_pack.is_empty() {
        println!("Authored Policies:  {}", loaded.policy_pack.len());
    }
    if let Some(notice) = loaded.withheld_sanitizers_notice() {
        println!("Note:               {notice}");
    }
    println!("==========================================================================");

    if !loaded.patterns.is_empty() {
        println!();
        println!("Advisory Patterns:");
        for pat in &loaded.patterns {
            let cwe = pat.cwe.as_deref().unwrap_or("N/A");
            let sev = pat.severity.as_deref().unwrap_or("Unspecified");
            println!("  - [{}] {} (Severity: {})", pat.id, cwe, sev);
            if !pat.rules.is_empty() {
                println!("      Rules: {}", pat.rules.join(", "));
            }
        }
    }

    Ok(())
}
