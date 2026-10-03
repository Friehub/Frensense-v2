// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::builder::build_facts_bundle;
use crate::fact_extract::LearnedFact;
use crate::format::load_bundle;
use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{FactTable, LearnedFactEntry};
use std::path::Path;

fn build_base_environment() -> (TaintConfig, FactTable) {
    let mut config = TaintConfig::default();
    let mut builtin = FactTable::default();
    for spec in frensense_lang::all_specs() {
        let c = frensense_engine::analysis::taint::facts::config_from_spec(spec);
        config.sources.extend(c.sources);
        config.sinks.extend(c.sinks);
        config.sanitizers.extend(c.sanitizers);
        builtin.merge(&frensense_engine::analysis::taint::facts::fact_table_from_spec(spec));
    }
    (config, builtin)
}

fn format_entry_tag(entry: &LearnedFactEntry) -> String {
    match entry {
        LearnedFactEntry::Source { pattern } => format!("source:{pattern}"),
        LearnedFactEntry::Sink { call, .. } => format!("sink:{call}"),
        LearnedFactEntry::Sanitizer { call, kind, .. } => format!("sanitizer:{call}({kind})"),
        LearnedFactEntry::Check {
            rule,
            call,
            unless_guard,
            ..
        } => {
            format!("check:{rule}({call}, guard={unless_guard:?})")
        }
        LearnedFactEntry::Policy {
            rule, when_call, ..
        } => format!("policy:{rule}({when_call})"),
        LearnedFactEntry::MemoryContract {
            name,
            returns_fresh,
            consumes_params,
            ..
        } => {
            format!("mem:{name}(fresh={returns_fresh},consumes={consumes_params:?})")
        }
        LearnedFactEntry::WeakCrypto(fact) => {
            format!(
                "weak_crypto:{}(call={},slot={:?})",
                fact.rule_id, fact.call, fact.selector_slot
            )
        }
        LearnedFactEntry::IntegerOverflowRule {
            rule,
            wrap_threshold,
            ..
        } => format!("io_rule:{rule}(max={wrap_threshold})"),
        _ => format_structural_entry(entry),
    }
}

fn format_structural_entry(entry: &LearnedFactEntry) -> String {
    match entry {
        LearnedFactEntry::GuardBypass(f) => format!("guard_bypass(sinks={:?})", f.credential_sinks),
        LearnedFactEntry::SchemaPolicy(f) => format!("schema_policy(builders={:?})", f.builders),
        LearnedFactEntry::GrammarRole {
            language,
            node_kind,
            role,
        } => {
            format!("grammar_role:{language}:{node_kind}({role:?})")
        }
        LearnedFactEntry::GrammarFeature {
            language,
            node_kind,
            feature,
        } => {
            format!("grammar_feature:{language}:{node_kind}({feature:?})")
        }
        LearnedFactEntry::Allocator { name } => format!("allocator:{name}"),
        LearnedFactEntry::Deallocator { name } => format!("deallocator:{name}"),
        LearnedFactEntry::IdorFinderSink { call, keys } => {
            format!("idor_sink:{call}(keys={keys:?})")
        }
        LearnedFactEntry::IdorKey { key } => format!("idor_key:{key}"),
        LearnedFactEntry::Propagator {
            call,
            input_args,
            preserves_taint,
        } => {
            format!("propagator:{call}(args={input_args:?},taints={preserves_taint})")
        }
        LearnedFactEntry::GuardDenylistPattern { pattern } => format!("guard_denylist:{pattern}"),
        _ => "unknown_fact".to_string(),
    }
}

fn print_published_facts(facts: &[LearnedFact]) {
    for f in facts {
        let call = format_entry_tag(&f.entry);
        eprintln!("  [{}] {} <- {}", f.status, call, f.families.join(", "));
    }
}

/// Compile a corpus directory into an .frc facts bundle.
pub fn run_facts_pipeline(corpus_dir: &Path, output_path: &Path) -> Result<(), String> {
    let (config, builtin) = build_base_environment();
    let (bytes, facts) = build_facts_bundle(corpus_dir, &config, &builtin)?;

    let loaded = load_bundle(&bytes)?;
    eprintln!(
        "[facts] round-trip OK: {} learned facts in bundle",
        loaded.learned_facts.len()
    );

    print_published_facts(&facts);

    std::fs::write(output_path, &bytes)
        .map_err(|e| format!("write {}: {e}", output_path.display()))?;
    eprintln!(
        "Facts bundle written to {} ({} bytes)",
        output_path.display(),
        bytes.len()
    );
    Ok(())
}
