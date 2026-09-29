// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::collections::BTreeSet;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{
    FactTable, GuardBypassFact, PolicyRequirement, PolicyScope, SchemaPolicyFact, WeakCryptoFact,
};
use frensense_engine::checks::memory_summary::MemorySummaryRegistry;

use super::call_analysis::{
    collect_calls, cross_function_helper, extract_call_arg_literals,
    variant_has_range_check_on_call, CallShape,
};
use super::candidate::Candidate;
use super::family::Family;
use super::gate::scan_variant;
use super::noise::looks_taint_relevant;

/// Propose candidate facts for one family from the pos/neg delta.
///
/// Signal extraction per family:
/// * If positives alert and negatives don't under the built-in table, the
///   family *confirms* current handling (no new fact needed).
/// * If positives do NOT alert (a real flow the engine missed), look for
///   calls in positives that the built-in table doesn't know -> propose them
///   as sinks (all-args; the replay gate validates).
/// * If negatives contain guard/transform calls between the source and the
///   sink that positives lack -> propose sanitizer facts.
pub fn propose(family: &Family, config: &TaintConfig, builtin: &FactTable) -> Vec<Candidate> {
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
        let summaries =
            MemorySummaryRegistry::from_facts(builtin).infer_program_summaries_into(&ir_refs);
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

    // Calls in positives that no table knows and no candidate yet -> sink
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
    if let Some(trigger) = family.declared_check_call.clone() {
        if pos_calls.contains_key(&trigger)
            && neg_calls.contains_key(&trigger)
            && builtin.learned_checks.iter().all(|c| c.call != trigger)
        {
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
            // DEFINED in the negatives' module but absent from positives - the
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
    }

    let mut pos_irs = Vec::new();
    for (path, src, ext) in &family.positives {
        if let Ok(fns) = frensense_engine::harness::lower_source(path, src, ext) {
            pos_irs.extend(fns.into_values());
        }
    }
    let mut neg_irs = Vec::new();
    for (path, src, ext) in &family.negatives {
        if let Ok(fns) = frensense_engine::harness::lower_source(path, src, ext) {
            neg_irs.extend(fns.into_values());
        }
    }

    // Non-taint policy proposals: argument literal constraints & weak crypto
    let pos_arg_literals = extract_call_arg_literals(&pos_irs);
    let neg_arg_literals = extract_call_arg_literals(&neg_irs);
    for ((call, slot), pos_vals) in &pos_arg_literals {
        for pos_val in pos_vals {
            let neg_has = neg_arg_literals
                .get(&(call.clone(), *slot))
                .map(|s| s.contains(pos_val))
                .unwrap_or(false);
            if !neg_has {
                candidates.push(Candidate::Policy {
                    rule: format!("policy_{call}_banned_arg_{slot}_{pos_val}"),
                    call: call.clone(),
                    message: format!(
                        "Corpus-verified policy violation: argument {} of `{call}` must not be '{pos_val}' (learned from family {})",
                        slot, family.id
                    ),
                    require: vec![PolicyRequirement::BannedArgLiteral {
                        slot: *slot,
                        values: vec![pos_val.clone()],
                    }],
                    scope: PolicyScope::Function,
                });
                if let Some(neg_vals) = neg_arg_literals.get(&(call.clone(), *slot)) {
                    for neg_val in neg_vals {
                        if neg_val != pos_val {
                            candidates.push(Candidate::Policy {
                                rule: format!("policy_{call}_required_arg_{slot}_{neg_val}"),
                                call: call.clone(),
                                message: format!(
                                    "Corpus-verified policy violation: argument {} of `{call}` requires '{neg_val}' (learned from family {})",
                                    slot, family.id
                                ),
                                require: vec![PolicyRequirement::RequiredArgLiteral {
                                    slot: *slot,
                                    values: vec![neg_val.clone()],
                                }],
                                scope: PolicyScope::Function,
                            });
                        }
                    }
                }
                candidates.push(Candidate::WeakCrypto {
                    fact: WeakCryptoFact {
                        rule_id: format!("learned_weak_crypto_{call}_{pos_val}"),
                        call: call.clone(),
                        selector_slot: Some(*slot),
                        weak_selectors: vec![pos_val.clone()],
                    },
                });
            }
        }
    }

    // Weak crypto: bare calls in positives not present in negatives
    for call in pos_calls.keys() {
        if !neg_calls.contains_key(call) {
            let cl = call.to_ascii_lowercase();
            if cl.contains("hash")
                || cl.contains("crypto")
                || cl.contains("md5")
                || cl.contains("sha1")
                || cl.contains("des")
                || cl.contains("rc4")
                || cl.contains("cipher")
            {
                candidates.push(Candidate::WeakCrypto {
                    fact: WeakCryptoFact {
                        rule_id: format!("learned_weak_crypto_{call}"),
                        call: call.clone(),
                        selector_slot: None,
                        weak_selectors: vec![],
                    },
                });
            }
        }
    }

    // Guard bypass: containment callees
    for ir in &pos_irs {
        let param_names: Vec<String> = ir
            .parameters
            .iter()
            .filter_map(|p| ir.var_metadata.get(p).and_then(|m| m.source_name.clone()))
            .collect();
        let has_url = param_names.iter().any(|n| {
            let l = n.to_ascii_lowercase();
            l.contains("url") || l.contains("redirect")
        });
        if has_url {
            for block in ir.blocks.values() {
                for instr in &block.instructions {
                    let callee = match instr {
                        frensense_engine::ir::function::Instruction::CallVirtual {
                            method, ..
                        } => method,
                        frensense_engine::ir::function::Instruction::CallStatic {
                            func, ..
                        } => func,
                        _ => continue,
                    };
                    let seg = callee.rsplit('.').next().unwrap_or(callee);
                    if !["includes", "indexOf", "contains"].contains(&seg)
                        && looks_taint_relevant(seg)
                    {
                        candidates.push(Candidate::GuardBypass {
                            fact: GuardBypassFact {
                                containment_callees: vec![seg.to_string()],
                                ..Default::default()
                            },
                        });
                    }
                }
            }
        }
    }

    // Guard bypass: credential sinks & params
    for ir in &pos_irs {
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                let (callee, args) = match instr {
                    frensense_engine::ir::function::Instruction::CallVirtual {
                        method,
                        args,
                        ..
                    } => (method, args),
                    frensense_engine::ir::function::Instruction::CallStatic {
                        func, args, ..
                    } => (func, args),
                    _ => continue,
                };
                let seg = callee.rsplit('.').next().unwrap_or(callee);
                for arg in args {
                    if let frensense_engine::ir::function::Operand::Var(v) = arg {
                        if let Some(src_name) =
                            ir.var_metadata.get(v).and_then(|m| m.source_name.clone())
                        {
                            let lower = src_name.to_ascii_lowercase();
                            let is_pwd = [
                                "password",
                                "passwd",
                                "pwd",
                                "cleartextpassword",
                                "clearpassword",
                                "newpassword",
                            ]
                            .contains(&lower.as_str());
                            if is_pwd
                                && ![
                                    "hash",
                                    "hashPassword",
                                    "hashpw",
                                    "setPassword",
                                    "set_password",
                                    "setSecret",
                                    "set_secret",
                                ]
                                .contains(&seg)
                            {
                                candidates.push(Candidate::GuardBypass {
                                    fact: GuardBypassFact {
                                        credential_sinks: vec![seg.to_string()],
                                        ..Default::default()
                                    },
                                });
                            }
                            if !is_pwd
                                && [
                                    "hash",
                                    "hashPassword",
                                    "hashpw",
                                    "setPassword",
                                    "set_password",
                                    "setSecret",
                                    "set_secret",
                                ]
                                .contains(&seg)
                                && (lower.contains("secret")
                                    || lower.contains("key")
                                    || lower.contains("token")
                                    || lower.contains("auth"))
                            {
                                candidates.push(Candidate::GuardBypass {
                                    fact: GuardBypassFact {
                                        credential_params: vec![src_name.clone()],
                                        ..Default::default()
                                    },
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Schema policy: builders and bound keywords
    for ir in &pos_irs {
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                if let frensense_engine::ir::function::Instruction::CallVirtual {
                    method,
                    args,
                    ..
                } = instr
                {
                    let seg = method.rsplit('.').next().unwrap_or(method);
                    if seg == "describe" || seg == "description" {
                        if let Some(frensense_engine::ir::function::Operand::StringLiteral(text)) =
                            args.first()
                        {
                            let lower = text.to_ascii_lowercase();
                            if lower.chars().any(|c| c.is_ascii_digit()) {
                                for b2 in ir.blocks.values() {
                                    for i2 in &b2.instructions {
                                        if let frensense_engine::ir::function::Instruction::CallVirtual { method: m2, .. } = i2 {
                                            let s2 = m2.rsplit('.').next().unwrap_or(m2);
                                            if !["number", "int", "float", "bigint"].contains(&s2)
                                                && !["max", "min", "minimum", "maximum", "int", "multipleOf", "step"].contains(&s2)
                                                && s2 != "describe"
                                                && s2 != "description"
                                            {
                                                candidates.push(Candidate::SchemaPolicy {
                                                    fact: SchemaPolicyFact {
                                                        builders: vec![s2.to_string()],
                                                        ..Default::default()
                                                    },
                                                });
                                            }
                                        }
                                    }
                                }
                                for word in lower.split_whitespace() {
                                    let clean: String =
                                        word.chars().filter(|c| c.is_alphabetic()).collect();
                                    if clean.len() >= 3
                                        && !["maximum", "max", "minimum", "min", "limit", "up to"]
                                            .contains(&clean.as_str())
                                    {
                                        candidates.push(Candidate::SchemaPolicy {
                                            fact: SchemaPolicyFact {
                                                bound_keywords: vec![clean],
                                                ..Default::default()
                                            },
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Schema policy: enforcers from negatives
    for ir in &neg_irs {
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                if let frensense_engine::ir::function::Instruction::CallVirtual { method, .. } =
                    instr
                {
                    let seg = method.rsplit('.').next().unwrap_or(method);
                    if ![
                        "max",
                        "min",
                        "minimum",
                        "maximum",
                        "int",
                        "multipleOf",
                        "step",
                    ]
                    .contains(&seg)
                        && !["number", "int", "float", "bigint"].contains(&seg)
                        && seg != "describe"
                        && seg != "description"
                    {
                        candidates.push(Candidate::SchemaPolicy {
                            fact: SchemaPolicyFact {
                                enforcers: vec![seg.to_string()],
                                ..Default::default()
                            },
                        });
                    }
                }
            }
        }
    }

    candidates
}
