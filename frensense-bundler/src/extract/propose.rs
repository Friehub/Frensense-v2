// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::collections::BTreeSet;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::facts::{
    FactTable, GuardBypassFact, PolicyRequirement, PolicyScope, SchemaPolicyFact, WeakCryptoFact,
};
use frensense_engine::checks::memory_summary::MemorySummaryRegistry;
use frensense_engine::ir::function::{FunctionIR, Instruction, Operand, Terminator, VarId};

use super::call_analysis::{
    collect_calls, cross_function_helper, extract_call_arg_literals,
    variant_has_range_check_on_call, CallShape,
};
use super::candidate::Candidate;
use super::family::Family;
use super::gate::{alerts, scan_variant};
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
    propose_with_trace(family, config, builtin).0
}

/// [`propose`] plus one human-readable note per decision: which branch the
/// delta took, why a call was NOT proposed (already known to a built-in
/// table, filtered as noise, positive already alerts so the sink path is
/// closed), and which candidates were produced.
///
/// The bundler prints these under `FXDBG` and stores them in the learn
/// report (`FXREPORT=<path>`), so a family that teaches nothing can say why
/// instead of the pipeline staying silent about it.
pub fn propose_with_trace(
    family: &Family,
    config: &TaintConfig,
    builtin: &FactTable,
) -> (Vec<Candidate>, Vec<String>) {
    let mut notes: Vec<String> = Vec::new();
    let mut candidates = Vec::new();
    // Author-declared discriminators (`require-arg-key:` metadata): when
    // present, automatic guard/co-occurrence synthesis must not also mint
    // requirements for the same family - the author stated the intent.
    let meta_explicit = !family.metadata.require_arg_keys.is_empty();

    // Memory allocation / deallocation wrapper discovery from corpus examples:
    let mut family_irs = Vec::new();
    for (path, src, ext) in family.positives.iter().chain(family.negatives.iter()) {
        if let Ok(fns) =
            frensense_engine::harness::lower_source_with_facts(path, src, ext, Some(builtin))
        {
            // Sort by function name: `lower_source` returns an
            // `FxHashMap` whose iteration order is insertion- and
            // hasher-dependent, and IR order feeds summary inference plus
            // every downstream proposal - bundle bytes must not depend on it.
            let mut fns: Vec<_> = fns.into_iter().collect();
            fns.sort_by(|a, b| a.0.cmp(&b.0));
            family_irs.extend(fns.into_iter().map(|(_, ir)| ir));
        }
    }
    if !family_irs.is_empty() {
        let ir_refs: Vec<&frensense_engine::ir::function::FunctionIR> = family_irs.iter().collect();
        let summaries =
            MemorySummaryRegistry::from_facts(builtin).infer_program_summaries_into(&ir_refs);
        for (name, summary) in summaries.summaries {
            if crate::format::is_pack_memory_builtin(&name) {
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

    // Corpus-declared allocation-size overflow rule: the positive's
    // `[frensense]` block names the prover rule this family teaches
    // (`check-rule:`), so propose it regardless of the taint delta - the
    // replay gate still validates pos/neg separation before publishing.
    if let Some(rule) = &family.metadata.check_rule {
        candidates.push(Candidate::IntegerOverflowRule {
            rule: rule.clone(),
            wrap_threshold: family.metadata.wrap_max.unwrap_or(u64::MAX as u128),
            severity: family
                .metadata
                .severity
                .as_deref()
                .unwrap_or("critical")
                .to_ascii_lowercase(),
            message: family
                .metadata
                .observation
                .clone()
                .unwrap_or_else(|| "Integer overflow in allocation size".to_string()),
        });
    }

    let pos = scan_variant(&family.positives, config, builtin);
    let neg = scan_variant(&family.negatives, config, builtin);
    let pos_alerts = alerts(&pos);
    let neg_alerts = alerts(&neg);

    if pos_alerts && !neg_alerts {
        // Taint flow already separates. Return any memory contracts discovered.
        notes.push(
            "positive alerts and the negative stays silent under the built-in tables: \
             the family already separates, so no sink/sanitizer fact is needed"
                .to_string(),
        );
        return (candidates, notes);
    }
    notes.push(format!(
        "delta under built-in tables: positive_alerts={pos_alerts} \
         negative_alerts={neg_alerts} (family does not separate)"
    ));

    // Guard/transform calls present in negatives but not in positives,
    // these are likely the *reason* the negative is safe.
    let pos_calls = collect_calls(&family.positives, Some(builtin));
    let neg_calls = collect_calls(&family.negatives, Some(builtin));
    for (call, shape) in &neg_calls {
        if pos_calls.contains_key(call) {
            notes.push(format!(
                "sanitizer `{call}` not proposed: the positives call it too, so it is not a difference"
            ));
            continue;
        }
        if builtin.sanitizer_fact(call).is_some() {
            notes.push(format!(
                "sanitizer `{call}` not proposed: already a built-in sanitizer"
            ));
            continue;
        }
        if !looks_taint_relevant(call) {
            notes.push(format!(
                "sanitizer `{call}` not proposed: filtered as non-taint-relevant"
            ));
            continue;
        }
        let package = package_for_call(family, call, true);
        notes.push(format!(
            "sanitizer candidate: `{call}` ({}), present only in negatives",
            if *shape == CallShape::Predicate {
                "predicate-style"
            } else {
                "transform"
            }
        ));
        candidates.push(Candidate::Sanitizer {
            call: call.clone(),
            package,
            guard: *shape == CallShape::Predicate,
        });
    }

    // Calls in positives that no table knows and no candidate yet -> sink
    // proposals (validated by replay).
    if !pos_alerts {
        for call in pos_calls.keys() {
            if builtin.sink_signature(call).is_some() {
                notes.push(format!(
                    "sink `{call}` not proposed: the built-in table already treats it as a sink, \
                     so it cannot be the reason the positive stays silent"
                ));
                continue;
            }
            if builtin.sanitizer_fact(call).is_some() {
                notes.push(format!(
                    "sink `{call}` not proposed: the built-in table treats it as a sanitizer"
                ));
                continue;
            }
            if !looks_taint_relevant(call) {
                notes.push(format!(
                    "sink `{call}` not proposed: filtered as non-taint-relevant"
                ));
                continue;
            }
            if candidates
                .iter()
                .any(|c| matches!(c, Candidate::Sanitizer { call: c2, .. } if c2 == call))
            {
                notes.push(format!(
                    "sink `{call}` not proposed: already proposed as a sanitizer for this family"
                ));
                continue;
            }
            let package = package_for_call(family, call, false);
            notes.push(format!(
                "sink candidate: `{call}` (unknown to every built-in table)"
            ));
            candidates.push(Candidate::Sink {
                call: call.clone(),
                package,
                dangerous: BTreeSet::new(), // all args; replay validates
            });
        }
    } else {
        notes.push(
            "unknown-call sink proposals skipped: they require a silent positive, and this \
             positive already alerts"
                .to_string(),
        );
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
        if builtin.learned_checks.iter().any(|(c, _)| c.call == *call) {
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
        let message = family
            .metadata
            .observation
            .clone()
            .unwrap_or_else(|| format!("Policy violation: `{call}`"));
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
                    .map(|v| collect_calls(std::slice::from_ref(v), Some(builtin)))
                    .all(|calls| calls.contains_key(g))
            };
            let mut eligible_guards: Vec<&String> = neg_calls
                .keys()
                .filter(|g| {
                    !pos_has(g)
                        && !builtin.sanitizer_fact(g).is_some()
                        && !super::noise::is_exception_name(g)
                        && looks_taint_relevant(g)
                })
                .collect();
            eligible_guards.sort_by_key(|g| {
                (
                    if all_negs_have(g) { 1 } else { 0 },
                    super::noise::guard_priority(g),
                    std::cmp::Reverse(*g),
                )
            });
            unless_guard = eligible_guards.last().cloned().cloned();
            // Inline modality: any negative compares a trigger-argument var
            // against a literal bound.
            if family
                .negatives
                .iter()
                .any(|v| variant_has_range_check_on_call(&[v.clone()], call, Some(builtin)))
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
        if family.declared_check_call.as_ref() == Some(call) && unless_guard.is_some() {
            // Emitted natively as Candidate::Policy in the declared_check_call block below.
            continue;
        }
        if meta_explicit {
            // Explicit author requirements own this family's suppression
            // shape; a synthesized guard would weaken or contradict them.
            continue;
        }
        candidates.push(Candidate::Check {
            rule,
            call: call.clone(),
            message,
            unless_guard,
            unless_range_check,
            // Family-declared package scopes the learned check so its
            // generic trigger cannot collide on other bundle families.
            package: package_for_call(family, call, false),
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
            && builtin
                .learned_checks
                .iter()
                .all(|(c, _)| c.call != trigger)
        {
            let pos_has = |g: &str| pos_calls.contains_key(g);
            let all_negs_have = |g: &str| {
                family
                    .negatives
                    .iter()
                    .map(|v| collect_calls(std::slice::from_ref(v), Some(builtin)))
                    .all(|calls| calls.contains_key(g))
            };
            // Author-declared discriminators (`// require-arg-key:` block
            // lines) replace automatic guard/co-occurrence synthesis: the
            // metadata states the exact discriminator the corpus intends,
            // so the proposal never invents one from a coincidental twin
            // difference (the "GuardCall { call: \"Date\" }" class).
            let explicit_req = !family.metadata.require_arg_keys.is_empty();
            if explicit_req {
                let pkg = package_for_call(family, &trigger, false);
                let require = family
                    .metadata
                    .require_arg_keys
                    .iter()
                    .map(|(slot, key)| PolicyRequirement::RequireArgKey {
                        slot: *slot,
                        keys: vec![key.clone()],
                    })
                    .collect();
                candidates.push(Candidate::Policy {
                    rule: format!("policy_{trigger}"),
                    call: trigger.clone(),
                    message: family
                        .metadata
                        .observation
                        .clone()
                        .unwrap_or_else(|| format!("Policy violation: `{trigger}`")),
                    require,
                    scope: PolicyScope::Function,
                    package: pkg,
                });
            }
            // Shape (b-native): required guard call in the same function.
            let mut eligible_guards: Vec<&String> = neg_calls
                .keys()
                .filter(|g| {
                    g.as_str() != trigger
                        && !pos_has(g)
                        && builtin.sanitizer_fact(g).is_none()
                        && builtin.sink_signature(g).is_none()
                        && !super::noise::is_exception_name(g)
                        && looks_taint_relevant(g)
                })
                .collect();
            eligible_guards.sort_by_key(|g| {
                (
                    if all_negs_have(g) { 1 } else { 0 },
                    super::noise::guard_priority(g),
                    std::cmp::Reverse(*g),
                )
            });
            if explicit_req {
                // Explicit author requirements own this family's suppression
                // shape; a synthesized guard would weaken or contradict
                // them, so the eligible-guard set stays empty.
                eligible_guards.clear();
            }
            if let Some(guard) = eligible_guards.last() {
                let pkg = package_for_call(family, &trigger, false);
                candidates.push(Candidate::Policy {
                    rule: format!("policy_{trigger}"),
                    call: trigger.clone(),
                    message: family.metadata.observation.clone().unwrap_or_else(|| {
                        format!("Policy violation: `{trigger}` requires `{guard}` guard")
                    }),
                    require: vec![PolicyRequirement::GuardCall {
                        call: (*guard).clone(),
                    }],
                    scope: PolicyScope::Function,
                    package: pkg,
                });
            }
            // Shape (c): banned-call co-occurrence. Calls the POSITIVES make
            // that no negative makes: candidate `NotCall` requirements.
            let mut banned: Vec<String> = pos_calls
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
            // Pick alphabetically, not in FxHashMap iteration order: the
            // chosen name is baked into the learned fact's bytes.
            banned.sort();
            if explicit_req {
                banned.clear();
            }
            if let Some(banned_call) = banned.first() {
                let pkg = package_for_call(family, &trigger, false);
                candidates.push(Candidate::Policy {
                    rule: format!("policy_{trigger}_no_{banned_call}"),
                    call: trigger.clone(),
                    message: family.metadata.observation.clone().unwrap_or_else(|| {
                        format!(
                            "Policy violation: `{trigger}` must not co-occur with `{banned_call}`"
                        )
                    }),
                    require: vec![PolicyRequirement::NotCall {
                        call: banned_call.clone(),
                    }],
                    scope: PolicyScope::Function,
                    package: pkg,
                });
            }

            // Shape (d): cross-function enforcement. The enforcement helper is
            // DEFINED in the negatives' module but absent from positives - the
            // enforcement lives outside the trigger's function, so the fact
            // uses Module scope (the engine accepts the definition site as
            // enforcement evidence).
            let helper = if explicit_req {
                None
            } else {
                cross_function_helper(family, &pos_calls, &neg_calls, Some(builtin))
            };
            if let Some(helper) = helper {
                if builtin.sanitizer_fact(&helper).is_none() {
                    let pkg = package_for_call(family, &trigger, false);
                    candidates.push(Candidate::Policy {
                        rule: format!("policy_{trigger}_with_{helper}"),
                        call: trigger.clone(),
                        message: family.metadata.observation.clone().unwrap_or_else(|| {
                            format!("Policy violation: `{trigger}` requires `{helper}` enforcement")
                        }),
                        require: vec![PolicyRequirement::RequireCall {
                            any_of: vec![helper.clone()],
                        }],
                        scope: PolicyScope::Module,
                        package: pkg,
                    });
                }
            }
        }
    }

    let mut pos_irs = Vec::new();
    for (path, src, ext) in &family.positives {
        if let Ok(fns) =
            frensense_engine::harness::lower_source_with_facts(path, src, ext, Some(builtin))
        {
            let mut fns: Vec<_> = fns.into_iter().collect();
            fns.sort_by(|a, b| a.0.cmp(&b.0));
            pos_irs.extend(fns.into_iter().map(|(_, ir)| ir));
        }
    }
    let mut neg_irs = Vec::new();
    for (path, src, ext) in &family.negatives {
        if let Ok(fns) =
            frensense_engine::harness::lower_source_with_facts(path, src, ext, Some(builtin))
        {
            let mut fns: Vec<_> = fns.into_iter().collect();
            fns.sort_by(|a, b| a.0.cmp(&b.0));
            neg_irs.extend(fns.into_iter().map(|(_, ir)| ir));
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
                let pkg = package_for_call(family, call, false);
                candidates.push(Candidate::Policy {
                    rule: format!("policy_{call}_banned_arg_{slot}_{pos_val}"),
                    call: call.clone(),
                    message: family.metadata.observation.clone().unwrap_or_else(|| {
                        format!(
                            "Policy violation: argument {slot} of `{call}` must not be '{pos_val}'"
                        )
                    }),
                    require: vec![PolicyRequirement::BannedArgLiteral {
                        slot: *slot,
                        values: vec![pos_val.clone()],
                    }],
                    scope: PolicyScope::Function,
                    package: pkg,
                });
                if let Some(neg_vals) = neg_arg_literals.get(&(call.clone(), *slot)) {
                    for neg_val in neg_vals {
                        if neg_val != pos_val {
                            let pkg = package_for_call(family, call, false);
                            candidates.push(Candidate::Policy {
                                rule: format!("policy_{call}_required_arg_{slot}_{neg_val}"),
                                call: call.clone(),
                                message: family.metadata.observation.clone().unwrap_or_else(|| {
                                    format!("Policy violation: argument {slot} of `{call}` requires '{neg_val}'")
                                }),
                                require: vec![PolicyRequirement::RequiredArgLiteral {
                                    slot: *slot,
                                    values: vec![neg_val.clone()],
                                }],
                                scope: PolicyScope::Function,
                                package: pkg,
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
                        severity: family
                            .metadata
                            .severity
                            .as_deref()
                            .unwrap_or("warning")
                            .to_ascii_lowercase(),
                        message: family
                            .metadata
                            .observation
                            .clone()
                            .unwrap_or_else(|| format!("Weak cryptography call `{call}`")),
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
                        severity: family
                            .metadata
                            .severity
                            .as_deref()
                            .unwrap_or("warning")
                            .to_ascii_lowercase(),
                        message: family
                            .metadata
                            .observation
                            .clone()
                            .unwrap_or_else(|| format!("Weak cryptography call `{call}`")),
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

    // Coincidental-Guard Rejection: a fact must prove its suppression.
    // Every proposed guard must discriminate the negatives in at least one
    // variant, via one of three shapes shared with the scanner's guard
    // model:
    // 1. dataflow: the guard's value feeds the trigger call's arguments
    //    (def-use through assign/cast/store chains),
    // 2. control: the guard's value gates the branch condition the trigger
    //    executes under, or the guard CALL itself dominates the trigger
    //    call (bare `guard(x);` before the call site - the scanner's
    //    `guard_executes_before` accepts exactly these),
    // 3. decorator: the negative lowers the guard as an entry decorator
    //    (`@guard(...)` / `#[guard]`), which dominates the whole body.
    // A guard merely present somewhere in the negative (the
    // `GuardCall { call: "Date" }` coincidence class, learned from a twin
    // that happened to call `new Date()` inside its where clause) does not
    // discriminate anything about the trigger and is rejected; guards
    // nested inside the trigger's own argument lowering are excluded by
    // span containment. Families that lose their only discriminator
    // publish nothing, which is loud (the family stops teaching) instead
    // of silently wrong.
    candidates.retain(|c| match candidate_guard(c) {
        Some((trigger, guard)) => {
            let gseg = guard.rsplit('.').next().unwrap_or(guard.as_str());
            let tseg = trigger.rsplit('.').next().unwrap_or(trigger.as_str());
            let dataflow = guard_feeds_trigger_args(&neg_irs, gseg, tseg);
            let dominant = neg_irs
                .iter()
                .any(|ir| {
                    frensense_engine::checks::policy::guard_dominates_trigger_call(
                        ir, gseg, tseg,
                    )
                });
            let decorator = neg_irs
                .iter()
                .any(|ir| {
                    ir.entry_guards
                        .iter()
                        .any(|g| g.rsplit('.').next().unwrap_or(g) == gseg)
                });
            let grounded = dataflow || dominant || decorator;
            if !grounded {
                notes.push(format!(
                    "guard `{guard}` rejected: does not feed `{trigger}` arguments in any negative (coincidental guard)"
                ));
            }
            grounded
        }
        None => true,
    });

    notes.push(format!(
        "proposed {} candidate(s): {}",
        candidates.len(),
        candidate_keys(&candidates)
    ));
    (candidates, notes)
}

/// The `(trigger, guard)` pair a policy/check candidate suppresses by, if any.
fn candidate_guard(c: &Candidate) -> Option<(String, String)> {
    match c {
        Candidate::Policy { call, require, .. } => {
            for r in require {
                if let PolicyRequirement::GuardCall { call: guard } = r {
                    return Some((call.clone(), guard.clone()));
                }
            }
            None
        }
        Candidate::Check {
            call, unless_guard, ..
        } => unless_guard.as_ref().map(|g| (call.clone(), g.clone())),
        _ => None,
    }
}

/// Grounding test: does the guard call produce a value that reaches the
/// trigger call's argument vars in at least one of `irs`? Forward def-use
/// BFS from the guard's produced values over
/// `Assign`/`BinaryOp`/`UnaryOp`/`Cast`/`Await`/call-arg passes and
/// `StoreField{src}` (a stored value reaches its base object, which is how
/// `where: { lt: new Date() }` connects the `Date` result to the config
/// argument). Bounded (visited set + hop cap) - a proposal filter, not an
/// analysis pass.
fn guard_feeds_trigger_args(irs: &[FunctionIR], guard_seg: &str, trigger_seg: &str) -> bool {
    for ir in irs {
        let mut guard_values: Vec<VarId> = Vec::new();
        let mut trigger_arg_vars: rustc_hash::FxHashSet<VarId> = Default::default();

        for b in ir.blocks.values() {
            for instr in &b.instructions {
                let (callee, dest, args) = match instr {
                    Instruction::CallStatic {
                        func, dest, args, ..
                    } => (func.rsplit('.').next().unwrap_or(func), dest.as_ref(), args),
                    Instruction::CallVirtual {
                        method, dest, args, ..
                    } => (
                        method.rsplit('.').next().unwrap_or(method),
                        dest.as_ref(),
                        args,
                    ),
                    _ => continue,
                };
                if callee == trigger_seg {
                    push_all_arg_vars(&mut trigger_arg_vars, args);
                }
                if callee == guard_seg {
                    guard_values.extend(dest.iter().map(|d| *d));
                }
            }
        }
        if guard_values.is_empty() || trigger_arg_vars.is_empty() {
            continue;
        }

        let mut seen: rustc_hash::FxHashSet<VarId> = Default::default();
        let mut frontier = guard_values;
        for _ in 0..64 {
            let mut next = Vec::new();
            for v in frontier.drain(..) {
                if trigger_arg_vars.contains(&v) {
                    return true;
                }
                // Control-flow guard: the guard's value gates whether the
                // trigger executes (feeds a branch/switch condition) even
                // though it never reaches the trigger's argument list
                // (`if (!verify_admin_permission(...)) return;`). This is a
                // legitimate discriminator, not a coincidental guard.
                for b in ir.blocks.values() {
                    let cond_is_v = match &b.terminator {
                        Terminator::Branch { cond, .. } => {
                            matches!(cond, Operand::Var(x) if *x == v)
                        }
                        Terminator::Switch { cond, .. } => {
                            matches!(cond, Operand::Var(x) if *x == v)
                        }
                        _ => false,
                    };
                    if cond_is_v {
                        return true;
                    }
                }
                for b in ir.blocks.values() {
                    for instr in &b.instructions {
                        if !operand_in_instr(instr, v) {
                            continue;
                        }
                        match instr {
                            Instruction::Assign { dest, .. }
                            | Instruction::BinaryOp { dest, .. }
                            | Instruction::UnaryOp { dest, .. }
                            | Instruction::Cast { dest, .. }
                            | Instruction::Await { dest, .. }
                            | Instruction::ExtractValue { dest, .. } => {
                                if seen.insert(*dest) {
                                    next.push(*dest);
                                }
                            }
                            Instruction::CallStatic { dest, .. }
                            | Instruction::CallVirtual { dest, .. }
                            | Instruction::CallPointer { dest, .. } => {
                                if let Some(d) = dest {
                                    if seen.insert(*d) {
                                        next.push(*d);
                                    }
                                }
                            }
                            // value reaches the object it is stored into
                            Instruction::StoreField { base, .. }
                            | Instruction::StoreElement { base, .. } => {
                                if seen.insert(*base) {
                                    next.push(*base);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
    }
    false
}

/// True when `v` appears in any operand position of `instr`.
fn operand_in_instr(instr: &Instruction, v: VarId) -> bool {
    let eq = |op: &Operand| matches!(op, Operand::Var(x) if *x == v);
    match instr {
        Instruction::Assign { src, .. }
        | Instruction::Cast { src, .. }
        | Instruction::UnaryOp { src, .. } => eq(src),
        Instruction::BinaryOp { lhs, rhs, .. } => eq(lhs) || eq(rhs),
        Instruction::LoadField { base, .. } => *base == v,
        Instruction::StoreField { base, src, .. } => *base == v || eq(src),
        Instruction::LoadElement { base, index, .. } => *base == v || eq(index),
        Instruction::StoreElement {
            base, index, src, ..
        } => *base == v || eq(index) || eq(src),
        Instruction::CallStatic { args, .. } => args.iter().any(eq),
        Instruction::CallVirtual { receiver, args, .. } => eq(receiver) || args.iter().any(eq),
        Instruction::CallPointer { func_ptr, args, .. } => eq(func_ptr) || args.iter().any(eq),
        Instruction::AddressOf { src, .. } => *src == v,
        Instruction::Dereference { ptr, .. } => eq(ptr),
        Instruction::ExtractValue { tuple, .. } => eq(tuple),
        Instruction::Await { promise, .. } => eq(promise),
        Instruction::Yield { src, .. } => src.as_ref().is_some_and(eq),
        _ => false,
    }
}

fn push_all_arg_vars(out: &mut rustc_hash::FxHashSet<VarId>, args: &[Operand]) {
    for op in args {
        if let Operand::Var(v) = op {
            out.insert(*v);
        }
    }
}

/// Compact `kind:name` list of candidates, for the proposal trace.
fn candidate_keys(candidates: &[Candidate]) -> String {
    if candidates.is_empty() {
        return "(none)".to_string();
    }
    candidates
        .iter()
        .map(|c| match c {
            Candidate::Sink { call, package, .. } => match package {
                Some(p) => format!("sink:{p}:{call}"),
                None => format!("sink:{call}"),
            },
            Candidate::Sanitizer {
                call,
                package,
                guard,
            } => {
                let g = if *guard { "guard" } else { "fn" };
                match package {
                    Some(p) => format!("san:{p}:{call}:{g}"),
                    None => format!("san:{call}:{g}"),
                }
            }
            Candidate::Check { rule, call, .. } => format!("check:{rule}:{call}"),
            Candidate::Policy { rule, call, .. } => format!("policy:{rule}:{call}"),
            Candidate::MemoryContract { name, .. } => format!("mem:{name}"),
            Candidate::IntegerOverflowRule { rule, .. } => format!("io_rule:{rule}"),
            _ => "candidate".to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Mirrors the engine's import normalization (`graph/module.rs`): a
/// `node:` builtin keeps only its bare name, so a check/sink policy scoped
/// to `node:crypto` can match the engine's stored import token.
pub(crate) fn normalize_pkg(pkg: &str) -> &str {
    pkg.strip_prefix("node:").unwrap_or(pkg)
}

fn package_for_call(family: &Family, call: &str, is_negative: bool) -> Option<String> {
    // The order mirrors the engine's token model: collect the import
    // tokens the family's files actually ship, then resolve the call's
    // package to one of them. The engine's package filter compares the
    // fact's token to its import map exactly, so a published fact must
    // carry a token that appears verbatim in the scanned files (declared
    // aliases like `package: prisma` for `@prisma/client` otherwise drop
    // their whole fact at the replay gate as "positive never alerts").
    let mut import_pkgs: Vec<String> = Vec::new();
    for files in [
        if is_negative {
            family.negatives.iter()
        } else {
            family.positives.iter()
        },
        family.positives.iter(),
    ] {
        for (_path, source, ext) in files {
            if let Some(spec) = frensense_lang::spec_for_ext(ext) {
                let mut parser = tree_sitter::Parser::new();
                if parser.set_language(&spec.tree_sitter_language()).is_ok() {
                    if let Some(tree) = parser.parse(source, None) {
                        for imp in spec.extract_imports(tree.root_node(), source) {
                            let norm = normalize_pkg(&imp.package).to_string();
                            if !import_pkgs.contains(&norm) {
                                import_pkgs.push(norm);
                            }
                        }
                    }
                }
            }
        }
    }
    // A family-declared package wins — but resolve the alias to the real
    // import token when the declared name is not a verbatim import:
    // `prisma` matches the npm scope of `@prisma/client`; `crypto` matches
    // the builtin `node:crypto`.
    if let Some(pkg) = &family.metadata.package {
        if import_pkgs.iter().any(|t| t == pkg) {
            return Some(pkg.clone());
        }
        if let Some(tok) = import_pkgs.iter().find(|t| {
            t.strip_prefix("node:") == Some(pkg.as_str())
                || t.strip_prefix('@')
                    .and_then(|s| s.split_once('/'))
                    .map(|(scope, _rest)| scope == pkg)
                    .unwrap_or(false)
        }) {
            return Some(tok.clone());
        }
        return Some(pkg.clone());
    }
    let receiver = call.split('.').next().unwrap_or(call);
    for files in [
        if is_negative {
            family.negatives.iter()
        } else {
            family.positives.iter()
        },
        family.positives.iter(),
    ] {
        for (_path, source, ext) in files {
            if let Some(spec) = frensense_lang::spec_for_ext(ext) {
                let mut parser = tree_sitter::Parser::new();
                if parser.set_language(&spec.tree_sitter_language()).is_ok() {
                    if let Some(tree) = parser.parse(source, None) {
                        let imports = spec.extract_imports(tree.root_node(), source);
                        if let Some(imp) = imports.iter().find(|i| {
                            i.local_name == call
                                || i.local_name == receiver
                                || i.symbol.as_deref() == Some(call)
                        }) {
                            return Some(normalize_pkg(&imp.package).to_string());
                        }
                    }
                }
            }
        }
    }
    None
}
