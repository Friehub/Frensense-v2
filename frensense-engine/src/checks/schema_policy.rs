// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Schema-policy seed mechanisms (R1): policy bugs that live in *tool
//! schemas*, the LLM-era analogue of config bugs.
//!
//! 1. **Unbounded number schema** (`unbounded_number_schema`): a schema
//!    builder describes a numeric bound in prose ("maximum 10") but the
//!    builder chain never applies `.max()`/`.min()`, the declared policy is
//!    decorative, enforced nowhere. The LLM's own decision is the "source",
//!    so no taint path can exist; this is a policy assertion over the IR.
//!
//! Mechanism only: which schema builders (`z.number`, `number`, ...) and
//! which bounds matter is corpus-refinable via learned checks.

use crate::analysis::taint::facts::FactTable;
use crate::checks::CheckerFinding;
use crate::checks::Provenance;
use crate::ir::function::{FunctionIR, Instruction, Operand};

type BuilderEntry = (String, bool, Option<(usize, usize)>);

pub fn check(ir: &FunctionIR, facts: &FactTable) -> Vec<CheckerFinding> {
    let mut findings = Vec::new();
    // Collect describe/description string args keyed by their receiver chain,
    // and builder+enforcer method calls with their spans.
    let mut described: Vec<(String, Option<(usize, usize)>)> = Vec::new();
    let mut builders: Vec<BuilderEntry> = Vec::new();
    let mut enforcers: Vec<&str> = Vec::new();
    for block in ir.blocks.values() {
        for instr in &block.instructions {
            if let Instruction::CallVirtual {
                method,
                receiver,
                args,
                dest,
                ..
            } = instr
            {
                let seg = method.rsplit('.').next().unwrap_or(method);
                if seg == "describe" || seg == "description" {
                    let text = args.first().and_then(|a| match a {
                        Operand::StringLiteral(s) => Some(s.clone()),
                        _ => None,
                    });
                    if let Some(text) = text {
                        let span = dest
                            .as_ref()
                            .and_then(|d| ir.var_metadata.get(d))
                            .and_then(|m| m.byte_range)
                            .or_else(|| {
                                if let Operand::Var(r) = receiver {
                                    ir.var_metadata.get(r).and_then(|m| m.byte_range)
                                } else {
                                    None
                                }
                            });
                        described.push((text, span));
                    }
                } else if facts
                    .schema_enforcers
                    .iter()
                    .any(|e| e.eq_ignore_ascii_case(seg))
                {
                    enforcers.push(seg);
                } else {
                    let is_builtin_builder = facts
                        .schema_builders
                        .iter()
                        .any(|b| b.eq_ignore_ascii_case(seg));
                    let is_learned_builder = facts
                        .schema_builders
                        .iter()
                        .any(|b| b.eq_ignore_ascii_case(seg));
                    if is_builtin_builder || is_learned_builder {
                        let span = dest
                            .as_ref()
                            .and_then(|d| ir.var_metadata.get(d))
                            .and_then(|m| m.byte_range);
                        builders.push((seg.to_string(), is_learned_builder, span));
                    }
                }
            }
        }
    }
    if enforcers.is_empty() && !described.is_empty() && !builders.is_empty() {
        for (_builder, builder_learned, span) in &builders {
            for (text, _dspan) in &described {
                let lower = text.to_ascii_lowercase();
                let is_builtin_keyword = facts
                    .schema_keywords
                    .iter()
                    .any(|k| lower.contains(&k.to_ascii_lowercase()));
                let is_learned_keyword = is_builtin_keyword;
                if (is_builtin_keyword || is_learned_keyword)
                    && lower.chars().any(|c| c.is_ascii_digit())
                {
                    findings.push(CheckerFinding {
                        provenance: if *builder_learned || is_learned_keyword {
                            Provenance::Learned
                        } else {
                            Provenance::Spec
                        },
                        function: ir.name.clone(),
                        rule: frensense_lang::rules::UNBOUNDED_NUMBER_SCHEMA.to_string(),
                        message: String::new(),
                        params: vec![("text", text.clone())],
                        span: *span,
                        severity: String::new(),
                    });
                    break;
                }
            }
            if !findings.is_empty() {
                break;
            }
        }
    }
    findings
}
