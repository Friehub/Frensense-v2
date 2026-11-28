// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Store-base hints: which receiver produced a field write, so a field name
//! alone never arms a store sink.

use crate::analysis::taint::facts::FactTable;
use crate::ir::function::{FunctionIR, Instruction, Operand, VarId};

/// Last segment of the call that produced `var`, following one load or
/// receiver hop: `document.querySelector(".c")` yields `querySelector`.
///
/// Store sinks use this as their *base kind*. A declared type name is the
/// other spelling the matcher accepts (`ir.var_metadata[var].type_name`),
/// so the same fact works in a typed language and in JS/TS where only the
/// factory is visible.
pub(super) fn base_origin(ir: &FunctionIR, var: VarId) -> Option<String> {
    let mut cur = var;
    for _ in 0..8 {
        let mut copied: Option<VarId> = None;
        for block in ir.blocks.values() {
            for instr in &block.instructions {
                match instr {
                    Instruction::CallStatic {
                        dest: Some(dest),
                        func,
                        ..
                    } if *dest == cur => {
                        return Some(func.rsplit('.').next().unwrap_or(func).to_string());
                    }
                    Instruction::CallVirtual {
                        dest: Some(dest),
                        method,
                        ..
                    } if *dest == cur => return Some(method.clone()),
                    // Copy propagation: lowering may bind `el` from a temp.
                    Instruction::Assign {
                        dest,
                        src: Operand::Var(src),
                    } if *dest == cur => copied = Some(*src),
                    _ => {}
                }
            }
        }
        cur = copied
            .or_else(|| ir.loadfield_def(cur).map(|(base, _)| base))
            .or_else(|| ir.call_receiver_def(cur))?;
    }
    None
}

/// Whether a store's base satisfies the fact's `base_kinds` hint.
///
/// Empty hint = any base (legacy). Otherwise the base's origin, its declared
/// type name, or any of their suffixes must match one kind. A base the
/// engine cannot resolve matches nothing: silence beats a false positive,
/// and the corpus cannot teach what the engine refuses to guess.
pub(super) fn base_kind_matches(ir: &FunctionIR, base: VarId, kinds: &[String]) -> bool {
    if kinds.is_empty() {
        return true;
    }
    let origin = base_origin(ir, base);
    let declared = ir
        .var_metadata
        .get(&base)
        .and_then(|meta| meta.type_name.as_deref());
    [origin.as_deref(), declared]
        .into_iter()
        .flatten()
        .any(|candidate| {
            kinds.iter().any(|kind| {
                candidate.eq_ignore_ascii_case(kind) || candidate.ends_with(kind.as_str())
            })
        })
}

/// Whether a store sink's base-kind hint allows this write. An empty hint
/// allows everything (legacy); an unresolvable base allows nothing, so a
/// field name alone never arms a write sink.
pub(super) fn store_hint_allows(
    facts: &FactTable,
    ir: &FunctionIR,
    base: VarId,
    field: &str,
    language: Option<&str>,
) -> bool {
    facts
        .sink_signature_for_language(field, language)
        .is_none_or(|sig| base_kind_matches(ir, base, &sig.base_kinds))
}
