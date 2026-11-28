// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing
//! The sanitizer stop, and how much of a node the fact neutralises.
//!
//! A guard-style fact and an unqualified transform fact cut the whole node.
//! A transform fact that declares `sanitizes_args` cuts only the argument
//! edges those slots name: it neutralises the values that enter there, and
//! taint arriving through any other argument keeps its edge and still reaches
//! its sink.

use super::*;

/// What the walk does at the node it stands on.
pub(super) enum WalkStop {
    /// Not a stop: keep exploring.
    Continue,
    /// The node ends the branch clean.
    Stop,
    /// A transform fact's declared argument slots: cut those incoming edges
    /// and keep exploring everything else.
    CutArgs(std::collections::BTreeSet<usize>),
}

impl<'a> BackwardTaintEngine<'a> {
    /// The sanitizer decision for the node the walk stands on.
    ///
    /// Stops are fact-table aware and role-qualified; a package-scoped fact
    /// additionally needs the call's own import origin to name its package,
    /// and stays inert otherwise.
    pub(super) fn sanitizer_stop(
        &mut self,
        cf: usize,
        ir: &FunctionIR,
        key: &NodeKey,
        state: &mut ExploreState,
    ) -> WalkStop {
        let san_origin = self.sanitizer_origin_package(cf, key);
        if is_sanitizer_effective_for_role(
            ir,
            self.config,
            &self.facts,
            key,
            state.sink_role,
            state.sink_label.as_deref(),
            Some(state.sink_name.as_str()),
            san_origin.as_deref(),
        ) {
            let fact = crate::analysis::forward::sanitizer_fact_defeating(
                ir,
                &self.facts,
                key,
                state.sink_role,
                state.sink_label.as_deref(),
                Some(state.sink_name.as_str()),
                san_origin.as_deref(),
            );
            if let Some(fact) = fact {
                let suppression = SanitizerSuppression {
                    call: fact.call.clone(),
                    classes: self
                        .facts
                        .sanitizer_classes(&fact.call, san_origin.as_deref()),
                };
                if !state.suppressions.contains(&suppression) {
                    state.suppressions.push(suppression);
                }
                // A transform (non-guard) fact that declares slots neutralises
                // the values that enter through them, not its result: the cut
                // belongs on those argument edges, so defer it to
                // `split_sanitized_arg_edges` and keep walking the rest. An
                // empty set keeps the node-level cut below.
                if !fact.guard_style && !fact.sanitizes_args.is_empty() {
                    record_cut(&mut state.cuts, "sanitizer-args");
                    return WalkStop::CutArgs(fact.sanitizes_args.clone());
                }
            }
            state.saw_sanitized_root_only = true;
            record_cut(&mut state.cuts, "sanitizer");
            return WalkStop::Stop;
        }

        WalkStop::Continue
    }

    /// Split a sanitizer call node's local predecessors into the edges its
    /// declared argument slots cover and the ones that stay live.
    ///
    /// The walk arrives at the call's *result*, whose local predecessors are
    /// the operand nodes the call was handed. A slot in the fact's set carries
    /// a value the call neutralises, so that edge is cut; an unlisted argument,
    /// the receiver and the incoming memory keep their edges, which is exactly
    /// how taint entering the call another way still reaches its sink.
    ///
    /// Returns the surviving predecessors and whether anything was cut, so a
    /// node whose every entry is a listed slot reads as clean instead of
    /// falling through to the dead-end classification.
    pub(super) fn split_sanitized_arg_edges(
        &self,
        ir: &FunctionIR,
        key: &NodeKey,
        preds: Vec<NodeKey>,
        slots: &std::collections::BTreeSet<usize>,
    ) -> (Vec<NodeKey>, bool) {
        let args = match key.instruction(ir) {
            Some(Instruction::CallStatic { args, .. })
            | Some(Instruction::CallVirtual { args, .. }) => args,
            _ => return (preds, false),
        };
        let mut covered: Vec<(BlockId, VarId)> = Vec::new();
        for (slot, arg) in args.iter().enumerate() {
            if slots.contains(&slot)
                && let Operand::Var(v) = arg
            {
                covered.push((key.block, *v));
            }
        }
        if covered.is_empty() {
            return (preds, false);
        }
        let mut cut = false;
        let kept: Vec<NodeKey> = preds
            .into_iter()
            .filter(|p| {
                let hit = covered.iter().any(|(b, v)| *b == p.block && *v == p.var);
                cut |= hit;
                !hit
            })
            .collect();
        (kept, cut)
    }
}
