// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::analysis::taint::facts::{FactTable, GrammarFeature};
use crate::ir::function::*;
use frensense_lang::{LanguageSpec, NodeRole};
use rustc_hash::FxHashMap;
use tree_sitter::Node;

/// Innermost `break`/`continue` target while lowering a loop or C switch.
/// `break` jumps to `break_target`; `continue` jumps to the innermost
/// *loop*'s `continue_target` (switches contribute `None` so a `continue`
/// below them still finds the enclosing loop).
pub struct LoopTarget {
    pub break_target: BlockId,
    pub continue_target: Option<BlockId>,
}

pub struct LoweringContext<'a> {
    pub spec: &'a dyn LanguageSpec,
    pub source: &'a str,
    pub ir: FunctionIR,

    /// The current BasicBlock being populated
    pub current_block: BlockId,

    /// Lexical Environment mapping variable names to their VarId
    pub env: Vec<FxHashMap<String, VarId>>,

    /// The single mutable VarId representing the entire Heap State.
    /// It is mutated by Store/Call instructions. The SSABuilder will automatically
    /// version this into mem_1, mem_2, mem_3 and generate Memory Phis.
    pub memory_var: VarId,

    /// Jump target blocks for labeled statements: label_name -> BlockId
    pub labels: FxHashMap<String, BlockId>,

    /// Loop/switch stack for `break` and `continue` (innermost last).
    pub loop_stack: Vec<LoopTarget>,

    /// Optional learned fact table providing dynamic grammar overrides.
    pub facts: Option<&'a FactTable>,
}

impl<'a> LoweringContext<'a> {
    pub fn new(spec: &'a dyn LanguageSpec, source: &'a str, func_name: String) -> Self {
        Self::new_with_facts(spec, source, func_name, None)
    }

    pub fn new_with_facts(
        spec: &'a dyn LanguageSpec,
        source: &'a str,
        func_name: String,
        facts: Option<&'a FactTable>,
    ) -> Self {
        let ir = FunctionIR::new(func_name);
        let entry = ir.entry_block;
        let memory_var = ir.initial_memory_state; // Start with the initial parameter

        Self {
            spec,
            source,
            ir,
            current_block: entry,
            env: vec![FxHashMap::default()], // Global/Function scope
            memory_var,
            labels: FxHashMap::default(),
            loop_stack: Vec::new(),
            facts,
        }
    }

    /// Retrieve or allocate a BlockId for a named label.
    pub fn get_or_create_label_block(&mut self, name: &str) -> BlockId {
        if let Some(&bid) = self.labels.get(name) {
            bid
        } else {
            let bid = self.ir.new_block();
            self.labels.insert(name.to_string(), bid);
            bid
        }
    }

    /// Dynamic node role query: consults learned bundle facts, then falls back to `LanguageSpec::classify`.
    pub fn classify_node(&self, kind: &str) -> NodeRole {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(role) = facts.get_grammar_role(lang, kind)
        {
            return role;
        }
        self.spec.classify(kind)
    }

    /// Dynamic cast query: consults learned bundle facts, then falls back to `LanguageSpec::is_cast`.
    pub fn is_cast(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) = facts.has_grammar_feature(lang, kind, GrammarFeature::Cast)
        {
            return has_feat;
        }
        self.spec.is_cast(kind)
    }

    /// Dynamic template string query.
    pub fn is_template_string(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) =
                facts.has_grammar_feature(lang, kind, GrammarFeature::TemplateString)
        {
            return has_feat;
        }
        self.spec.is_template_string(kind)
    }

    /// Dynamic template fragment query.
    pub fn is_template_fragment(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) =
                facts.has_grammar_feature(lang, kind, GrammarFeature::TemplateFragment)
        {
            return has_feat;
        }
        self.spec.is_template_literal_fragment(kind)
    }

    /// Dynamic destructuring pattern query.
    pub fn is_destructuring_pattern(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) =
                facts.has_grammar_feature(lang, kind, GrammarFeature::DestructuringPattern)
        {
            return has_feat;
        }
        self.spec.is_destructuring_pattern(kind)
    }

    /// Dynamic pair pattern query.
    pub fn is_pair_pattern(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) =
                facts.has_grammar_feature(lang, kind, GrammarFeature::PairPattern)
        {
            return has_feat;
        }
        self.spec.is_pair_pattern(kind)
    }

    /// Dynamic pair entry query.
    pub fn is_pair_entry(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) = facts.has_grammar_feature(lang, kind, GrammarFeature::PairEntry)
        {
            return has_feat;
        }
        self.spec.is_pair_entry(kind)
    }

    /// Dynamic straight-line ternary query.
    pub fn is_ternary_straight_line(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) =
                facts.has_grammar_feature(lang, kind, GrammarFeature::TernaryStraightLine)
        {
            return has_feat;
        }
        self.spec.is_ternary_straight_line(kind)
    }

    /// Dynamic declaration assignment query.
    pub fn is_declaration_assignment(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) =
                facts.has_grammar_feature(lang, kind, GrammarFeature::DeclarationAssignment)
        {
            return has_feat;
        }
        self.spec.is_declaration_assignment(kind)
    }

    /// Dynamic property kind query.
    pub fn is_property_kind(&self, kind: &str) -> bool {
        let lang = self.spec.name();
        if let Some(facts) = self.facts
            && let Some(has_feat) =
                facts.has_grammar_feature(lang, kind, GrammarFeature::PropertyKind)
        {
            return has_feat;
        }
        self.spec.is_property_kind(kind)
    }

    pub fn resolve_identifier(&mut self, node: Node) -> Operand {
        let name = self.source[node.start_byte()..node.end_byte()].to_string();

        for scope in self.env.iter().rev() {
            if let Some(&var) = scope.get(&name) {
                return Operand::Var(var);
            }
        }

        let new_var = self.ir.new_var(VarMetadata {
            source_name: Some(name.clone()),
            type_name: None,
            byte_range: Some((node.start_byte(), node.end_byte())),
            is_memory_state: false,
            object_keys: Vec::new(),
            declared: false,
        });

        self.env.last_mut().unwrap().insert(name, new_var);
        Operand::Var(new_var)
    }

    /// Fresh temporary for lowering-synthesized values (compound assignment,
    /// increment/decrement). Spanned to `node` so findings on the result
    /// resolve to the statement that produced it.
    pub fn new_temp(&mut self, node: Node) -> VarId {
        self.ir.new_var(VarMetadata {
            source_name: None,
            type_name: None,
            byte_range: Some((node.start_byte(), node.end_byte())),
            is_memory_state: false,
            object_keys: Vec::new(),
            declared: false,
        })
    }

    /// Generic child walk shared by degenerate shapes (returns the last
    /// child operand, same semantics as the catch-all arm).
    pub fn visit_children_generic(&mut self, node: Node) -> Option<Operand> {
        let mut cursor = node.walk();
        let mut last_op = None;
        for child in node.children(&mut cursor) {
            if child.is_named()
                && let Some(op) = self.visit_node(child)
            {
                last_op = Some(op);
            }
        }
        last_op
    }
}
