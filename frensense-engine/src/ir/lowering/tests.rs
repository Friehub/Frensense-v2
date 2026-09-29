// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use crate::analysis::taint::facts::{
    GrammarFeature, LearnedFactEntry, TeachableNodeRole, fact_table_from_entries,
};
use crate::harness::lower_source_with_facts;
use crate::ir::lowering::LoweringContext;

#[test]
fn test_dynamic_grammar_role_and_feature_roundtrip() {
    let entries = vec![
        LearnedFactEntry::GrammarRole {
            language: "typescript".into(),
            node_kind: "custom_decl".into(),
            role: TeachableNodeRole::Declaration {
                name_field: "target".into(),
                value_field: "source".into(),
            },
        },
        LearnedFactEntry::GrammarFeature {
            language: "typescript".into(),
            node_kind: "custom_cast".into(),
            feature: GrammarFeature::Cast,
        },
        LearnedFactEntry::GrammarFeature {
            language: "*".into(),
            node_kind: "universal_template".into(),
            feature: GrammarFeature::TemplateString,
        },
    ];

    // Verify bincode roundtrip (bundle serialization codec)
    let encoded = bincode::serialize(&entries).expect("bincode serialize");
    let decoded: Vec<LearnedFactEntry> =
        bincode::deserialize(&encoded).expect("bincode deserialize");
    assert_eq!(entries, decoded);

    // Apply to FactTable
    let table = fact_table_from_entries(&decoded);

    let role = table
        .get_grammar_role("typescript", "custom_decl")
        .expect("role found");
    assert_eq!(
        *role,
        frensense_lang::NodeRole::Declaration {
            name_field: "target",
            value_field: "source",
        }
    );

    assert_eq!(
        table.has_grammar_feature("typescript", "custom_cast", GrammarFeature::Cast),
        Some(true)
    );
    assert_eq!(
        table.has_grammar_feature("typescript", "other_node", GrammarFeature::Cast),
        None
    );

    // Wildcard language test
    assert_eq!(
        table.has_grammar_feature(
            "python",
            "universal_template",
            GrammarFeature::TemplateString
        ),
        Some(true)
    );
}

#[test]
fn test_lowering_context_dynamic_grammar_queries() {
    let spec = frensense_lang::spec_for_ext("ts").expect("ts spec");
    let source = "const a = 1;";

    // Without facts
    let ctx_plain = LoweringContext::new(spec, source, "test".into());
    assert!(!ctx_plain.is_cast("custom_cast_node"));
    assert!(!ctx_plain.is_template_string("custom_tmpl_node"));
    assert_eq!(
        ctx_plain.classify_node("custom_role_node"),
        frensense_lang::NodeRole::Other
    );

    // With bundle facts
    let entries = vec![
        LearnedFactEntry::GrammarRole {
            language: "typescript".into(),
            node_kind: "custom_role_node".into(),
            role: TeachableNodeRole::Branch,
        },
        LearnedFactEntry::GrammarFeature {
            language: "typescript".into(),
            node_kind: "custom_cast_node".into(),
            feature: GrammarFeature::Cast,
        },
        LearnedFactEntry::GrammarFeature {
            language: "typescript".into(),
            node_kind: "custom_tmpl_node".into(),
            feature: GrammarFeature::TemplateString,
        },
    ];
    let table = fact_table_from_entries(&entries);
    let ctx_teachable = LoweringContext::new_with_facts(spec, source, "test".into(), Some(&table));

    assert!(ctx_teachable.is_cast("custom_cast_node"));
    assert!(ctx_teachable.is_template_string("custom_tmpl_node"));
    assert_eq!(
        ctx_teachable.classify_node("custom_role_node"),
        frensense_lang::NodeRole::Branch
    );
}

#[test]
fn test_lower_source_with_dynamic_facts() {
    let src = r#"
        function test(param) {
            let x = param;
            return x;
        }
    "#;

    // Normal lowering
    let fns_normal = lower_source_with_facts("test.js", src, "js", None).expect("lower normal");
    assert!(fns_normal.contains_key("test"));

    // Lowering with empty facts
    let empty_table = fact_table_from_entries(&[]);
    let fns_facts =
        lower_source_with_facts("test.js", src, "js", Some(&empty_table)).expect("lower facts");
    assert!(fns_facts.contains_key("test"));

    // Verify IR equality
    let ir1 = &fns_normal["test"];
    let ir2 = &fns_facts["test"];
    assert_eq!(ir1.blocks.len(), ir2.blocks.len());
}

#[test]
fn test_fact_table_merge_grammar_roles_and_features() {
    use crate::analysis::taint::facts::FactTable;

    let mut table1 = FactTable::default();
    let entries1 = vec![
        LearnedFactEntry::GrammarRole {
            language: "javascript".into(),
            node_kind: "kind_a".into(),
            role: TeachableNodeRole::Loop,
        },
        LearnedFactEntry::GrammarFeature {
            language: "javascript".into(),
            node_kind: "kind_a".into(),
            feature: GrammarFeature::Cast,
        },
    ];
    for e in entries1 {
        e.apply(&mut table1);
    }

    let mut table2 = FactTable::default();
    let entries2 = vec![
        LearnedFactEntry::GrammarRole {
            language: "javascript".into(),
            node_kind: "kind_b".into(),
            role: TeachableNodeRole::Return,
        },
        LearnedFactEntry::GrammarFeature {
            language: "javascript".into(),
            node_kind: "kind_a".into(),
            feature: GrammarFeature::TemplateString,
        },
    ];
    for e in entries2 {
        e.apply(&mut table2);
    }

    table1.merge(&table2);

    // Both roles should be present
    assert_eq!(
        table1.get_grammar_role("javascript", "kind_a"),
        Some(&frensense_lang::NodeRole::Loop)
    );
    assert_eq!(
        table1.get_grammar_role("javascript", "kind_b"),
        Some(&frensense_lang::NodeRole::Return)
    );

    // Both features on kind_a should be accumulated
    assert_eq!(
        table1.has_grammar_feature("javascript", "kind_a", GrammarFeature::Cast),
        Some(true)
    );
    assert_eq!(
        table1.has_grammar_feature("javascript", "kind_a", GrammarFeature::TemplateString),
        Some(true)
    );
}

#[test]
fn test_dynamic_destructuring_and_straight_line_ternary() {
    let src = r#"
        function process(obj) {
            const { name, email } = obj;
            const status = obj.active ? "active" : "inactive";
            return status;
        }
    "#;

    let fns = lower_source_with_facts("test.js", src, "js", None).expect("lower test.js");
    let ir = &fns["process"];

    // Find LoadField instructions from destructuring
    let mut loaded_fields = Vec::new();
    for block in ir.blocks.values() {
        for instr in &block.instructions {
            if let crate::ir::function::Instruction::LoadField { field, .. } = instr {
                loaded_fields.push(field.clone());
            }
        }
    }
    assert!(loaded_fields.contains(&"name".to_string()));
    assert!(loaded_fields.contains(&"email".to_string()));
}
