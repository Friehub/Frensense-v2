// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the allocation-size integer overflow prover (CWE-190/680).

#[cfg(test)]
pub mod int_overflow_spec {
    use crate::analysis::taint::facts::FactTable;
    use crate::checks::Provenance;
    use crate::checks::int_overflow;
    use crate::checks::memory_summary::MemorySummaryRegistry;
    use crate::harness::lower_source;

    /// Production-seeded table (spec seed -> default pack -> pack language
    /// sections): the checks read `FactTable` only, so test fixtures must
    /// seed the vocabulary exactly like a production scan.
    fn ts_facts() -> FactTable {
        crate::analysis::taint::facts::seeded_tables(["ts"]).1
    }

    fn hits(src: &str, facts: &FactTable) -> Vec<String> {
        let fns = lower_source("t.c", src, "c").unwrap();
        let c_table = crate::analysis::taint::facts::seeded_tables(["c"]).1;
        let summaries = MemorySummaryRegistry::from_facts(&c_table);
        let mut rules: Vec<String> = fns
            .values()
            .flat_map(|ir| int_overflow::check(ir, &summaries, facts))
            .map(|f| f.rule)
            .collect();
        rules.sort();
        rules
    }

    /// Unguarded attacker-sized count feeding malloc: the emptiness guard
    /// proves a lower bound, the upper bound stays unbounded, so the
    /// product can wrap past SIZE_MAX and the allocation is undersized.
    #[test]
    fn unguarded_count_mul_fires() {
        let src = r#"
#include <stdlib.h>
void handler(unsigned long count) {
  if (count < 1) return;
  void *p = malloc(count * 528);
  (void)p;
}
"#;
        let rules = hits(src, &ts_facts());
        assert!(
            rules.contains(&"integer_overflow_alloc".to_string()),
            "expected integer_overflow_alloc to fire: {:?}",
            rules
        );
    }

    /// Pre-division guard: count bounded above by SIZE_MAX/528 keeps the
    /// product within the threshold - the prover stays silent.
    #[test]
    fn guarded_count_mul_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler(unsigned long count) {
  if (count < 1 || count > 34937015291116575) return;
  void *p = malloc(count * 528);
  (void)p;
}
"#;
        let rules = hits(src, &ts_facts());
        assert!(
            rules.is_empty(),
            "guarded site must stay silent: {:?}",
            rules
        );
    }

    /// Unknown operand (no range, no guard): skip, not fire.
    #[test]
    fn unknown_operand_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler(unsigned long count) {
  void *p = malloc(count * 528);
  (void)p;
}
"#;
        let rules = hits(src, &ts_facts());
        assert!(rules.is_empty(), "unprovable range must skip: {:?}", rules);
    }

    /// Provenance gate: the wrap-capable product never reaches an
    /// allocation capacity argument.
    #[test]
    fn non_alloc_sink_is_silent() {
        let src = r#"
void handler(unsigned long count) {
  if (count < 1) return;
  unsigned long bytes = count * 528;
  (void)bytes;
}
"#;
        let rules = hits(src, &ts_facts());
        assert!(
            rules.is_empty(),
            "no alloc provenance must skip: {:?}",
            rules
        );
    }

    /// The product flows into a calloc slot, but calloc multiplies
    /// internally (lang-declared `ParamProduct`) - excluded by design.
    #[test]
    fn calloc_product_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler(unsigned long count) {
  if (count < 1) return;
  void *p = calloc(count * 2, 528);
  (void)p;
}
"#;
        let rules = hits(src, &ts_facts());
        assert!(rules.is_empty(), "calloc must stay silent: {:?}", rules);
    }

    /// Constant product within threshold: silent.
    #[test]
    fn constant_size_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler() {
  void *p = malloc(64 * 4);
  (void)p;
}
"#;
        let rules = hits(src, &ts_facts());
        assert!(
            rules.is_empty(),
            "constant size must stay silent: {:?}",
            rules
        );
    }

    /// A corpus-extended rule (bundle teaches a tighter, 32-bit threshold)
    /// fires under its own rule id while the bootstrap rule stays silent
    /// on the same site: the corpus extends the rule table, the engine's
    /// prover does not change.
    #[test]
    fn corpus_extended_rule_fires_under_own_id() {
        let src = r#"
#include <stdlib.h>
void handler(unsigned long count) {
  if (count < 1 || count > 34937015291116575) return;
  void *p = malloc(count * 528);
  (void)p;
}
"#;
        let mut facts = ts_facts();
        facts.integer_overflow_rules.push((
            crate::analysis::taint::facts::IntegerOverflowRule {
                rule_id: "integer_overflow_alloc_32bit".to_string(),
                wrap_threshold: 4_294_967_295,
                severity: "critical".to_string(),
                message: "Corpus-taught 32-bit wrap rule".to_string(),
            },
            Provenance::Learned,
        ));
        let rules = hits(src, &facts);
        assert!(
            rules.contains(&"integer_overflow_alloc_32bit".to_string()),
            "extended rule must fire: {:?}",
            rules
        );
        assert!(
            !rules.contains(&"integer_overflow_alloc".to_string()),
            "bootstrap rule must stay silent on the guarded site: {:?}",
            rules
        );
    }

    /// The bundle entry round-trips losslessly through bincode (the .frc codec).
    #[cfg(feature = "serialize")]
    #[test]
    fn integer_overflow_entry_bincode_roundtrip() {
        use crate::analysis::taint::facts::LearnedFactEntry;
        let original = LearnedFactEntry::IntegerOverflowRule {
            rule: "integer_overflow_alloc".to_string(),
            wrap_threshold: 18_446_744_073_709_551_615,
            severity: "critical".to_string(),
            message: "m".to_string(),
        };
        let encoded = bincode::serialize(&original).expect("serialize");
        let decoded: LearnedFactEntry = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(original, decoded);
    }
}
