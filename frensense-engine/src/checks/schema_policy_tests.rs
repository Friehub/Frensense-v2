// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the schema-policy and allowlist-definition seed checks (R1),
//! including the multi-line span reporting that lets consumers match a
//! finding against any line its span covers.

#[cfg(test)]
#[allow(clippy::module_inception)] // test file convention: module name repeats parent path segment
pub mod schema_policy_tests {
    use crate::analysis::taint::facts::FactTable;
    use crate::checks::Provenance;
    use crate::checks::check_all;
    use crate::harness::lower_source;

    /// Spec-seeded table: the checks read `FactTable` only, so test
    /// fixtures must seed the vocabulary exactly like a production scan.
    fn ts_facts() -> FactTable {
        let spec = frensense_lang::spec_for_ext("ts").expect("ts spec");
        crate::analysis::taint::facts::fact_table_from_spec(spec)
    }

    /// The chatbot tool-schema shape: a z.number() whose describe text
    /// declares a maximum in prose, with no .max() enforcement anywhere.
    const UNBOUNDED: &str = r#"
import { tool } from 'ai'
import { z } from 'zod'
export const tools = {
  generateCoupon: tool({
    description: 'Generate a discount coupon (maximum 10)',
    inputSchema: z.object({
      discount: z.number().describe('The discount percentage (maximum 10)')
    }),
    execute: async ({ discount }) => {
      return { coupon: discount }
    }
  })
}
"#;

    fn run(src: &str) -> Vec<crate::checks::CheckerFinding> {
        let irs = lower_source("test.ts", src, "ts").expect("lower");
        check_all(irs.values(), &ts_facts())
    }

    #[test]
    fn unbounded_number_schema_fires_on_prose_bound() {
        let findings = run(UNBOUNDED);
        let f = findings
            .iter()
            .find(|f| f.rule == "unbounded_number_schema")
            .expect("unbounded schema must fire");
        assert!(
            f.params
                .iter()
                .any(|(k, v)| *k == "text" && v.contains("maximum 10")),
            "text param quotes the declared policy"
        );
        assert!(
            f.message.is_empty(),
            "spec findings carry params, not prose"
        );
        assert!(f.span.is_some(), "span recorded for line reporting");
    }

    #[test]
    fn bounded_schema_is_silent() {
        // The .max() enforcer applies the bound the prose declares: no finding.
        let src = r#"
import { z } from 'zod'
export const schema = {
  discount: z.number().max(10).describe('maximum 10 percent')
}
"#;
        assert!(
            run(src).iter().all(|f| f.rule != "unbounded_number_schema"),
            "enforced schema must not fire"
        );
    }

    #[test]
    fn prose_without_numbers_is_silent() {
        // Describes semantics, not a numeric policy, no bound claim.
        let src = r#"
import { z } from 'zod'
export const schema = {
  name: z.string().describe('The customer name')
}
"#;
        assert!(
            run(src).iter().all(|f| f.rule != "unbounded_number_schema"),
            "no numeric prose, no finding"
        );
    }

    #[test]
    fn allowlist_definition_fires_with_containment_guard() {
        // The redirectChallenge shape: URL Set + includes() guard elsewhere.
        let src = r#"
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm'
])
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
"#;
        let findings = run(src);
        let def = findings
            .iter()
            .find(|f| f.rule == "allowlist_definition_bypassable")
            .expect("allowlist definition must fire alongside the guard");
        let (start, end) = def.span.expect("definition span");
        assert!(end > start, "definition span is multi-line");
        // The guard itself fires too.
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "substring_allowlist_guard"),
            "guard rule fires"
        );
    }

    #[test]
    fn allowlist_without_containment_guard_is_silent() {
        // Exact-match guard: the Set is fine, the definition rule must not fire.
        let src = r#"
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop'
])
export const isRedirectAllowed = (url: string) => redirectAllowlist.has(url)
"#;
        assert!(
            run(src)
                .iter()
                .all(|f| f.rule != "allowlist_definition_bypassable"),
            "no containment guard, no definition finding"
        );
    }

    /// Learned schema builder positive & negative test.
    #[test]
    fn learned_schema_builder_positive_and_negative() {
        let mut facts = ts_facts();
        facts.schema_builders.insert("customQuantity".into());

        // Positive sample: custom builder with prose bound without enforcement
        let pos_src = r#"
export const schema = {
  qty: builder.customQuantity().describe('maximum 50 items')
}
"#;
        let pos_irs = lower_source("t.ts", pos_src, "ts").expect("lower");
        let pos_findings = check_all(pos_irs.values(), &facts);
        let f = pos_findings
            .iter()
            .find(|f| f.rule == "unbounded_number_schema")
            .expect("learned builder must fire on positive sample");
        assert_eq!(f.provenance, Provenance::Learned);

        // Negative sample: custom builder with enforcement
        let neg_src = r#"
export const schema = {
  qty: builder.customQuantity().max(50).describe('maximum 50 items')
}
"#;
        let neg_irs = lower_source("t.ts", neg_src, "ts").expect("lower");
        let neg_findings = check_all(neg_irs.values(), &facts);
        assert!(
            neg_findings
                .iter()
                .all(|f| f.rule != "unbounded_number_schema"),
            "enforced builder must stay silent"
        );
    }

    /// Learned schema enforcer positive & negative test.
    #[test]
    fn learned_schema_enforcer_positive_and_negative() {
        let mut facts = ts_facts();
        facts.schema_enforcers.insert("customClamp".into());

        // Positive sample: standard number builder with prose bound, but lacking customClamp
        let pos_src = r#"
import { z } from 'zod'
export const schema = {
  count: z.number().describe('limit 20')
}
"#;
        let pos_irs = lower_source("t.ts", pos_src, "ts").expect("lower");
        let pos_findings = check_all(pos_irs.values(), &facts);
        assert!(
            pos_findings
                .iter()
                .any(|f| f.rule == "unbounded_number_schema"),
            "unenforced schema must fire on positive sample"
        );

        // Negative sample: uses customClamp to enforce the bound
        let neg_src = r#"
import { z } from 'zod'
export const schema = {
  count: z.number().customClamp(20).describe('limit 20')
}
"#;
        let neg_irs = lower_source("t.ts", neg_src, "ts").expect("lower");
        let neg_findings = check_all(neg_irs.values(), &facts);
        assert!(
            neg_findings
                .iter()
                .all(|f| f.rule != "unbounded_number_schema"),
            "schema enforced with customClamp must stay silent"
        );
    }

    /// Learned bound keyword positive & negative test.
    #[test]
    fn learned_bound_keyword_positive_and_negative() {
        let mut facts = ts_facts();
        facts.schema_keywords.insert("ceiling".into());

        // Positive sample: description uses 'ceiling 100' without enforcer
        let pos_src = r#"
import { z } from 'zod'
export const schema = {
  val: z.number().describe('ceiling 100')
}
"#;
        let pos_irs = lower_source("t.ts", pos_src, "ts").expect("lower");
        let pos_findings = check_all(pos_irs.values(), &facts);
        let f = pos_findings
            .iter()
            .find(|f| f.rule == "unbounded_number_schema")
            .expect("learned keyword must trigger on positive sample");
        assert_eq!(f.provenance, Provenance::Learned);

        // Negative sample: description uses 'ceiling 100' with .max(100) enforcer
        let neg_src = r#"
import { z } from 'zod'
export const schema = {
  val: z.number().max(100).describe('ceiling 100')
}
"#;
        let neg_irs = lower_source("t.ts", neg_src, "ts").expect("lower");
        let neg_findings = check_all(neg_irs.values(), &facts);
        assert!(
            neg_findings
                .iter()
                .all(|f| f.rule != "unbounded_number_schema"),
            "enforced schema with learned keyword must stay silent"
        );
    }
}
