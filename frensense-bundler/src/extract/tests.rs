// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use std::fs;
use tempfile::TempDir;

use frensense_engine::analysis::taint::config::TaintConfig;
use frensense_engine::analysis::taint::engine::BackwardVerdict;
use frensense_engine::analysis::taint::facts::{
    config_from_spec, fact_table_from_entries_with, fact_table_from_spec, FactTable,
    LearnedFactEntry, PolicyFact, PolicyRequirement, PolicyScope, Provenance,
};
use frensense_engine::scan;

use super::*;

mod metadata_tests {
    //! `[frensense]` advisory metadata: parsing from positive comment
    //! blocks (both comment syntaxes) and baking into the `.frc` payload as
    //! `BundlePattern` entries.

    use super::*;

    const TS_BLOCK: &str = r#"// [frensense]
// observation: User data reaches the sink unescaped.
// impact: Stored XSS against every viewer of the record.
// improvement: Escape on render with the framework's auto-escaping.
// cwe: CWE-79
// cvss: 7.4
// owasp: A03:2021
// severity: High

export function handle(req: any) { return req; }
"#;

    #[test]
    fn parse_full_block_all_fields() {
        let meta = FamilyMetadata::parse(TS_BLOCK, "ts", 30);
        assert_eq!(
            meta.observation.as_deref(),
            Some("User data reaches the sink unescaped.")
        );
        assert_eq!(
            meta.impact.as_deref(),
            Some("Stored XSS against every viewer of the record.")
        );
        assert_eq!(
            meta.improvement.as_deref(),
            Some("Escape on render with the framework's auto-escaping.")
        );
        assert_eq!(meta.cwe.as_deref(), Some("CWE-79"));
        assert_eq!(meta.cvss, Some(7.4));
        assert_eq!(meta.owasp.as_deref(), Some("A03:2021"));
        assert_eq!(meta.severity.as_deref(), Some("High"));
    }

    #[test]
    fn parse_python_hash_comments() {
        let src = "# [frensense]\n# observation: Exec runs user input.\n# severity: Critical\n\ndef h():\n    pass\n";
        let meta = FamilyMetadata::parse(src, "py", 30);
        assert_eq!(meta.observation.as_deref(), Some("Exec runs user input."));
        assert_eq!(meta.severity.as_deref(), Some("Critical"));
        assert_eq!(meta.impact, None);
    }

    #[test]
    fn no_block_yields_default() {
        let meta = FamilyMetadata::parse("export function h() {}\n", "ts", 30);
        assert_eq!(meta, FamilyMetadata::default());
    }

    #[test]
    fn block_must_open_with_marker() {
        // Comment lines WITHOUT the [frensense] opener must not be parsed.
        let src = "// observation: not in a block\nexport function h() {}\n";
        assert_eq!(
            FamilyMetadata::parse(src, "ts", 30),
            FamilyMetadata::default()
        );
    }

    #[test]
    fn non_comment_line_closes_block() {
        // The block ends at the first non-comment line; a later `key: value`
        // in a second comment run must not leak into the first block.
        let src = "// [frensense]\n// severity: High\n\nexport function h() {}\n// severity: Low\n";
        let meta = FamilyMetadata::parse(src, "ts", 30);
        assert_eq!(meta.severity.as_deref(), Some("High"));
    }

    #[test]
    fn metadata_survives_bundle_roundtrip() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("adv_positive.ts"), TS_BLOCK).unwrap();
        fs::write(
            dir.path().join("adv_negative.ts"),
            "// SAFE: parameterized\nexport function handle(req: any) { return escape(req); }\n",
        )
        .unwrap();

        let families = group_families(dir.path()).unwrap();
        assert_eq!(families[0].id, "adv");
        assert_eq!(families[0].metadata.cwe.as_deref(), Some("CWE-79"));

        let (bytes, _) = crate::builder::build_facts_bundle(dir.path()).unwrap();
        let loaded = crate::format::load_bundle(&bytes).unwrap();
        let pat = loaded
            .patterns
            .iter()
            .find(|p| p.id == "adv")
            .expect("family pattern in bundle");
        assert_eq!(
            pat.observation.as_deref(),
            Some("User data reaches the sink unescaped.")
        );
        assert_eq!(pat.cwe.as_deref(), Some("CWE-79"));
        assert_eq!(pat.cvss, Some(7.4));
        assert_eq!(pat.severity.as_deref(), Some("High"));
    }

    #[test]
    fn family_without_block_ships_all_none_pattern() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("bare_positive.ts"),
            "export function h(req: any) { return req; }\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("bare_negative.ts"),
            "export function h() { return 1; }\n",
        )
        .unwrap();

        let (bytes, _) = crate::builder::build_facts_bundle(dir.path()).unwrap();
        let loaded = crate::format::load_bundle(&bytes).unwrap();
        let pat = loaded
            .patterns
            .iter()
            .find(|p| p.id == "bare")
            .expect("family pattern in bundle");
        assert!(pat.observation.is_none() && pat.cwe.is_none() && pat.severity.is_none());
    }
}

mod grouping_tests {
    //! Family grouping pins: multi-language stem collisions must split into
    //! per-language sub-families (learned facts are language-blind - call
    //! matching is by last segment), while clean single-language corpora
    //! keep their bare family ids.

    use super::*;

    fn write(dir: &TempDir, rel: &str, body: &str) {
        let p = dir.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    #[test]
    fn same_stem_different_languages_splits_into_sub_families() {
        let dir = TempDir::new().unwrap();
        write(&dir, "foo_positive.py", "def h(req):\n    return req\n");
        write(&dir, "foo_negative.py", "def h():\n    return 1\n");
        write(
            &dir,
            "foo_positive.ts",
            "export function h(req: any) { return req; }\n",
        );
        write(
            &dir,
            "foo_negative.ts",
            "export function h() { return 1; }\n",
        );

        let families = group_families(dir.path()).unwrap();
        let ids: Vec<&str> = families.iter().map(|f| f.id.as_str()).collect();
        // The bare id must NOT exist anymore: votes would cross languages.
        assert!(!ids.contains(&"foo"), "ids: {ids:?}");
        assert!(ids.contains(&"foo (python)"), "ids: {ids:?}");
        assert!(ids.contains(&"foo (typescript)"), "ids: {ids:?}");
        for f in &families {
            assert_eq!(f.positives.len(), 1, "{}", f.id);
            assert_eq!(f.negatives.len(), 1, "{}", f.id);
            // Each sub-family is single-language.
            let lang = f.positives[0].2.as_str();
            assert!(
                f.negatives.iter().all(|(_, _, e)| e == lang),
                "family {} mixed languages",
                f.id
            );
        }
    }

    #[test]
    fn ts_and_tsx_stay_one_family() {
        // Both extensions resolve to the same language spec (typescript).
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "bar_positive.ts",
            "export function h(req: any) { return req; }\n",
        );
        write(
            &dir,
            "bar_negative.tsx",
            "export function h() { return 1; }\n",
        );

        let families = group_families(dir.path()).unwrap();
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].id, "bar");
        assert_eq!(families[0].positives.len(), 1);
        assert_eq!(families[0].negatives.len(), 1);
    }

    #[test]
    fn clean_single_language_corpus_keeps_bare_ids() {
        let dir = TempDir::new().unwrap();
        write(&dir, "sql_positive.py", "def h(req):\n    return req\n");
        write(&dir, "sql_negative.py", "def h():\n    return 1\n");
        write(
            &dir,
            "xss_positive.ts",
            "export function h(req: any) { return req; }\n",
        );
        write(
            &dir,
            "xss_negative.ts",
            "export function h() { return 1; }\n",
        );

        let families = group_families(dir.path()).unwrap();
        let ids: Vec<&str> = families.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"sql"), "ids: {ids:?}");
        assert!(ids.contains(&"xss"), "ids: {ids:?}");
        assert_eq!(families.len(), 2);
    }

    #[test]
    fn heldout_variants_are_excluded_from_grouping() {
        // Held-out files are blind-verification material: they must never
        // contribute a family, facts, or votes to the extracted bundle.
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "uaf_positive.c",
            "void h(void) { char *p; free(p); }\n",
        );
        write(
            &dir,
            "uaf_negative.c",
            "void h(void) { char *p = 0; free(p); }\n",
        );
        write(
            &dir,
            "uaf_heldout_positive.c",
            "void g(void) { char *q; free(q); }\n",
        );
        write(
            &dir,
            "uaf_heldout_negative.c",
            "void g(void) { char *q = 0; free(q); }\n",
        );

        let families = group_families(dir.path()).unwrap();
        let ids: Vec<&str> = families.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["uaf"], "ids: {ids:?}");
        assert_eq!(
            families[0].positives.len(),
            1,
            "held-out leaked into positives"
        );
        assert_eq!(
            families[0].negatives.len(),
            1,
            "held-out leaked into negatives"
        );
    }

    #[test]
    fn declared_check_call_survives_language_split() {
        // The metadata comment is language-specific syntax; the py variant
        // declares it and only the python sub-family carries it.
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "adm_positive.py",
            "# check-call: admin_reset\ndef h():\n    admin_reset()\n",
        );
        write(&dir, "adm_negative.py", "def h():\n    return 1\n");
        write(
            &dir,
            "adm_positive.ts",
            "export function h() { adminReset(); }\n",
        );
        write(
            &dir,
            "adm_negative.ts",
            "export function h() { return 1; }\n",
        );

        let families = group_families(dir.path()).unwrap();
        let py = families.iter().find(|f| f.id == "adm (python)").unwrap();
        let ts = families
            .iter()
            .find(|f| f.id == "adm (typescript)")
            .unwrap();
        assert_eq!(py.declared_check_call.as_deref(), Some("admin_reset"));
        assert_eq!(ts.declared_check_call, None);
    }

    #[test]
    fn partial_collision_only_splits_the_colliding_stem() {
        // `baz` mixes py+ts; sibling stem `qux` is py-only and must keep its
        // bare id and its files untouched.
        let dir = TempDir::new().unwrap();
        write(&dir, "baz_positive.py", "def h(req):\n    return req\n");
        write(
            &dir,
            "baz_negative.ts",
            "export function h() { return 1; }\n",
        );
        write(&dir, "qux_positive.py", "def h(req):\n    return req\n");
        write(&dir, "qux_negative.py", "def h():\n    return 1\n");

        let families = group_families(dir.path()).unwrap();
        let ids: Vec<&str> = families.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"baz (python)"), "ids: {ids:?}");
        assert!(ids.contains(&"baz (typescript)"), "ids: {ids:?}");
        assert!(ids.contains(&"qux"), "ids: {ids:?}");
        let qux = families.iter().find(|f| f.id == "qux").unwrap();
        assert_eq!(qux.positives.len(), 1);
        assert_eq!(qux.negatives.len(), 1);
    }
}

mod policy_proposal_tests {
    //! Generalized Policy fact proposals: the two family shapes the legacy
    //! Check fact cannot express - banned-call co-occurrence (NotCall) and
    //! cross-function enforcement (RequireCall under Module scope) - plus
    //! the guards that keep Policy proposals conservative.

    use super::*;

    fn write(dir: &TempDir, rel: &str, body: &str) {
        let p = dir.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn builtin() -> (TaintConfig, FactTable) {
        let mut config = TaintConfig::default();
        let mut table = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            table.merge(&fact_table_from_spec(spec));
        }
        // Production `family_tables` seeds spec -> default pack -> pack
        // language sections; mirror it.
        let pack_entries = crate::format::default_pack().learned_facts.as_slice();
        table.merge(&fact_table_from_entries_with(
            pack_entries,
            Provenance::Spec,
        ));
        let all_languages: Vec<&str> = frensense_lang::all_specs().map(|s| s.name()).collect();
        frensense_engine::analysis::taint::facts::apply_language_entries(
            &mut config,
            &mut table,
            pack_entries,
            &all_languages,
        );
        (config, table)
    }

    #[test]
    fn banned_call_co_occurrence_proposes_notcall_policy() {
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "ban_positive.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); shellExec(request); }\n",
        );
        write(
            &dir,
            "ban_negative.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); }\n",
        );
        let families = group_families(dir.path()).unwrap();
        let (config, table) = builtin();
        let (learned, published) = extract_facts_with_tables(&families, &config, &table);

        let _policies: Vec<&PolicyFact> = published
            .iter()
            .filter_map(|f| match &f.entry {
                LearnedFactEntry::Policy { .. } => match learned
                    .policy_facts
                    .iter()
                    .find(|(p, _)| p.rule == rule_of(&f.entry))
                {
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let entries: Vec<&LearnedFactEntry> = published.iter().map(|f| &f.entry).collect();
        assert!(
            entries.iter().any(|e| matches!(
                e,
                LearnedFactEntry::Policy {
                    require,
                    scope: PolicyScope::Function,
                    ..
                } if matches!(require.as_slice(),
                    [PolicyRequirement::NotCall { call }] if call == "shellExec")
            )),
            "expected a NotCall policy for shellExec, got: {entries:?}"
        );
    }

    fn rule_of(e: &LearnedFactEntry) -> String {
        match e {
            LearnedFactEntry::Policy { rule, .. } => rule.clone(),
            _ => String::new(),
        }
    }

    #[test]
    fn cross_function_enforcement_proposes_requirecall_module_policy() {
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "xfn_positive.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); }\n",
        );
        write(
            &dir,
            "xfn_negative.ts",
            "// check-call: evaluate\nfunction enforcePolicy() { return 1; }\nfunction run() { evaluate(request); }\n",
        );
        let families = group_families(dir.path()).unwrap();
        let (config, table) = builtin();
        let (_, published) = extract_facts_with_tables(&families, &config, &table);
        let entries: Vec<&LearnedFactEntry> = published.iter().map(|f| &f.entry).collect();
        assert!(
            entries.iter().any(|e| matches!(
                e,
                LearnedFactEntry::Policy {
                    scope: PolicyScope::Module,
                    require,
                    ..
                } if matches!(require.as_slice(),
                    [PolicyRequirement::RequireCall { any_of }] if any_of.contains(&"enforcePolicy".to_string()))
            )),
            "expected a Module-scope RequireCall policy for enforcePolicy, got: {entries:?}"
        );
    }

    #[test]
    fn undeclared_families_get_no_policy_proposals() {
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "und_positive.ts",
            "function run() { evaluate(request); shellExec(request); }\n",
        );
        write(
            &dir,
            "und_negative.ts",
            "function run() { evaluate(request); }\n",
        );
        let families = group_families(dir.path()).unwrap();
        assert!(families[0].declared_check_call.is_none());
        let (config, table) = builtin();
        let (_, published) = extract_facts_with_tables(&families, &config, &table);
        assert!(
            published
                .iter()
                .all(|f| !matches!(f.entry, LearnedFactEntry::Policy { .. })),
            "no Policy facts may be mined without a declared trigger"
        );
    }

    #[test]
    fn policy_facts_survive_bundle_roundtrip() {
        let dir = TempDir::new().unwrap();
        write(
            &dir,
            "ban_positive.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); shellExec(request); }\n",
        );
        write(
            &dir,
            "ban_negative.ts",
            "// check-call: evaluate\nfunction run() { evaluate(request); }\n",
        );
        let (bytes, published) = crate::builder::build_facts_bundle(dir.path()).unwrap();
        let loaded = crate::format::load_bundle(&bytes).unwrap();
        let has_policy = loaded
            .learned_facts
            .iter()
            .any(|e| matches!(e, LearnedFactEntry::Policy { .. }));
        assert!(
            has_policy || published.is_empty(),
            "policy facts must survive the FRC1 round-trip (or the family failed the gate)"
        );
    }

    /// End-to-end security-policy teaching: the bundler observes
    /// `delete_user_account` called in BOTH variants, but only the safe
    /// variant also calls `verify_admin_permission`. The expected outcome is a
    /// GuardCall-style Check or Policy fact that fires on the unguarded
    /// positive and stays silent on the guarded negative.
    #[test]
    fn security_policy_guard_call_extracted_and_fires() {
        let dir = TempDir::new().unwrap();
        // Positive: privileged delete without authorization check.
        write(
            &dir,
            "delete_account_positive.py",
            concat!(
                "# check-call: delete_user_account\n",
                "def handle(uid):\n",
                "    delete_user_account(uid)\n",
            ),
        );
        // Negative: same privileged delete guarded by admin verification.
        write(
            &dir,
            "delete_account_negative.py",
            concat!(
                "def handle(uid):\n",
                "    if not verify_admin_permission(uid):\n",
                "        raise Exception('denied')\n",
                "    delete_user_account(uid)\n",
            ),
        );

        let (config, table) = builtin();
        let families = group_families(dir.path()).unwrap();
        assert_eq!(
            families.len(),
            1,
            "corpus must form exactly one family; got: {:?}",
            families.iter().map(|f| &f.id).collect::<Vec<_>>()
        );

        let (_, published) = extract_facts_with_tables(&families, &config, &table);

        // The bundler must publish at least one Check or Policy fact for the
        // `delete_user_account` trigger with the guard.
        let found_policy = published.iter().any(|f| match &f.entry {
            LearnedFactEntry::Check {
                call, unless_guard, ..
            } => {
                call.ends_with("delete_user_account")
                    && unless_guard
                        .as_deref()
                        .map(|g| g.contains("verify_admin_permission"))
                        .unwrap_or(false)
            }
            LearnedFactEntry::Policy {
                when_call, require, ..
            } => {
                when_call.ends_with("delete_user_account")
                    && require.iter().any(|r| {
                        matches!(r, PolicyRequirement::GuardCall { call }
                            if call.contains("verify_admin_permission"))
                    })
            }
            _ => false,
        });
        assert!(
            found_policy,
            "expected a GuardCall policy for delete_user_account + verify_admin_permission; got: {:#?}",
            published.iter().map(|f| &f.entry).collect::<Vec<_>>()
        );

        // The learned fact table must separate the family: positive alerts,
        // negative stays silent.
        let (learned, _) = extract_facts_with_tables(&families, &config, &table);
        let family = &families[0];
        let prep = gate::PreparedFamily::new(family).unwrap();
        assert!(
            prep.separates(&config, &learned),
            "family must separate under learned facts: positive alerts, negative is silent"
        );
    }
}

mod slot_regression_tests {
    //! Corpus-level regression pins for per-slot sink awareness (see
    //! `docs/JUICESHOP_BASELINE.md` and the FP-reduction work): the replay
    //! gate must never publish a fact that (a) re-alerts the parameterized
    //! query binding channel, (b) suppresses the dangerous SQL string slot,
    //! or (c) re-promotes validator APIs (`jwt.verify`) to sinks.

    use super::*;

    fn builtin() -> (TaintConfig, FactTable) {
        let mut config = TaintConfig::default();
        let mut table = FactTable::default();
        for spec in frensense_lang::all_specs() {
            let c = config_from_spec(spec);
            config.sources.extend(c.sources);
            config.sinks.extend(c.sinks);
            config.sanitizers.extend(c.sanitizers);
            table.merge(&fact_table_from_spec(spec));
        }
        // Production `family_tables` seeds spec -> default pack -> pack
        // language sections; mirror it.
        let pack_entries = crate::format::default_pack().learned_facts.as_slice();
        table.merge(&fact_table_from_entries_with(
            pack_entries,
            Provenance::Spec,
        ));
        let all_languages: Vec<&str> = frensense_lang::all_specs().map(|s| s.name()).collect();
        frensense_engine::analysis::taint::facts::apply_language_entries(
            &mut config,
            &mut table,
            pack_entries,
            &all_languages,
        );
        (config, table)
    }

    fn ts_file(name: &str, source: &str) -> (String, String, String) {
        (name.to_string(), source.to_string(), "ts".to_string())
    }

    const PARAM_POSITIVE: &str = r#"
import { Pool } from "pg";
const pool = new Pool();
export function getUser (req: any) {
  const id = req.body.id;
  return pool.query("SELECT * FROM users WHERE id = " + id)
}
"#;

    const PARAM_NEGATIVE: &str = r#"
import { Pool } from "pg";
const pool = new Pool();
export function getUser (req: any) {
  const id = req.body.id;
  return pool.query("SELECT * FROM users WHERE id = $1", [id])
}
"#;

    const JWT_VERIFY: &str = r#"
import jwt from "jsonwebtoken";
const JWT_SECRET = "dev-secret";
export function auth (req: any) {
  const token: string = req.cookies.token;
  return jwt.verify(token, JWT_SECRET)
}
"#;

    const CONTROL_SINK: &str = r#"
import { Pool } from "pg";
const pool = new Pool();
export function badSearch (req: any) {
  const q = req.query.q;
  return pool.query("SELECT * FROM items WHERE name = '" + q + "'")
}
"#;

    #[test]
    fn builtin_table_is_slot_aware() {
        let (_, table) = builtin();

        let q = table
            .sink_signature("query")
            .expect("query must be a known sink");
        assert!(q.is_dangerous(0), "SQL string slot is dangerous");
        assert!(
            !q.is_dangerous(1),
            "params slot is the safe binding channel"
        );
        assert!(q.is_binding(1));

        let d = table
            .sink_signature("decrypt")
            .expect("decrypt must be a known sink");
        assert!(d.is_dangerous(0), "ciphertext slot is dangerous");
        assert!(!d.is_dangerous(1), "key slot must not alert");
    }

    #[test]
    fn jwt_verify_is_a_validator_not_a_sink() {
        let (config, table) = builtin();
        assert!(
            !config.sinks.contains("verify"),
            "verify must not be a configured sink"
        );
        assert!(table.sink_signature("verify").is_none());

        let res = scan::scan(&[ts_file("jwt.ts", JWT_VERIFY)], &config, &table);
        assert!(
            !alerts(&res),
            "jwt.verify(token, secret) must not alert; got {:?}",
            res.findings
                .iter()
                .filter(|f| { f.verdict == BackwardVerdict::Vulnerable && f.alert.is_some() })
                .collect::<Vec<_>>()
        );

        let ctrl = scan::scan(&[ts_file("ctrl.ts", CONTROL_SINK)], &config, &table);
        assert!(alerts(&ctrl), "control injection flow must still alert");
    }

    #[test]
    fn parameterized_query_family_separates() {
        let (config, table) = builtin();
        let pos = scan::scan(
            &[ts_file("pq_positive.ts", PARAM_POSITIVE)],
            &config,
            &table,
        );
        let neg = scan::scan(
            &[ts_file("pq_negative.ts", PARAM_NEGATIVE)],
            &config,
            &table,
        );
        assert!(alerts(&pos), "taint in the SQL slot must alert");
        assert!(
            !alerts(&neg),
            "taint in the params binding channel must not alert"
        );
    }

    #[test]
    fn replay_gate_cannot_override_builtin_slot_facts() {
        let (config, table) = builtin();

        let param = Family {
            id: "parameterized_query".into(),
            positives: vec![ts_file("parameterized_query_positive.ts", PARAM_POSITIVE)],
            negatives: vec![ts_file("parameterized_query_negative.ts", PARAM_NEGATIVE)],
            declared_check_call: None,
            metadata: FamilyMetadata::default(),
        };
        let jwt = Family {
            id: "jwt_validator".into(),
            positives: vec![ts_file("jwt_validator_positive.ts", JWT_VERIFY)],
            negatives: vec![ts_file("jwt_validator_negative.ts", CONTROL_SINK)],
            declared_check_call: None,
            metadata: FamilyMetadata::default(),
        };

        let (learned, published) = extract_facts_with_tables(&[param, jwt], &config, &table);

        let query_fact = published.iter().any(
            |f| matches!(&f.entry, LearnedFactEntry::Sink { call, .. } if call.as_str() == "query"),
        );
        assert!(
            !query_fact,
            "gate must not publish a query sink fact over the built-in slot signature"
        );

        let mut merged = table.clone();
        merged.merge(&learned);
        let pos = scan::scan(
            &[ts_file("pq_positive.ts", PARAM_POSITIVE)],
            &config,
            &merged,
        );
        let neg = scan::scan(
            &[ts_file("pq_negative.ts", PARAM_NEGATIVE)],
            &config,
            &merged,
        );
        assert!(alerts(&pos), "SQL-slot danger must survive fact merge");
        assert!(
            !alerts(&neg),
            "binding-channel safety must survive fact merge"
        );
    }
}
