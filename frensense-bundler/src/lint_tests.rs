use super::*;
use std::fs;

const REGISTRY: &str = r#"{"version":1,"class":[
 {"id":"inj.sql","name":"SQL injection","cwe":"CWE-89","related_cwe":[]},
 {"id":"inj.nosql","name":"NoSQL injection","cwe":"CWE-943","related_cwe":["CWE-89"]},
 {"id":"path.traversal","name":"Path traversal","cwe":"CWE-22","related_cwe":[]}
]}"#;

fn good_block() -> String {
    "// [frensense]\n\
     // observation: Request body reaches the raw query API without parameters\n\
     // impact: An attacker can read or modify arbitrary rows in the database\n\
     // improvement: Pass values as bound parameters instead of concatenating\n\
     // cwe: CWE-89\n\
     // severity: high\n\
     // class: inj.sql\n\
     // purpose: knowledge\n\
     // shape: raw driver, concat\n\
     // source: CVE-2024-12345, https://github.com/o/r/security/advisories/1, MIT\n"
        .to_string()
}

fn corpus() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("bug_classes.json"), REGISTRY).unwrap();
    d
}

fn put(d: &tempfile::TempDir, name: &str, body: &str) {
    fs::write(d.path().join(name), body).unwrap();
}

const POS_CODE: &str = "function h(req, db) {\n  const q = 'SELECT * FROM t WHERE id=' + req.body.id;\n  return db.rawQuery(q);\n}\n";
const NEG_CODE: &str = "function h(req, db) {\n  return db.rawQuery('SELECT * FROM t WHERE id=?', [req.body.id]);\n}\n";
const HELD_POS: &str = "export async function other(ctx) {\n  const sql = `DELETE FROM u WHERE n='${ctx.params.name}'`;\n  await pool.exec(sql);\n}\n";
const HELD_NEG: &str = "export async function other(ctx) {\n  await pool.exec('DELETE FROM u WHERE n=$1', [ctx.params.name]);\n}\n";

fn full_family(d: &tempfile::TempDir, stem: &str, block: &str) {
    put(
        d,
        &format!("{stem}_positive.js"),
        &format!("{block}{POS_CODE}"),
    );
    put(d, &format!("{stem}_negative.js"), NEG_CODE);
    put(d, &format!("{stem}_heldout_positive.js"), HELD_POS);
    put(d, &format!("{stem}_heldout_negative.js"), HELD_NEG);
}

fn lint(d: &tempfile::TempDir, strict_heldout: bool) -> Report {
    run(
        d.path(),
        &Options {
            gate: false,
            require_heldout: strict_heldout,
            ..Options::default()
        },
    )
    .unwrap()
}

fn codes(r: &Report) -> Vec<&'static str> {
    r.issues.iter().map(|i| i.code).collect()
}

#[test]
fn clean_family_passes() {
    let d = corpus();
    full_family(&d, "sqli_raw", &good_block());
    let r = lint(&d, true);
    assert_eq!(r.errors(), 0, "{}", render_text(&r));
    assert_eq!(r.warnings(), 0, "{}", render_text(&r));
    assert_eq!(r.families.len(), 1);
    assert_eq!(r.families[0].class.as_deref(), Some("inj.sql"));
}

#[test]
fn missing_class_purpose_source_are_errors() {
    let d = corpus();
    let block = "// [frensense]\n\
        // observation: Request body reaches the raw query API without parameters\n\
        // impact: An attacker can read or modify arbitrary rows in the database\n\
        // improvement: Pass values as bound parameters instead of concatenating\n\
        // cwe: CWE-89\n\
        // severity: high\n";
    full_family(&d, "bare", block);
    let c = codes(&lint(&d, false)).join(",");
    for want in ["C001", "C005", "P001"] {
        assert!(c.contains(want), "{c}");
    }
}

#[test]
fn unknown_class_suggests_nearest() {
    let d = corpus();
    full_family(&d, "x", &good_block().replace("inj.sql", "inj.sqll"));
    let r = lint(&d, false);
    let i = r.issues.iter().find(|i| i.code == "C002").unwrap();
    assert!(i.message.contains("inj.sql"), "{}", i.message);
}

#[test]
fn cwe_must_belong_to_class() {
    let d = corpus();
    full_family(&d, "x", &good_block().replace("CWE-89", "CWE-79"));
    assert!(codes(&lint(&d, false)).contains(&"C003"));
    // A related CWE is accepted.
    let d = corpus();
    full_family(
        &d,
        "y",
        &good_block()
            .replace("CWE-89", "CWE-89")
            .replace("inj.sql", "inj.nosql"),
    );
    assert!(!codes(&lint(&d, false)).contains(&"C003"));
}

#[test]
fn typo_in_key_is_reported_with_suggestion() {
    let d = corpus();
    full_family(&d, "x", &good_block().replace("severity:", "serverity:"));
    let r = lint(&d, false);
    let c = codes(&r);
    assert!(c.contains(&"M004") && c.contains(&"M001"), "{c:?}");
    assert!(r
        .issues
        .iter()
        .any(|i| i.code == "M004" && i.message.contains("severity")));
}

#[test]
fn bad_severity_cwe_and_placeholder_text() {
    let d = corpus();
    let b = good_block()
        .replace("severity: high", "severity: scary")
        .replace("cwe: CWE-89", "cwe: 89")
        .replace(
            "Request body reaches the raw query API without parameters",
            "TODO",
        );
    full_family(&d, "x", &b);
    let c = codes(&lint(&d, false));
    for want in ["M002", "M003", "M005"] {
        assert!(c.contains(&want), "{c:?}");
    }
}

#[test]
fn source_formats() {
    let d = corpus();
    full_family(
        &d,
        "a",
        &good_block().replace(
            "CVE-2024-12345, https://github.com/o/r/security/advisories/1, MIT",
            "trust me",
        ),
    );
    assert!(codes(&lint(&d, false)).contains(&"P002"));

    let d = corpus();
    full_family(
        &d,
        "b",
        &good_block().replace(
            "CVE-2024-12345, https://github.com/o/r/security/advisories/1, MIT",
            "synthetic: modeled on the generic driver pattern",
        ),
    );
    let c = codes(&lint(&d, false));
    assert!(!c.iter().any(|c| c.starts_with('P')), "{c:?}");

    let d = corpus();
    full_family(&d, "c", &good_block().replace("MIT\n", "\n"));
    assert!(codes(&lint(&d, false)).contains(&"P003"));
}

#[test]
fn cve_in_stem_must_match_source() {
    let d = corpus();
    full_family(&d, "cve_2023_99999_thing", &good_block());
    assert!(codes(&lint(&d, false)).contains(&"P004"));
    let d = corpus();
    full_family(&d, "cve_2024_12345_thing", &good_block());
    assert!(!codes(&lint(&d, false)).contains(&"P004"));
}

#[test]
fn structure_errors() {
    let d = corpus();
    put(
        &d,
        "lonely_positive.js",
        &format!("{}{POS_CODE}", good_block()),
    );
    assert!(codes(&lint(&d, false)).contains(&"S001"));

    let d = corpus();
    put(&d, "lonely_negative.js", NEG_CODE);
    assert!(codes(&lint(&d, false)).contains(&"S002"));

    let d = corpus();
    put(&d, "orphan_heldout_positive.js", HELD_POS);
    assert!(codes(&lint(&d, false)).contains(&"S003"));

    let d = corpus();
    put(&d, "p_positive.js", &format!("{}{POS_CODE}", good_block()));
    put(&d, "p_negative.js", NEG_CODE);
    let r = lint(&d, false);
    assert!(r
        .issues
        .iter()
        .any(|i| i.code == "S004" && i.level == Level::Warn));
    let r = lint(&d, true);
    assert!(r
        .issues
        .iter()
        .any(|i| i.code == "S004" && i.level == Level::Error));
}

#[test]
fn metadata_block_only_on_training_positive() {
    let d = corpus();
    full_family(&d, "x", &good_block());
    put(&d, "x_negative.js", &format!("{}{NEG_CODE}", good_block()));
    put(
        &d,
        "x_heldout_positive.js",
        &format!("{}{HELD_POS}", good_block()),
    );
    let n = codes(&lint(&d, false))
        .iter()
        .filter(|c| **c == "S010")
        .count();
    assert_eq!(n, 2);
}

#[test]
fn positive_without_block_or_with_late_block() {
    let d = corpus();
    put(&d, "x_positive.js", POS_CODE);
    put(&d, "x_negative.js", NEG_CODE);
    assert!(codes(&lint(&d, false)).contains(&"S012"));

    let d = corpus();
    let late = format!("{}{}", "// filler\n".repeat(35) + POS_CODE, good_block());
    put(&d, "x_positive.js", &late);
    put(&d, "x_negative.js", NEG_CODE);
    assert!(codes(&lint(&d, false)).contains(&"S013"));
}

#[test]
fn same_stem_in_two_languages() {
    let d = corpus();
    full_family(&d, "x", &good_block());
    put(&d, "x_positive.py", &good_block().replace("//", "#"));
    put(&d, "x_negative.py", "def f():\n    pass\n");
    assert!(codes(&lint(&d, false)).contains(&"S006"));
}

#[test]
fn tautological_pair_is_rejected() {
    let d = corpus();
    put(&d, "t_positive.js", &format!("{}{POS_CODE}", good_block()));
    put(&d, "t_negative.js", &format!("// fixed\n{POS_CODE}"));
    assert!(codes(&lint(&d, false)).contains(&"D003"));
}

#[test]
fn heldout_copy_is_rejected() {
    let d = corpus();
    full_family(&d, "x", &good_block());
    put(&d, "x_heldout_positive.js", POS_CODE);
    assert!(codes(&lint(&d, false)).contains(&"D004"));
}

#[test]
fn near_duplicate_families_in_one_class() {
    let d = corpus();
    let code =
        "function h(a) {\n  parse(a);\n  trim(a);\n  split(a);\n  lower(a);\n  rawQuery(a);\n}\n";
    for stem in ["one", "two"] {
        put(
            &d,
            &format!("{stem}_positive.js"),
            &format!("{}{code}", good_block()),
        );
        put(
            &d,
            &format!("{stem}_negative.js"),
            "function h(a) { return 1; }\n",
        );
    }
    let r = lint(&d, false);
    let c = codes(&r);
    assert!(c.contains(&"D001") && c.contains(&"D002"), "{c:?}");
}

#[test]
fn different_classes_may_share_calls() {
    let d = corpus();
    let code =
        "function h(a) {\n  parse(a);\n  trim(a);\n  split(a);\n  lower(a);\n  rawQuery(a);\n}\n";
    put(&d, "one_positive.js", &format!("{}{code}", good_block()));
    put(&d, "one_negative.js", "function h(a) { return 1; }\n");
    put(
        &d,
        "two_positive.js",
        &format!("{}{code}", good_block().replace("inj.sql", "inj.nosql")),
    );
    put(&d, "two_negative.js", "function h(a) { return 1; }\n");
    let c = codes(&lint(&d, false));
    assert!(!c.contains(&"D001") && !c.contains(&"D002"), "{c:?}");
}

#[test]
fn generic_trigger_needs_package() {
    let d = corpus();
    full_family(&d, "x", &format!("{}// check-call: send\n", good_block()));
    assert!(codes(&lint(&d, false)).contains(&"E040"));
    let d = corpus();
    full_family(
        &d,
        "y",
        &format!("{}// check-call: send\n// package: mailer\n", good_block()),
    );
    assert!(!codes(&lint(&d, false)).contains(&"E040"));
}

#[test]
fn synthetic_trigger_name_warns() {
    let d = corpus();
    full_family(
        &d,
        "x",
        &format!(
            "{}// check-call: vulnerableSend\n// package: mailer\n",
            good_block()
        ),
    );
    assert!(codes(&lint(&d, false)).contains(&"D005"));
}

#[test]
fn missing_registry_is_a_hard_error() {
    let d = tempfile::tempdir().unwrap();
    assert!(run(d.path(), &Options::default()).is_err());
}

#[test]
fn coverage_counts_only_clean_families() {
    let d = corpus();
    full_family(&d, "ok", &good_block());
    put(
        &d,
        "bad_positive.js",
        &format!("{}{POS_CODE}", good_block()),
    );
    let r = lint(&d, false);
    let t = coverage_table(&r);
    assert!(
        t.contains("inj.sql | JavaScript | 1 / 1 / 1")
            || t.contains("inj.sql | javascript | 1 / 1 / 1"),
        "{t}"
    );
}

#[test]
fn cli_exit_codes() {
    let d = corpus();
    full_family(&d, "ok", &good_block());
    let args = |extra: &[&str]| -> Vec<String> {
        std::iter::once(d.path().to_str().unwrap().to_string())
            .chain(extra.iter().map(|s| s.to_string()))
            .collect()
    };
    assert_eq!(cli(&args(&["--no-gate"])), 0);
    assert_eq!(cli(&args(&["--bogus"])), 2);
    put(
        &d,
        "bad_positive.js",
        &format!("{}{POS_CODE}", good_block()),
    );
    assert_eq!(cli(&args(&["--no-gate"])), 1);
}

#[test]
fn every_positive_is_linted_and_must_agree() {
    let d = corpus();
    full_family(&d, "multi", &good_block());
    // A second positive with a different class and no source.
    let second = good_block().replace("inj.sql", "inj.nosql").replace(
        "// source: CVE-2024-12345, https://github.com/o/r/security/advisories/1, MIT\n",
        "",
    );
    put(&d, "multi_positive_b.js", &format!("{second}{POS_CODE}"));
    let r = lint(&d, false);
    let c = codes(&r);
    assert!(c.contains(&"M008") && c.contains(&"P001"), "{c:?}");
    assert!(r
        .issues
        .iter()
        .any(|i| i.code == "P001" && i.file.as_deref().is_some_and(|f| f.contains("positive_b"))));
}

#[test]
fn renamed_copy_is_a_structural_clone() {
    let d = corpus();
    let a = "function handle(req, db) {\n  const q = 'SELECT * FROM t WHERE id=' + req.body.id;\n  const rows = db.rawQuery(q);\n  if (rows.length > 0) { return rows[0]; }\n  return null;\n}\n";
    let b = "function serve(request, conn) {\n  const sql = 'SELECT * FROM u WHERE name=' + request.body.name;\n  const out = conn.rawQuery(sql);\n  if (out.length > 0) { return out[0]; }\n  return null;\n}\n";
    put(&d, "one_positive.js", &format!("{}{a}", good_block()));
    put(&d, "one_negative.js", "function h() { return 1; }\n");
    put(
        &d,
        "two_positive.js",
        &format!(
            "{}{b}",
            good_block().replace("raw driver, concat", "template literal")
        ),
    );
    put(&d, "two_negative.js", "function h() { return 2; }\n");
    let c = codes(&lint(&d, false));
    assert!(c.contains(&"D008"), "{c:?}");
    assert!(!c.contains(&"D002"), "shape tags differ: {c:?}");
}

fn index(d: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = d.path().join("advisories.json");
    fs::write(&p, body).unwrap();
    p
}

fn lint_with(d: &tempfile::TempDir, adv: PathBuf) -> Report {
    run(
        d.path(),
        &Options {
            gate: false,
            advisories: Some(adv),
            ..Options::default()
        },
    )
    .unwrap()
}

#[test]
fn advisory_index_verifies_existence_and_cwe() {
    let d = corpus();
    full_family(&d, "a", &good_block());
    // Present and matching.
    let ok = index(&d, r#"{"CVE-2024-12345":{"cwe":["CWE-89"]}}"#);
    assert!(!codes(&lint_with(&d, ok))
        .iter()
        .any(|c| c.starts_with("P00") && *c != "P003"));
    // Missing from the index.
    let missing = index(&d, r#"{"CVE-2020-1":{"cwe":[]}}"#);
    assert!(codes(&lint_with(&d, missing)).contains(&"P005"));
    // Filed under a different CWE.
    let wrong = index(&d, r#"{"CVE-2024-12345":{"cwe":["CWE-79"]}}"#);
    assert!(codes(&lint_with(&d, wrong)).contains(&"P006"));
    // Index that lists no CWE does not fail the comparison.
    let blank = index(&d, r#"{"CVE-2024-12345":{"cwe":[]}}"#);
    assert!(!codes(&lint_with(&d, blank)).contains(&"P006"));
}

#[test]
fn same_advisory_in_two_families_is_flagged() {
    let d = corpus();
    full_family(&d, "a", &good_block());
    full_family(
        &d,
        "b",
        &good_block().replace("raw driver, concat", "other"),
    );
    assert!(codes(&lint(&d, false)).contains(&"P008"));
}

#[test]
fn ghsa_must_link_to_github() {
    let d = corpus();
    let b = good_block().replace(
        "CVE-2024-12345, https://github.com/o/r/security/advisories/1",
        "GHSA-abcd-efgh-ijkl, https://example.com/x",
    );
    full_family(&d, "g", &b);
    assert!(codes(&lint(&d, false)).contains(&"P007"));
}

#[test]
fn families_teaching_identical_facts_are_semantic_duplicates() {
    let d = corpus();
    // Different shapes and wrappers, same unknown sink taught the same way.
    let a_pos = "function h(req, db) {\n  const q = 'SELECT * FROM t WHERE id=' + req.body.id;\n  return db.zzRawExec(q);\n}\n";
    let a_neg = "function h(req, db) {\n  return db.zzRawExec('SELECT * FROM t WHERE id=?', [req.body.id]);\n}\n";
    let b_pos = "async function other(ctx, conn) {\n  const sql = `DELETE FROM u WHERE n='${ctx.params.name}'`;\n  await conn.zzRawExec(sql);\n}\n";
    let b_neg = "async function other(ctx, conn) {\n  await conn.zzRawExec('DELETE FROM u WHERE n=$1', [ctx.params.name]);\n}\n";
    put(&d, "a_positive.js", &format!("{}{a_pos}", good_block()));
    put(&d, "a_negative.js", a_neg);
    put(
        &d,
        "b_positive.js",
        &format!(
            "{}{b_pos}",
            good_block()
                .replace("raw driver, concat", "template literal")
                .replace("CVE-2024-12345", "CVE-2024-54321")
        ),
    );
    put(&d, "b_negative.js", b_neg);
    let r = run(
        d.path(),
        &Options {
            gate: true,
            ..Options::default()
        },
    )
    .unwrap();
    let c = codes(&r);
    assert!(c.contains(&"D006"), "{}", render_text(&r));
}

#[test]
fn knowledge_family_that_cannot_teach_says_why() {
    // The bare engine is silent on `db.rawQuery`, so the knowledge premise
    // holds (PU001 stays quiet) and every metadata check passes - yet the only
    // fact this pair proposes is "rawQuery is a sink", and under it the
    // parameterized negative alerts too. The gate would publish nothing, so
    // lint must say so rather than pass a family the bundle will ignore.
    let d = corpus();
    put(
        &d,
        "sqli_raw_positive.js",
        &format!("{}{POS_CODE}", good_block()),
    );
    put(&d, "sqli_raw_negative.js", NEG_CODE);
    let r = run(
        d.path(),
        &Options {
            gate: true,
            ..Options::default()
        },
    )
    .unwrap();
    let pu: Vec<_> = r.issues.iter().filter(|i| i.code == "PU004").collect();
    assert_eq!(pu.len(), 1, "{}", render_text(&r));
    assert_eq!(pu[0].level, Level::Warn);
    let msg = &pu[0].message;
    assert!(msg.contains("declared knowledge"), "{msg}");
    assert!(msg.contains("learn nothing"), "{msg}");
    // The reason names the fact that did not separate and the side that sank
    // it: the negative alerts under the learned sink too.
    assert!(msg.contains("sink:rawQuery"), "{msg}");
    assert!(msg.contains("negative_alerts=true"), "{msg}");
}

/// The e2e shape from the corpus guide: the negative enforces an extra
/// predicate before the write. Both twins alert at baseline, so the family is
/// a precision family, and the learned `isAllowed` guard silences the
/// negative - it teaches, and lint must stay quiet about PU004.
const PATH_POS: &str = "function writeUpload(cfg: any, req: any) {\n  const target = req.body.path;\n  if (!cfg.isSafePath(target)) {\n    return reject(target);\n  }\n  writeFile(target, req.body.contents);\n}\n";
const PATH_NEG: &str = "function writeUpload(cfg: any, req: any) {\n  const target = req.body.path;\n  if (!isAllowed(target)) {\n    return reject(target);\n  }\n  if (!cfg.isSafePath(target)) {\n    return reject(target);\n  }\n  writeFile(target, req.body.contents);\n}\n";

fn path_block() -> String {
    "// [frensense]\n\
     // observation: A request-controlled path reaches a filesystem write without the safety predicate\n\
     // impact: An attacker can escape the intended directory and overwrite arbitrary files\n\
     // improvement: Require the configured path predicate to run before the write\n\
     // cwe: CWE-22\n\
     // severity: high\n\
     // class: path.traversal\n\
     // purpose: precision\n\
     // shape: policy, guard call\n\
     // check-call: isSafePath\n\
     // source: synthetic: lint teachability test\n"
        .to_string()
}

#[test]
fn precision_family_that_teaches_a_guard_is_not_flagged() {
    // A companion to the test above: this family *does* teach (`san:isAllowed`
    // silences the negative), so lint passes it silently. The trial evidence is
    // asserted directly, so a silently inert check cannot make this pass.
    let d = corpus();
    put(
        &d,
        "path_validator_positive.ts",
        &format!("{}{PATH_POS}", path_block()),
    );
    put(&d, "path_validator_negative.ts", PATH_NEG);
    let v = bare_engine_verdicts(d.path());
    let verdict = &v[&("path_validator".to_string(), "typescript".to_string())];
    assert!(
        verdict.trials.iter().any(|t| t.1 && !t.2),
        "expected a separating candidate, trials={:?}",
        verdict.trials
    );
    let r = run(
        d.path(),
        &Options {
            gate: true,
            ..Options::default()
        },
    )
    .unwrap();
    assert!(
        !codes(&r).contains(&"PU004"),
        "teachable family flagged: {}",
        render_text(&r)
    );
}
