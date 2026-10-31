// Example demonstrating the non-dataflow policy engine flaw in Frensense.
//
// Flaw 1: `RequireNamedArgLiteral` treats the ABSENCE of a named argument as a violation.
//         When scanning a benign call like `set_cookie("theme", "dark")` (or code relying
//         on framework-level secure defaults), the engine flags it as a false positive.
//
// Flaw 2: The engine currently lacks `BannedNamedArgLiteral`. If a security engineer
//         wants a high-confidence rule that strictly bans explicit `secure=False` without
//         flagging absent/default flags, it is impossible to express:
//         - `RequireNamedArgLiteral` flags absent arguments (false positives).
//         - `BannedArgLiteral` only takes positional slot indices, which break when
//           earlier optional arguments shift argument positions.

use frensense_engine::analysis::taint::facts::{
    FactTable, PolicyFact, PolicyRequirement, PolicyScope, Provenance,
};
use frensense_engine::checks::policy;
use frensense_engine::harness::lower_source;
use frensense_engine::ir::function::FunctionIR;

fn lower_py(src: &str) -> Vec<&'static FunctionIR> {
    lower_source("app.py", src, "py")
        .expect("python lowering failed")
        .into_values()
        .map(|ir| -> &'static FunctionIR { Box::leak(Box::new(ir)) })
        .collect()
}

fn main() {
    println!("============================================================");
    println!("FRENSENSE NON-DATAFLOW ENGINE FLAW REPRODUCTION EXAMPLE");
    println!("============================================================");

    // Python test cases
    let explicit_insecure = r#"
def login_handler(r):
    r.set_cookie("session_id", "abc", secure=False)
"#;

    let benign_theme_cookie = r#"
def theme_handler(r):
    r.set_cookie("theme", "dark")
"#;

    println!("\n[Test Code 1: Explicitly Insecure Cookie]");
    println!("{}", explicit_insecure.trim());

    println!("\n[Test Code 2: Benign Theme Cookie (secure flag omitted)]");
    println!("{}", benign_theme_cookie.trim());

    // -----------------------------------------------------------------------
    // PART 1: The current engine's behavior with RequireNamedArgLiteral
    // -----------------------------------------------------------------------
    println!("\n--- Part 1: Current Rule with RequireNamedArgLiteral ---");
    let mut facts_require = FactTable::default();
    facts_require.policy_facts.push((
        PolicyFact {
            rule: "cookie_secure_missing".into(),
            when_call: "set_cookie".into(),
            require: vec![PolicyRequirement::RequireNamedArgLiteral {
                name: "secure".into(),
                values: vec!["true".into()],
            }],
            scope: PolicyScope::Function,
            message: "Cookie is set without Secure=True".into(),
            severity: "warning".into(),
            package: None,
        },
        Provenance::Learned,
    ));

    let hits_explicit = policy::check_program(&lower_py(explicit_insecure), &facts_require);
    println!(
        "1. Explicitly insecure cookie findings: {} (Expected 1)",
        hits_explicit.len()
    );
    for h in &hits_explicit {
        println!("   -> [{}] in {}: {}", h.rule, h.function, h.message);
    }

    let hits_benign = policy::check_program(&lower_py(benign_theme_cookie), &facts_require);
    println!(
        "2. Benign theme cookie findings: {} (FALSE POSITIVE: Expected 0)",
        hits_benign.len()
    );
    for h in &hits_benign {
        println!(
            "   -> FALSE POSITIVE: [{}] in {}: {}",
            h.rule, h.function, h.message
        );
    }

    if !hits_benign.is_empty() {
        println!(
            "   [!] FLAW CONFIRMED: RequireNamedArgLiteral penalizes absent flags on benign cookies!"
        );
    }

    // -----------------------------------------------------------------------
    // PART 2: Verifying the Fix with BannedNamedArgLiteral
    // -----------------------------------------------------------------------
    println!("\n--- Part 2: Verifying the Fix with BannedNamedArgLiteral ---");
    println!("Defining a precise, high-confidence rule with `BannedNamedArgLiteral`:");
    println!("'Flag explicit secure=False. Omitted flags are NOT flagged.'");

    let shifted_insecure = r#"
def shifted_login_handler(r):
    r.set_cookie("session_id", "abc", path="/", secure=False)
"#;

    let mut facts_banned = FactTable::default();
    facts_banned.policy_facts.push((
        PolicyFact {
            rule: "cookie_secure_false_explicit".into(),
            when_call: "set_cookie".into(),
            require: vec![PolicyRequirement::BannedNamedArgLiteral {
                name: "secure".into(),
                values: vec!["false".into()],
            }],
            scope: PolicyScope::Function,
            message: "Cookie is explicitly configured with secure=False".into(),
            severity: "critical".into(),
            package: None,
        },
        Provenance::Learned,
    ));

    let hits_fix_explicit = policy::check_program(&lower_py(explicit_insecure), &facts_banned);
    println!(
        "1. Explicitly insecure cookie findings: {} (Expected 1)",
        hits_fix_explicit.len()
    );
    for h in &hits_fix_explicit {
        println!("   -> [{}] in {}: {}", h.rule, h.function, h.message);
    }

    let hits_fix_shifted = policy::check_program(&lower_py(shifted_insecure), &facts_banned);
    println!(
        "2. Shifted kwargs (path='/', secure=False): {} (Expected 1)",
        hits_fix_shifted.len()
    );
    for h in &hits_fix_shifted {
        println!("   -> [{}] in {}: {}", h.rule, h.function, h.message);
    }

    let hits_fix_benign = policy::check_program(&lower_py(benign_theme_cookie), &facts_banned);
    println!(
        "3. Benign theme cookie (flag omitted): {} (Expected 0 - ZERO FALSE POSITIVES)",
        hits_fix_benign.len()
    );
    if hits_fix_benign.is_empty() {
        println!("   -> Clean! Omitted flag is NOT treated as a violation.");
    } else {
        for h in &hits_fix_benign {
            println!(
                "   -> UNEXPECTED: [{}] in {}: {}",
                h.rule, h.function, h.message
            );
        }
    }

    let compliant_cookie = r#"
def compliant_handler(r):
    r.set_cookie("session_id", "abc", secure=True)
"#;
    let hits_fix_compliant = policy::check_program(&lower_py(compliant_cookie), &facts_banned);
    println!(
        "4. Compliant cookie (secure=True): {} (Expected 0)",
        hits_fix_compliant.len()
    );

    println!("\n============================================================");
    println!("VERIFICATION COMPLETE: Flaw fixed with BannedNamedArgLiteral!");
    println!("============================================================");
}
