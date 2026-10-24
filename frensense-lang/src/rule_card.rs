// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Rule cards: the one place a finding's identity, title, CWE and advice
//! live. Terminal, SARIF, JSON and `explain` all render from here, so the
//! surfaces cannot drift and a built-in rule cannot ship without a CWE
//! (see the coverage tests here and in `frensense-packgen`).
//!
//! Taint findings resolve a card from the sink label slug
//! (`SinkLabel::slug`); non-dataflow checkers resolve one from the checker
//! rule id. Bundle-learned and user policy rules are not listed: they carry
//! their own prose, and their CWE comes from the bundle pattern overlay.

use crate::severity::SinkRole;

/// Static description of one built-in rule.
#[derive(Debug, PartialEq, Eq)]
pub struct RuleCard {
    /// Stable id, `taint.<class>` or `check.<class>`. Never contains
    /// whitespace, backticks, or finding-specific text.
    pub id: &'static str,
    /// Short class name: "SQL injection".
    pub title: &'static str,
    /// CWE ids, primary first. Never empty for a built-in rule.
    pub cwe: &'static [&'static str],
    /// One sentence: why this is a problem.
    pub why: &'static str,
    /// One sentence: how to fix it.
    pub fix: &'static str,
}

const fn card(
    id: &'static str,
    title: &'static str,
    cwe: &'static [&'static str],
    why: &'static str,
    fix: &'static str,
) -> RuleCard {
    RuleCard {
        id,
        title,
        cwe,
        why,
        fix,
    }
}

/// Fallback card ids: the ones that name no vulnerability class.
///
/// A finding that resolves to one of these says only "untrusted data reached
/// a sensitive operation": the sink's class is unknown, so the report gives
/// the reader nothing to fix, suppress or trend. The scanner's reporting
/// policy drops those findings instead of printing them.
const GENERIC_IDS: &[&str] = &["taint.untrusted-data", "taint.injection"];

impl RuleCard {
    /// Does this card name no vulnerability class (a fallback card)?
    #[must_use]
    pub fn is_generic(&self) -> bool {
        GENERIC_IDS.contains(&self.id)
    }
}

/// Taint-finding cards, keyed by sink label slug (first field of each pair).
static TAINT: &[(&str, RuleCard)] = &[
    ("sql", card("taint.sql-injection", "SQL injection", &["CWE-89"],
        "Attacker-supplied text becomes part of the query and can change its meaning.",
        "Pass the value as a bound parameter instead of building the query string.")),
    ("nosql", card("taint.nosql-injection", "NoSQL injection", &["CWE-943"],
        "Attacker-supplied objects or operators can alter the query's logic.",
        "Validate the value as a plain string or number and reject operator objects before querying.")),
    ("command", card("taint.command-injection", "OS command injection", &["CWE-78"],
        "Attacker-supplied text reaches a shell or process launcher and can run other commands.",
        "Pass arguments as a list without a shell, and validate the value against an allowlist.")),
    ("execution", card("taint.code-injection", "Code injection", &["CWE-94"],
        "Attacker-supplied text is evaluated as code.",
        "Do not evaluate user input; use a data format and a parser instead.")),
    ("template", card("taint.template-injection", "Template injection", &["CWE-1336", "CWE-94"],
        "A template built from user input can run expressions on the server.",
        "Keep the template constant and pass user input only as data to render.")),
    ("traversal", card("taint.path-traversal", "Path traversal", &["CWE-22"],
        "Attacker-supplied path segments can reach files outside the intended directory.",
        "Resolve the path, then check it stays inside the allowed base directory; prefer fixed names.")),
    ("ssrf", card("taint.ssrf", "Server-side request forgery", &["CWE-918"],
        "The server can be made to request internal or attacker-chosen addresses.",
        "Allowlist the destination host and scheme; do not build the URL from user input.")),
    ("redirect", card("taint.open-redirect", "Open redirect", &["CWE-601"],
        "Users can be sent to an attacker-controlled site from a trusted address.",
        "Redirect only to relative paths or hosts on an allowlist.")),
    ("xss", card("taint.xss", "Cross-site scripting", &["CWE-79"],
        "Attacker-supplied text is written into a page and can run script in the victim's browser.",
        "Escape the value for its output context, or use an API that does not interpret markup.")),
    ("deserialize", card("taint.unsafe-deserialization", "Unsafe deserialization", &["CWE-502"],
        "Deserializing attacker-supplied data can instantiate objects and run code.",
        "Parse untrusted input with a data-only format (JSON) and validate it against a schema.")),
    ("ldap", card("taint.ldap-injection", "LDAP injection", &["CWE-90"],
        "Attacker-supplied text can change the directory query.",
        "Escape filter values with the LDAP escaping routine or use parameterized filters.")),
    ("xpath", card("taint.xpath-injection", "XPath injection", &["CWE-643"],
        "Attacker-supplied text can change the XPath expression.",
        "Use parameterized XPath variables instead of concatenating the value.")),
    ("graphql", card("taint.graphql-injection", "GraphQL injection", &["CWE-943"],
        "Attacker-supplied text can change the GraphQL operation.",
        "Pass user values through query variables, never by string concatenation.")),
    ("xxe", card("taint.xxe", "XML external entity", &["CWE-611"],
        "A parser that resolves external entities can read local files or reach internal hosts.",
        "Disable DTDs and external entity resolution in the XML parser.")),
    ("prototype", card("taint.prototype-pollution", "Prototype pollution", &["CWE-1321"],
        "Attacker-chosen keys can modify Object.prototype and change behaviour across the app.",
        "Reject __proto__, constructor and prototype keys, or use Map / Object.create(null).")),
    ("regex", card("taint.regex-dos", "Regular-expression denial of service", &["CWE-1333"],
        "A pattern built from user input can take exponential time to match.",
        "Use a fixed pattern, escape user text, or a linear-time regex engine.")),
    ("header_injection", card("taint.header-injection", "HTTP header injection", &["CWE-113"],
        "Line breaks in a header value can add headers or split the response.",
        "Reject CR/LF in header values or encode them before setting the header.")),
    ("cookie_poisoning", card("taint.cookie-poisoning", "Cookie built from user input", &["CWE-565"],
        "Attacker-chosen cookie names or values can fix or overwrite a victim's session state.",
        "Set cookies from server-generated values and validate any value read back.")),
    ("content_type", card("taint.content-type-injection", "Content-Type injection", &["CWE-436"],
        "An attacker-chosen content type can make the browser interpret a response as active content.",
        "Set the content type from a fixed allowlist.")),
    ("storage", card("taint.untrusted-storage-write", "Untrusted data written to storage", &["CWE-20"],
        "Unvalidated input is persisted and will be trusted by later readers.",
        "Validate and constrain the value (type, length, allowed set) before storing it.")),
    ("log_leak", card("taint.sensitive-data-in-log", "Sensitive data in log", &["CWE-532"],
        "Sensitive values written to logs are readable by anyone with log access.",
        "Remove the value from the log call or mask it before logging.")),
    ("response", card("taint.sensitive-data-in-response", "Sensitive data in response", &["CWE-200"],
        "Internal or sensitive values are sent to the client.",
        "Return only the fields the client needs and omit secrets and internals.")),
    ("credential_leak", card("taint.credential-exposure", "Credential exposure", &["CWE-522"],
        "A credential flows to a place where it is stored or sent unprotected.",
        "Keep credentials out of logs, URLs and responses; store only hashes or use a secrets manager.")),
    ("toctou", card("taint.toctou", "Time-of-check to time-of-use race", &["CWE-367"],
        "The resource can change between the check and its use.",
        "Open the resource once and operate on the handle, or make the check and use atomic.")),
    ("jwt", card("taint.jwt-misuse", "JWT verification weakness", &["CWE-347"],
        "A token is accepted without verifying its signature or with an attacker-chosen algorithm.",
        "Verify with a fixed algorithm and key; never decode untrusted tokens without verification.")),
    ("buffer_overflow", card("taint.buffer-overflow", "Buffer overflow", &["CWE-120", "CWE-787"],
        "Attacker-controlled length or data can write past the end of a buffer.",
        "Bound the copy by the destination size and validate lengths before use.")),
    ("format_string", card("taint.format-string", "Format string", &["CWE-134"],
        "Attacker-controlled format text can read or write memory.",
        "Use a constant format string and pass user text as an argument.")),
    ("idor", card("taint.insecure-direct-object-reference", "Insecure direct object reference", &["CWE-639"],
        "A user-chosen identifier selects a record without an ownership check.",
        "Authorize the caller against the record's owner before returning or changing it.")),
    ("injection", card("taint.injection", "Injection", &["CWE-74"],
        "Untrusted data reaches an interpreter without neutralization.",
        "Pass untrusted values as parameters or data, never as part of the command text.")),
    ("other", card("taint.untrusted-data", "Untrusted data reaches a sensitive operation", &["CWE-20"],
        "Input is used without validation.",
        "Validate the value (type, range, allowed set) before it reaches this call.")),
];

/// Non-dataflow checker cards, keyed by checker rule id.
static CHECK: &[(&str, RuleCard)] = &[
    ("weak_hash", card("check.weak-hash", "Weak hash function", &["CWE-328"],
        "MD5 and SHA-1 are broken for security use and fast enough to brute-force.",
        "Use SHA-256 or better for digests, and bcrypt, scrypt or argon2 for passwords.")),
    ("weak_hash_wrapper", card("check.weak-hash-wrapper", "Password hashed through a wrapper", &["CWE-328"],
        "The wrapper may use a fast or broken digest for passwords.",
        "Confirm the wrapper uses bcrypt, scrypt or argon2.")),
    ("learned_broken_hash_func", card("check.weak-hash-function", "Weak hash function", &["CWE-328"],
        "The function is known to use a broken digest.",
        "Replace it with SHA-256 or better, or a password KDF for passwords.")),
    ("weak_rsa_key_size", card("check.weak-rsa-key-size", "RSA key too short", &["CWE-326"],
        "Keys under 2048 bits can be factored with modest resources.",
        "Generate RSA keys of at least 2048 bits (3072 recommended).")),
    ("learned_weak_cipher_des", card("check.weak-cipher", "Weak cipher", &["CWE-327"],
        "DES and similar ciphers are broken or too small to be secure.",
        "Use AES-GCM or ChaCha20-Poly1305.")),
    ("insecure_jwt_algorithm", card("check.insecure-jwt-algorithm", "Insecure JWT algorithm", &["CWE-347"],
        "The `none` algorithm or an unchecked algorithm lets attackers forge tokens.",
        "Pin the verification algorithm to a strong one such as RS256 or ES256.")),
    ("credential_kdf_policy", card("check.password-kdf", "Password not hashed with a password KDF", &["CWE-916"],
        "Fast digests let attackers test billions of guesses per second.",
        "Hash passwords with bcrypt, scrypt or argon2 and a per-password salt.")),
    ("use_after_free", card("check.use-after-free", "Use after free", &["CWE-416"],
        "Memory is used after it has been released.",
        "Do not use the pointer after free, and set it to NULL after releasing it.")),
    ("double_free", card("check.double-free", "Double free", &["CWE-415"],
        "Memory is released twice, corrupting the allocator.",
        "Free each allocation exactly once; set the pointer to NULL after freeing.")),
    ("uninitialized_free", card("check.uninitialized-free", "Free of uninitialized pointer", &["CWE-908"],
        "Freeing an uninitialized pointer corrupts memory.",
        "Initialize pointers to NULL or a valid allocation before they can be freed.")),
    ("buffer_overflow", card("check.buffer-overflow", "Buffer overflow", &["CWE-120"],
        "A write can run past the end of the buffer.",
        "Bound the write by the buffer size.")),
    ("out_of_bounds_read", card("check.out-of-bounds-read", "Out-of-bounds read", &["CWE-125"],
        "An index or length can exceed the buffer.",
        "Check the index against the buffer length before reading.")),
    ("out_of_bounds_access", card("check.out-of-bounds-write", "Out-of-bounds write", &["CWE-787"],
        "An index or length can exceed the buffer.",
        "Check the index against the buffer length before writing.")),
    ("integer_overflow_alloc", card("check.integer-overflow-allocation", "Integer overflow in allocation size", &["CWE-190"],
        "The size computation can wrap, allocating less memory than later code uses.",
        "Check the multiplication for overflow before allocating, or use a checked or calloc-style API.")),
    ("memory_leak", card("check.memory-leak", "Memory leak", &["CWE-401"],
        "Allocated memory is never released on some path.",
        "Free the allocation on every path, or return or store it intentionally.")),
    ("substring_allowlist_guard", card("check.substring-allowlist", "Allowlist checked by substring", &["CWE-20"],
        "A substring test is satisfied by hostile values such as `evil.com/trusted.com`.",
        "Parse the URL and compare the exact host against the allowlist.")),
    ("guard_bypass", card("check.guard-bypass", "Bypassable validation guard", &["CWE-20"],
        "The guard accepts inputs it was meant to reject.",
        "Compare against an exact allowlist after parsing, not with contains/startsWith.")),
    ("allowlist_definition_bypassable", card("check.permissive-allowlist", "Permissive allowlist", &["CWE-183"],
        "The allowlist is too loose to contain a hostile value.",
        "List exact hosts or paths and compare for equality.")),
    ("unbounded_number_schema", card("check.unbounded-number", "Numeric input without bounds", &["CWE-1284"],
        "A number accepted without min/max can be negative, huge, or non-finite.",
        "Declare minimum and maximum (and integer-ness) in the schema.")),
    ("schema_policy", card("check.schema-validation", "Input schema too permissive", &["CWE-20"],
        "Input is accepted without a strict schema.",
        "Validate request data against a strict schema before using it.")),
    ("cookie_secure_missing", card("check.cookie-secure-missing", "Cookie without Secure flag", &["CWE-614"],
        "The cookie can be sent over plain HTTP and intercepted.",
        "Set Secure=True (and SameSite) on cookies that carry session data.")),
    ("cookie_httponly_missing", card("check.cookie-httponly-missing", "Cookie without HttpOnly flag", &["CWE-1004"],
        "Page scripts can read the cookie, so XSS can steal it.",
        "Set HttpOnly=True on cookies that do not need script access.")),
    ("policy_open_redirect", card("check.open-redirect-policy", "Unvalidated redirect target", &["CWE-601"],
        "A redirect uses a target that was not checked against an allowlist.",
        "Validate the redirect target against relative paths or allowed hosts first.")),
    ("policy_banned_insecure_transport", card("check.insecure-transport", "Insecure transport", &["CWE-319"],
        "Data is sent without TLS and can be read or altered in transit.",
        "Use https:// (or TLS-enabled clients) and keep certificate verification on.")),
    ("policy_require_secure_algorithm", card("check.insecure-algorithm", "Insecure algorithm selected", &["CWE-327"],
        "The selected algorithm is not considered secure.",
        "Choose a current algorithm (AES-GCM, SHA-256+, Ed25519).")),
    ("regex", card("check.regex-dos", "Regular-expression denial of service", &["CWE-1333"],
        "The pattern can backtrack exponentially on crafted input.",
        "Simplify the pattern, bound the input length, or use a linear-time engine.")),
    ("function_complexity", card("check.function-complexity", "Function too complex", &["CWE-1121"],
        "Control flow this tangled is hard to review, and defects hide in branches nobody re-reads.",
        "Split the function into smaller single-purpose pieces until every path is reviewable.")),
];

/// Resolve the card for a taint finding.
///
/// `label` is the sink label slug (`SinkLabel::slug`), `role` the sink's
/// role, `idor` whether the finding's class is an access-control shape.
/// Always returns a card: unlabeled sinks fall back by role to the
/// generic injection / untrusted-data cards.
#[must_use]
pub fn taint_card(label: Option<&str>, role: SinkRole, idor: bool) -> &'static RuleCard {
    if idor {
        return taint_by_slug("idor");
    }
    let slug = match (label, role) {
        // "eval" is the historic slug for code-execution sinks.
        (Some("eval"), _) => "execution",
        (Some(l), _) if find(TAINT, l).is_some() => l,
        (_, SinkRole::Xss) => "xss",
        (_, SinkRole::Execution) => "injection",
        _ => "other",
    };
    taint_by_slug(slug)
}

fn taint_by_slug(slug: &str) -> &'static RuleCard {
    find(TAINT, slug).unwrap_or_else(|| find(TAINT, "other").expect("fallback card"))
}

/// The taint class a CWE id names, as `(role, label slug)`.
///
/// Corpus families declare `cwe:` in their `[frensense]` block and the bundler
/// records it on the published advisory pattern, so this is class information
/// every `.frc` has always carried. Deriving a learned sink's role and label
/// from it classifies the sink **without a bundle format change**, which is
/// what keeps previously published bundles loadable.
///
/// Only the TAINT cards are considered: a CWE that only a checker rule names
/// (weak hash, TOCTOU) says nothing about what a sink does with its input.
#[must_use]
pub fn taint_class_for_cwe(cwe: &str) -> Option<(SinkRole, &'static str)> {
    let want = cwe.trim();
    // Parent CWEs describe "improper validation" in general, not what a sink
    // does with its input, and several class cards list them. Deriving a
    // class from one would invent a verdict the corpus never made.
    const BROAD: &[&str] = &["cwe-20", "cwe-74", "cwe-693"];
    let lower = want.to_ascii_lowercase();
    if BROAD.contains(&lower.as_str()) {
        return None;
    }
    // CWE variants an advisory files a defect under that our cards name by
    // their canonical id: Django's SQL injection is CWE-564, argument
    // injection is CWE-88. Aliased here rather than appended to the cards so
    // a finding's own CWE tags keep the canonical id.
    const ALIASES: &[(&str, &str)] = &[("cwe-564", "sql"), ("cwe-88", "command")];
    if let Some((_, slug)) = ALIASES.iter().find(|(alias, _)| *alias == lower) {
        return Some((taint_role_for_slug(slug), *slug));
    }
    TAINT
        .iter()
        // A generic card ("untrusted data reaches a sensitive operation")
        // names no class, so landing on one would classify nothing. CWE-20
        // and CWE-74 are attached to those catch-all cards.
        .filter(|(_, c)| !c.is_generic())
        .find(|(_, c)| c.cwe.iter().any(|id| id.eq_ignore_ascii_case(want)))
        .map(|(slug, _)| (taint_role_for_slug(slug), *slug))
}

/// The role a taint card's class implies. Classes with a dedicated role keep
/// it; every other class is code/SQL/command/deserialization, i.e.
/// `Execution`.
fn taint_role_for_slug(slug: &str) -> SinkRole {
    match slug {
        "traversal" => SinkRole::Resource,
        "storage" => SinkRole::Storage,
        "xss" => SinkRole::Xss,
        "response" => SinkRole::Response,
        "validation" => SinkRole::Validation,
        _ => SinkRole::Execution,
    }
}

/// Does a taint finding on this `(label, role)` pair name a vulnerability
/// class a consumer can act on?
///
/// Single source of truth for "is this taint finding reportable". The bundler's
/// replay gate and the CLI's advisory policy both answer it here, because they
/// answered it separately before: the gate asked only whether a finding
/// existed, the CLI asked whether it named a class, and the gate came to
/// approve learned sinks no surface would ever report.
#[must_use]
pub fn names_vulnerability_class(label: Option<&str>, role: SinkRole, idor: bool) -> bool {
    !taint_card(label, role, idor).is_generic()
}

/// Card for a built-in checker rule id, if one exists.
#[must_use]
pub fn checker_card(rule: &str) -> Option<&'static RuleCard> {
    find(CHECK, rule)
}

/// The checker rule key (`weak_hash`) a card id (`check.weak-hash`) belongs
/// to, for callers that hold a card id but need the registry key (tier,
/// suppression, per-rule scoring).
#[must_use]
pub fn checker_key(card_id: &str) -> Option<&'static str> {
    CHECK.iter().find(|(_, c)| c.id == card_id).map(|(k, _)| *k)
}

/// Card by its stable id (`taint.sql-injection`, `check.weak-hash`).
#[must_use]
pub fn card_by_id(id: &str) -> Option<&'static RuleCard> {
    all_cards().find(|c| c.id == id)
}

/// Every built-in card: taint first, then checkers.
pub fn all_cards() -> impl Iterator<Item = &'static RuleCard> {
    TAINT.iter().chain(CHECK.iter()).map(|(_, c)| c)
}

/// Sink-label slugs that have a card (for coverage tests in crates that
/// own the label enum).
pub fn taint_slugs() -> impl Iterator<Item = &'static str> {
    TAINT.iter().map(|(s, _)| *s)
}

fn find(table: &'static [(&'static str, RuleCard)], key: &str) -> Option<&'static RuleCard> {
    table.iter().find(|(k, _)| *k == key).map(|(_, c)| c)
}

/// Reference URL for a CWE id such as `CWE-89`.
#[must_use]
pub fn cwe_url(cwe: &str) -> String {
    let n = cwe.trim_start_matches("CWE-");
    format!("https://cwe.mitre.org/data/definitions/{n}.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_card_has_cwe_and_clean_id() {
        for c in all_cards() {
            assert!(!c.cwe.is_empty(), "{} has no CWE", c.id);
            for w in c.cwe {
                assert!(
                    w.starts_with("CWE-") && w[4..].chars().all(|d| d.is_ascii_digit()),
                    "{}: bad CWE {w}",
                    c.id
                );
            }
            assert!(
                c.id.starts_with("taint.") || c.id.starts_with("check."),
                "{}",
                c.id
            );
            assert!(
                c.id.chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '.' || ch == '-'),
                "{} must be lowercase kebab",
                c.id
            );
            assert!(!c.title.is_empty() && !c.why.is_empty() && !c.fix.is_empty());
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in all_cards() {
            assert!(seen.insert(c.id), "duplicate card id {}", c.id);
        }
    }

    #[test]
    fn unlabeled_sinks_still_resolve_a_cwe() {
        for role in [
            SinkRole::Execution,
            SinkRole::Resource,
            SinkRole::Storage,
            SinkRole::Crypto,
            SinkRole::Response,
            SinkRole::Validation,
            SinkRole::Xss,
            SinkRole::Other,
        ] {
            assert!(!taint_card(None, role, false).cwe.is_empty());
        }
    }

    #[test]
    fn only_the_fallback_cards_are_generic() {
        let generic: Vec<&str> = all_cards()
            .filter(|c| c.is_generic())
            .map(|c| c.id)
            .collect();
        assert_eq!(generic, ["taint.injection", "taint.untrusted-data"]);
        for id in ["taint.sql-injection", "taint.ssrf", "check.weak-hash"] {
            assert!(!card_by_id(id).expect(id).is_generic(), "{id}");
        }
    }

    #[test]
    fn historic_eval_slug_maps_to_code_injection() {
        assert_eq!(
            taint_card(Some("eval"), SinkRole::Execution, false).id,
            "taint.code-injection"
        );
    }
}

#[cfg(test)]
mod cwe_class_tests {
    use super::*;

    #[test]
    fn cwe_maps_to_the_taint_class_it_names() {
        assert_eq!(taint_class_for_cwe("CWE-89").map(|c| c.1), Some("sql"));
        assert_eq!(taint_class_for_cwe("CWE-564").map(|c| c.1), Some("sql"));
        assert_eq!(
            taint_class_for_cwe("CWE-22").map(|c| c.1),
            Some("traversal")
        );
        assert_eq!(
            taint_class_for_cwe("CWE-502").map(|c| c.1),
            Some("deserialize")
        );
        assert_eq!(taint_class_for_cwe("cwe-89").map(|c| c.1), Some("sql"));
    }

    #[test]
    fn cwe_roles_follow_the_class() {
        assert_eq!(
            taint_class_for_cwe("CWE-22").map(|c| c.0),
            Some(SinkRole::Resource)
        );
        assert_eq!(
            taint_class_for_cwe("CWE-79").map(|c| c.0),
            Some(SinkRole::Xss)
        );
        assert_eq!(
            taint_class_for_cwe("CWE-89").map(|c| c.0),
            Some(SinkRole::Execution)
        );
    }

    #[test]
    fn unknown_cwe_names_no_class() {
        assert!(taint_class_for_cwe("CWE-20").is_none());
        assert!(taint_class_for_cwe("").is_none());
    }

    #[test]
    fn classified_cwe_satisfies_the_reportability_predicate() {
        let (role, slug) = taint_class_for_cwe("CWE-89").expect("sql class");
        assert!(names_vulnerability_class(Some(slug), role, false));
        assert!(!names_vulnerability_class(None, SinkRole::Other, false));
    }
}
