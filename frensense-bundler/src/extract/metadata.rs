// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The `[frensense]` advisory metadata block a corpus family's positive
//! carries: observation, impact, declared guards, declared sanitizers and the
//! identity the file is expected to report.
//!
//! Parsing is separate from family grouping: grouping needs the block (a
//! declaration can name a family's trigger), but nothing here knows about
//! files, variants or language splits.

/// Advisory metadata from a positive's `[frensense]` comment block.
///
/// Human-facing advisory text baked into the `.frc` as a `BundlePattern`;
/// flow knowledge lives in `learned_facts`, never here. All fields are
/// optional: a family without a `[frensense]` block still groups and votes,
/// it just ships no advisory text.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FamilyMetadata {
    pub observation: Option<String>,
    pub impact: Option<String>,
    pub improvement: Option<String>,
    pub cwe: Option<String>,
    pub cvss: Option<f32>,
    pub owasp: Option<String>,
    pub severity: Option<String>,
    /// Declared prover rule id (`check-rule:`): the family teaches this
    /// allocation-size integer-overflow rule; extraction proposes it as an
    /// `IntegerOverflowRule` fact regardless of delta signal (the replay
    /// gate still validates separation).
    pub check_rule: Option<String>,
    /// Declared wrap threshold (`wrap-max:`): products above this value
    /// cannot be an allocation size on the family's target platform
    /// (default u64::MAX == SIZE_MAX on LP64/LLP64).
    pub wrap_max: Option<u128>,
    /// Declared unbounded-operand modality (`unbounded-product: true`): the
    /// taught integer-overflow rule also fires when BOTH operands of the
    /// size multiplication are unboundedly dynamic (`malloc(rows * cols)`
    /// with operator-provided values). Default off: rules keep the
    /// zero-FP provable-range contract unless the author opts in, and the
    /// replay gate still validates that the corpus separates (the
    /// negative clamps the operands with literal-bound guards).
    pub unbounded_product: bool,
    /// Declared framework package provenance (`package: name`).
    pub package: Option<String>,
    /// Declared enforcement guards (`guard: verify_admin_permission` or a
    /// comma-separated synonym set `guard: verify_admin_permission, user.can`).
    /// Declaring them replaces automatic guard synthesis: the learned fact
    /// accepts ANY of them executing before the trigger (RequireCall
    /// `any_of`), so one family can teach equivalent enforcement helpers,
    /// member-qualified predicates, and alternate spellings. Names are
    /// matched by last callee segment (member paths welcome).
    pub guards: Vec<String>,
    /// Explicit policy requirements authored in the metadata block
    /// (`require-arg-key: <slot|any> <key[,key...]>`): the trigger call's
    /// argument at `slot` must trace to an object construction carrying
    /// one of the keys (`updateMany({ where: ... })`). `usize::MAX` slot
    /// means any argument position. Declaration replaces automatic guard
    /// synthesis: authors state the discriminator instead of hoping the
    /// twin diff collides with it (the Date-guard coincidence class).
    pub require_arg_keys: Vec<(usize, String)>,
    /// Declared vulnerability class (`class:`), a `bug_classes.json` id such
    /// as `inj.sql` or `net.ssrf`. This is the class a learned sanitizer is
    /// scoped to: `isURL` in an SSRF family may not clear a command sink.
    pub class: Option<String>,
    /// Declared purpose (`purpose:`): `knowledge`, `precision` or `anchor`.
    pub purpose: Option<String>,
    /// Declared reporting tier for its authored policy (`tier:`): `stable`,
    /// `beta`, `hygiene` or `experimental`. Only certified corpus bundles can
    /// ship a `stable` policy; the loader caps every other trust tier at
    /// `hygiene`. Absent = the consumer's registry default.
    pub tier: Option<String>,
    /// Declared lifecycle for its authored policy (`status:`): `active`,
    /// `deprecated` or `removed`. `deprecated` loads hidden by default and
    /// announces itself when enabled; `removed` is dropped at load.
    pub status: Option<String>,
    /// `policy: authored` marks a family whose Check/Policy facts are
    /// explicitly authored. Policies are never inferred from a family diff:
    /// without this declaration (or an explicit `guard:` / `require-arg-key:`
    /// requirement) the proposal stage emits no policy fact.
    pub policy_authored: bool,
    /// Explicitly declared sanitizer calls (`sanitizer: name[, name...]`).
    /// An explicit declaration is what the lint can scope-check; automatic
    /// delta sanitizers are linted against their family's `class:` instead.
    pub sanitizers: Vec<String>,
    /// Declared identities the positive is expected to report
    /// (`expect: policy_aget_user_by_uuid`). A `policy_<call>` entry names the
    /// policy rule the family teaches, so the call after the prefix is the
    /// trigger the proposal stage builds that rule for - the author states the
    /// identity, the bundler does not have to infer it from the delta.
    pub expect: Vec<String>,
}

impl FamilyMetadata {
    /// The policy trigger a family's declared identity names.
    ///
    /// `expect: policy_aget_user_by_uuid` says the defect is executing that
    /// call without the enforcement its negative demonstrates. Policies are
    /// authored, never inferred, so this is the author's declaration arriving
    /// in the identity form the replay gate checks - the rule name *is* the
    /// call, prefixed.
    pub fn declared_policy_call(&self) -> Option<String> {
        self.expect
            .iter()
            .find_map(|id| id.strip_prefix("policy_"))
            .filter(|call| !call.is_empty())
            .map(str::to_string)
    }

    /// Parse a `[frensense]` block from a variant's first `head_lines`
    /// lines. Comment prefixes follow the language (`#` for Python, `//`
    /// elsewhere), matching the `check-call` convention. The block is a
    /// run of comment lines whose first line opens with `[frensense]`;
    /// `key: value` lines inside it fill the fields. Only positives
    /// should carry the block, but parsing is variant-agnostic.
    pub fn parse(source: &str, ext: &str, head_lines: usize) -> Self {
        let hash_style = ext == "py" || ext == "pyi" || ext == "pyw";
        let prefixes: &[&str] = if hash_style {
            &["#", "//"]
        } else {
            &["//", "#"]
        };
        fn strip<'a>(prefixes: &[&'a str], line: &'a str) -> Option<&'a str> {
            let t = line.trim();
            prefixes
                .iter()
                .find_map(|p| t.strip_prefix(p))
                .map(|s| s.trim())
        }

        let mut meta = Self::default();
        let mut in_block = false;
        for line in source.lines().take(head_lines) {
            let Some(body) = strip(prefixes, line) else {
                // A non-comment line ends the block once it has started.
                if in_block {
                    break;
                }
                continue;
            };
            if body == "[frensense]" {
                in_block = true;
                continue;
            }
            if !in_block {
                continue;
            }
            let Some((key, value)) = body.split_once(':') else {
                // Unknown line inside the block (e.g. `check-call:`) -
                // other parsers consume it; skip here.
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match key.trim().to_ascii_lowercase().as_str() {
                "observation" => meta.observation = Some(value.to_string()),
                "impact" => meta.impact = Some(value.to_string()),
                "improvement" => meta.improvement = Some(value.to_string()),
                "cwe" => meta.cwe = Some(value.to_string()),
                "cvss" => {
                    if let Ok(v) = value.parse::<f32>() {
                        meta.cvss = Some(v);
                    }
                }
                "owasp" => meta.owasp = Some(value.to_string()),
                "severity" => meta.severity = Some(value.to_string()),
                "check-rule" => meta.check_rule = Some(value.to_string()),
                "wrap-max" => {
                    if let Ok(v) = value.parse::<u128>() {
                        meta.wrap_max = Some(v);
                    }
                }
                "unbounded-product" => {
                    meta.unbounded_product = value.eq_ignore_ascii_case("true");
                }
                "package" => meta.package = Some(value.to_string()),
                "class" => meta.class = Some(value.to_string()),
                "purpose" => meta.purpose = Some(value.to_string()),
                "tier" => meta.tier = Some(value.to_ascii_lowercase()),
                "status" => meta.status = Some(value.to_ascii_lowercase()),
                "policy" => {
                    meta.policy_authored = matches!(
                        value.to_ascii_lowercase().as_str(),
                        "authored" | "true" | "yes"
                    );
                }
                "sanitizer" => {
                    for name in split_csv_keys(value) {
                        if !meta.sanitizers.contains(&name) {
                            meta.sanitizers.push(name);
                        }
                    }
                }
                "expect" => {
                    for id in split_csv_keys(value) {
                        if !meta.expect.contains(&id) {
                            meta.expect.push(id);
                        }
                    }
                }
                "guard" => {
                    for g in split_csv_keys(value) {
                        if !meta.guards.contains(&g) {
                            meta.guards.push(g);
                        }
                    }
                }
                "require-arg-key" => {
                    let mut parts = value.split_whitespace();
                    match parts.next() {
                        Some("any") => {
                            for key in parts {
                                meta.require_arg_keys.push((usize::MAX, key.to_string()));
                            }
                        }
                        Some(slot) => match slot.parse::<usize>() {
                            Ok(slot) => {
                                let keys: Vec<String> = match parts.next() {
                                    Some(rest) => split_csv_keys(rest),
                                    None => Vec::new(),
                                };
                                for key in keys {
                                    meta.require_arg_keys.push((slot, key));
                                }
                            }
                            Err(_) => {}
                        },
                        None => {}
                    }
                }
                _ => {}
            }
        }
        meta
    }
}

/// Split a declared list (`guard:`, `sanitizer:`, `expect:`): comma and/or
/// whitespace separated (`where`, `where,filter`, `where filter`).
fn split_csv_keys(rest: &str) -> Vec<String> {
    rest.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}
