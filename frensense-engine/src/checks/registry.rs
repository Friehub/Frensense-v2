// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! The non-dataflow check seam: one trait, one registry, one driver.
//!
//! Every non-dataflow check declares *how often it runs* and *how to run*;
//! the driver in [`super::check_all_with_graph_scoped`] supplies everything
//! that is common to all of them - the IR set, the whole-program value-flow
//! graph, the fact table, the package scope, the interprocedural memory
//! summaries - and owns the single finding-identity/dedup rule.
//!
//! Adding a check class is a new module plus one line in
//! [`default_registry`]. The driver does not change, `scan.rs` does not
//! change, and every existing check keeps its own mechanism (a proof over
//! the IR), while the *vocabulary* it consumes stays in [`FactTable`].
//!
//! Layering: the context deliberately carries no [`TaintConfig`], so a
//! non-dataflow check cannot reach into the taint engine's configuration.
//! Checks see lowered IR and facts only.
//!
//! [`TaintConfig`]: crate::analysis::taint::TaintConfig

use crate::analysis::forward::ProgramSvfg;
use crate::analysis::taint::facts::FactTable;
use crate::checks::CheckerFinding;
use crate::checks::memory_summary::MemorySummaryRegistry;
use crate::checks::policy::PackageScope;
use crate::ir::function::FunctionIR;

/// How often a registered check runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckScope {
    /// Once per function, with [`CheckContext::current`] set.
    Function,
    /// Once over the whole IR set, for checks that correlate definitions
    /// and guards across function boundaries.
    Program,
}

/// Everything a non-dataflow check may consult.
///
/// All fields are shared references owned by the driver for the duration
/// of one `check_all*` call; a check returns findings and never mutates
/// the context.
#[derive(Clone, Copy)]
pub struct CheckContext<'a> {
    /// Every function in the scanned program, in driver order.
    pub irs: &'a [&'a FunctionIR],
    /// The function under check: `Some` exactly when the running check is
    /// [`CheckScope::Function`].
    pub current: Option<&'a FunctionIR>,
    /// Whole-program value-flow graph, when the scan built one.
    pub prog: Option<&'a ProgramSvfg<'a>>,
    /// Built-in (pack-seeded) plus bundle-learned knowledge.
    pub facts: &'a FactTable,
    /// Package-import filter for policy facts; `None` disables filtering.
    pub pkg_scope: Option<&'a PackageScope<'a>>,
    /// Interprocedural memory summaries, inferred once per scan.
    pub summaries: &'a MemorySummaryRegistry,
}

impl<'a> CheckContext<'a> {
    /// The function under check.
    ///
    /// Panics when a [`CheckScope::Program`] check asks for a single
    /// subject: the scope method and `run` disagree, which is a
    /// programming error, not a property of the scanned code.
    pub fn ir(&self) -> &'a FunctionIR {
        self.current
            .expect("function-scoped check ran without a current function")
    }
}

/// One non-dataflow check class.
///
/// Implementations live in [`default_registry`] as thin adapters over the
/// mechanism modules, so a mechanism module stays a plain function over IR
/// and never needs to know that a registry exists.
///
/// `Sync` is required because the default registry is a `static`: every
/// implementation is stateless.
pub trait NonDataflowCheck: Sync {
    /// Stable id for this check class, used by diagnostics, per-class
    /// stats, and (future) bundle capability declarations.
    fn id(&self) -> &'static str;

    /// How often [`Self::run`] should be called by the driver.
    fn scope(&self) -> CheckScope;

    /// Run the check and return its findings. The driver deduplicates and
    /// orders the union of every check's output; a check itself makes no
    /// ordering promises and must not dedup against other checks.
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding>;
}

/// An ordered set of check classes.
///
/// Registry order is part of the output contract: the driver's final sort
/// is stable, so findings sharing a `(function, span)` key keep their
/// insertion order, which follows this list on function-scoped runs.
pub struct CheckRegistry {
    checks: &'static [&'static dyn NonDataflowCheck],
}

impl CheckRegistry {
    /// The registered check classes, in run order.
    pub fn checks(&self) -> impl Iterator<Item = &'static dyn NonDataflowCheck> + '_ {
        self.checks.iter().copied()
    }

    /// Number of registered check classes.
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// Whether no check is registered (only constructible by a caller
    /// building its own registry; [`default_registry`] is never empty).
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Adapters: one per mechanism module, in the order the driver used to chain
// them. These are the only place the registry knows a mechanism's name.
// ---------------------------------------------------------------------------

/// Weak hash / key size / insecure algorithm selectors.
struct WeakHash;
impl NonDataflowCheck for WeakHash {
    fn id(&self) -> &'static str {
        "weak_crypto"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::weak_hash::check(ctx.ir(), ctx.facts)
    }
}

/// Allowlist containment calls (URL/host predicates).
struct GuardBypass;
impl NonDataflowCheck for GuardBypass {
    fn id(&self) -> &'static str {
        "guard_bypass"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::guard_bypass::check(ctx.ir(), ctx.facts)
    }
}

/// Credential values reaching logs, responses, or telemetry.
struct CredentialLeak;
impl NonDataflowCheck for CredentialLeak {
    fn id(&self) -> &'static str {
        "credential_leak"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::guard_bypass::check_credentials_in(ctx.ir(), ctx.facts, ctx.irs)
    }
}

/// Schema-validation builders/enforcers (suppression vocabulary).
struct SchemaPolicy;
impl NonDataflowCheck for SchemaPolicy {
    fn id(&self) -> &'static str {
        "schema_policy"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::schema_policy::check(ctx.ir(), ctx.facts)
    }
}

/// Free-then-use / double-free / uninitialized free.
struct UseAfterFree;
impl NonDataflowCheck for UseAfterFree {
    fn id(&self) -> &'static str {
        "use_after_free"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        // The program graph upgrades discovery (callee-internal frees,
        // factory provenance); without it, parameter-consumption summaries
        // still recognise frees at call sites.
        match ctx
            .prog
            .and_then(|p| p.function_index(&ctx.ir().name).map(|fi| (p, fi)))
        {
            Some((p, fi)) => super::uaf::check_with_prog(fi, p, ctx.summaries),
            None => super::uaf::check_with_summaries(ctx.ir(), ctx.summaries),
        }
    }
}

/// Spatial memory safety (overflow / OOB read / negative index).
struct OutOfBounds;
impl NonDataflowCheck for OutOfBounds {
    fn id(&self) -> &'static str {
        "out_of_bounds"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::oob::check_with_summaries(ctx.ir(), ctx.summaries, ctx.facts)
    }
}

/// Allocation-size integer overflow.
struct IntegerOverflow;
impl NonDataflowCheck for IntegerOverflow {
    fn id(&self) -> &'static str {
        "integer_overflow"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::int_overflow::check(ctx.ir(), ctx.summaries, ctx.facts)
    }
}

/// Frame-owned allocation reaching function exit (CWE-401).
struct MemoryLeak;
impl NonDataflowCheck for MemoryLeak {
    fn id(&self) -> &'static str {
        "memory_leak"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::leak::check(ctx.ir(), ctx.summaries, ctx.facts)
    }
}

/// Corpus-verified structural checks from the fact table.
struct LearnedChecks;
impl NonDataflowCheck for LearnedChecks {
    fn id(&self) -> &'static str {
        "learned_check"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::learned::check(ctx.ir(), ctx.facts)
    }
}

/// Functions whose control flow has outgrown review (hygiene tier).
struct FunctionComplexity;
impl NonDataflowCheck for FunctionComplexity {
    fn id(&self) -> &'static str {
        "function_complexity"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Function
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::health::check(ctx.ir())
    }
}

/// Allowlist definitions that are too weak to contain a hostile URL.
/// Program-scoped: correlates the definition with its call sites.
struct AllowlistDefinitions;
impl NonDataflowCheck for AllowlistDefinitions {
    fn id(&self) -> &'static str {
        "guard_bypass_definitions"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Program
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::guard_bypass::check_allowlist_definitions(ctx.irs, ctx.facts)
    }
}

/// Co-occurrence / guard / argument policies (built-in and bundle-learned
/// `PolicyFact`s). Program-scoped: module-scope requirements may be
/// satisfied by any function in the scanned set.
struct Policies;
impl NonDataflowCheck for Policies {
    fn id(&self) -> &'static str {
        "policy"
    }
    fn scope(&self) -> CheckScope {
        CheckScope::Program
    }
    fn run(&self, ctx: &CheckContext<'_>) -> Vec<CheckerFinding> {
        super::policy::check_program_scoped(ctx.irs, ctx.facts, ctx.pkg_scope)
    }
}

/// The default check set, in run order.
///
/// Function-scoped checks are listed in the order the driver used to chain
/// them per function; program-scoped checks are listed first because they
/// run once, before any per-function pass.
pub fn default_registry() -> CheckRegistry {
    static CHECKS: &[&dyn NonDataflowCheck] = &[
        &AllowlistDefinitions,
        &Policies,
        &WeakHash,
        &GuardBypass,
        &CredentialLeak,
        &SchemaPolicy,
        &UseAfterFree,
        &OutOfBounds,
        &IntegerOverflow,
        &MemoryLeak,
        &LearnedChecks,
        &FunctionComplexity,
    ];
    CheckRegistry { checks: CHECKS }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hash::FxHashSet;

    /// Ids identify classes: two checks sharing one would make per-class
    /// stats and gating ambiguous.
    #[test]
    fn ids_are_unique_and_non_empty() {
        let registry = default_registry();
        let mut seen: FxHashSet<&'static str> = FxHashSet::default();
        for check in registry.checks() {
            let id = check.id();
            assert!(!id.is_empty(), "check id must not be empty");
            assert!(seen.insert(id), "duplicate check id: {id}");
        }
    }

    /// The driver has two passes; a registry missing either scope silently
    /// drops that whole class of findings.
    #[test]
    fn registry_covers_both_scopes() {
        let registry = default_registry();
        assert!(
            registry.checks().any(|c| c.scope() == CheckScope::Program),
            "no program-scoped check registered"
        );
        assert!(
            registry.checks().any(|c| c.scope() == CheckScope::Function),
            "no function-scoped check registered"
        );
    }

    /// Pins the composition: adding a check class is a deliberate edit to
    /// `default_registry`, not an accident.
    #[test]
    fn default_registry_has_expected_size() {
        assert_eq!(default_registry().len(), 12);
        assert!(!default_registry().is_empty());
    }

    /// A function-scoped check must never be handed a context without a
    /// subject; the accessor fails loudly rather than scanning `None`.
    #[test]
    #[should_panic(expected = "function-scoped check ran without a current function")]
    fn ir_accessor_requires_a_current_function() {
        let irs: Vec<&FunctionIR> = Vec::new();
        let facts = FactTable::default();
        let summaries = MemorySummaryRegistry::default();
        let ctx = CheckContext {
            irs: &irs,
            current: None,
            prog: None,
            facts: &facts,
            pkg_scope: None,
            summaries: &summaries,
        };
        let _ = ctx.ir();
    }
}
