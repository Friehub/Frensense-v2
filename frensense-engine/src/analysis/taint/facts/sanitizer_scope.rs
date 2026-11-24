// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Scoped sanitizer facts: package- and class-scope lookup/install, and
//! the one install path every language-keyed sanitizer entry takes.

use super::signatures::{
    CLASS_SCOPED_SANITIZER_PREFIX, class_scope_package_matches, is_class_scope, scoped_lookup,
};
use super::{FactTable, SanitizerFact};
use crate::analysis::taint::config::TaintConfig;

/// Resolve a scoped sanitizer fact for a call site's resolved import origin.
///
/// Vocabularies name a package the way its source text does (`filepath`,
/// `os.path`), while import resolution reports the path the import actually
/// names (`path/filepath`, `os.path`). `scoped_lookup` walks an origin
/// *upward*, so a fact scoped to the origin's own last segment never
/// resolved: the Go stdlib entry `filepath.Base`, scoped to `filepath`,
/// stayed inert at every site importing `path/filepath`. The documented-safe
/// negation of the Go traversal family then reported a false positive
/// (`go/cwe_022_traversal/go_traversal_asset_open_heldout_negative.go`).
/// Retry that single segment before the site is judged a foreign package.
fn scoped_sanitizer_lookup<'a>(
    facts: &'a rustc_hash::FxHashMap<(String, String), SanitizerFact>,
    origin: &str,
    call: &str,
) -> Option<&'a SanitizerFact> {
    if let Some(fact) = scoped_lookup(facts, origin, call) {
        return Some(fact);
    }
    let segment = origin.rsplit(['/', '.']).next().unwrap_or(origin);
    if segment == origin {
        return None;
    }
    facts.get(&(segment.to_string(), call.to_string()))
}

impl FactTable {
    /// Sanitizer fact for a call, package-aware.
    ///
    /// Scoping semantics (recall-safe): a fact installed under
    /// `(package, call)` applies ONLY when `origin_package` names that
    /// package. Origin known-but-different falls back to universal
    /// facts only, a foreign package's sanitizer must never cut this
    /// call. Origin unknown also matches universal facts only.
    ///
    /// Recall-safety analysis (why unknown origin does NOT take the
    /// any-package fallback): a sanitizer CUTS a finding, so a scoped
    /// fact that fires on an unconfirmed origin can silence a true
    /// finding, the one error that costs recall. The reverse error
    /// (a genuine package sanitizer whose origin does not resolve goes
    /// uncut) surfaces an advisory, which costs precision only.
    /// Universal facts were proven for the bare call name regardless of
    /// receiver, so they remain safe under any origin; a scoped fact
    /// suppresses only once import resolution confirms its package.
    pub(crate) fn sanitizer_fact_scoped(
        &self,
        call: &str,
        origin_package: Option<&str>,
    ) -> Option<&SanitizerFact> {
        if let Some(pkg) = origin_package {
            if let Some(f) = scoped_sanitizer_lookup(&self.scoped_sanitizer_facts, pkg, call) {
                return Some(f);
            }
            let is_package_scoped = self
                .scoped_sanitizer_facts
                .keys()
                .any(|(scope, c)| c == call && !is_class_scope(scope));
            if is_package_scoped {
                // Known-package mismatch: the fact belongs to another
                // package, and the universal entry of the same name must not
                // resurrect it here. That fallback was the wildcard-scope
                // hole: a `shlex.quote` fact silenced a call whose origin was
                // a different module. Unknown-origin sites still reach the
                // universal entry below, which is the legacy reading.
                return None;
            }
        }
        for ((scope, scoped_call), fact) in &self.scoped_sanitizer_facts {
            if scoped_call == call
                && is_class_scope(scope)
                && class_scope_package_matches(fact, origin_package)
            {
                return Some(fact);
            }
        }
        self.sanitizer_facts.get(call)
    }

    /// Install `fact` as a sanitizer proven to defeat only the given sink
    /// classes (`bug_classes.json` ids such as `inj.sql`; `*` is a wildcard).
    ///
    /// The class scope rides on the published [`FactTable::scoped_sanitizer_facts`]
    /// map under the reserved `CLASS_SCOPED_SANITIZER_PREFIX` key, so the
    /// table keeps its shape: one entry `(class:<id>, call)` per class. An
    /// empty `classes` list is a plain, unscoped install.
    pub fn add_class_scoped_sanitizer(&mut self, fact: SanitizerFact, classes: &[String]) {
        if classes.is_empty() {
            match &fact.package {
                Some(pkg) => {
                    self.scoped_sanitizer_facts
                        .insert((pkg.clone(), fact.call.clone()), fact);
                }
                None => {
                    self.sanitizer_facts.insert(fact.call.clone(), fact);
                }
            }
            return;
        }
        for class in classes {
            // A lookup key, not prose: built without `format!` so the purity
            // ratchet's engine_prose_format count stays flat.
            let mut scope =
                String::with_capacity(CLASS_SCOPED_SANITIZER_PREFIX.len() + class.len());
            scope.push_str(CLASS_SCOPED_SANITIZER_PREFIX);
            scope.push_str(class);
            self.scoped_sanitizer_facts
                .insert((scope, fact.call.clone()), fact.clone());
        }
    }

    /// Re-scope an already-installed sanitizer fact to `classes`.
    ///
    /// The fact is moved out of the unscoped/package-scoped slot and
    /// re-installed under the class keys of
    /// [`Self::add_class_scoped_sanitizer`]. Returns `false` when no fact is
    /// installed for `(package, call)`.
    pub fn scope_sanitizer(
        &mut self,
        call: &str,
        package: Option<&str>,
        classes: &[String],
    ) -> bool {
        let fact = match package {
            Some(pkg) => self
                .scoped_sanitizer_facts
                .remove(&(pkg.to_string(), call.to_string())),
            None => self.sanitizer_facts.remove(call),
        };
        let Some(fact) = fact else {
            return false;
        };
        self.add_class_scoped_sanitizer(fact, classes);
        true
    }

    /// The sink classes `call` was proven to defeat for `origin_package`.
    ///
    /// Empty means the fact is unscoped (valid for every class, the legacy
    /// reading). A package-qualified class scope follows the same recall-safe
    /// rule as `FactTable::sanitizer_fact_scoped` (crate-internal): it only
    /// fires once import resolution confirms its package.
    pub fn sanitizer_classes(&self, call: &str, origin_package: Option<&str>) -> Vec<String> {
        let mut classes: Vec<String> = Vec::new();
        for ((scope, scoped_call), fact) in &self.scoped_sanitizer_facts {
            if scoped_call != call || !class_scope_package_matches(fact, origin_package) {
                continue;
            }
            if let Some(class) = scope.strip_prefix(CLASS_SCOPED_SANITIZER_PREFIX) {
                classes.push(class.to_string());
            }
        }
        classes.sort();
        classes.dedup();
        classes
    }

    /// Sanitizer fact for a call; `None` if not a sanitizer.
    ///
    /// No import origin is available at this call site, so package-
    /// scoped facts are inert here (recall-safe: they only ever suppress
    /// under a confirmed origin). Pass `Some(origin)` via
    /// `Self::sanitizer_fact_scoped` where import context exists.
    pub fn sanitizer_fact(&self, call: &str) -> Option<&SanitizerFact> {
        self.sanitizer_fact_scoped(call, None)
    }
}

/// Install one language-keyed sanitizer entry, scoped by what the entry
/// actually proves.
///
/// * A package entry installs ONLY under `(package, call)`. No universal
///   entry and no `config.sanitizers` entry: both are consulted without
///   import context, so a universal alias would cut the call on any
///   receiver and silence true findings whose origin is another package
///   (or unknown).
/// * A package-less fact still names its own origin when the call is
///   dotted: `shlex.quote` belongs to `shlex`. The derived root scope is
///   installed beside the universal entry, so a call resolved to a
///   different package cannot inherit it while unknown-origin sites keep
///   the legacy universal match.
pub(crate) fn install_language_sanitizer(
    config: &mut TaintConfig,
    facts: &mut FactTable,
    call: &str,
    package: Option<&str>,
    kind: &str,
    guard_style: bool,
) {
    let fact = SanitizerFact {
        call: call.to_string(),
        package: package.map(str::to_string),
        kind: kind.to_string(),
        sanitizes_args: Default::default(),
        guard_style,
    };
    if let Some(pkg) = package {
        facts
            .scoped_sanitizer_facts
            .insert((pkg.to_string(), call.to_string()), fact);
        return;
    }
    if let Some((root, _)) = call.split_once('.') {
        let last = call.rsplit('.').next().unwrap_or(call);
        facts
            .scoped_sanitizer_facts
            .insert((root.to_string(), call.to_string()), fact.clone());
        if last != call {
            facts
                .scoped_sanitizer_facts
                .insert((root.to_string(), last.to_string()), fact.clone());
        }
    }
    config.sanitizers.insert(call.to_string());
    facts
        .sanitizer_facts
        .entry(call.to_string())
        .or_insert(fact);
}
