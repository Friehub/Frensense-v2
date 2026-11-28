// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Which sink signature answers for a call: the package-exact entry, the
//! decorated sibling of a taught operation, or a sibling *package* of the same
//! category.
//!
//! Split out of `signatures.rs`: every rule here reasons about the same two
//! inputs (the call site's resolved origin and its language), so they stay
//! together rather than in three places across the matcher.

use super::signatures::scoped_lookup;
use super::{FactTable, SinkSignature};

impl FactTable {
    /// Sink signature for a call, package-aware.
    ///
    /// Scoping semantics (zero-FP): a fact installed under `(package, call)`
    /// matches ONLY when `origin_package` names that package. Origin
    /// unknown matches universal facts only for non-verb sinks; origin
    /// known-but-different matches universal facts only (the walker arms
    /// origin via import resolution before implying a package from the
    /// receiver root). This is what keeps a bundle fact like
    /// `(@prisma/client).$queryRawUnsafe` from firing on a local object
    /// whose method happens to share the name.
    pub(crate) fn sink_signature_scoped(
        &self,
        call: &str,
        origin_package: Option<&str>,
        language: Option<&str>,
    ) -> Option<&SinkSignature> {
        if let Some(pkg) = origin_package {
            if let Some(sig) = scoped_lookup(&self.scoped_sink_signatures, pkg, call) {
                return Some(sig);
            }
            // Decorated sibling of a taught operation (`extractAllToAsync`
            // for `extractAllTo`) is the same sink under the same package.
            if let Some(base) = super::mirror_call_base(call)
                && let Some(sig) = scoped_lookup(&self.scoped_sink_signatures, pkg, base)
            {
                return Some(sig);
            }
            // Same-kind sibling package: the risk follows what the language
            // says the library is. `sqlite3.execute` taught the query-string
            // layout; a MySQL driver's `execute` takes it the same way.
            if let Some(lang) = language
                && let Some(sig) = self.category_sink_signature(lang, pkg, call)
            {
                return Some(sig);
            }
            let is_package_scoped = self
                .scoped_sink_signatures
                .keys()
                .any(|(_, c)| c == call || super::mirror_call_base(call) == Some(c.as_str()));
            if is_package_scoped {
                // Known package origin mismatch: do not fall back to other
                // packages' scoped sinks, only the caller's own language and
                // the language-agnostic facts.
                return self.sink_signature_for_language(call, language);
            }
        }
        // Origin unknown: universal + this language's facts only (same rule
        // as sanitizers - a package-scoped fact applies only under a
        // confirmed origin). Scope-separated callees
        // (`std::fs::read_to_string`) fall back through their `::` suffixes
        // exactly like [`Self::sink_signature`], so a qualified call matches
        // the bare callable entry when no qualified shape was declared
        // (WI-11); exact matches keep precedence.
        self.sink_signature_for_language(call, language)
    }

    /// The signature a *sibling package* proved for `call`, when no entry
    /// names this package.
    ///
    /// A sink fact is proven for one package (`sqlite3.execute`), but the risk
    /// follows the kind of library the language classifies it into: a MySQL
    /// driver's `execute` takes the query string at the same slot, the same
    /// way. Only a member name a fact already proved is generalised, and only
    /// across packages the language places in the same
    /// [`PackageCategory`](frensense_lang::spec::PackageCategory), so no call
    /// is armed on its category alone - the argument layout, the role and the
    /// label all come from the measured fact. Ties break on the package name
    /// so a scan stays deterministic.
    pub(super) fn category_sink_signature<'a>(
        &'a self,
        language: &str,
        origin_package: &str,
        call: &str,
    ) -> Option<&'a SinkSignature> {
        let spec = frensense_lang::registry::LanguageRegistry::global().for_name(language)?;
        let category = spec.package_category(origin_package)?;
        self.scoped_sink_signatures
            .iter()
            .filter(|((pkg, scoped_call), _)| {
                scoped_call == call && spec.package_category(pkg) == Some(category)
            })
            .min_by(|((a, _), _), ((b, _), _)| a.cmp(b))
            .map(|(_, sig)| sig)
    }
}

impl FactTable {
    /// Attach store-sink base kinds to an already-installed signature.
    ///
    /// The hint rides in the bundle's payload side table (v10+), keyed by
    /// `(call, package)`, because no entry variant carries it. Returns `false`
    /// when no signature is installed for that key, so a stale table is
    /// visible instead of silent.
    pub fn qualify_sink_base_kinds(
        &mut self,
        call: &str,
        package: Option<&str>,
        kinds: &[String],
    ) -> bool {
        // A pack installs `LanguageSink` signatures into the per-language
        // tables, so a lookup can resolve to any of them: hint every copy.
        let mut hit = false;
        if package.is_none() {
            if let Some(sig) = self.sink_signatures.get_mut(call) {
                sig.base_kinds = kinds.to_vec();
                hit = true;
            }
            for table in self.lang_sink_signatures.values_mut() {
                if let Some(sig) = table.get_mut(call) {
                    sig.base_kinds = kinds.to_vec();
                    hit = true;
                }
            }
        } else if let Some(pkg) = package
            && let Some(sig) = self
                .scoped_sink_signatures
                .get_mut(&(pkg.to_string(), call.to_string()))
        {
            sig.base_kinds = kinds.to_vec();
            hit = true;
        }
        hit
    }
}

impl FactTable {
    /// Apply a whole `(call, package, kinds)` table, as a bundle payload
    /// carries it. Returns how many installed signatures it reached.
    pub fn apply_sink_base_kinds<'a, I>(&mut self, scopes: I) -> usize
    where
        I: IntoIterator<Item = (&'a str, Option<&'a str>, &'a [String])>,
    {
        scopes
            .into_iter()
            .filter(|(call, package, kinds)| self.qualify_sink_base_kinds(call, *package, kinds))
            .count()
    }
}
