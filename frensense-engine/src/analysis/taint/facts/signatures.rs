// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

/// Resolve a `(package, call)` entry for a call site's import origin.
///
/// A corpus family declares the *package* it teaches (`lodash`, `django`,
/// `@scope/pkg`), but an import names a path *into* that package:
/// `require("lodash/template")`, `from django.db.models.functions import
/// Trunc`, `github.com/mholt/archiver/v4`. Under exact-key matching the
/// fact went inert on every subpath import of its own package - the
/// Django family's own positive was silent through the CLI while the
/// replay gate, which installs the candidate unscoped, accepted it.
///
/// Match the origin itself first, then each shorter root above it at a
/// path boundary. Only a root that is actually a key can match, so a
/// partial segment (`@scope` from `@scope/pkg`) never arms anything, and
/// a fact proven for `pkg/sub` still never arms the whole of `pkg` - the
/// walk only ever widens a call site's origin, never a fact's scope.
fn scoped_lookup<'a, V>(
    map: &'a rustc_hash::FxHashMap<(String, String), V>,
    origin: &str,
    call: &str,
) -> Option<&'a V> {
    let mut end = origin.len();
    loop {
        let root = &origin[..end];
        if let Some(v) = map.get(&(root.to_string(), call.to_string())) {
            return Some(v);
        }
        match origin[..end].rfind(['/', '.']) {
            Some(i) if i > 0 => {
                // `@scope` alone is not a package; its name follows the slash.
                if root.starts_with('@') && !root[1..].contains('/') {
                    return None;
                }
                end = i;
            }
            _ => return None,
        }
    }
}

impl FactTable {
    /// Session-accessor check over the receiver's full access path.
    /// Session stores are usually namespaced (`security.authenticatedUsers`),
    /// so ANY dotted segment matching a declared root qualifies:
    /// `security.authenticatedUsers.get(t)` hits root `authenticatedUsers`.
    pub fn is_session_path(&self, last: &str, receiver_path: Option<&str>) -> bool {
        if !self.is_session_accessor(last) {
            return false;
        }
        let Some(path) = receiver_path else {
            return false;
        };
        path.split('.').any(|seg| self.session_roots.contains(seg))
    }

    /// Resolve the receiver's full member-access path from the IR by
    /// walking LoadField defs and joining named segments:
    /// `security.authenticatedUsers.get(...)` →
    /// `Some("security.authenticatedUsers")`.
    ///
    /// Mirrors [`FactTable::receiver_root`] but keeps every named hop, so
    /// namespaced session stores match their declared root segment.
    pub fn receiver_access_path(
        ir: &crate::ir::function::FunctionIR,
        var: crate::ir::function::VarId,
    ) -> Option<String> {
        let mut segments: Vec<String> = Vec::new();
        let mut cur = var;
        for _ in 0..8 {
            if let Some(meta) = ir.var_metadata.get(&cur)
                && let Some(name) = &meta.source_name
            {
                segments.push(name.clone());
                break;
            }
            // Continue through the LoadField that defines `cur`.
            let (base, field) = ir.loadfield_def(cur)?;
            segments.push(field);
            cur = base;
        }
        if segments.is_empty() {
            return None;
        }
        segments.reverse();
        Some(segments.join("."))
    }

    /// Signature for a sink call, without a call site's language context;
    /// `None` if the call is not a declared sink in any language.
    ///
    /// This is the "no call site" accessor (bundler candidate checks, table
    /// assertions): it takes the language-agnostic lane, then over-
    /// approximates across every installed language. The scan path always
    /// has an IR and must use [`Self::sink_signature_for_language`] with its
    /// language instead, or a Rust fact would arm a TypeScript call.
    pub fn sink_signature(&self, call: &str) -> Option<&SinkSignature> {
        self.sink_signature_for_language(call, None)
    }

    /// Role for a sink call, receiver-aware.
    ///
    /// When the receiver root matches a dotted entry's declared root (e.g.
    /// `KVNamespace` for `kv.put(t)`), that entry's role wins over the bare
    /// last-segment entry's. Falls back to [`Self::sink_signature`] when no
    /// receiver-specific role exists.
    pub fn role_for_call(
        &self,
        last: &str,
        receiver_root: Option<&str>,
    ) -> Option<crate::analysis::taint::role::SinkRole> {
        self.role_for_call_scoped(last, receiver_root, None, None)
    }

    /// Semantic label slug for a sink call, receiver-aware.
    pub fn label_for_call(&self, last: &str, receiver_root: Option<&str>) -> Option<String> {
        self.label_for_call_scoped(last, receiver_root, None, None)
    }

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
    pub fn sink_signature_scoped(
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

    /// Role for a sink call, receiver-aware and package-aware.
    ///
    /// Consults (in order): the (receiver-root, method) pair from dotted
    /// entries, the (origin-package, method) scoped entry set, then the
    /// universal signature map.
    pub fn role_for_call_scoped(
        &self,
        last: &str,
        receiver_root: Option<&str>,
        origin_package: Option<&str>,
        language: Option<&str>,
    ) -> Option<crate::analysis::taint::role::SinkRole> {
        if let Some(pkg) = origin_package
            && let Some(sig) = scoped_lookup(&self.scoped_sink_signatures, pkg, last)
        {
            return Some(sig.role);
        }
        if let Some(root) = receiver_root
            && let Some(role) = self
                .receiver_roles
                .get(&(root.to_string(), last.to_string()))
        {
            return Some(*role);
        }
        self.sink_signature_for_language(last, language)
            .map(|s| s.role)
    }

    /// Semantic label slug for a sink call, receiver- and package-aware.
    pub fn label_for_call_scoped(
        &self,
        last: &str,
        receiver_root: Option<&str>,
        origin_package: Option<&str>,
        language: Option<&str>,
    ) -> Option<String> {
        if let Some(pkg) = origin_package
            && let Some(sig) = scoped_lookup(&self.scoped_sink_signatures, pkg, last)
            && let Some(label) = sig.label.clone()
        {
            return Some(label);
        }
        if let Some(root) = receiver_root
            && let Some(slug) = self
                .receiver_labels
                .get(&(root.to_string(), last.to_string()))
        {
            return Some(slug.clone());
        }
        self.sink_signature_for_language(last, language)
            .and_then(|s| s.label.clone())
    }

    /// Sanitizer fact for a call, package-aware.
    ///
    /// Scoping semantics (recall-safe): a fact installed under
    /// `(package, call)` applies ONLY when `origin_package` names that
    /// package. Origin known-but-different falls back to universal
    /// facts only — a foreign package's sanitizer must never cut this
    /// call. Origin unknown also matches universal facts only.
    ///
    /// Recall-safety analysis (why unknown origin does NOT take the
    /// any-package fallback): a sanitizer CUTS a finding, so a scoped
    /// fact that fires on an unconfirmed origin can silence a true
    /// finding — the one error that costs recall. The reverse error
    /// (a genuine package sanitizer whose origin does not resolve goes
    /// uncut) surfaces an advisory, which costs precision only.
    /// Universal facts were proven for the bare call name regardless of
    /// receiver, so they remain safe under any origin; a scoped fact
    /// suppresses only once import resolution confirms its package.
    pub fn sanitizer_fact_scoped(
        &self,
        call: &str,
        origin_package: Option<&str>,
    ) -> Option<&SanitizerFact> {
        if let Some(pkg) = origin_package {
            if let Some(f) = scoped_lookup(&self.scoped_sanitizer_facts, pkg, call) {
                return Some(f);
            }
            let is_package_scoped = self.scoped_sanitizer_facts.keys().any(|(_, c)| c == call);
            if is_package_scoped {
                // Known-package mismatch: another package's sanitizer
                // must never cut this call — universal facts only.
                return self.sanitizer_facts.get(call);
            }
        }
        self.sanitizer_facts.get(call)
    }

    /// Sanitizer fact for a call; `None` if not a sanitizer.
    ///
    /// No import origin is available at this call site, so package-
    /// scoped facts are inert here (recall-safe: they only ever suppress
    /// under a confirmed origin). Pass `Some(origin)` via
    /// [`Self::sanitizer_fact_scoped`] where import context exists.
    pub fn sanitizer_fact(&self, call: &str) -> Option<&SanitizerFact> {
        self.sanitizer_fact_scoped(call, None)
    }

    /// Receiver-aware and package-aware sink check.
    pub fn is_sink_call_scoped(
        &self,
        last: &str,
        receiver_root: Option<&str>,
        origin_package: Option<&str>,
        language: Option<&str>,
    ) -> bool {
        if !self.verb_sinks.contains(last) {
            // Ordinary sink: presence in the signature table decides, with
            // one carve-out: a global-only fact (schema §WI-12) arms the
            // bare / unqualified call form only. A receiver-qualified call
            // (`engine.eval(x)`) matches just once its origin resolves to a
            // known package — an unrelated receiver's method must never
            // inherit a global builtin's semantics.
            if let Some(sig) = self.sink_signature_scoped(last, origin_package, language) {
                if sig.global_only && receiver_root.is_some() && origin_package.is_none() {
                    return false;
                }
                // A name that is only ever declared QUALIFIED arms only
                // under the receiver root (or import origin) its
                // declaration named. A dotted declaration publishes a bare
                // shadow of its last segment (the walker matches a virtual
                // call by method name), and that shadow must not arm an
                // unrelated receiver: `json.loads(t)` is a safe JSON
                // parser, not `pickle.loads`; `client.urlopen(t)` is not
                // `urllib.request.urlopen`.
                if self.is_receiver_qualified_only(last)
                    && !self.qualified_receiver_matches(last, receiver_root, origin_package)
                {
                    return false;
                }
                return true;
            }
            return false;
        }
        match receiver_root {
            Some(root) => {
                // A client root alone no longer arms every verb: `db` must
                // qualify for a method through a dotted entry (db.query,
                // db.prepare). Prisma reaches the same root with model
                // methods (`db.trade.aggregate(..)`, `db.template
                // .delete(..)`) that are fully parameterized ORM calls,
                // not SQL execution - requiring the exact (root, method)
                // pair keeps generic client handles from matching
                // arbitrary methods. Import-origin resolution still
                // qualifies known client packages.
                let pair = (root.to_string(), last.to_string());
                if self.receiver_roles.contains_key(&pair) {
                    true
                } else if let Some(pkg) = origin_package {
                    self.client_roots.contains(pkg)
                } else {
                    false
                }
            }
            None => {
                if let Some(pkg) = origin_package {
                    self.client_roots.contains(pkg)
                } else {
                    true
                }
            }
        }
    }

    /// Is `last` a sink name that is only ever declared under a receiver
    /// root? Such a name must not arm on an unrelated receiver.
    ///
    /// A name declared bare (the language builtin's own name) is not
    /// receiver-gated; a name that only ever appeared in a dotted
    /// declaration is.
    pub fn is_receiver_qualified_only(&self, last: &str) -> bool {
        !self.bare_sink_names.contains(last) && self.receiver_qualified_sinks.contains_key(last)
    }

    /// Does the call site's receiver root (or import origin) name one of
    /// the roots declared for `last`?
    ///
    /// A receiver root matches when it IS a declared root. An import
    /// origin matches when it IS a declared root or lives under it
    /// (`urllib.request` under the declared root `urllib`).
    pub fn qualified_receiver_matches(
        &self,
        last: &str,
        receiver_root: Option<&str>,
        origin_package: Option<&str>,
    ) -> bool {
        let Some(roots) = self.receiver_qualified_sinks.get(last) else {
            return false;
        };
        if let Some(root) = receiver_root
            && roots.contains(root)
        {
            return true;
        }
        if let Some(origin) = origin_package {
            return roots.iter().any(|r| {
                origin == r
                    || (origin.starts_with(r.as_str())
                        && origin.as_bytes().get(r.len()) == Some(&b'.'))
            });
        }
        false
    }

    /// [`Self::is_sink_call_scoped`] for a call that HAS a receiver
    /// expression. When that receiver's root cannot be resolved (a chained
    /// call result such as `req.limits().get(..)`, or `a.route(..).post(h)`)
    /// a gated verb must not match by name alone: only an import origin
    /// that names a client package arms it. A bare call (`exec(code)`,
    /// no receiver) keeps the unqualified semantics.
    pub fn is_recv_sink_call_scoped(
        &self,
        last: &str,
        receiver_root: Option<&str>,
        origin_package: Option<&str>,
        language: Option<&str>,
        has_receiver: bool,
    ) -> bool {
        if has_receiver && receiver_root.is_none() && self.verb_sinks.contains(last) {
            return origin_package.is_some_and(|pkg| self.client_roots.contains(pkg));
        }
        self.is_sink_call_scoped(last, receiver_root, origin_package, language)
    }

    /// Flat-name or scoped sink check. The flat `config.sinks` set keeps
    /// every sink's last segment, including the ambiguous verbs and the
    /// receiver-qualified shadows that receiver gating exists for, so a
    /// bare `contains` must not arm either on its own.
    pub fn sink_name_armed(
        &self,
        flat_sinks: &rustc_hash::FxHashSet<String>,
        name: &str,
        receiver_root: Option<&str>,
        origin_package: Option<&str>,
        language: Option<&str>,
        has_receiver: bool,
    ) -> bool {
        (flat_sinks.contains(name)
            && !self.verb_sinks.contains(name)
            && !self.is_receiver_qualified_only(name))
            || self.is_recv_sink_call_scoped(
                name,
                receiver_root,
                origin_package,
                language,
                has_receiver,
            )
    }

    /// Receiver-aware sink check for virtual calls. `last` is the method
    /// name; `receiver_root` the first segment of the receiver's access
    /// path (e.g. `got` for `got.get(url)`), `None` when unresolvable.
    ///
    /// - Non-verb names match as before (name-configured sinks).
    /// - Verb names (`get`, `post`, ...) only match when they were sourced
    ///   from dotted client entries AND the receiver root is a known
    ///   client, `m.get(t)` on an arbitrary Map is never a sink, while
    ///   `got.get(taint)` is.
    pub fn is_sink_call(&self, last: &str, receiver_root: Option<&str>) -> bool {
        self.is_sink_call_scoped(last, receiver_root, None, None)
    }

    /// Walk a receiver var to the root of its member-access chain via the
    /// IR: `const c = got; got.get(x)` and direct `got.get(x)` both
    /// resolve to root `got`. Returns `None` when the def is not a
    /// LoadField chain grounded in a named var.
    pub fn receiver_root(
        ir: &crate::ir::function::FunctionIR,
        var: crate::ir::function::VarId,
    ) -> Option<String> {
        let mut cur = var;
        for _ in 0..8 {
            if let Some(meta) = ir.var_metadata.get(&cur)
                && let Some(name) = &meta.source_name
            {
                return Some(name.split('.').next().unwrap_or(name).to_string());
            }
            cur = match ir.loadfield_def(cur) {
                Some((base, _)) => base,
                None => ir.call_receiver_def(cur)?,
            };
        }
        None
    }

    /// Learned checks whose trigger call's last segment matches `call`.
    /// The engine matches calls by last segment, so a bundle rule written
    /// for `security.hash` also fires on bare `hash`, same over-approximate
    /// semantics as built-in seed checks. Each match carries the entry's
    /// provenance so findings report where the rule came from.
    pub fn learned_checks_for(&self, call: &str) -> Vec<(&LearnedCheckFact, Provenance)> {
        let seg = call.rsplit('.').next().unwrap_or(call);
        let mirror = super::mirror_call_base(seg);
        self.learned_checks
            .iter()
            .filter(|(c, _)| {
                let taught = c.call.rsplit('.').next();
                taught == Some(seg) || (taught.is_some() && taught == mirror)
            })
            .map(|(c, p)| (c, *p))
            .collect()
    }
}
