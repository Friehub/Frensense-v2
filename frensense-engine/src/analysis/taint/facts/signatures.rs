// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

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

    /// Signature for a sink call; `None` if the call is not a configured sink.
    pub fn sink_signature(&self, call: &str) -> Option<&SinkSignature> {
        if let Some(sig) = self.sink_signatures.get(call) {
            return Some(sig);
        }
        if call.contains("::") {
            let parts: Vec<&str> = call.split("::").collect();
            for i in 1..parts.len() {
                let suffix = parts[i..].join("::");
                if let Some(sig) = self.sink_signatures.get(&suffix) {
                    return Some(sig);
                }
            }
        }
        None
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
        if let Some(root) = receiver_root
            && let Some(role) = self
                .receiver_roles
                .get(&(root.to_string(), last.to_string()))
        {
            return Some(*role);
        }
        self.sink_signature(last).map(|s| s.role)
    }

    /// Semantic label slug for a sink call, receiver-aware.
    pub fn label_for_call(&self, last: &str, receiver_root: Option<&str>) -> Option<String> {
        if let Some(root) = receiver_root
            && let Some(slug) = self
                .receiver_labels
                .get(&(root.to_string(), last.to_string()))
        {
            return Some(slug.clone());
        }
        self.sink_signature(last).and_then(|s| s.label.clone())
    }

    /// Sanitizer fact for a call; `None` if not a sanitizer.
    pub fn sanitizer_fact(&self, call: &str) -> Option<&SanitizerFact> {
        self.sanitizer_facts.get(call)
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
        if !self.verb_sinks.contains(last) {
            // Ordinary sink: presence in the signature table decides.
            return self.sink_signature(last).is_some();
        }
        match receiver_root {
            Some(root) => self.client_roots.contains(root),
            // Unresolvable receiver: over-approximate (sound, noisier).
            None => true,
        }
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
            cur = ir.loadfield_def(cur)?.0;
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
        self.learned_checks
            .iter()
            .filter(|(c, _)| c.call.rsplit('.').next() == Some(seg))
            .map(|(c, p)| (c, *p))
            .collect()
    }
}
