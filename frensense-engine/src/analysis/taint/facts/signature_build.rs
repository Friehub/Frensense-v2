// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! `SinkSignature` constructors, split out of `kinds.rs` so the type's
//! definitions stay one screen and the builders stay next to their defaults.

use std::collections::BTreeSet;

use super::kinds::SinkSignature;

impl SinkSignature {
    /// A signature where every argument is dangerous (the legacy default).
    pub fn all_args(call: &str) -> Self {
        Self {
            call: call.to_string(),
            package: None,
            dangerous_args: BTreeSet::new(),
            binding_args_safe: false,
            idor_keys: Vec::new(),
            role: crate::analysis::taint::role::SinkRole::Other,
            label: None,
            global_only: false,
            base_kinds: Vec::new(),
        }
    }

    /// A signature with explicit dangerous slots.
    pub fn with_args(call: &str, slots: &[usize]) -> Self {
        Self {
            call: call.to_string(),
            package: None,
            dangerous_args: slots.iter().copied().collect(),
            binding_args_safe: false,
            idor_keys: Vec::new(),
            role: crate::analysis::taint::role::SinkRole::Other,
            label: None,
            global_only: false,
            base_kinds: Vec::new(),
        }
    }

    /// Is argument slot `slot` dangerous when tainted?
    ///
    /// ```
    /// use frensense_engine::analysis::taint::facts::SinkSignature;
    ///
    /// // No explicit slots: every *argument* is dangerous.
    /// assert!(SinkSignature::all_args("eval").is_dangerous(3));
    /// // Explicit slots: only those.
    /// let sig = SinkSignature::with_args("query", &[0]);
    /// assert!(sig.is_dangerous(0));
    /// assert!(!sig.is_dangerous(1));
    /// // The receiver (`usize::MAX`) is a slot like any other here; the walk
    /// // reports it only when it is actually tainted (see `explore_sink_args`).
    /// assert!(SinkSignature::all_args("write").is_dangerous(usize::MAX));
    /// ```
    pub fn is_dangerous(&self, slot: usize) -> bool {
        self.dangerous_args.is_empty() || self.dangerous_args.contains(&slot)
    }

    /// Is this slot an explicitly-safe binding channel?
    ///
    /// ```
    /// use frensense_engine::analysis::taint::facts::SinkSignature;
    ///
    /// let mut sig = SinkSignature::with_args("query", &[0]);
    /// assert!(!sig.is_binding(1)); // `binding_args_safe` is off by default
    /// sig.binding_args_safe = true;
    /// assert!(sig.is_binding(1));
    /// assert!(!sig.is_binding(0)); // a dangerous slot is never a binding channel
    /// ```
    pub fn is_binding(&self, slot: usize) -> bool {
        self.binding_args_safe && !self.is_dangerous(slot)
    }

    /// Does this signature carry any API knowledge at all? A blanket
    /// signature is what [`SinkSignature::all_args`] produces: every slot
    /// dangerous, no binding channel, no identity-payload keys, no
    /// global-only marking. It is the "this name is a sink, nothing else is
    /// known" placeholder (`FactTable::from_config` seeds one per configured
    /// sink), so it must never outrank a fact that knows the call's slots,
    /// exactly like the merge rule that keeps an all-args entry from
    /// widening a slot-restricted one.
    pub(crate) fn is_blanket(&self) -> bool {
        self.dangerous_args.is_empty()
            && !self.binding_args_safe
            && self.idor_keys.is_empty()
            && !self.global_only
    }
}
