// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Python propagator rules: (call, tainted_arg-slot, tainted_receiver).
//! Travels taint from arguments/receiver to the return value, enabling
//! downstream sinks. Receiver-tainted calls (str methods) flow the taint
//! into the returned string.

use crate::role_map::PropagatorRule;

/// All Python propagators, grouped by family.
pub(crate) static PYTHON_PROPAGATORS: &[PropagatorRule] = &[
    // ── str methods: receiver taints the returned string ──
    PropagatorRule {
        call: "format",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "format_map",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "split",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "strip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "lstrip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "rstrip",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "lower",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "upper",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "title",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "encode",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "decode",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // ── type coercions propagate taint (not sanitization) ──
    PropagatorRule {
        call: "str",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "bytes",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "list",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "tuple",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "dict",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // ── json ──
    PropagatorRule {
        call: "loads",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "dumps",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // ── re / regex ──
    PropagatorRule {
        call: "sub",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "subn",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "group",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "groups",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // f-string interpolation and `%` formatting are handled by the
    // flow_fingerprint's interpolation checks, not propagator rules, so
    // they are deliberately NOT listed here.
];
