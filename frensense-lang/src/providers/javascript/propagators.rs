// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Propagator rules: how taint flows through string/array operations.

use crate::spec::PropagatorRule;

pub(super) static JS_PROPAGATORS: &[PropagatorRule] = &[
    // String methods - receiver taints return
    PropagatorRule {
        call: "concat",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "replace",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "replaceAll",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "slice",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "substring",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trim",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trimStart",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "trimEnd",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "toLowerCase",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "toUpperCase",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "split",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "toString",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "padStart",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "padEnd",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // Array methods - receiver taints return
    PropagatorRule {
        call: "map",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "filter",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "flatMap",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "reduce",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "flat",
        tainted_arg: None,
        tainted_receiver: true,
    },
    // JSON
    PropagatorRule {
        call: "parse",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "stringify",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Buffer / encoding
    PropagatorRule {
        call: "from",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "toString",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "atob",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "btoa",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "decodeURIComponent",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "encodeURIComponent",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Template tags
    PropagatorRule {
        call: "format",
        tainted_arg: None,
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "template",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "render",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Path manipulation
    PropagatorRule {
        call: "join",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "resolve",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "normalize",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Modern String methods
    PropagatorRule {
        call: "charAt",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "charCodeAt",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "indexOf",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "lastIndexOf",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "includes",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "startsWith",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "endsWith",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "repeat",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "matchAll",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "at",
        tainted_receiver: true,
        tainted_arg: None,
    },
    // Template tags
    PropagatorRule {
        call: "interpolate",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "compile",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "tag",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Object spread
    PropagatorRule {
        call: "keys",
        tainted_arg: Some(0),
        tainted_receiver: true,
    }, // handles array keys() too
    PropagatorRule {
        call: "values",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "entries",
        tainted_arg: Some(0),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "assign",
        tainted_arg: Some(1),
        tainted_receiver: true,
    },
    PropagatorRule {
        call: "fromEntries",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "structuredClone",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "cloneDeep",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Array methods
    PropagatorRule {
        call: "find",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "findIndex",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "findLast",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "some",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "every",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "forEach",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "sort",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "reverse",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "fill",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "copyWithin",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "splice",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "push",
        tainted_receiver: true,
        tainted_arg: Some(0),
    },
    PropagatorRule {
        call: "unshift",
        tainted_receiver: true,
        tainted_arg: Some(0),
    },
    // Promise
    PropagatorRule {
        call: "then",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "catch",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "finally",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "all",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "allSettled",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "race",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    // Lodash
    PropagatorRule {
        call: "get",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "pick",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "omit",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "mapKeys",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "mapValues",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "flattenDeep",
        tainted_receiver: true,
        tainted_arg: None,
    },
    PropagatorRule {
        call: "groupBy",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "zip",
        tainted_arg: None,
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "unzip",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
];
