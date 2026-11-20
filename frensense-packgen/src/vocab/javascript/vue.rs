// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Vue 3, Vue Router, and Pinia provider vocabulary.
//!
//! Covers:
//! - `vue-router` / `@vue/router`: `navigateTo`, `router.push`, `router.replace`, `useRoute`, `useRouter`
//! - `vue`: reactivity wrappers (`ref`, `reactive`, `computed`, `toRef`, `toRefs`)
//! - `pinia`: `defineStore` state management

use crate::role_map::{PropagatorRule, SinkLabel};

/// Package-scoped sinks for Vue and Vue Router (`call`, `package`, `label`).
pub(super) static VUE_PACKAGE_SCOPED_SINKS: &[(&str, &str, SinkLabel)] = &[
    ("navigateTo", "vue-router", SinkLabel::OpenRedirect),
    ("router.push", "vue-router", SinkLabel::OpenRedirect),
    ("router.replace", "vue-router", SinkLabel::OpenRedirect),
    ("navigateTo", "@vue/router", SinkLabel::OpenRedirect),
    ("router.push", "@vue/router", SinkLabel::OpenRedirect),
    ("router.replace", "@vue/router", SinkLabel::OpenRedirect),
];

/// Source patterns for Vue Router route objects and composition hooks.
pub(super) static VUE_SOURCE_PATTERNS: &[&str] = &[
    "route.params",
    "route.query",
    "route.hash",
    "route.fullPath",
    "useRoute",
    "useRouter",
];

/// Propagator rules for Vue reactivity wrappers and Pinia stores.
pub(super) static VUE_PROPAGATORS: &[PropagatorRule] = &[
    PropagatorRule {
        call: "ref",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "reactive",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "computed",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "toRef",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "toRefs",
        tainted_arg: Some(0),
        tainted_receiver: false,
    },
    PropagatorRule {
        call: "defineStore",
        tainted_arg: Some(1),
        tainted_receiver: false,
    },
];
