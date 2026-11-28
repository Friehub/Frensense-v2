// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Angular's sanitizer-bypass sinks.
//!
//! Angular sanitizes markup bindings (`[innerHTML]`, `[outerHTML]`,
//! `[srcdoc]`) by default, so the binding is not the XSS point. A value only
//! becomes dangerous when it is marked trusted with
//! `DomSanitizer.bypassSecurityTrust*`, which makes the next binding set it
//! verbatim. These calls are therefore the sinks; the language spec reports
//! the bindings that contain them.

use crate::role_map::SinkLabel;

pub(super) static ANGULAR_SINK_NAMES: &[(&str, SinkLabel)] = &[
    ("bypassSecurityTrustHtml", SinkLabel::XssDom),
    ("bypassSecurityTrustScript", SinkLabel::XssDom),
    ("bypassSecurityTrustStyle", SinkLabel::XssDom),
    ("bypassSecurityTrustUrl", SinkLabel::XssDom),
    ("bypassSecurityTrustResourceUrl", SinkLabel::XssDom),
];
