// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Regression: an Angular inline template reads the component instance, so a
//! field used inside a sanitizer-bypass binding must link to the class's
//! initializer instead of an empty module binding.

use crate::analysis::forward::ProgramSvfg;
use crate::analysis::taint::config::TaintConfig;
use crate::analysis::taint::engine::{BackwardTaintEngine, BackwardVerdict};
use crate::harness::{lower_source, lower_source_detailed};
use crate::ir::function::FunctionIR;
use rustc_hash::FxHashMap;

#[test]
fn external_template_links_companion_component_fields() {
    let html = "<div [innerHTML]=\"san.bypassSecurityTrustHtml(raw)\"></div>\n";
    let ts = concat!(
        "@Component({ templateUrl: './hero.component.html' })\n",
        "export class HeroComponent {\n",
        "  raw = process.argv[2]\n",
        "}\n",
    );
    let spec = frensense_lang::spec_for_path(std::path::Path::new("hero.component.ts"))
        .expect("TypeScript spec");
    let bindings = spec.template_bindings(ts);
    assert_eq!(bindings.len(), 1, "{bindings:?}");
    let (fns, _) = lower_source_detailed(
        "hero.component.html",
        html,
        "component.html",
        None,
        Some((ts, &bindings)),
    )
    .expect("template must lower");
    let owned: Vec<FunctionIR> = fns.into_values().collect();
    let mut statics: FxHashMap<String, &FunctionIR> = FxHashMap::default();
    for ir in &owned {
        statics.insert(ir.name.clone(), ir);
    }
    let mut config = TaintConfig::default();
    config.sources.insert("process.argv.2".into());
    config.sinks.insert("bypassSecurityTrustHtml".into());
    let prog = ProgramSvfg::new(&statics, &config);
    let mut engine = BackwardTaintEngine::new(&prog, &config);
    engine.run();
    let vuln: Vec<_> = engine
        .findings
        .iter()
        .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
        .collect();
    assert!(
        !vuln.is_empty(),
        "the companion field must reach the template bypass: {:?}",
        engine.findings
    );
}

#[test]
fn angular_inline_template_links_component_fields() {
    let src = concat!(
        "import { Component } from '@angular/core'\n",
        "// FIXTURE: an inline Angular template whose bypass reads a field.\n",
        "@Component({ template: `<div [innerHTML]=\"san.bypassSecurityTrustHtml(raw)\"></div>` })\n",
        "export class HeroComponent {\n",
        "  raw = process.argv[2]\n",
        "}\n",
    );
    let fns = lower_source("probe.ts", src, "ts").expect("component must lower");
    let owned: Vec<FunctionIR> = fns.into_values().collect();
    let mut statics: FxHashMap<String, &FunctionIR> = FxHashMap::default();
    for ir in &owned {
        statics.insert(ir.name.clone(), ir);
    }
    let mut config = TaintConfig::default();
    config.sources.insert("process.argv.2".into());
    config.sinks.insert("bypassSecurityTrustHtml".into());
    let prog = ProgramSvfg::new(&statics, &config);
    let mut engine = BackwardTaintEngine::new(&prog, &config);
    engine.run();
    let vuln: Vec<_> = engine
        .findings
        .iter()
        .filter(|f| f.verdict == BackwardVerdict::Vulnerable)
        .collect();
    assert!(
        !vuln.is_empty(),
        "the field must reach the bypass: {:?}",
        engine.findings
    );
}
