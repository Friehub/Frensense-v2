// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Tests for `frensense probe`: each disposition must be reachable from a
//! real scan of a real family directory, because the point of the command is
//! to decide whether the engine can carry the family.

use std::path::{Path, PathBuf};

use super::probe::{Verdict, pack_models, probe};

const HEADER: &str = "# [frensense]\n# class: inj.command\n# cwe: CWE-78\n# purpose: anchor\n";

fn family(name: &str, positive: &str, negative: Option<&str>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("frensense-probe-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(dir.join(format!("{name}_positive.py")), positive).expect("write positive");
    if let Some(negative) = negative {
        std::fs::write(dir.join(format!("{name}_negative.py")), negative).expect("write negative");
    }
    dir
}

const POSITIVE: &str = "import os\nfrom flask import request\n\n\ndef run():\n    name = request.args.get(\"f\")\n    os.system(\"ls \" + name)\n";

const NEGATIVE: &str = "import os, shlex\nfrom flask import request\n\n\ndef run():\n    name = request.args.get(\"f\")\n    os.system(\"ls \" + shlex.quote(name))\n";

#[test]
fn separating_pair_is_accepted() {
    let positive = format!("{HEADER}{POSITIVE}");
    let negative = format!("{HEADER}{NEGATIVE}");
    let dir = family("separating", &positive, Some(&negative));
    let report = probe(&dir, None).expect("probe");
    assert_eq!(report.language, "python");
    assert_eq!(report.class.as_deref(), Some("inj.command"));
    assert!(!report.positive.advisories.is_empty(), "positive must fire");
    assert_eq!(report.verdict, Verdict::Separated, "{}", report.render());
    assert!(report.verdict.accepted());
    let json = report.to_json();
    assert_eq!(json["verdict"], serde_json::json!("separated"));
    assert_eq!(json["accepted"], serde_json::json!(true));
}

#[test]
fn unmodelled_sink_is_a_vocabulary_gap() {
    let positive = format!(
        "{HEADER}from flask import request\n\n\ndef run():\n    name = request.args.get(\"f\")\n    totally_unknown_call(name)\n"
    );
    let dir = family("vocabulary", &positive, None);
    let report = probe(&dir, None).expect("probe");
    assert_eq!(
        report.verdict,
        Verdict::NoSinkRecognised,
        "{}",
        report.render()
    );
    assert!(!report.verdict.accepted());
    assert!(report.positive.advisories.is_empty());
}

#[test]
fn cwe_with_no_card_is_an_engine_gap() {
    let positive = format!(
        "# [frensense]\n# class: exotic.thing\n# cwe: CWE-99999\n# purpose: knowledge\n{POSITIVE}"
    );
    let dir = family("gap", &positive, None);
    let report = probe(&dir, None).expect("probe");
    assert_eq!(
        report.verdict,
        Verdict::ClassNotExpressible,
        "{}",
        report.render()
    );
    assert_eq!(
        report.to_json()["expressible"]["expressible"],
        serde_json::json!(false)
    );
}

#[test]
fn both_twins_alerting_is_a_family_bug() {
    // The "negative" has no guard at all: the engine alerts on both sides.
    let positive = format!("{HEADER}{POSITIVE}");
    let negative = format!("{HEADER}{POSITIVE}");
    let dir = family("both", &positive, Some(&negative));
    let report = probe(&dir, None).expect("probe");
    assert_eq!(
        report.verdict,
        Verdict::FactDoesNotSeparate,
        "{}",
        report.render()
    );
}

#[test]
fn pack_models_knows_training_vocabulary() {
    assert!(
        pack_models("python", "os.system"),
        "os.system is in the python sink vocabulary"
    );
    assert!(!pack_models("python", "totally_unknown_call"));
}

#[test]
fn a_missing_positive_is_an_error_not_a_panic() {
    let dir = std::env::temp_dir().join(format!("frensense-probe-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let result = probe(&dir, None);
    assert!(
        result.is_err(),
        "a family with no positive must be an error"
    );
    if let Err(err) = result {
        assert!(err.contains("no *_positive.* file"), "{err}");
    }
    assert!(Path::new(&dir).is_dir());
}
