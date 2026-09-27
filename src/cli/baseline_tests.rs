// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Baseline mode tests against the real engine: a finding that shifts
//! lines (unrelated edit) must NOT count as a regression; a genuinely
//! new finding must.

use super::{compare_baseline, save_baseline};
use crate::engine::Engine;
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("frensense-baseline-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn scan(dir: &PathBuf, file: &str) -> Vec<crate::Advisory> {
    Engine::new().run(&dir.join(file)).expect("scan")
}

#[test]
fn baseline_tolerates_line_shifts_flags_new_finding() {
    let dir = tempdir("main");
    let file = dir.join("app.py");
    std::fs::write(
        &file,
        "import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();

    // Round 1: capture baseline with the pre-existing finding.
    let baseline = scan(&dir, "app.py");
    assert_eq!(baseline.len(), 1);
    let baseline_path = dir.join("baseline.json");
    save_baseline(&baseline, baseline_path.to_str().unwrap()).expect("save");

    // Round 2: unrelated edit shifts the finding 6 lines down.
    std::fs::write(
        &file,
        "import hashlib\n# a\n# b\n# c\n# d\n# e\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();
    let current = scan(&dir, "app.py");
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].line, baseline[0].line + 5);
    assert_eq!(current[0].fingerprint, baseline[0].fingerprint);

    let no_regression = compare_baseline(&current, baseline_path.to_str().unwrap())
        .expect("compare");
    assert!(!no_regression, "shifted finding must not be a regression");

    // Round 3: an actual second bug appears.
    std::fs::write(
        &file,
        "import hashlib\n# a\n# b\n# c\n# d\n# e\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n\n\ndef other(x):\n    return hashlib.sha1(x).hexdigest()\n",
    )
    .unwrap();
    let with_new = scan(&dir, "app.py");
    assert_eq!(with_new.len(), 2);
    let regression = compare_baseline(&with_new, baseline_path.to_str().unwrap())
        .expect("compare 2");
    assert!(regression, "a second bug IS a regression");
    let _ = std::fs::remove_dir_all(&dir);
}
