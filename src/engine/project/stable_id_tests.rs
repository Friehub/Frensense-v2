// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for stable finding IDs: the fingerprint excludes line/column,
//! so a finding that shifts lines keeps its identity across scans. This
//! is the property baselines and diff gates rely on.

use super::runner::stable_fingerprint;
use crate::engine::Engine;
use std::path::PathBuf;

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("frensense-stable-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[test]
fn fingerprint_is_deterministic_and_component_sensitive() {
    let a = stable_fingerprint(&["f.py", "weak_hash", "digest"]);
    let b = stable_fingerprint(&["f.py", "weak_hash", "digest"]);
    assert_eq!(a, b, "same inputs must give the same ID");
    assert_eq!(a.len(), 16);
    assert_ne!(stable_fingerprint(&["f.py", "weak_hash", "other"]), a);
    // Component boundaries: ("ab","c") must differ from ("a","bc").
    assert_ne!(
        stable_fingerprint(&["ab", "c"]),
        stable_fingerprint(&["a", "bc"])
    );
}

#[test]
fn fingerprint_survives_line_shift() {
    let dir = tempdir("shift");
    let file = dir.join("app.py");
    std::fs::write(
        &file,
        "import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();

    let mut e = Engine::new();
    let before = e.run(&file).expect("scan");
    assert_eq!(before.len(), 1);
    let first_line = before[0].line;

    // Insert 10 unrelated lines above the finding.
    let padding = "x = 0\n".repeat(10);
    std::fs::write(
        &file,
        format!("import hashlib\n\n{padding}\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n"),
    )
    .unwrap();

    let after = e.run(&file).expect("rescan");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].line, first_line + 10, "finding must have moved");
    assert_eq!(
        after[0].fingerprint, before[0].fingerprint,
        "fingerprint must NOT change when only the line moved"
    );
    // The stable_id string embeds the line as display context, so the
    // hash PORTION must match even though the rendered string differs.
    let id_before = before[0].stable_id();
    let id_after = after[0].stable_id();
    fn hash_of(id: &str) -> &str {
        id.split('@').next().unwrap_or("")
    }
    assert_eq!(
        hash_of(&id_after),
        hash_of(&id_before),
        "hash portion is the identity"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fingerprint_changes_when_the_bug_changes() {
    let dir = tempdir("mutate");
    let file = dir.join("app.py");
    std::fs::write(
        &file,
        "import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();
    let mut e = Engine::new();
    let before = e.run(&file).expect("scan");

    // Fix it: different function content → different ID.
    std::fs::write(
        &file,
        "import hashlib\n\n\ndef digest(data):\n    return hashlib.sha256(data).hexdigest()\n",
    )
    .unwrap();
    let after = e.run(&file).expect("rescan");
    assert!(after.is_empty(), "fixed file must be clean");

    // Same file shape, DIFFERENT bug name → different ID.
    std::fs::write(
        &file,
        "import hashlib\n\n\ndef other_name(data):\n    return hashlib.md5(data).hexdigest()\n",
    )
    .unwrap();
    let renamed = e.run(&file).expect("rescan");
    assert_eq!(renamed.len(), 1);
    assert_ne!(renamed[0].fingerprint, before[0].fingerprint);
    let _ = std::fs::remove_dir_all(&dir);
}
