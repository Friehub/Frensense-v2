// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Type-named sources: a framework request extractor is a source, a borrowed
//! value of the same name is not.
//!
//! Rust request handlers take extractors **by value** (`Path<T>`, `Query<Q>`,
//! `Json<B>`): the framework builds the value from the request, so the
//! parameter carries attacker input. A borrowed `&Path` is the language's own
//! value - `std::path::Path` - and carries whatever the caller passed, which
//! for library code is not attacker data.
//!
//! The type matcher used to strip the borrow marker before matching, so
//! `fn load(root: &Path)` matched the axum `Path` extractor fact and every
//! helper that reads a file from a borrowed path became a taint source. On
//! this repository that produced a path-traversal finding on the scanner's
//! own bundle loader. The fix keeps `&`, and these fixtures pin both sides:
//!
//! 1. a borrowed `&Path` parameter is NOT a source (no finding);
//! 2. a borrowed `&'a Path` with a lifetime parameter is NOT a source;
//! 3. a by-value `Path<T>` extractor parameter IS a source (finding fires).

#[cfg(test)]
#[allow(clippy::module_inception)] // test file convention: module name repeats parent path segment
pub mod type_source_tests {
    use crate::analysis::taint::engine::{BackwardVerdict, SinkFinding};
    use crate::analysis::taint::facts::seeded_tables_all;
    use crate::scan::{prepare, scan_prepared};

    const SINK: &str = "std::fs::read";

    fn findings(src: &str) -> Vec<SinkFinding> {
        let files = vec![("bundle.rs".to_string(), src.to_string(), "rs".to_string())];
        let (config, facts) = seeded_tables_all();
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts).findings
    }

    fn vulnerable_sink(findings: &[SinkFinding]) -> Option<&SinkFinding> {
        findings
            .iter()
            .find(|f| f.sink.contains(SINK) && f.verdict == BackwardVerdict::Vulnerable)
    }

    /// Library code: the caller decides what path is read. Not attacker data.
    const BORROWED: &str = r#"
use std::path::Path;

pub fn load(root: &Path) -> std::io::Result<()> {
    let path = root.join("frensense-corpus.frc");
    let bytes = std::fs::read(&path)?;
    println!("{bytes:?}");
    Ok(())
}
"#;

    /// Same shape with an explicit lifetime, the other way a borrow appears
    /// in real signatures.
    const BORROWED_WITH_LIFETIME: &str = r#"
use std::path::Path;

pub fn load<'a>(root: &'a Path) -> std::io::Result<()> {
    let bytes = std::fs::read(root)?;
    println!("{bytes:?}");
    Ok(())
}
"#;

    /// Axum handler: `Path<T>` is deserialized from the request path, so the
    /// value is attacker-controlled and the read is a real traversal risk.
    const EXTRACTOR: &str = r#"
use std::path::Path;

pub fn download(Path(name): Path<String>) -> std::io::Result<()> {
    let bytes = std::fs::read(&name)?;
    println!("{bytes:?}");
    Ok(())
}
"#;

    #[test]
    fn borrowed_path_parameter_is_not_a_source() {
        let fs = findings(BORROWED);
        assert!(
            vulnerable_sink(&fs).is_none(),
            "`&Path` is std::path::Path, not an extractor: {:?}",
            fs.iter().map(|f| (&f.sink, &f.verdict)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn borrowed_path_with_lifetime_is_not_a_source() {
        let fs = findings(BORROWED_WITH_LIFETIME);
        assert!(vulnerable_sink(&fs).is_none(), "{fs:?}");
    }

    #[test]
    fn extractor_path_parameter_is_still_a_source() {
        let fs = findings(EXTRACTOR);
        let finding = vulnerable_sink(&fs).expect("`Path<String>` is request input");
        assert_eq!(finding.source_desc.as_deref(), Some("name"));
    }

    /// The origin is a step with a location and no echo: SARIF renders the
    /// first codeFlow step from it, so it cannot be unlocatable.
    #[test]
    fn the_origin_step_has_a_location_and_is_not_repeated() {
        let fs = findings(EXTRACTOR);
        let finding = vulnerable_sink(&fs).expect("finding");
        let origin = finding
            .path
            .spans
            .first()
            .and_then(Option::as_ref)
            .expect("origin location");
        assert!(origin.0.ends_with("bundle.rs"), "{origin:?}");
        let repeats = finding
            .path
            .spans
            .iter()
            .skip(1)
            .filter(|s| s.as_ref() == Some(origin))
            .count();
        assert_eq!(
            repeats, 0,
            "the origin is printed once: {:?}",
            finding.path.spans
        );
    }
}
