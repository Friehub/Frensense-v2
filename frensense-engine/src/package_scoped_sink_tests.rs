// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Package-scoped sink facts: a framework sink installed under a package
//! (`@prisma/client`) must fire only when the caller's import origin
//! resolves to that package, and stay silent otherwise.
//!
//! Triplets:
//! 1. import + factory singleton (`new PrismaClient()`) arms `@prisma/client`
//!    — fires (the legitimate Prisma raw-SQL shape).
//! 2. no import, unrelated receiver object — silent (the false-positive
//!    class package scoping exists to close).
//! 3. wrong-package import (`database-js` lookalike) — silent (origin
//!    mismatch must not fall back to another package's scoped fact).

#[cfg(test)]
#[allow(clippy::module_inception)] // test file convention: module name repeats parent path segment
pub mod package_scoped_sink_tests {
    use crate::analysis::taint::facts::seeded_tables;
    use crate::scan::{prepare, scan_prepared};

    /// The legitimate shape: `@prisma/client` imported, client constructed,
    /// tainted input interpolated into `$queryRawUnsafe`.
    const PRISMA_POSITIVE: &str = r#"
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
export async function bad(email: string) {
  await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)
}
"#;

    /// Same method name, but the receiver is an unrelated local object and
    /// no `@prisma/client` import exists: the call name stays inert.
    const UNRELATED_RECEIVER: &str = r#"
declare const helper: any
export async function fine(email: string) {
  await helper.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)
}
"#;

    /// An import from a DIFFERENT package with the same method name: the
    /// origin mismatch must not fall back to `@prisma/client`'s scoped fact.
    const WRONG_PACKAGE: &str = r#"
import { thing } from 'some-other-package'
export async function fine(email: string) {
  await thing.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)
}
"#;

    fn run(src: &str) -> Vec<crate::analysis::taint::engine::SinkFinding> {
        let files = vec![("test.ts".to_string(), src.to_string(), "ts".to_string())];
        let (config, facts) = seeded_tables(["ts"]);
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts).findings
    }

    fn has_raw_finding(findings: &[crate::analysis::taint::engine::SinkFinding]) -> bool {
        findings.iter().any(|f| f.sink.contains("queryRawUnsafe"))
    }

    #[test]
    fn scoped_sink_fires_with_prisma_import_origin() {
        let findings = run(PRISMA_POSITIVE);
        assert!(
            has_raw_finding(&findings),
            "the Prisma raw-unsafe query with import origin must fire; got {findings:?}"
        );
    }

    #[test]
    fn scoped_sink_is_silent_on_unrelated_receiver() {
        let findings = run(UNRELATED_RECEIVER);
        assert!(
            !has_raw_finding(&findings),
            "an unrelated receiver with the same method name must stay silent; got {findings:?}"
        );
    }

    #[test]
    fn scoped_sink_is_silent_on_wrong_package_origin() {
        let findings = run(WRONG_PACKAGE);
        assert!(
            !has_raw_finding(&findings),
            "an origin from a different package must not inherit the scoped fact; got {findings:?}"
        );
    }
}
