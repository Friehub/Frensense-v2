// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Package-scoped sink facts: a framework sink installed under a package
//! (`@prisma/client`) must fire only when the caller's import origin
//! resolves to that package, and stay silent otherwise.
//!
//! Triplets:
//! 1. import + factory singleton (`new PrismaClient()`) arms `@prisma/client`,
//!    fires (the legitimate Prisma raw-SQL shape).
//! 2. no import, unrelated receiver object, silent (the false-positive
//!    class package scoping exists to close).
//! 3. wrong-package import (`database-js` lookalike), silent (origin
//!    mismatch must not fall back to another package's scoped fact).

#[cfg(test)]
#[allow(clippy::module_inception)] // test file convention: module name repeats parent path segment
pub(crate) mod package_scoped_sink_tests {
    use crate::analysis::taint::facts::{FactTable, SinkSignature, seeded_tables};
    use crate::analysis::taint::role::SinkRole;
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

    /// Prisma's tagged-template form parameterizes the interpolations at the
    /// driver: the legitimate shape, not a sink. Only the `Unsafe` variants
    /// (plus `sql.raw`) take a buildable string. Declaring `$queryRaw` as a
    /// scoped sink reintroduces the tagged-template false positive.
    const TAGGED_TEMPLATE: &str = r#"
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
export async function fine(id: string) {
  await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`
}
"#;

    fn run(src: &str) -> Vec<crate::analysis::taint::engine::SinkFinding> {
        let files = vec![("test.ts".to_string(), src.to_string(), "ts".to_string())];
        let (config, facts) = seeded_tables(["ts"]);
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts).findings
    }

    fn run_files(files: &[(&str, &str, &str)]) -> Vec<crate::analysis::taint::engine::SinkFinding> {
        let files: Vec<(String, String, String)> = files
            .iter()
            .map(|(p, s, e)| (p.to_string(), s.to_string(), e.to_string()))
            .collect();
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

    /// The barrel re-export is the shape that used to lose provenance: the
    /// importing file's specifier is `./lib/prisma`, a local file, so the
    /// package origin only exists if the re-export chain carries it.
    const PRISMA_BARREL: &str = "export { PrismaClient } from '@prisma/client';\n";
    const NAMESPACE_BARREL: &str = "export * as prisma from '@prisma/client';\n";
    const LOOKALIKE_BARREL: &str = "export { PrismaClient } from 'database-js';\n";

    const APP_VIA_BARREL: &str = r#"
import { PrismaClient } from './lib/prisma'
const prisma = new PrismaClient()
export async function bad(req: any) {
  const email = req.query.email
  await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)
}
"#;

    const NAMESPACE_HELPER: &str = r#"
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
export async function runQuery(email: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)
}
"#;

    const APP_VIA_NAMESPACE_HELPER: &str = r#"
import * as db from './lib/db'
export async function bad(req: any) {
  await db.runQuery(req.query.email)
}
"#;

    const APP_VIA_NAMESPACE_BARREL: &str = r#"
import { prisma } from './lib/prisma'
export async function bad(req: any) {
  const email = req.query.email
  await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`)
}
"#;

    #[test]
    fn scoped_sink_fires_through_a_barrel_reexport() {
        let findings = run_files(&[
            ("lib/prisma.ts", PRISMA_BARREL, "ts"),
            ("app.ts", APP_VIA_BARREL, "ts"),
        ]);
        assert!(
            findings.iter().any(|f| f.sink.contains("queryRawUnsafe")
                && f.verdict == crate::analysis::taint::engine::BackwardVerdict::Vulnerable),
            "a scoped sink reached through a local barrel re-export must fire; got {findings:?}"
        );
    }

    /// `export * as ns from "<pkg>"` publishes the module, not a member
    /// called `ns`, so a call through the binding is a call on the package
    /// and the package-scoped fact must reach it.
    #[test]
    fn scoped_sink_fires_through_a_namespace_reexport() {
        let findings = run_files(&[
            ("lib/prisma.ts", NAMESPACE_BARREL, "ts"),
            ("app.ts", APP_VIA_NAMESPACE_BARREL, "ts"),
        ]);
        assert!(
            findings.iter().any(|f| f.sink.contains("queryRawUnsafe")
                && f.verdict == crate::analysis::taint::engine::BackwardVerdict::Vulnerable),
            "a scoped sink reached through `export * as` must fire; got {findings:?}"
        );
    }

    /// The same barrel shape must not launder a foreign package into the
    /// scoped fact: the origin carried is `database-js`, not "the file".
    #[test]
    fn barrel_reexport_carries_the_foreign_origin_not_the_file() {
        let findings = run_files(&[
            ("lib/prisma.ts", LOOKALIKE_BARREL, "ts"),
            ("app.ts", APP_VIA_BARREL, "ts"),
        ]);
        assert!(
            !findings.iter().any(|f| f.sink.contains("queryRawUnsafe")
                && f.verdict == crate::analysis::taint::engine::BackwardVerdict::Vulnerable),
            "a lookalike package reached through a barrel must stay silent; got {findings:?}"
        );
    }

    /// A call through a namespace binding is program code, not a library
    /// call: taint entering the module helper's parameter reaches the sink
    /// inside it.
    #[test]
    fn taint_flows_into_a_namespace_module_helper() {
        let findings = run_files(&[
            ("lib/db.ts", NAMESPACE_HELPER, "ts"),
            ("app.ts", APP_VIA_NAMESPACE_HELPER, "ts"),
        ]);
        assert!(
            findings.iter().any(|f| f.sink.contains("queryRawUnsafe")
                && f.verdict == crate::analysis::taint::engine::BackwardVerdict::Vulnerable),
            "taint passed through `import * as db` must reach the helper's sink; got {findings:?}"
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

    #[test]
    fn scoped_sink_is_silent_on_tagged_template() {
        let findings = run(TAGGED_TEMPLATE);
        assert!(
            !findings.iter().any(|f| f.sink.contains("queryRaw")),
            "parameterized `$queryRaw` tagged template must stay silent; got {findings:?}"
        );
    }

    /// Next.js `NextResponse.rewrite` package-scoped to `next/server`.
    const NEXTJS_POSITIVE: &str = r#"
import { NextResponse } from 'next/server'
export function GET(request: Request) {
  const url = new URL(request.url).searchParams.get('dest') || '/'
  return NextResponse.rewrite(url)
}
"#;

    const NEXTJS_WRONG_ORIGIN: &str = r#"
import { NextResponse } from 'custom-server'
export function GET(request: Request) {
  const url = new URL(request.url).searchParams.get('dest') || '/'
  return NextResponse.rewrite(url)
}
"#;

    #[test]
    fn nextjs_rewrite_fires_with_next_server_import() {
        let findings = run(NEXTJS_POSITIVE);
        assert!(
            findings.iter().any(|f| f.sink.contains("rewrite")),
            "NextResponse.rewrite with next/server origin must fire; got {findings:?}"
        );
    }

    #[test]
    fn nextjs_rewrite_silent_on_foreign_origin() {
        let findings = run(NEXTJS_WRONG_ORIGIN);
        assert!(
            !findings.iter().any(|f| f.sink.contains("rewrite")),
            "NextResponse.rewrite without next/server origin must stay silent; got {findings:?}"
        );
    }

    /// Vue Router `navigateTo` package-scoped to `vue-router`.
    const VUE_ROUTER_POSITIVE: &str = r#"
import { navigateTo } from 'vue-router'
export function redirectUser(target: string) {
  navigateTo(target)
}
"#;

    const VUE_ROUTER_WRONG_ORIGIN: &str = r#"
import { navigateTo } from 'local-navigator'
export function redirectUser(target: string) {
  navigateTo(target)
}
"#;

    #[test]
    fn vue_router_navigateto_fires_with_vue_router_import() {
        let findings = run(VUE_ROUTER_POSITIVE);
        assert!(
            findings.iter().any(|f| f.sink.contains("navigateTo")),
            "navigateTo with vue-router origin must fire; got {findings:?}"
        );
    }

    #[test]
    fn vue_router_navigateto_silent_on_foreign_origin() {
        let findings = run(VUE_ROUTER_WRONG_ORIGIN);
        assert!(
            !findings.iter().any(|f| f.sink.contains("navigateTo")),
            "navigateTo without vue-router origin must stay silent; got {findings:?}"
        );
    }

    /// Nuxt / ofetch `$fetch` SSRF sink package-scoped to `ofetch`.
    const OFETCH_POSITIVE: &str = r#"
import { $fetch } from 'ofetch'
export async function fetchUser(url: string) {
  return await $fetch(url)
}
"#;

    const OFETCH_WRONG_ORIGIN: &str = r#"
import { $fetch } from 'custom-http'
export async function fetchUser(url: string) {
  return await $fetch(url)
}
"#;

    #[test]
    fn ofetch_sink_fires_with_ofetch_import() {
        let findings = run(OFETCH_POSITIVE);
        assert!(
            findings.iter().any(|f| f.sink.contains("$fetch")),
            "$fetch with ofetch origin must fire; got {findings:?}"
        );
    }

    #[test]
    fn ofetch_sink_silent_on_foreign_origin() {
        let findings = run(OFETCH_WRONG_ORIGIN);
        assert!(
            !findings.iter().any(|f| f.sink.contains("$fetch")),
            "$fetch without ofetch origin must stay silent; got {findings:?}"
        );
    }

    /// NestJS `@nestjs/typeorm` createQueryBuilder SQL injection sink.
    const NESTJS_TYPEORM_POSITIVE: &str = r#"
import { DataSource } from '@nestjs/typeorm'
const ds = new DataSource()
export async function search(query: string) {
  return ds.createQueryBuilder(query)
}
"#;

    const NESTJS_TYPEORM_WRONG_ORIGIN: &str = r#"
import { DataSource } from 'custom-repo'
const ds = new DataSource()
export async function search(query: string) {
  return ds.createQueryBuilder(query)
}
"#;

    #[test]
    fn nestjs_typeorm_fires_with_import() {
        let findings = run(NESTJS_TYPEORM_POSITIVE);
        assert!(
            findings
                .iter()
                .any(|f| f.sink.contains("createQueryBuilder")),
            "createQueryBuilder with @nestjs/typeorm origin must fire; got {findings:?}"
        );
    }

    #[test]
    fn nestjs_typeorm_silent_on_foreign_origin() {
        let findings = run(NESTJS_TYPEORM_WRONG_ORIGIN);
        assert!(
            !findings
                .iter()
                .any(|f| f.sink.contains("createQueryBuilder")),
            "createQueryBuilder without @nestjs/typeorm origin must stay silent; got {findings:?}"
        );
    }

    /// A sink fact proven for one package arms the same member on a *sibling*
    /// package of the same category - and nothing else. The layout, role and
    /// label all come from the measured fact, so a MySQL driver's
    /// `run_query` is ranked by what SQLite's taught.
    #[test]
    fn taught_sink_covers_a_sibling_package_of_the_same_category() {
        let mut facts = FactTable::default();
        facts.scoped_sink_signatures.insert(
            ("sqlite3".to_string(), "run_query".to_string()),
            SinkSignature {
                call: "run_query".to_string(),
                package: Some("sqlite3".to_string()),
                dangerous_args: [0].into_iter().collect(),
                binding_args_safe: true,
                idor_keys: Vec::new(),
                role: SinkRole::Execution,
                label: Some("sql".to_string()),
                global_only: false,
            },
        );

        // Sibling driver, same category: same layout, same role, same label.
        let sibling = Some("pymysql");
        assert!(facts.is_sink_call_scoped("run_query", None, sibling, Some("python")));
        assert_eq!(
            facts.role_for_call_scoped("run_query", None, sibling, Some("python")),
            Some(SinkRole::Execution)
        );
        assert_eq!(
            facts.label_for_call_scoped("run_query", None, sibling, Some("python")),
            Some("sql".to_string())
        );
        let armed = facts
            .sink_signature_scoped("run_query", sibling, Some("python"))
            .expect("sibling signature");
        assert_eq!(armed.dangerous_args.len(), 1);

        // A package of a different category does not inherit it, and without
        // a language nothing can be classified.
        assert!(!facts.is_sink_call_scoped("run_query", None, Some("flask"), Some("python")));
        assert!(!facts.is_sink_call_scoped("run_query", None, sibling, None));
    }
}
