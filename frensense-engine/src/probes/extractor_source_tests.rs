// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Typed request extractors as taint sources.
//!
//! In a typed language the *type* of a handler parameter decides that the
//! argument is attacker-controlled, while the parameter's name is the
//! author's choice: `fn h(Query(p): Query<P>)` and `fn h(zzz: web::Query<P>)`
//! are the same source. Before this, `bind_params` named the parameter after
//! the whole pattern text ("Query(p)") and never recorded the annotation, so
//! no Rust extractor was ever a source and every Rust framework fixture
//! stayed silent. The source vocabulary stays in the pack (`Query`,
//! `web::Query`); the mechanism (match a parameter's annotation path against
//! it) is name-agnostic.

use super::*;

/// The canonical axum shape: a destructured extractor whose inner binding
/// feeds a raw SQL string.
#[test]
fn probe_rust_extractor_pattern_param_is_a_source() {
    let src = r#"
use axum::extract::Query;
use serde::Deserialize;

#[derive(Deserialize)]
struct P { id: String }

async fn h(Query(p): Query<P>) -> String {
    let rows = sqlx::query(&format!("SELECT * FROM users WHERE id = '{}'", p.id)).fetch_all().await.unwrap();
    rows.len().to_string()
}
"#;
    assert_detected(&scan_rust(src), "rust_extractor_pattern_param", "query");
}

/// Renaming the binding must not change the verdict: the extractor TYPE is
/// the source, not the identifier (`zzz` is not a source name anywhere).
#[test]
fn probe_rust_extractor_param_name_does_not_matter() {
    let src = r#"
use axum::extract::Query;
use serde::Deserialize;

#[derive(Deserialize)]
struct P { id: String }

async fn h(Query(zzz): Query<P>) -> String {
    std::fs::read_to_string(&zzz.id).unwrap()
}
"#;
    assert_detected(
        &scan_rust(src),
        "rust_extractor_param_name_x",
        "read_to_string",
    );
}

/// Typed (non-destructured) extractor parameter: `q: web::Query<P>`.
#[test]
fn probe_rust_typed_param_annotation_is_a_source() {
    let src = r#"
use actix_web::web;

async fn h(q: web::Query<P>) -> String {
    let out = std::process::Command::new("sh").arg("-c").arg(&q.cmd).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}
"#;
    assert_detected(&scan_rust(src), "rust_typed_param_annotation", "arg");
}

/// Negative control: the same body with a parameter whose annotation is NOT
/// in the source vocabulary stays silent - the new rule must not turn every
/// parameter into a source.
#[test]
fn probe_rust_plain_typed_param_is_not_a_source() {
    let src = r#"
async fn h(name: String) -> String {
    std::fs::read_to_string(&name).unwrap()
}
"#;
    assert_clean(&scan_rust(src), "rust_plain_typed_param");
}

/// Negative control for the destructuring change: the inner binding is the
/// parameter, so a *local* variable of the same name shadowing it is not a
/// source either (no global "any destructured parameter" widening).
#[test]
fn probe_rust_non_extractor_pattern_param_is_not_a_source() {
    let src = r#"
async fn h(p: String) -> String {
    let q = p;
    std::fs::read_to_string(&q).unwrap()
}
"#;
    assert_clean(&scan_rust(src), "rust_non_extractor_pattern_param");
}

/// The pack additions the Rust framework fixtures needed: diesel's raw
/// `sql_query` escape hatch is a SQL sink, and `Xml`-free `Html(body)` is a
/// reflected-XSS sink (the escaped path goes through a template instead).
#[test]
fn probe_rust_raw_sql_and_html_sinks_fire() {
    let sql = r#"
use axum::extract::Query;

async fn h(Query(p): Query<P>) -> String {
    let q = diesel::sql_query(format!("SELECT * FROM users WHERE id = '{}'", p.id));
    q.execute(&mut conn).unwrap().to_string()
}
"#;
    assert_detected(&scan_rust(sql), "rust_diesel_sql_query", "sql_query");

    let html = r#"
use axum::extract::Query;

async fn h(Query(p): Query<P>) -> axum::response::Html<String> {
    axum::response::Html(format!("<h1>{}</h1>", p.id))
}
"#;
    assert_detected(&scan_rust(html), "rust_html_format", "Html");
}

/// The two Rust sanitizers the fixtures rely on: the numeric parse and the
/// basename extractor. Each must cut the flow it is supposed to cut, and
/// must not cut an unrelated one (checked by the sibling probe below).
#[test]
fn probe_rust_numeric_parse_sanitizes_sql() {
    let src = r#"
use axum::extract::Query;

async fn h(Query(p): Query<P>) -> String {
    let n: i64 = p.id.parse().unwrap();
    sqlx::query(&format!("SELECT * FROM users WHERE id = {}", n)).fetch_all().await.unwrap();
    n.to_string()
}
"#;
    assert_clean(&scan_rust(src), "rust_numeric_parse_sanitizer");
}

/// `Path::new(p).file_name()` drops every directory component, so the read
/// that consumes the basename is not a traversal.
#[test]
fn probe_rust_file_name_sanitizes_path() {
    let src = r#"
use axum::extract::Query;

async fn h(Query(p): Query<P>) -> String {
    let name = std::path::Path::new(&p.id).file_name().unwrap();
    std::fs::read_to_string(std::path::Path::new("/data").join(name)).unwrap()
}
"#;
    assert_clean(&scan_rust(src), "rust_file_name_sanitizer");
}

/// Control: the basename extraction must not sanitize a *different*
/// dangerous use of the same tainted value (the sanitizer applies to the
/// call's result, not to the variable).
#[test]
fn probe_rust_file_name_does_not_sanitize_the_original_value() {
    let src = r#"
use axum::extract::Query;

async fn h(Query(p): Query<P>) -> String {
    let name = std::path::Path::new(&p.id).file_name().unwrap();
    std::fs::read_to_string(&p.id).unwrap()
}
"#;
    assert_detected(
        &scan_rust(src),
        "rust_file_name_keeps_original",
        "read_to_string",
    );
}
