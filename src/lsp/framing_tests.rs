// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

use super::*;

#[test]
fn round_trips_a_message() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let mut buf = Vec::new();
    write_message(&mut buf, body).unwrap();
    let mut reader: &[u8] = &buf;
    let got = read_message(&mut reader).unwrap().unwrap();
    assert_eq!(got, body);
}

#[test]
fn handles_multiple_messages_and_eof() {
    let mut buf = Vec::new();
    write_message(&mut buf, "{\"a\":1}").unwrap();
    write_message(&mut buf, "{\"b\":2}").unwrap();
    let mut reader: &[u8] = &buf;
    assert_eq!(read_message(&mut reader).unwrap().unwrap(), "{\"a\":1}");
    assert_eq!(read_message(&mut reader).unwrap().unwrap(), "{\"b\":2}");
    assert!(read_message(&mut reader).unwrap().is_none(), "EOF → None");
}

#[test]
fn rejects_missing_content_length() {
    let raw = b"Content-Type: text\r\n\r\n{}";
    let mut reader: &[u8] = raw;
    assert!(read_message(&mut reader).is_err());
}

#[test]
fn tolerates_utf8_bodies() {
    let body = "{\"m\":\"héllo ✓\"}";
    let mut buf = Vec::new();
    write_message(&mut buf, body).unwrap();
    let mut reader: &[u8] = &buf;
    assert_eq!(read_message(&mut reader).unwrap().unwrap(), body);
}
