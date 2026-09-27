// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! LSP `Content-Length` framing: read one JSON-RPC message from a byte
//! stream, write one out. Kept separate from the server logic so the
//! framing round-trip is testable without a real editor.

use std::io::{BufRead, Write};

/// Read headers + body; returns the raw JSON text. `None` on clean EOF.
///
/// # Errors
/// `Err` on malformed headers (missing `Content-Length`) or a truncated
/// body — both mean the transport is broken and the loop should stop.
pub fn read_message(reader: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let line = line.trim_end();
        if line.is_empty() {
            break; // headers done
        }
        if let Some(value) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            content_length = value.trim().parse::<usize>().ok();
        }
    }
    let Some(len) = content_length else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing Content-Length header",
        ));
    };
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    String::from_utf8(body)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Write one framed message.
///
/// # Errors
/// Propagates write failures (broken pipe: the client went away).
pub fn write_message(writer: &mut impl Write, body: &str) -> std::io::Result<()> {
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(body.as_bytes())?;
    writer.flush()
}

#[cfg(test)]
#[path = "framing_tests.rs"]
mod tests;
