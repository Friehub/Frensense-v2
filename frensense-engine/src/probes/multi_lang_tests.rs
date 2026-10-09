// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Frontier 3: Multi-Language Providers (Go and Rust).

use super::*;

#[test]
fn probe_ml_01_go_http_command_injection() {
    let src = r#"
        package main

        import (
            "net/http"
            "os/exec"
        )

        func handler(w http.ResponseWriter, r *http.Request) {
            cmd := r.FormValue("c")
            exec.Command(cmd)
        }
    "#;
    assert_detected(&scan_go(src), "ml_01_go_http_command_injection", "Command");
}

#[test]
#[ignore = "Blind spot: Go channel send and receive dataflow propagation"]
fn probe_ml_02_go_channel_concurrency() {
    let src = r#"
        package main

        import (
            "net/http"
            "os/exec"
        )

        func handler(w http.ResponseWriter, r *http.Request) {
            ch := make(chan string)
            ch <- r.FormValue("c")
            cmd := <-ch
            exec.Command(cmd)
        }
    "#;
    assert_detected(&scan_go(src), "ml_02_go_channel_concurrency", "Command");
}

#[test]
fn probe_ml_03_go_struct_field_flow() {
    let src = r#"
        package main

        import (
            "net/http"
            "os/exec"
        )

        type Payload struct {
            Cmd string
        }

        func handler(w http.ResponseWriter, r *http.Request) {
            p := Payload{Cmd: r.FormValue("c")}
            exec.Command(p.Cmd)
        }
    "#;
    assert_detected(&scan_go(src), "ml_03_go_struct_field_flow", "Command");
}

#[test]
fn probe_ml_04_rust_env_command_unwrap() {
    let src = r#"
        use std::process::Command;

        pub fn test() {
            let cmd = std::env::var("CMD").unwrap();
            Command::new(cmd);
        }
    "#;
    assert_detected(&scan_rust(src), "ml_04_rust_env_command_unwrap", "Command");
}

#[test]
fn probe_ml_05_rust_match_result_flow() {
    let src = r#"
        use std::process::Command;

        pub fn test() {
            let res = std::env::var("CMD");
            match res {
                Ok(cmd) => {
                    Command::new(cmd);
                }
                Err(_) => {}
            }
        }
    "#;
    assert_detected(&scan_rust(src), "ml_05_rust_match_result_flow", "Command");
}
