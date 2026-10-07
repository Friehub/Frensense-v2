// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Frontier 7: Quantitative Finance, Enterprise Patterns, and High-Frequency Trading.
//!
//! Models core enterprise trading patterns (Jane Street, Bloomberg, Stripe, Citadel):
//! - Monadic `Result` / `Option` railway pipelines
//! - Function pointer vtable strategy dispatch
//! - Zero-allocation ring buffer indexing (LMAX Disruptor)
//! - Order state machine transition invariants
//! - Double-entry ledger range and precision checks
//! - Java-style enterprise interface polymorphism
//! - Java-style immutable record field propagation

use super::*;

#[test]
#[ignore = "Blind spot: Rust scoped call query for Command and and_then pipeline"]
fn probe_fin_01_rust_monadic_result_pipeline() {
    let src = r#"
        use std::process::Command;

        fn parse_order(input: &str) -> Result<String, ()> {
            Ok(input.to_string())
        }

        fn risk_check(order: String) -> Result<String, ()> {
            Ok(order)
        }

        fn execute_market_order(order: String) {
            Command::new(order);
        }

        pub fn test() {
            let raw = std::env::var("RAW_ORDER").unwrap();
            let _ = parse_order(&raw)
                .and_then(risk_check)
                .map(execute_market_order);
        }
    "#;
    assert_detected(
        &scan_rust(src),
        "fin_01_rust_monadic_result_pipeline",
        "Command",
    );
}

#[test]
#[ignore = "Blind spot: C struct function pointer strategy table callgraph resolution"]
fn probe_fin_02_c_function_pointer_strategy_vtable() {
    let src = r#"
        #include <stdlib.h>

        typedef void (*strategy_fn)(char *data);

        void aggressive_strategy(char *data) {
            system(data);
        }

        struct Engine {
            strategy_fn strategies[4];
        };

        void test(void) {
            char *order = getenv("ORDER");
            struct Engine engine;
            engine.strategies[0] = aggressive_strategy;
            engine.strategies[0](order);
        }
    "#;
    assert_detected(
        &scan_c(src),
        "fin_02_c_function_pointer_strategy_vtable",
        "system",
    );
}

#[test]
#[ignore = "Blind spot: Pre-allocated struct array slot mutation and strcpy outparam"]
fn probe_fin_03_ring_buffer_zero_alloc_slots() {
    let src = r#"
        #include <stdlib.h>
        #include <string.h>

        struct Slot {
            char payload[64];
            int id;
        };

        struct RingBuffer {
            struct Slot slots[16];
        };

        void test(void) {
            char *input = getenv("FIX_MESSAGE");
            struct RingBuffer rb;
            strcpy(rb.slots[3].payload, input);
            system(rb.slots[3].payload);
        }
    "#;
    assert_detected(
        &scan_c(src),
        "fin_03_ring_buffer_zero_alloc_slots",
        "system",
    );
}

#[test]
fn probe_fin_04_state_machine_guard_transition() {
    let src = r#"
        export function test(req: any) {
            let state = "CREATED";
            const order = req.body.order;

            if (req.body.riskApproved) {
                state = "APPROVED";
            }

            if (state === "APPROVED") {
                eval(order);
            }
        }
    "#;
    assert_detected(
        &scan_ts(src),
        "fin_04_state_machine_guard_transition",
        "eval",
    );
}

#[test]
fn probe_fin_05_double_entry_ledger_range_check() {
    let src = r#"
        export function test(req: any) {
            const amount = parseInt(req.body.amount, 10);
            if (amount <= 0 || amount > 1000000) {
                return;
            }
            eval(amount);
        }
    "#;
    // Bounded integer coercion is clean
    assert_clean(&scan_ts(src), "fin_05_double_entry_ledger_range_check");
}

#[test]
fn probe_fin_06_java_style_interface_polymorphism() {
    let src = r#"
        interface PaymentGateway {
            processTransaction(payload: any): void;
        }

        class RealTradingGateway implements PaymentGateway {
            processTransaction(payload: any): void {
                eval(payload);
            }
        }

        export function test(req: any) {
            const gateway: PaymentGateway = new RealTradingGateway();
            gateway.processTransaction(req.body.payload);
        }
    "#;
    assert_detected(
        &scan_ts(src),
        "fin_06_java_style_interface_polymorphism",
        "eval",
    );
}

#[test]
fn probe_fin_07_java_style_builder_immutability() {
    let src = r#"
        class OrderRecord {
            constructor(
                public readonly symbol: string,
                public readonly payload: any
            ) {}
        }

        export function test(req: any) {
            const order = new OrderRecord("AAPL", req.body.payload);
            eval(order.payload);
        }
    "#;
    assert_detected(
        &scan_ts(src),
        "fin_07_java_style_builder_immutability",
        "eval",
    );
}
