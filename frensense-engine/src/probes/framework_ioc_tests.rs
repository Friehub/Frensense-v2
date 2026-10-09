// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Frontier 6: Framework Inversion-of-Control (Express, Flask, NestJS).

use super::*;

#[test]
fn probe_fw_01_express_route_handler() {
    let src = r#"
        const express = require("express");
        const app = express();

        app.get("/search", (req: any, res: any) => {
            eval(req.query.q);
        });
    "#;
    assert_detected(&scan_ts(src), "fw_01_express_route_handler", "eval");
}

#[test]
fn probe_fw_02_express_middleware_chain() {
    let src = r#"
        const express = require("express");
        const app = express();

        app.use((req: any, res: any, next: any) => {
            req.customPayload = req.body.data;
            next();
        });

        app.post("/exec", (req: any, res: any) => {
            eval(req.customPayload);
        });
    "#;
    assert_detected(&scan_ts(src), "fw_02_express_middleware_chain", "eval");
}

#[test]
fn probe_fw_03_flask_route_decorator() {
    let src = r#"
        from flask import Flask, request

        app = Flask(__name__)

        @app.route('/run')
        def run_cmd():
            eval(request.args.get('cmd'))
    "#;
    assert_detected(&scan_py(src), "fw_03_flask_route_decorator", "eval");
}

#[test]
fn probe_fw_04_nestjs_controller_body() {
    let src = r#"
        export class AppController {
            handleRequest(req: any) {
                eval(req.body.payload);
            }
        }
    "#;
    assert_detected(&scan_ts(src), "fw_04_nestjs_controller_body", "eval");
}
