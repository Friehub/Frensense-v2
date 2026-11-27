// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub

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

#[test]
fn probe_fw_05_py_list_append() {
    let src = r#"
        from flask import Flask, request
        import sqlite3

        app = Flask(__name__)

        @app.route('/u')
        def u():
            items = []
            items.append(request.args.get('id'))
            return str(sqlite3.connect('x').execute("SELECT * FROM t WHERE id = " + items[0]).fetchall())
    "#;
    assert_detected(&scan_py(src), "fw_05_py_list_append", "execute");
}

#[test]
fn probe_fw_06_ts_array_push() {
    let src = r#"
        import express from 'express';
        import { Pool } from 'pg';

        const app = express();
        const pool = new Pool();

        app.get('/u', (req: any, res: any) => {
            const items: any[] = [];
            items.push(req.query.id);
            pool.query("SELECT * FROM t WHERE id = " + items[0]);
        });
    "#;
    assert_detected(&scan_ts(src), "fw_06_ts_array_push", "query");
}

/// Vue SFC: the `<script setup>` declaration and the desugared template write
/// are both module scope. They link only because the whole module is one
/// dataflow unit - the definition used to sit in a separate pseudo-function.
#[test]
fn probe_fw_07_vue_template_write_from_script_scope() {
    let src = "<template>\n  <div v-html=\"a\"></div>\n</template>\n\n<script setup lang=\"ts\">\nconst a = process.argv[2];\n</script>\n";
    let res = scan_files(&[("app/Component.vue", src, "vue")]);
    assert_detected(&res, "fw_07_vue_template_write", "vhtml");
}
