// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.

//! Industrial-grade Dataflow Consistency & Capability Probe Suite.
//!
//! Structured after the NIST / Juliet Flow-Variant Taxonomy and CodeQL
//! dataflow consistency suites:
//!
//! * Tier 1 (Variants 01-18): Intra-procedural syntactic matrix
//! * Tier 2 (Variants 51-68): Inter-procedural function calls & summaries
//! * Tier 3 (Variants 71-78): Cross-file module graph, imports & linkages

use crate::analysis::taint::engine::BackwardVerdict;
use crate::analysis::taint::facts::seeded_tables_all;
use crate::scan::{ScanResult, scan};

fn scan_files(files: &[(&str, &str, &str)]) -> ScanResult {
    let (config, facts) = seeded_tables_all();
    let file_tuples: Vec<(String, String, String)> = files
        .iter()
        .map(|(p, s, e)| (p.to_string(), s.to_string(), e.to_string()))
        .collect();
    scan(&file_tuples, &config, &facts)
}

fn scan_ts(src: &str) -> ScanResult {
    scan_files(&[("app/probe.ts", src, "ts")])
}

fn scan_py(src: &str) -> ScanResult {
    scan_files(&[("app/probe.py", src, "py")])
}

fn scan_c(src: &str) -> ScanResult {
    scan_files(&[("app/probe.c", src, "c")])
}

fn assert_detected(res: &ScanResult, probe_name: &str, expected_sink: &str) {
    let found = res.located.iter().any(|l| {
        l.finding.sink.contains(expected_sink) && l.finding.verdict == BackwardVerdict::Vulnerable
    });
    assert!(
        found,
        "PROBE FAILED: [{probe_name}] expected vulnerable sink '{expected_sink}' not detected.\nFindings: {:?}",
        res.located
            .iter()
            .map(|l| (&l.file, &l.finding.sink, l.line, l.finding.verdict.clone()))
            .collect::<Vec<_>>()
    );
}

#[allow(dead_code)]
fn assert_clean(res: &ScanResult, probe_name: &str) {
    let vulnerable: Vec<_> = res
        .located
        .iter()
        .filter(|l| l.finding.verdict == BackwardVerdict::Vulnerable)
        .collect();
    assert!(
        vulnerable.is_empty(),
        "PROBE FAILED (FALSE POSITIVE): [{probe_name}] expected clean, but detected:\nFindings: {:?}",
        vulnerable
            .iter()
            .map(|l| (&l.file, &l.finding.sink, l.line))
            .collect::<Vec<_>>()
    );
}

// ============================================================================
// Tier 1: Intra-Procedural Syntactic Matrix (Juliet Variants 01..18)
// ============================================================================
mod tier1_syntactic_probes {
    use super::*;

    #[test]
    fn probe_01_baseline_assignment() {
        let src = r#"
            export function test(req: any) {
                const x = req.body.payload;
                eval(x);
            }
        "#;
        assert_detected(&scan_ts(src), "01_baseline_assignment", "eval");
    }

    #[test]
    fn probe_02_ternary_conditional() {
        let src = r#"
            export function test(req: any, flag: boolean) {
                const x = flag ? req.body.payload : "safe";
                eval(x);
            }
        "#;
        assert_detected(&scan_ts(src), "02_ternary_conditional", "eval");
    }

    #[test]
    fn probe_03_nullish_coalescing() {
        let src = r#"
            export function test(req: any) {
                let x = null;
                x = x ?? req.body.payload;
                eval(x);
            }
        "#;
        assert_detected(&scan_ts(src), "03_nullish_coalescing", "eval");
    }

    #[test]
    fn probe_04_array_literal_index() {
        let src = r#"
            export function test(req: any) {
                const arr = [req.body.payload];
                eval(arr[0]);
            }
        "#;
        assert_detected(&scan_ts(src), "04_array_literal_index", "eval");
    }

    #[test]
    fn probe_05_array_destructuring() {
        let src = r#"
            export function test(req: any) {
                const [first] = [req.body.payload];
                eval(first);
            }
        "#;
        assert_detected(&scan_ts(src), "05_array_destructuring", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Array map transform element-level propagation"]
    fn probe_06_array_map_transform() {
        let src = r#"
            export function test(req: any) {
                const arr = [req.body.payload].map((x: any) => x);
                eval(arr[0]);
            }
        "#;
        assert_detected(&scan_ts(src), "06_array_map_transform", "eval");
    }

    #[test]
    fn probe_07_object_literal_property() {
        let src = r#"
            export function test(req: any) {
                const obj = { p: req.body.payload };
                eval(obj.p);
            }
        "#;
        assert_detected(&scan_ts(src), "07_object_literal_property", "eval");
    }

    #[test]
    fn probe_08_object_spread() {
        let src = r#"
            export function test(req: any) {
                const base = { p: req.body.payload };
                const obj = { ...base };
                eval(obj.p);
            }
        "#;
        assert_detected(&scan_ts(src), "08_object_spread", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Multi-level nested object destructuring binding"]
    fn probe_09_object_destructuring_nested() {
        let src = r#"
            export function test(req: any) {
                const { a: { b } } = { a: { b: req.body.payload } };
                eval(b);
            }
        "#;
        assert_detected(&scan_ts(src), "09_object_destructuring_nested", "eval");
    }

    #[test]
    fn probe_10_template_literal() {
        let src = r#"
            export function test(req: any) {
                const str = `cmd ${req.body.payload}`;
                eval(str);
            }
        "#;
        assert_detected(&scan_ts(src), "10_template_literal", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Promise await target variable taint transfer"]
    fn probe_11_promise_await() {
        let src = r#"
            export async function test(req: any) {
                const p = await Promise.resolve(req.body.payload);
                eval(p);
            }
        "#;
        assert_detected(&scan_ts(src), "11_promise_await", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Promise.then chaining callback resolution"]
    fn probe_12_promise_then_chain() {
        let src = r#"
            export function test(req: any) {
                Promise.resolve(req.body.payload).then((x: any) => {
                    eval(x);
                });
            }
        "#;
        assert_detected(&scan_ts(src), "12_promise_then_chain", "eval");
    }

    #[test]
    fn probe_13_closure_captured_var() {
        let src = r#"
            export function test(req: any) {
                const p = req.body.payload;
                const fn = () => {
                    eval(p);
                };
                fn();
            }
        "#;
        assert_detected(&scan_ts(src), "13_closure_captured_var", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Parenthesized IIFE expression callee resolution"]
    fn probe_14_iife_argument() {
        let src = r#"
            export function test(req: any) {
                ((v: any) => {
                    eval(v);
                })(req.body.payload);
            }
        "#;
        assert_detected(&scan_ts(src), "14_iife_argument", "eval");
    }

    #[test]
    fn probe_15_python_comprehension() {
        let src = r#"
def test(request):
    val = [x for x in [request.GET['p']]][0]
    eval(val)
        "#;
        assert_detected(&scan_py(src), "15_python_comprehension", "eval");
    }

    #[test]
    fn probe_16_dynamic_property_lookup() {
        let src = r#"
            export function test(req: any) {
                const obj: any = {};
                const key = "data";
                obj[key] = req.body.payload;
                eval(obj[key]);
            }
        "#;
        assert_detected(&scan_ts(src), "16_dynamic_property_lookup", "eval");
    }

    #[test]
    fn probe_17_optional_chaining() {
        let src = r#"
            export function test(req: any) {
                const x = req?.body?.payload;
                eval(x);
            }
        "#;
        assert_detected(&scan_ts(src), "17_optional_chaining", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Object.assign in-place destination mutation"]
    fn probe_18_object_assign_target() {
        let src = r#"
            export function test(req: any) {
                const target: any = {};
                Object.assign(target, { p: req.body.payload });
                eval(target.p);
            }
        "#;
        assert_detected(&scan_ts(src), "18_object_assign_target", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Array filter element content preservation"]
    fn probe_19_array_filter() {
        let src = r#"
            export function test(req: any) {
                const arr = [req.body.payload].filter((x: any) => true);
                eval(arr[0]);
            }
        "#;
        assert_detected(&scan_ts(src), "19_array_filter", "eval");
    }

    #[test]
    fn probe_20_array_reduce() {
        let src = r#"
            export function test(req: any) {
                const val = [req.body.payload].reduce((acc: any, x: any) => x, "");
                eval(val);
            }
        "#;
        assert_detected(&scan_ts(src), "20_array_reduce", "eval");
    }

    #[test]
    #[ignore = "Blind spot: C strcpy destination buffer taint propagation"]
    fn probe_21_c_pointer_strcpy_sink() {
        let src = r#"
            #include <stdlib.h>
            #include <string.h>
            void test(void) {
                char *src = getenv("USER_INPUT");
                char dst[128];
                strcpy(dst, src);
                system(dst);
            }
        "#;
        assert_detected(&scan_c(src), "21_c_pointer_strcpy_sink", "system");
    }

    #[test]
    fn probe_22_c_struct_field_flow() {
        let src = r#"
            #include <stdlib.h>
            struct Request {
                char *payload;
            };
            void test(void) {
                struct Request req;
                req.payload = getenv("CMD");
                system(req.payload);
            }
        "#;
        assert_detected(&scan_c(src), "22_c_struct_field_flow", "system");
    }

    #[test]
    #[ignore = "Blind spot: Python kwargs unpack lowering"]
    fn probe_23_python_kwargs_unpack() {
        let src = r#"
def sink(cmd=None):
    eval(cmd)

def test(request):
    d = {"cmd": request.GET['c']}
    sink(**d)
        "#;
        assert_detected(&scan_py(src), "23_python_kwargs_unpack", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Python generator yield summary"]
    fn probe_24_python_generator_yield() {
        let src = r#"
def gen(p):
    yield p

def test(request):
    for val in gen(request.GET['c']):
        eval(val)
        "#;
        assert_detected(&scan_py(src), "24_python_generator_yield", "eval");
    }

    #[test]
    fn probe_25_try_catch_finally_flow() {
        let src = r#"
            export function test(req: any) {
                let x = "safe";
                try {
                    x = req.body.payload;
                    throw new Error("fail");
                } catch (e: any) {
                    eval(x);
                }
            }
        "#;
        assert_detected(&scan_ts(src), "25_try_catch_finally_flow", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Set collection forward heap modeling"]
    fn probe_26_set_collection_flow() {
        let src = r#"
            export function test(req: any) {
                const s = new Set<string>();
                s.add(req.body.payload);
                for (const item of s) {
                    eval(item);
                }
            }
        "#;
        assert_detected(&scan_ts(src), "26_set_collection_flow", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Map collection key-value association"]
    fn probe_27_map_collection_flow() {
        let src = r#"
            export function test(req: any) {
                const m = new Map<string, any>();
                m.set("key", req.body.payload);
                eval(m.get("key"));
            }
        "#;
        assert_detected(&scan_ts(src), "27_map_collection_flow", "eval");
    }

    #[test]
    fn probe_28_buffer_base64_decode() {
        let src = r#"
            export function test(req: any) {
                const b = Buffer.from(req.body.payload, "base64").toString("utf-8");
                eval(b);
            }
        "#;
        assert_detected(&scan_ts(src), "28_buffer_base64_decode", "eval");
    }

    #[test]
    fn probe_29_url_decode_propagator() {
        let src = r#"
            export function test(req: any) {
                const decoded = decodeURIComponent(req.body.payload);
                eval(decoded);
            }
        "#;
        assert_detected(&scan_ts(src), "29_url_decode_propagator", "eval");
    }

    #[test]
    fn probe_30_python_slice_flow() {
        let src = r#"
def test(request):
    p = request.GET['p']
    sliced = p[1:]
    eval(sliced)
        "#;
        assert_detected(&scan_py(src), "30_python_slice_flow", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Python dict merge unpack AST lowering"]
    fn probe_31_python_dict_merge_unpack() {
        let src = r#"
def test(request):
    base = {"cmd": request.GET['c']}
    merged = {**base, "mode": "fast"}
    eval(merged["cmd"])
        "#;
        assert_detected(&scan_py(src), "31_python_dict_merge_unpack", "eval");
    }

    #[test]
    #[ignore = "Blind spot: C snprintf format buffer taint propagation"]
    fn probe_32_c_snprintf_format_flow() {
        let src = r#"
            #include <stdio.h>
            #include <stdlib.h>
            void test(void) {
                char buf[256];
                snprintf(buf, sizeof(buf), "%s", getenv("CMD"));
                system(buf);
            }
        "#;
        assert_detected(&scan_c(src), "32_c_snprintf_format_flow", "system");
    }

    #[test]
    fn probe_33_numeric_sanitizer_clean() {
        let src = r#"
            export function test(req: any) {
                const safe = parseInt(req.body.payload, 10);
                eval(safe);
            }
        "#;
        assert_clean(&scan_ts(src), "33_numeric_sanitizer_clean");
    }

    #[test]
    fn probe_34_incomplete_replace_bypass() {
        let src = r#"
            export function test(req: any) {
                const bypassed = req.body.payload.replace("<script>", "");
                eval(bypassed);
            }
        "#;
        assert_detected(&scan_ts(src), "34_incomplete_replace_bypass", "eval");
    }
}

// ============================================================================
// Tier 2: Inter-Procedural Dataflow (Juliet Variants 51..68)
// ============================================================================
mod tier2_interprocedural_probes {
    use super::*;

    #[test]
    fn probe_51_passthrough_param_to_return() {
        let src = r#"
            function identity(x: any) {
                return x;
            }

            export function test(req: any) {
                const val = identity(req.body.payload);
                eval(val);
            }
        "#;
        assert_detected(&scan_ts(src), "51_passthrough_param_to_return", "eval");
    }

    #[test]
    fn probe_52_deep_call_chain_3hop() {
        let src = r#"
            function step1(a: any) { return step2(a); }
            function step2(b: any) { return step3(b); }
            function step3(c: any) { return c; }

            export function test(req: any) {
                const val = step1(req.body.payload);
                eval(val);
            }
        "#;
        assert_detected(&scan_ts(src), "52_deep_call_chain_3hop", "eval");
    }

    #[test]
    fn probe_53_multiple_call_sites_isolation() {
        let src = r#"
            function id(x: any) { return x; }

            export function safeSite() {
                const safe = id("safe string");
                eval(safe);
            }

            export function vulnerableSite(req: any) {
                const tainted = id(req.body.payload);
                eval(tainted);
            }
        "#;
        let res = scan_ts(src);
        assert_detected(&res, "53_vulnerable_site", "eval");
        let vulnerable: Vec<_> = res
            .located
            .iter()
            .filter(|l| l.finding.verdict == BackwardVerdict::Vulnerable)
            .collect();
        assert_eq!(
            vulnerable.len(),
            1,
            "safe site must not be contaminated by tainted summary: {:?}",
            vulnerable
        );
    }

    #[test]
    fn probe_54_sink_in_callee() {
        let src = r#"
            function executeCommand(cmd: any) {
                eval(cmd);
            }

            export function test(req: any) {
                executeCommand(req.body.payload);
            }
        "#;
        assert_detected(&scan_ts(src), "54_sink_in_callee", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Callback parameter formal argument closure binding"]
    fn probe_55_callback_parameter_dispatch() {
        let src = r#"
            function runWith(cb: (data: any) => void, val: any) {
                cb(val);
            }

            export function test(req: any) {
                runWith((data: any) => {
                    eval(data);
                }, req.body.payload);
            }
        "#;
        assert_detected(&scan_ts(src), "55_callback_parameter_dispatch", "eval");
    }

    #[test]
    fn probe_56_class_method_dispatch() {
        let src = r#"
            class CommandService {
                run(cmd: any) {
                    eval(cmd);
                }
            }

            export function test(req: any) {
                const s = new CommandService();
                s.run(req.body.payload);
            }
        "#;
        assert_detected(&scan_ts(src), "56_class_method_dispatch", "eval");
    }

    #[test]
    fn probe_57_return_object_field() {
        let src = r#"
            function wrap(val: any) {
                return { data: val };
            }

            export function test(req: any) {
                const w = wrap(req.body.payload);
                eval(w.data);
            }
        "#;
        assert_detected(&scan_ts(src), "57_return_object_field", "eval");
    }

    #[test]
    fn probe_58_callee_field_mutation() {
        let src = r#"
            function mutate(obj: any, val: any) {
                obj.secret = val;
            }

            export function test(req: any) {
                const container: any = {};
                mutate(container, req.body.payload);
                eval(container.secret);
            }
        "#;
        assert_detected(&scan_ts(src), "58_callee_field_mutation", "eval");
    }

    #[test]
    fn probe_59_rest_parameters() {
        let src = r#"
            function executeFirst(...args: any[]) {
                eval(args[0]);
            }

            export function test(req: any) {
                executeFirst(req.body.payload);
            }
        "#;
        assert_detected(&scan_ts(src), "59_rest_parameters", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Spread argument tuple lowering into formal parameters"]
    fn probe_60_spread_arguments() {
        let src = r#"
            function executeTarget(safe: string, cmd: any) {
                eval(cmd);
            }

            export function test(req: any) {
                const args = ["safe", req.body.payload];
                executeTarget(...args);
            }
        "#;
        assert_detected(&scan_ts(src), "60_spread_arguments", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Python interprocedural kwargs dictionary unpacking"]
    fn probe_61_python_kwargs_interprocedural() {
        let src = r#"
def execute_runner(**kwargs):
    eval(kwargs.get('cmd'))

def test(request):
    execute_runner(cmd=request.GET['c'])
        "#;
        assert_detected(&scan_py(src), "61_python_kwargs_interprocedural", "eval");
    }

    #[test]
    #[ignore = "Blind spot: C pointer out-parameter dereference write"]
    fn probe_62_c_pointer_outparam() {
        let src = r#"
            #include <stdlib.h>
            void get_command(char **out) {
                *out = getenv("CMD");
            }
            void test(void) {
                char *cmd = NULL;
                get_command(&cmd);
                system(cmd);
            }
        "#;
        assert_detected(&scan_c(src), "62_c_pointer_outparam", "system");
    }

    #[test]
    fn probe_63_currying_closure_factory() {
        let src = r#"
            function makeRunner(cmd: any) {
                return () => {
                    eval(cmd);
                };
            }

            export function test(req: any) {
                const run = makeRunner(req.body.payload);
                run();
            }
        "#;
        assert_detected(&scan_ts(src), "63_currying_closure_factory", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Fluent method chaining receiver identity"]
    fn probe_64_method_chaining_fluent() {
        let src = r#"
            class QueryBuilder {
                private cmd: any;
                setCommand(c: any) {
                    this.cmd = c;
                    return this;
                }
                build() {
                    return this.cmd;
                }
            }

            export function test(req: any) {
                const qb = new QueryBuilder();
                const res = qb.setCommand(req.body.payload).build();
                eval(res);
            }
        "#;
        assert_detected(&scan_ts(src), "64_method_chaining_fluent", "eval");
    }

    #[test]
    fn probe_65_getter_property_dispatch() {
        let src = r#"
            class PayloadHolder {
                private val: any;
                constructor(val: any) {
                    this.val = val;
                }
                get value() {
                    return this.val;
                }
            }

            export function test(req: any) {
                const h = new PayloadHolder(req.body.payload);
                eval(h.value);
            }
        "#;
        assert_detected(&scan_ts(src), "65_getter_property_dispatch", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Function prototype call and apply dispatch"]
    fn probe_66_call_apply_dispatch() {
        let src = r#"
            function runner(this: any, arg: any) {
                eval(arg);
            }

            export function test(req: any) {
                runner.call(null, req.body.payload);
            }
        "#;
        assert_detected(&scan_ts(src), "66_call_apply_dispatch", "eval");
    }

    #[test]
    fn probe_67_polymorphic_super_call() {
        let src = r#"
            class BaseRunner {
                execute(x: any) {
                    eval(x);
                }
            }

            class SubRunner extends BaseRunner {
                execute(x: any) {
                    super.execute(x);
                }
            }

            export function test(req: any) {
                const r = new SubRunner();
                r.execute(req.body.payload);
            }
        "#;
        assert_detected(&scan_ts(src), "67_polymorphic_super_call", "eval");
    }

    #[test]
    fn probe_68_mutual_recursion() {
        let src = r#"
            function ping(n: number, data: any) {
                if (n <= 0) {
                    eval(data);
                    return;
                }
                pong(n - 1, data);
            }

            function pong(n: number, data: any) {
                ping(n - 1, data);
            }

            export function test(req: any) {
                ping(2, req.body.payload);
            }
        "#;
        assert_detected(&scan_ts(src), "68_mutual_recursion", "eval");
    }
}

// ============================================================================
// Tier 3: Cross-File & Module Boundaries (Juliet Variants 71..78)
// ============================================================================
mod tier3_cross_file_probes {
    use super::*;

    #[test]
    fn probe_71_named_import_export() {
        let file_a = r#"
            export function sinkHelper(x: any) {
                eval(x);
            }
        "#;
        let file_b = r#"
            import { sinkHelper } from "./sink_module";

            export function handler(req: any) {
                sinkHelper(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/sink_module.ts", file_a, "ts"),
            ("app/handler.ts", file_b, "ts"),
        ]);
        assert_detected(&res, "71_named_import_export", "eval");
    }

    #[test]
    fn probe_72_default_import_export() {
        let file_a = r#"
            export default function sinkHelper(x: any) {
                eval(x);
            }
        "#;
        let file_b = r#"
            import sinkHelper from "./sink_default";

            export function handler(req: any) {
                sinkHelper(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/sink_default.ts", file_a, "ts"),
            ("app/handler.ts", file_b, "ts"),
        ]);
        assert_detected(&res, "72_default_import_export", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Import alias renaming callgraph linkage"]
    fn probe_73_import_alias_rename() {
        let file_a = r#"
            export function rawSink(x: any) {
                eval(x);
            }
        "#;
        let file_b = r#"
            import { rawSink as sanitizedLookingCall } from "./sink_raw";

            export function handler(req: any) {
                sanitizedLookingCall(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/sink_raw.ts", file_a, "ts"),
            ("app/handler.ts", file_b, "ts"),
        ]);
        assert_detected(&res, "73_import_alias_rename", "eval");
    }

    #[test]
    fn probe_74_namespace_import() {
        let file_a = r#"
            export function execute(x: any) {
                eval(x);
            }
        "#;
        let file_b = r#"
            import * as executor from "./executor_mod";

            export function handler(req: any) {
                executor.execute(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/executor_mod.ts", file_a, "ts"),
            ("app/handler.ts", file_b, "ts"),
        ]);
        assert_detected(&res, "74_namespace_import", "eval");
    }

    #[test]
    fn probe_75_reexport_passthrough() {
        let file_a = r#"
            export function innerSink(x: any) {
                eval(x);
            }
        "#;
        let file_b = r#"
            export { innerSink } from "./inner";
        "#;
        let file_c = r#"
            import { innerSink } from "./gateway";

            export function handler(req: any) {
                innerSink(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/inner.ts", file_a, "ts"),
            ("app/gateway.ts", file_b, "ts"),
            ("app/entry.ts", file_c, "ts"),
        ]);
        assert_detected(&res, "75_reexport_passthrough", "eval");
    }

    #[test]
    fn probe_76_cross_file_3hop_chain() {
        let file_sink = r#"
            export function doSink(cmd: any) {
                eval(cmd);
            }
        "#;
        let file_transform = r#"
            import { doSink } from "./service_sink";

            export function passThrough(data: any) {
                doSink(data);
            }
        "#;
        let file_source = r#"
            import { passThrough } from "./service_transform";

            export function entry(req: any) {
                passThrough(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/service_sink.ts", file_sink, "ts"),
            ("app/service_transform.ts", file_transform, "ts"),
            ("app/service_entry.ts", file_source, "ts"),
        ]);
        assert_detected(&res, "76_cross_file_3hop_chain", "eval");
    }

    #[test]
    fn probe_77_cross_file_commonjs() {
        let file_a = r#"
            function run(cmd) {
                eval(cmd);
            }
            module.exports = { run: run };
        "#;
        let file_b = r#"
            const mod = require('./mod_a');

            function handle(req) {
                mod.run(req.body.payload);
            }
            module.exports = { handle: handle };
        "#;
        let res = scan_files(&[
            ("app/mod_a.js", file_a, "js"),
            ("app/mod_b.js", file_b, "js"),
        ]);
        assert_detected(&res, "77_cross_file_commonjs", "eval");
    }

    #[test]
    fn probe_78_python_cross_module() {
        let file_utils = r#"
import os

def execute_helper(cmd):
    eval(cmd)
        "#;
        let file_views = r#"
from .utils import execute_helper

def view_handler(request):
    execute_helper(request.GET['c'])
        "#;
        let res = scan_files(&[
            ("app/utils.py", file_utils, "py"),
            ("app/views.py", file_views, "py"),
        ]);
        assert_detected(&res, "78_python_cross_module", "eval");
    }

    #[test]
    fn probe_79_cross_file_class_inheritance() {
        let file_a = r#"
            export class BaseService {
                run(cmd: any) {
                    eval(cmd);
                }
            }
        "#;
        let file_b = r#"
            import { BaseService } from "./base_service";

            export class DerivedService extends BaseService {}

            export function handler(req: any) {
                const s = new DerivedService();
                s.run(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/base_service.ts", file_a, "ts"),
            ("app/derived_service.ts", file_b, "ts"),
        ]);
        assert_detected(&res, "79_cross_file_class_inheritance", "eval");
    }

    #[test]
    fn probe_80_circular_module_dependency() {
        let file_a = r#"
            import { helperB } from "./cycle_b";

            export function doSink(cmd: any) {
                eval(cmd);
            }

            export function entry(req: any) {
                helperB(req.body.payload);
            }
        "#;
        let file_b = r#"
            import { doSink } from "./cycle_a";

            export function helperB(data: any) {
                doSink(data);
            }
        "#;
        let res = scan_files(&[
            ("app/cycle_a.ts", file_a, "ts"),
            ("app/cycle_b.ts", file_b, "ts"),
        ]);
        assert_detected(&res, "80_circular_module_dependency", "eval");
    }

    #[test]
    fn probe_81_cross_file_barrel_export() {
        let file_sink = r#"
            export function execute(cmd: any) {
                eval(cmd);
            }
        "#;
        let file_index = r#"
            export * from "./sink";
        "#;
        let file_entry = r#"
            import { execute } from "./index";

            export function test(req: any) {
                execute(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/sink.ts", file_sink, "ts"),
            ("app/index.ts", file_index, "ts"),
            ("app/entry.ts", file_entry, "ts"),
        ]);
        assert_detected(&res, "81_cross_file_barrel_export", "eval");
    }

    #[test]
    #[ignore = "Blind spot: Cross-file re-export with alias linkage"]
    fn probe_82_cross_file_reexport_with_alias() {
        let file_raw = r#"
            export function coreSink(p: any) {
                eval(p);
            }
        "#;
        let file_bridge = r#"
            export { coreSink as aliasedSink } from "./raw";
        "#;
        let file_consumer = r#"
            import { aliasedSink } from "./bridge";

            export function test(req: any) {
                aliasedSink(req.body.payload);
            }
        "#;
        let res = scan_files(&[
            ("app/raw.ts", file_raw, "ts"),
            ("app/bridge.ts", file_bridge, "ts"),
            ("app/consumer.ts", file_consumer, "ts"),
        ]);
        assert_detected(&res, "82_cross_file_reexport_with_alias", "eval");
    }

    #[test]
    fn probe_83_cross_file_3hop_diamond() {
        let file_sink = r#"
            export function doRun(x: any) {
                eval(x);
            }
        "#;
        let file_branch_a = r#"
            import { doRun } from "./sink";
            export function stepA(x: any) {
                doRun(x);
            }
        "#;
        let file_branch_b = r#"
            import { doRun } from "./sink";
            export function stepB(x: any) {
                doRun(x);
            }
        "#;
        let file_entry = r#"
            import { stepA } from "./branch_a";
            import { stepB } from "./branch_b";

            export function test(req: any, flag: boolean) {
                if (flag) {
                    stepA(req.body.payload);
                } else {
                    stepB("safe");
                }
            }
        "#;
        let res = scan_files(&[
            ("app/sink.ts", file_sink, "ts"),
            ("app/branch_a.ts", file_branch_a, "ts"),
            ("app/branch_b.ts", file_branch_b, "ts"),
            ("app/entry.ts", file_entry, "ts"),
        ]);
        assert_detected(&res, "83_cross_file_3hop_diamond", "eval");
    }
}
