#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2024-2026 Friehub. All rights reserved.
# Commercial use requires a separate license: https://friehub.com/licensing
"""Emit a generated-parser-shaped JS file with N sequential if branches.

Usage:
    python3 repros/n10_perf/gen.py N > /tmp/seq.js
    frensense /tmp/seq.js

Real generated parsers/validators (parsers generated from a grammar, or
long schema validators) contain hundreds of sequential branches like these.
Measured before the per-function budget: N=100 0.13 s, N=200 0.9 s,
N=400 6.8 s (~n^3), N=3000 never finished inside 60 s.
"""
import sys


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    out = sys.stdout
    out.write("function handle(req) {\n")
    out.write("  const s = req.body;\n")
    out.write("  let out = '';\n")
    for k in range(n):
        # One sequential branch per accepted token: the shape a generator
        # emits for `token | token | token | ...` decisions.
        out.write(f"  if (s.charCodeAt({k}) === {k % 256}) {{ out = out + s[{k}]; }}\n")
    out.write("  sink(out);\n")
    out.write("}\n")


if __name__ == "__main__":
    main()
