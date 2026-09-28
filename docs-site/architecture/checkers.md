# Checkers

Checkers are queries over the program graph. The current set:

| Checker | What it reports |
| --- | --- |
| Taint reachability | Source-to-sink flows for XSS, SQLi, command injection, SSRF, path traversal, IDOR. |
| Session-trust / guard bypass | Authentication guards that a flow escapes. |
| Use-after-free / double-free | Dangling use or repeated deallocation, including through wrapper functions (interprocedural allocation summaries). |
| Out-of-bounds | Indexed accesses that escape every bounding guard, judged against the value lattice. |
| Policy | Program-level rules: required calls (e.g. an authorization helper) and forbidden calls, at function or module scope. |
| Learned checks | Facts learned from the corpus: sources, sinks, sanitisers, policies, merged from `.frc` bundles. |

## Learned facts

Bundles can contribute five kinds of facts: **Source**, **Sink**,
**Sanitizer**, **Policy**, and **Check**. Learned `unless_range_check`
requirements are satisfied by guards the value lattice proves, not by the
mere textual presence of a call.
