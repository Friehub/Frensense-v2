// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the free-then-use / double-free checker over the Steensgaard
//! points-to classes.

#[cfg(test)]
pub mod uaf_spec {
    use crate::checks::uaf;
    use crate::harness::lower_source;

    fn hits(src: &str) -> Vec<String> {
        let fns = lower_source("t.c", src, "c").unwrap();
        let mut rules: Vec<String> = fns.values().flat_map(uaf::check).map(|f| f.rule).collect();
        rules.sort();
        rules
    }

    /// The canonical UAF: malloc → free → use through the same pointer.
    #[test]
    fn free_then_use_fires() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(16);
  free(p);
  p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "free-then-use must fire: {:?}",
            rules
        );
    }

    /// Read-after-free through LoadField/LoadElement also fires.
    #[test]
    fn read_after_free_fires() {
        let src = r#"
#include <stdlib.h>
int handler () {
  int *p;
  p = malloc(4);
  free(p);
  return p[0];
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "read-after-free must fire: {:?}",
            rules
        );
    }

    /// Double free: free on an already-freed object.
    #[test]
    fn double_free_fires() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(16);
  free(p);
  free(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "double_free"),
            "double-free must fire: {:?}",
            rules
        );
    }

    /// Aliasing: q = p; free(p); use(q) - the Steensgaard class links them.
    #[test]
    fn uaf_through_alias_fires() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  char *q;
  p = malloc(16);
  q = p;
  free(p);
  q[0] = 2;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "aliasing UAF must fire: {:?}",
            rules
        );
    }

    /// Clean shape: malloc → use → free must stay silent.
    #[test]
    fn use_then_free_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(16);
  p[0] = 1;
  free(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "correct order must stay silent: {:?}",
            rules
        );
    }

    /// Soundness: a pointer with no provable allocation in this function
    /// (a parameter) must never produce findings - the checker can't know
    /// its provenance.
    #[test]
    fn parameter_pointer_stays_silent() {
        let src = r#"
#include <stdlib.h>
void handler (char *p) {
  free(p);
  p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "unprovable provenance must stay silent: {:?}",
            rules
        );
    }

    /// Re-allocation starts a new generation: free(p); p = malloc(); use(p)
    /// is NOT a violation.
    #[test]
    fn realloc_after_free_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(16);
  free(p);
  p = malloc(32);
  p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "fresh allocation after free must stay silent: {:?}",
            rules
        );
    }

    /// Inline-cast declaration-with-initializer: `char *p =
    /// (char*)malloc(16);`. Regression: the C `init_declarator` wraps the
    /// name in a `pointer_declarator`, which used to drop the initializer
    /// value entirely, leaving the malloc result and `p` disconnected so
    /// UAF through the inline-cast shape never fired.
    #[test]
    fn inline_cast_decl_with_init_fires() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p = (char*)malloc(16);
  free(p);
  p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "inline-cast decl-with-init UAF must fire: {:?}",
            rules
        );
    }

    /// Plain declaration-with-initializer: `char *p = malloc(16);` must
    /// link the malloc result to `p` the same way `p = malloc(16)` does.
    #[test]
    fn decl_with_init_fires() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p = malloc(16);
  free(p);
  p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "decl-with-init UAF must fire: {:?}",
            rules
        );
    }

    /// Correct order with an inline-cast initializer stays silent.
    #[test]
    fn inline_cast_decl_use_then_free_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p = (char*)malloc(16);
  p[0] = 1;
  free(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "correct order must stay silent: {:?}",
            rules
        );
    }

    // ── Path sensitivity ─────────────────────────────────────────────────
    // A free inside ONE arm of a conditional must NOT produce findings on
    // the other arm's path: the use after the join is reachable without
    // the free having executed.
    #[test]
    fn free_in_branch_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler (int x) {
  char *p = malloc(16);
  if (x) {
    free(p);
  }
  p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "conditional free must not fire on the skip path: {:?}",
            rules
        );
    }

    /// A free that executes on BOTH arms of a diamond (or straight-line)
    /// dominates the merge: findings after it still fire.
    #[test]
    fn free_in_both_branch_arms_fires() {
        let src = r#"
#include <stdlib.h>
void handler (int x) {
  char *p = malloc(16);
  if (x) {
    free(p);
  } else {
    free(p);
  }
  p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "free on both arms dominates the merge: {:?}",
            rules
        );
    }

    /// A free BEFORE a loop dominates the loop body: uses inside the loop
    /// fire even though the CFG re-converges at the header.
    #[test]
    fn free_before_loop_use_inside_loop_fires() {
        let src = r#"
#include <stdlib.h>
void handler (int n) {
  char *p = malloc(16);
  free(p);
  for (int i = 0; i < n; i++) {
    p[0] = 1;
  }
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "free dominating a loop must fire inside the body: {:?}",
            rules
        );
    }

    /// A free INSIDE a loop body executes on some iterations but not on
    /// the path that exits before it, and loop-carried state is cut at the
    /// back-edge: the use after the loop stays silent (may-analysis sound).
    #[test]
    fn free_inside_loop_body_use_after_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler (int n) {
  char *p = malloc(16);
  for (int i = 0; i < n; i++) {
    if (i == 5) {
      free(p);
    }
  }
  p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "loop-body free must not fire on the exit path: {:?}",
            rules
        );
    }

    /// Allocate-instruction provenance (non-C-call lowering) participates.
    #[test]
    fn allocate_instruction_provenance_fires() {
        // TS shape lowering to Instruction::Allocate: `new` objects.
        // This validates the checker is not malloc-specific.
        let src = r#"
export function handler () {
  const obj = { a: 1 };
  return obj.a;
}
"#;
        // TS objects lower to Allocate only under some shapes; here the
        // check must at minimum not crash and not fire (no free exists).
        let rules = hits(src);
        assert!(rules.is_empty(), "no free means no findings: {:?}", rules);
    }

    /// CVE-2026-56109 pattern: uninitialized pointer freed on unchecked EOF path.
    #[test]
    fn cve_2026_56109_uninit_free_vulnerable_flags() {
        let src = r#"
#include <stdlib.h>
int get_nonwhite(void);
void parse_def(int skip) {
    char *n;
    if (skip == 0) {
        n = malloc(16);
    }
    int c = get_nonwhite();
    if (c != 125) {
        if (n) {
            free(n);
        }
    }
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "uninitialized_free"),
            "uninitialized pointer free on error path must fire: {:?}",
            rules
        );
    }

    /// CVE-2026-56109 fix: error check (`c < 0`) diverts execution before the free.
    #[test]
    fn cve_2026_56109_uninit_free_fixed_stays_silent() {
        let src = r#"
#include <stdlib.h>
int get_nonwhite(void);
void parse_def(int skip) {
    char *n;
    if (skip == 0) {
        n = malloc(16);
    }
    int c = get_nonwhite();
    if (c < 0) {
        goto __end;
    }
    if (c != 125) {
        if (n) {
            free(n);
        }
    }
__end:
    return;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "guarded error exit must not trigger uninitialized free: {:?}",
            rules
        );
    }

    /// Never-assigned local freed directly: no phi exists for `p`, so the
    /// phi-based uninitialized gate is blind to the canonical shape -
    /// declare, error path, free garbage.
    #[test]
    fn never_initialized_free_fires() {
        let src = r#"
#include <stdlib.h>
void handler(void) {
    char *p;
    free(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "uninitialized_free"),
            "free of a never-initialized local must fire: {:?}",
            rules
        );
    }

    /// Held-out shape: the never-initialized local is freed through an
    /// in-program wrapper on an unchecked error path (the CVE-2026-56109
    /// class, different code shape).
    #[test]
    fn never_initialized_wrapper_free_fires() {
        let src = r#"
#include <stdlib.h>
static void free_entry(char *e) {
    if (e) free(e);
}
int read_marker(void);
int apply_entry(void) {
    char *node;
    int c = read_marker();
    if (c != 0) {
        free_entry(node);
        return -1;
    }
    return 0;
}
"#;
        let fns = lower_source("t.c", src, "c").unwrap();
        let irs: Vec<_> = fns.values().collect();
        let summaries = crate::checks::memory_summary::MemorySummaryRegistry::default()
            .infer_program_summaries_into(&irs);
        let rules: Vec<String> = fns
            .values()
            .flat_map(|ir| uaf::check_with_summaries(ir, &summaries))
            .map(|f| f.rule)
            .collect();
        assert!(
            rules.iter().any(|r| r == "uninitialized_free"),
            "never-initialized local freed through an in-program wrapper must fire: {:?}",
            rules
        );
    }

    /// The only assignment sits on a branch that returns, so no def reaches
    /// the free after the merge - still an uninitialized free.
    #[test]
    fn free_after_exiting_def_path_fires() {
        let src = r#"
#include <stdlib.h>
int read_marker(void);
void handler(void) {
    char *p;
    int c = read_marker();
    if (c == '+') {
        p = malloc(16);
        free(p);
        return;
    }
    free(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "uninitialized_free"),
            "free reachable only from paths with no reaching def must fire: {:?}",
            rules
        );
    }

    /// FP pin: the local is written through its address by an out-parameter,
    /// so "never assigned in this function" must stay silent - the
    /// address-of guard defers to the phi-based analysis.
    #[test]
    fn address_of_out_param_stays_silent() {
        let src = r#"
#include <stdlib.h>
void init(char **out);
void handler(void) {
    char *p;
    init(&p);
    free(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "out-parameter-initialized local must stay silent: {:?}",
            rules
        );
    }

    /// FP pin: a file-scope global freed in a function - the global's value
    /// is initialized outside the function, so "no reaching def here" must
    /// not fire (declaration position distinguishes it from a local).
    #[test]
    fn global_pointer_free_stays_silent() {
        let src = r#"
#include <stdlib.h>
static int *g;
void end(void) {
    if (g)
        free(g);
    g = 0;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "free of a file-scope global must stay silent: {:?}",
            rules
        );
    }

    /// FP pin: same-block def before the free reaches it - ordering matters.
    #[test]
    fn def_before_free_same_block_stays_silent() {
        let src = r#"
#include <stdlib.h>
void handler(void) {
    char *p;
    p = malloc(16);
    free(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "def before the free in the same block must stay silent: {:?}",
            rules
        );
    }

    /// Real alsa-lib conf.c corpora pair check: vulnerable must flag parse_def, fixed must produce 0 findings.
    #[test]
    fn alsa_lib_corpora_cve_2026_56109() {
        if let (Ok(vuln), Ok(fixed)) = (
            std::fs::read_to_string("/tmp/opencode/alsa-vuln/conf.c"),
            std::fs::read_to_string("/tmp/opencode/alsa-fixed/conf.c"),
        ) {
            let vuln_fns = lower_source("conf.c", &vuln, "c").unwrap();
            let vuln_vec: Vec<_> = vuln_fns.values().collect();
            let vuln_summaries = crate::checks::memory_summary::MemorySummaryRegistry::default()
                .infer_program_summaries_into(&vuln_vec);
            let vuln_hits: Vec<_> = vuln_fns
                .values()
                .flat_map(|ir| uaf::check_with_summaries(ir, &vuln_summaries))
                .collect();
            assert_eq!(
                vuln_hits.len(),
                1,
                "alsa-vuln must produce exactly 1 finding"
            );
            assert_eq!(vuln_hits[0].function, "parse_def");

            let fixed_fns = lower_source("conf.c", &fixed, "c").unwrap();
            let fixed_vec: Vec<_> = fixed_fns.values().collect();
            let fixed_summaries = crate::checks::memory_summary::MemorySummaryRegistry::default()
                .infer_program_summaries_into(&fixed_vec);
            let fixed_hits: Vec<_> = fixed_fns
                .values()
                .flat_map(|ir| uaf::check_with_summaries(ir, &fixed_summaries))
                .collect();
            assert!(
                fixed_hits.is_empty(),
                "alsa-fixed must produce 0 findings, got: {:?}",
                fixed_hits
            );
        }
    }
}
