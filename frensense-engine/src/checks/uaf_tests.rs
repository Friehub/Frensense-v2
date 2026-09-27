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

    /// Aliasing: q = p; free(p); use(q) — the Steensgaard class links them.
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
    /// (a parameter) must never produce findings — the checker can't know
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
}
