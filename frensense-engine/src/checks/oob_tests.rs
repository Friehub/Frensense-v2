// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the spatial memory safety checker (buffer overflow, out-of-bounds read/write).

#[cfg(test)]
pub mod oob_spec {
    use crate::checks::oob;
    use crate::harness::lower_source;

    fn hits(src: &str) -> Vec<String> {
        let fns = lower_source("t.c", src, "c").unwrap();
        let mut rules: Vec<String> = fns.values().flat_map(oob::check).map(|f| f.rule).collect();
        rules.sort();
        rules
    }

    /// Constant index out-of-bounds write.
    #[test]
    fn constant_oob_write_fires() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(10);
  p[10] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "buffer_overflow"),
            "index 10 on malloc(10) must fire buffer_overflow: {:?}",
            rules
        );
    }

    /// Constant index out-of-bounds read.
    #[test]
    fn constant_oob_read_fires() {
        let src = r#"
#include <stdlib.h>
int handler () {
  int *p;
  p = malloc(10);
  return p[15];
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "out_of_bounds_read"),
            "index 15 on malloc(10) must fire out_of_bounds_read: {:?}",
            rules
        );
    }

    /// Negative index access.
    #[test]
    fn negative_index_access_fires() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(10);
  p[-1] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "out_of_bounds_access"),
            "negative index must fire out_of_bounds_access: {:?}",
            rules
        );
    }

    /// Provably safe access bounded by capacity stays silent.
    #[test]
    fn safe_access_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(10);
  p[0] = 1;
  p[9] = 2;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "valid in-bounds access must stay silent: {:?}",
            rules
        );
    }

    /// Branch-guarded safe access stays silent.
    #[test]
    fn guarded_safe_access_is_silent() {
        let src = r#"
#include <stdlib.h>
void handler (int idx) {
  char *p;
  p = malloc(10);
  if (idx >= 0 && idx < 10) {
    p[idx] = 1;
  }
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "strictly guarded access idx < 10 must stay silent: {:?}",
            rules
        );
    }

    /// Off-by-one branch guard (idx <= 10) triggers buffer overflow.
    #[test]
    fn off_by_one_guard_fires() {
        let src = r#"
#include <stdlib.h>
void handler (int idx) {
  char *p;
  p = malloc(10);
  if (idx >= 0 && idx <= 10) {
    p[idx] = 1;
  }
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "buffer_overflow"),
            "off-by-one guard idx <= 10 on malloc(10) must fire: {:?}",
            rules
        );
    }

    /// Aliasing: q = p, q[20] = 1 on malloc(16) fires via points-to class.
    #[test]
    fn oob_through_alias_fires() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  char *q;
  p = malloc(16);
  q = p;
  q[20] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "buffer_overflow"),
            "aliased pointer OOB write must fire: {:?}",
            rules
        );
    }

    /// memset with write size > buffer capacity fires buffer overflow.
    #[test]
    fn memset_overflow_fires() {
        let src = r#"
#include <stdlib.h>
#include <string.h>
void handler () {
  char *p;
  p = malloc(16);
  memset(p, 0, 32);
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "buffer_overflow"),
            "memset size 32 on malloc(16) must fire: {:?}",
            rules
        );
    }

    /// memcpy with copy size > source buffer capacity fires out-of-bounds read.
    #[test]
    fn memcpy_oob_read_fires() {
        let src = r#"
#include <stdlib.h>
#include <string.h>
void handler () {
  char *src;
  char *dst;
  src = malloc(8);
  dst = malloc(32);
  memcpy(dst, src, 16);
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "out_of_bounds_read"),
            "memcpy size 16 on src malloc(8) must fire out_of_bounds_read: {:?}",
            rules
        );
    }

    /// calloc calculates capacity as count * size.
    #[test]
    fn calloc_capacity_checked() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = calloc(5, 4);
  p[20] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "buffer_overflow"),
            "index 20 on calloc(5, 4) [capacity 20] must fire: {:?}",
            rules
        );
    }

    /// Re-allocation / fresh allocation updates capacity and avoids false positives.
    #[test]
    fn realloc_fresh_generation_tracks_new_capacity() {
        let src = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(10);
  p = realloc(p, 50);
  p[20] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "p[20] after realloc(p, 50) must be safe and stay silent: {:?}",
            rules
        );

        let src_overflow = r#"
#include <stdlib.h>
void handler () {
  char *p;
  p = malloc(10);
  p = realloc(p, 50);
  p[60] = 1;
}
"#;
        let rules_overflow = hits(src_overflow);
        assert!(
            rules_overflow.iter().any(|r| r == "buffer_overflow"),
            "p[60] after realloc(p, 50) must fire buffer_overflow: {:?}",
            rules_overflow
        );
    }

    /// Unknown / parameter pointer stays silent (zero FP on unprovable provenance).
    #[test]
    fn unprovable_parameter_pointer_stays_silent() {
        let src = r#"
void handler (char *p, int idx) {
  p[idx] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "unprovable parameter pointer must stay silent: {:?}",
            rules
        );
    }
}
