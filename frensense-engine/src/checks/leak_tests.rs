// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the CWE-401 allocation-lifetime (leak) checker.

#[cfg(test)]
pub mod leak_spec {
    use crate::checks::leak;
    use crate::checks::memory_summary::MemorySummaryRegistry;
    use crate::harness::lower_source;

    fn rules(src: &str) -> Vec<String> {
        let spec = frensense_lang::spec_for_ext("c").expect("c spec");
        let facts = crate::analysis::taint::facts::fact_table_from_spec(spec);
        let summaries = MemorySummaryRegistry::from_facts(&facts);
        let fns = lower_source("t.c", src, "c").unwrap();
        let mut out: Vec<String> = fns
            .values()
            .flat_map(|ir| leak::check(ir, &summaries, &facts))
            .map(|f| f.rule)
            .collect();
        out.sort();
        out
    }

    /// Phase 4 teachability: a hand-built bundle drives the leak checker.
    /// `talloc` is invisible to the spec-only table (no allocation, no
    /// finding); the bundle's `custom_allocators` makes it a leak
    /// candidate; teaching it as a stack allocator suppresses it again.
    #[test]
    fn bundle_teaches_allocation_and_suppression() {
        let src = r#"
void handler(void)
{
    char *p = talloc(64);
    (void)p;
}
"#;
        let spec = frensense_lang::spec_for_ext("c").expect("c spec");
        let mut facts = crate::analysis::taint::facts::fact_table_from_spec(spec);
        let fns = crate::harness::lower_source("t.c", src, "c").unwrap();
        let leak_fires = |facts: &crate::analysis::taint::facts::FactTable| -> bool {
            let summaries = MemorySummaryRegistry::from_facts(facts);
            fns.values()
                .flat_map(|ir| leak::check(ir, &summaries, facts))
                .any(|f| f.rule == "memory_leak")
        };
        assert!(
            !leak_fires(&facts),
            "unknown callee must not allocate: bundle not applied yet"
        );
        facts.custom_allocators.insert("talloc".to_string());
        assert!(leak_fires(&facts), "bundle allocator must teach a leak");
        facts.stack_allocators.push("talloc".to_string());
        assert!(
            !leak_fires(&facts),
            "bundle stack allocator must suppress the leak"
        );
    }

    /// The corpus training shape: failure path releases, success path
    /// returns with the allocation still frame-owned.
    #[test]
    fn success_path_leak_fires() {
        let src = r#"
int read_path(const char *path, char *buf, int len);
int printf(const char *fmt, ...);
int process_request(const char *path)
{
    char *scratch = malloc(8192);
    if (scratch == NULL)
        return -1;
    if (read_path(path, scratch, 8192) < 0) {
        free(scratch);
        return -1;
    }
    printf("%s\n", scratch);
    return 0;
}
"#;
        let r = rules(src);
        assert!(
            r.contains(&"memory_leak".to_string()),
            "expected leak: {:?}",
            r
        );
    }

    /// FIXED variant: every path out releases.
    #[test]
    fn released_on_all_paths_is_silent() {
        let src = r#"
int read_path(const char *path, char *buf, int len);
int printf(const char *fmt, ...);
int process_request(const char *path)
{
    char *scratch = malloc(8192);
    if (scratch == NULL)
        return -1;
    if (read_path(path, scratch, 8192) < 0) {
        free(scratch);
        return -1;
    }
    printf("%s\n", scratch);
    free(scratch);
    return 0;
}
"#;
        let r = rules(src);
        assert!(
            r.is_empty(),
            "released allocation must stay silent: {:?}",
            r
        );
    }

    /// The NULL-check early return is not a leak: a proven-null pointer
    /// is not a live allocation (and the real path releases).
    #[test]
    fn null_check_return_is_silent() {
        let src = r#"
void use(char *p);
void f(void)
{
    char *p = malloc(16);
    if (p == NULL)
        return;
    use(p);
    free(p);
}
"#;
        let r = rules(src);
        assert!(r.is_empty(), "NULL path must stay silent: {:?}", r);
    }

    /// Returning the pointer transfers ownership to the caller.
    #[test]
    fn returned_pointer_is_silent() {
        let src = r#"
char *make(void)
{
    char *p = malloc(16);
    if (p == NULL)
        return 0;
    return p;
}
"#;
        let r = rules(src);
        assert!(
            r.is_empty(),
            "returned allocation must stay silent: {:?}",
            r
        );
    }

    /// Storing into an object hands ownership to that object.
    #[test]
    fn stored_field_is_silent() {
        let src = r#"
struct blob { char *buf; };
void f(struct blob *b)
{
    char *p = malloc(16);
    b->buf = p;
}
"#;
        let r = rules(src);
        assert!(r.is_empty(), "stored allocation must stay silent: {:?}", r);
    }

    /// A derived handle (`&p->next`) passed to a callee hands off the
    /// object - the uaf corpus' `list_add_tail(&path->list, ...)` shape.
    #[test]
    fn derived_handle_argument_is_silent() {
        let src = r#"
struct node { struct node *next; };
void init_node(struct node *n);
void f(void)
{
    struct node *p = malloc(16);
    if (p == NULL)
        return;
    init_node(&p->next);
}
"#;
        let r = rules(src);
        assert!(r.is_empty(), "derived handoff must stay silent: {:?}", r);
    }

    /// A direct pointer argument keeps frame ownership (readers and I/O
    /// never retain), so an unreleased buffer passed to a read call still
    /// leaks.
    #[test]
    fn direct_argument_keeps_ownership_and_leaks() {
        let src = r#"
int read_path(const char *path, char *buf, int len);
void f(const char *path)
{
    char *p = malloc(64);
    if (p == NULL)
        return;
    if (read_path(path, p, 64) < 0) {
        free(p);
        return;
    }
}
"#;
        let r = rules(src);
        assert!(
            r.contains(&"memory_leak".to_string()),
            "expected leak: {:?}",
            r
        );
    }

    /// Rebinding a parameter to a fresh allocation leaks it: C passes
    /// pointers by value, so the caller never receives the new object and
    /// it is unreachable when the frame exits.
    #[test]
    fn parameter_rebind_leaks() {
        let src = r#"
void fill(char *slot)
{
    slot = malloc(32);
}
"#;
        let r = rules(src);
        assert!(
            r.contains(&"memory_leak".to_string()),
            "expected leak: {:?}",
            r
        );
    }

    /// calloc (lang-declared fresh, not consuming) leaks the same way.
    #[test]
    fn calloc_leak_fires() {
        let src = r#"
void f(void)
{
    void *p = calloc(4, 8);
    if (p == NULL)
        return;
}
"#;
        let r = rules(src);
        assert!(
            r.contains(&"memory_leak".to_string()),
            "expected leak: {:?}",
            r
        );
    }

    /// No allocation vocabulary hit (unsummarized call): nothing to track.
    #[test]
    fn unknown_result_is_not_tracked() {
        let src = r#"
char *read_more(int n);
void f(void)
{
    char *p = read_more(4);
    (void)p;
}
"#;
        let r = rules(src);
        assert!(
            r.is_empty(),
            "unsummarized result must stay untracked: {:?}",
            r
        );
    }

    /// A phi merge carries the allocation to the release: `free(p)`
    /// after the join must see the value the taken branch bound.
    #[test]
    fn free_through_phi_merge_is_silent() {
        let src = r#"
void f(int cond)
{
    char *p;
    if (cond) {
        p = malloc(16);
    } else {
        p = 0;
    }
    if (p == NULL)
        return;
    free(p);
}
"#;
        let r = rules(src);
        assert!(r.is_empty(), "phi-released allocation: {:?}", r);
    }

    /// The same shape without the release leaks through the phi.
    #[test]
    fn leak_through_phi_merge_fires() {
        let src = r#"
void use(char *p);
void f(int cond)
{
    char *p;
    if (cond) {
        p = malloc(16);
    } else {
        p = 0;
    }
    if (p == NULL)
        return;
    use(p);
}
"#;
        let r = rules(src);
        assert!(
            r.contains(&"memory_leak".to_string()),
            "expected leak: {:?}",
            r
        );
    }

    /// `while (1)` lowers its condition to a literal; the placeholder
    /// block behind the statically dead edge is unreachable code, not a
    /// function exit, so an allocation live across the loop must not be
    /// reported from there.
    #[test]
    fn while_true_dangling_exit_is_silent() {
        let src = r#"
void use(int x);
void f(void)
{
    char *p = malloc(8);
    while (1) {
        use(1);
    }
}
"#;
        let r = rules(src);
        assert!(r.is_empty(), "dead loop-exit edge must not report: {:?}", r);
    }

    /// A real `break` jumps to the loop-exit block with live state, so
    /// code after `while (1)` is analysed from the break, not the dead
    /// condition edge.
    #[test]
    fn leak_after_break_fires() {
        let src = r#"
void f(void)
{
    char *p = malloc(8);
    while (1) {
        break;
    }
}
"#;
        let r = rules(src);
        assert!(
            r.contains(&"memory_leak".to_string()),
            "expected leak after break: {:?}",
            r
        );
    }

    /// ... and a release after the break covers it.
    #[test]
    fn released_after_break_is_silent() {
        let src = r#"
void f(void)
{
    char *p = malloc(8);
    while (1) {
        break;
    }
    free(p);
}
"#;
        let r = rules(src);
        assert!(r.is_empty(), "released after break: {:?}", r);
    }

    /// Stack storage is not leakable: the lang-declared stack-allocator
    /// vocabulary excludes `alloca` from the candidate set.
    #[test]
    fn alloca_is_never_tracked() {
        let src = r#"
void f(void)
{
    char *p = alloca(64);
    (void)p;
}
"#;
        let r = rules(src);
        assert!(r.is_empty(), "alloca must stay untracked: {:?}", r);
    }

    /// Pointer-identity guard (`p != buf` taken false) proves `p` holds
    /// the stack buffer on that edge: the heap object cannot live there.
    #[test]
    fn identity_guarded_free_is_silent() {
        let src = r#"
void f(void)
{
    char buf[16];
    char *p = malloc(8);
    if (p != buf)
        free(p);
}
"#;
        let r = rules(src);
        assert!(r.is_empty(), "identity-guarded free: {:?}", r);
    }

    /// Two variables bound to the *same* allocation join through the
    /// identity guard intact: the unequal path releases, the equal path
    /// still owns it.
    #[test]
    fn identity_alias_join_still_leaks() {
        let src = r#"
void f(void)
{
    char *p = malloc(8);
    char *q = p;
    if (p != q)
        free(p);
}
"#;
        let r = rules(src);
        assert!(
            r.contains(&"memory_leak".to_string()),
            "expected leak on the equal path: {:?}",
            r
        );
    }

    /// The uaf corpus' `parse_string` shape: a loop grows a buffer with
    /// malloc on the first iteration and realloc on later ones, so the
    /// loop-header phi carries the realloc result around the back-edge.
    /// The first-growth `if (!p) return` proves `p` NULL on that edge -
    /// no version of the storage holds a live object there, stale phi
    /// bindings included.
    #[test]
    fn stale_loop_binding_on_null_edge_is_silent() {
        let src = r#"
void f(int n)
{
    char *p = NULL;
    int grown = 0;
    while (n > 0) {
        if (!grown) {
            p = malloc(16);
            grown = 1;
            if (!p)
                return;
        } else {
            char *p2 = realloc(p, 32);
            if (!p2) {
                free(p);
                return;
            }
            p = p2;
        }
        n--;
    }
    free(p);
}
"#;
        let r = rules(src);
        assert!(
            r.is_empty(),
            "null-guarded storage must not leak through stale loop bindings: {:?}",
            r
        );
    }
}
