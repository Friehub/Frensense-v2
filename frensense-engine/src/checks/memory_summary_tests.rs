// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for interprocedural allocation & deallocation wrappers (Limitation M1).

#[cfg(test)]
pub mod memory_summary_spec {
    use crate::analysis::taint::facts::FactTable;
    use crate::checks::check_all;
    use crate::harness::lower_source;

    fn hits(src: &str) -> Vec<String> {
        let fns = lower_source("t.c", src, "c").unwrap();
        let ir_refs: Vec<_> = fns.values().collect();
        let findings = check_all(ir_refs, &FactTable::default());
        let mut rules: Vec<String> = findings.into_iter().map(|f| f.rule).collect();
        rules.sort();
        rules
    }

    /// Custom deallocator wrapper: free_wrapper(p) frees p, caller p[0] is UAF.
    #[test]
    fn custom_deallocator_wrapper_fires_uaf() {
        let src = r#"
#include <stdlib.h>
void free_wrapper(char *p) {
    free(p);
}

void caller() {
    char *p = malloc(16);
    free_wrapper(p);
    p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "calling free_wrapper then using p must fire use_after_free: {:?}",
            rules
        );
    }

    /// Custom deallocator wrapper: calling twice on same pointer fires double_free.
    #[test]
    fn custom_deallocator_wrapper_fires_double_free() {
        let src = r#"
#include <stdlib.h>
void free_wrapper(char *p) {
    free(p);
}

void caller() {
    char *p = malloc(16);
    free_wrapper(p);
    free_wrapper(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "double_free"),
            "calling free_wrapper twice on same pointer must fire double_free: {:?}",
            rules
        );
    }

    /// Custom factory function: create_buf returns fresh allocation; free then use fires UAF.
    #[test]
    fn custom_factory_wrapper_fires_uaf() {
        let src = r#"
#include <stdlib.h>
char *create_buf(int sz) {
    char *p = malloc(sz);
    return p;
}

void caller() {
    char *p = create_buf(16);
    free(p);
    p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "memory from create_buf used after free must fire use_after_free: {:?}",
            rules
        );
    }

    /// Custom factory function: create_buf returns fresh allocation with capacity; OOB access fires.
    #[test]
    fn custom_factory_wrapper_fires_oob() {
        let src = r#"
#include <stdlib.h>
char *create_buf(int sz) {
    char *p = malloc(sz);
    return p;
}

void caller() {
    char *p = create_buf(10);
    p[15] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "buffer_overflow"),
            "index 15 on create_buf(10) must fire buffer_overflow: {:?}",
            rules
        );
    }

    /// Multi-level nested deallocator wrappers: outer -> inner -> free.
    #[test]
    fn nested_deallocator_wrapper_fires_uaf() {
        let src = r#"
#include <stdlib.h>
void inner_free(char *p) {
    free(p);
}

void outer_free(char *q) {
    inner_free(q);
}

void caller() {
    char *p = malloc(16);
    outer_free(p);
    p[0] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "nested outer_free then use must fire use_after_free: {:?}",
            rules
        );
    }

    /// Safe wrapper usage stays completely silent.
    #[test]
    fn safe_wrapper_usage_is_silent() {
        let src = r#"
#include <stdlib.h>
char *create_buf(int sz) {
    char *p = malloc(sz);
    return p;
}

void free_wrapper(char *p) {
    free(p);
}

void caller() {
    char *p = create_buf(16);
    p[0] = 1;
    free_wrapper(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "safe allocation, use, then free_wrapper must be silent: {:?}",
            rules
        );
    }

    /// Non-deallocating helper taking pointer never consumes it (0-FP guardrail).
    #[test]
    fn non_deallocating_function_never_consumes() {
        let src = r#"
#include <stdlib.h>
void inspect(char *p) {
    char c = p[0];
}

void caller() {
    char *p = malloc(16);
    inspect(p);
    p[0] = 1;
    free(p);
}
"#;
        let rules = hits(src);
        assert!(
            rules.is_empty(),
            "inspect(p) must not consume p; subsequent access and free must be silent: {:?}",
            rules
        );
    }

    /// Builtin library wrappers (e.g. g_malloc, g_free) from registry.
    #[test]
    fn builtin_registry_library_wrappers() {
        let src = r#"
extern void *g_malloc(unsigned long n_bytes);
extern void g_free(void *mem);

void caller() {
    char *p = g_malloc(10);
    p[20] = 1;
}
"#;
        let rules = hits(src);
        assert!(
            rules.iter().any(|r| r == "buffer_overflow"),
            "g_malloc(10) with p[20] = 1 must fire buffer_overflow: {:?}",
            rules
        );
    }

    /// Corpus/bundle-learned allocation contract seeds registry and detects OOB.
    #[test]
    fn bundle_learned_allocator_fires_oob() {
        use crate::analysis::taint::facts::{FactTable, MemoryContractFact};
        use crate::checks::memory_summary::CapacitySpec;

        let mut facts = FactTable::default();
        facts.memory_contracts.push(MemoryContractFact {
            name: "custom_kalloc".to_string(),
            returns_fresh: true,
            return_capacity: CapacitySpec::Param(0),
            consumes_params: vec![],
        });

        let src = r#"
extern void *custom_kalloc(int size);

void caller() {
    char *p = custom_kalloc(10);
    p[20] = 1;
}
"#;
        let fns = lower_source("t.c", src, "c").unwrap();
        let ir_refs: Vec<_> = fns.values().collect();
        let findings = check_all(ir_refs, &facts);
        let rules: Vec<String> = findings.into_iter().map(|f| f.rule).collect();
        assert!(
            rules.iter().any(|r| r == "buffer_overflow"),
            "custom_kalloc(10) from bundle must fire buffer_overflow on p[20]: {:?}",
            rules
        );
    }

    /// Corpus/bundle-learned deallocator contract seeds registry and detects UAF.
    #[test]
    fn bundle_learned_deallocator_fires_uaf() {
        use crate::analysis::taint::facts::{FactTable, MemoryContractFact};
        use crate::checks::memory_summary::CapacitySpec;

        let mut facts = FactTable::default();
        facts.memory_contracts.push(MemoryContractFact {
            name: "external_release".to_string(),
            returns_fresh: false,
            return_capacity: CapacitySpec::Unknown,
            consumes_params: vec![0],
        });

        let src = r#"
#include <stdlib.h>
extern void external_release(void *ptr);

void caller() {
    char *p = malloc(16);
    external_release(p);
    p[0] = 1;
}
"#;
        let fns = lower_source("t.c", src, "c").unwrap();
        let ir_refs: Vec<_> = fns.values().collect();
        let findings = check_all(ir_refs, &facts);
        let rules: Vec<String> = findings.into_iter().map(|f| f.rule).collect();
        assert!(
            rules.iter().any(|r| r == "use_after_free"),
            "external_release(p) from bundle must fire use_after_free on p[0]: {:?}",
            rules
        );
    }

    /// LearnedFactEntry::MemoryContract round-trips losslessly through bincode.
    #[test]
    fn bundle_contract_roundtrip_bincode() {
        use crate::analysis::taint::facts::LearnedFactEntry;
        use crate::checks::memory_summary::CapacitySpec;

        let original = LearnedFactEntry::MemoryContract {
            name: "my_pool_alloc".to_string(),
            returns_fresh: true,
            return_capacity: CapacitySpec::ParamProduct(0, 1),
            consumes_params: vec![2],
        };

        let encoded = bincode::serialize(&original).expect("serialize MemoryContract");
        let decoded: LearnedFactEntry = bincode::deserialize(&encoded).expect("deserialize MemoryContract");

        assert_eq!(original, decoded);
    }
}

