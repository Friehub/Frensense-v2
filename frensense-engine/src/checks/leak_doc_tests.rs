// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! The allocation-lifetime example from `leak::check`'s documentation.
//!
//! It cannot stay a doctest: `check` is crate-private (the published surface is
//! the scan, not the checker), and a doctest is compiled as an outside crate.
//! The assertions live here so the documented behaviour stays executed.

#[cfg(test)]
pub(super) mod leak_doc_spec {
    use crate::analysis::taint::facts::FactTable;
    use crate::checks::leak;
    use crate::checks::memory_summary::{CapacitySpec, MemorySummary, MemorySummaryRegistry};
    use crate::harness::lower_source;

    /// The rule ids `f` raises with `malloc` as a factory and `free` as a
    /// consumer of its argument.
    fn rules(src: &str) -> Vec<String> {
        let mut summaries = MemorySummaryRegistry::default();
        summaries.summaries.insert(
            "malloc".into(),
            MemorySummary {
                returns_fresh: true,
                return_capacity: CapacitySpec::Unknown,
                consumes_params: vec![],
                out_params_fresh: vec![],
            },
        );
        summaries.summaries.insert(
            "free".into(),
            MemorySummary {
                returns_fresh: false,
                return_capacity: CapacitySpec::Unknown,
                consumes_params: vec![0],
                out_params_fresh: vec![],
            },
        );
        let fns = lower_source("t.c", src, "c").unwrap();
        leak::check(&fns["f"], &summaries, &FactTable::default())
            .into_iter()
            .map(|f| f.rule)
            .collect()
    }

    #[test]
    fn the_documented_example_still_holds() {
        assert_eq!(
            rules("void f(void) { char *p = malloc(8); p[0] = 1; }"),
            ["memory_leak"]
        );
        // Released on the only path: no leak.
        assert!(rules("void f(void) { char *p = malloc(8); free(p); }").is_empty());
    }
}
