// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub
// Use in proprietary products without GPL obligations needs a separate license: https://friehub.cloud/licensing

//! Deterministic, index-ordered parallel map for the corpus pipeline.
//!
//! Families are independent while they are proposed, lowered and baselined,
//! so that work parallelises cleanly. The workspace bans `std::sync::Mutex`
//! (see `clippy.toml`), so nothing here shares mutable state: each worker
//! owns a contiguous chunk of the input, returns its `(index, values)` pair,
//! and the caller receives a `Vec` in input order no matter how the work was
//! split. Bundle bytes therefore never depend on scheduling.

/// Map `items` across the available cores, preserving input order.
pub(crate) fn map_ordered<T, R, F>(items: &[T], work: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    map_ordered_with_threads(items, default_threads(items.len()), work)
}

/// Worker count for a run: every core, never more than there is work for.
pub(crate) fn default_threads(len: usize) -> usize {
    let hw = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    hw.clamp(1, len.max(1))
}

/// [`map_ordered`] with an explicit worker count, for tests.
pub(crate) fn map_ordered_with_threads<T, R, F>(items: &[T], threads: usize, work: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let threads = threads.clamp(1, items.len().max(1));
    if threads <= 1 || items.len() <= 1 {
        return items.iter().map(work).collect();
    }
    let chunk = items.len().div_ceil(threads);
    let mut parts: Vec<(usize, Vec<R>)> = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for (n, slice) in items.chunks(chunk).enumerate() {
            let base = n * chunk;
            let work = &work;
            handles.push(scope.spawn(move || (base, slice.iter().map(work).collect::<Vec<R>>())));
        }
        handles
            .into_iter()
            .map(|h| match h.join() {
                Ok(values) => values,
                // A worker panic is the caller's panic: propagate the original
                // payload instead of masking it behind a join error.
                Err(payload) => std::panic::resume_unwind(payload),
            })
            .collect()
    });
    parts.sort_by_key(|(base, _)| *base);
    parts.into_iter().flat_map(|(_, values)| values).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_is_independent_of_worker_count() {
        let items: Vec<usize> = (0..97).collect();
        for threads in [1, 2, 3, 8, 64] {
            let out = map_ordered_with_threads(&items, threads, |i| i * 2);
            assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
        }
    }

    #[test]
    fn empty_input_maps_to_empty_output() {
        let items: Vec<u8> = Vec::new();
        assert!(map_ordered(&items, |b| *b).is_empty());
    }
}
