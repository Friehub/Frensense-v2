// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Serialisable structure parts (task 4.5): structure <-> plain data.

use super::*;

// ---------------------------------------------------------------------------
// Serialisable structure parts (task 4.5)
// ---------------------------------------------------------------------------

/// Plain-data mirror of [`FunctionEntry`] containing only what the corpus
/// graph store persists: everything derived from source, nothing derived from
/// the rule set.
#[cfg(feature = "serialize")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionParts {
    pub name: String,
    /// A complete copy of the function's IR. At load time the caller-supplied
    /// IR takes precedence; this copy serves structural validation and makes
    /// the store self-contained.
    pub ir: FunctionIR,
    pub svfg: Svfg,
    /// VarId → defining node key. Serialises as a sorted pair list
    /// (`FxHashMap<VarId, _>` is not serde_json-key-compatible).
    #[cfg_attr(feature = "serialize", serde(with = "var_keyed_map"))]
    pub def_site: FxHashMap<VarId, NodeKey>,
    /// Resolved call-site bindings (callee indices are store-stable: they
    /// refer to positions in `functions`, which serialises in order).
    pub bindings: Vec<CallBinding>,
}

/// Plain-data mirror of the program-level graph (see [`ProgramSvfg::to_parts`]).
#[cfg(feature = "serialize")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProgramSvfgParts {
    /// Functions in store order (deterministic: sorted by name at build time).
    pub functions: Vec<FunctionParts>,
    /// DFS post-order (leaves first) over the call graph, as function indices.
    pub topological_order: Vec<usize>,
    /// `(from_fn, from_node) → [(to_fn, to_node)]`, stored as a sorted pair
    /// list (serde_json needs string map keys, and a sorted Vec is byte-
    /// deterministic for cache hashing). Keys via [`SerKey`].
    pub cross_edges: Vec<(SerKey, Vec<(usize, NodeKey)>)>,
}

/// Serde-friendly key for the cross-edge map: `(function index, node key)`.
#[cfg(feature = "serialize")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SerKey {
    pub f: usize,
    pub k: NodeKey,
}

/// Serde with-helper for `FxHashMap<VarId, V>`: round-trips through a sorted
/// `Vec<(VarId, V)>` (VarId is a newtype over usize; serde_json cannot use it
/// as a map key directly). Sorted = byte-deterministic serialisation.
#[cfg(feature = "serialize")]
mod var_keyed_map {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        map: &FxHashMap<VarId, NodeKey>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        let mut v: Vec<(VarId, NodeKey)> = map.iter().map(|(k, val)| (*k, *val)).collect();
        v.sort_by_key(|(k, _)| k.0);
        v.serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<FxHashMap<VarId, NodeKey>, D::Error> {
        Ok(FxHashMap::from_iter(Vec::<(VarId, NodeKey)>::deserialize(
            de,
        )?))
    }
}

impl<'a> ProgramSvfg<'a> {
    // -----------------------------------------------------------------------
    // Serialisation support (task 4.5): structure ↔ parts
    // -----------------------------------------------------------------------

    /// Extract the *config-independent* structure of this program graph as
    /// plain data, ready for serialisation (task 4.5's corpus graph store).
    ///
    /// What is captured: per-function SVFGs (nodes, kinds, edges), call-site
    /// bindings, cross edges and the bottom-up topological order, everything
    /// determined solely by the source code.
    ///
    /// What is deliberately NOT captured: [`TaintSummary`]s and the
    /// pass-through suppression set. Both depend on the **rule set**
    /// (sources/sinks/sanitizers), not the source, they are recomputed at
    /// load time from the freshly applied config. This is precisely what
    /// lets a new sink configuration re-scan a cached repo without re-running
    /// lower → SSA → SVFG build.
    #[cfg(feature = "serialize")]
    pub fn to_parts(&self) -> ProgramSvfgParts {
        ProgramSvfgParts {
            functions: self
                .functions
                .iter()
                .map(|f| FunctionParts {
                    name: f.name.clone(),
                    ir: f.ir.clone(),
                    svfg: f.svfg.clone(),
                    def_site: f.def_site.clone(),
                    bindings: f.bindings.clone(),
                })
                .collect(),
            topological_order: self.topological_order.clone(),
            cross_edges: {
                let mut v: Vec<(SerKey, Vec<(usize, NodeKey)>)> = self
                    .cross_edges
                    .iter()
                    .map(|((f, k), edges)| (SerKey { f: *f, k: *k }, edges.clone()))
                    .collect();
                v.sort_by_key(|(sk, _)| (sk.f, sk.k.block.0, sk.k.instr_idx, sk.k.var.0));
                v
            },
        }
    }

    /// Rebuild a [`ProgramSvfg`] from serialised parts plus a **new** taint
    /// config. Summaries and pass-through suppression are recomputed from the
    /// supplied config (not restored from disk), so the returned graph answers
    /// queries under the new rule set.
    #[cfg(feature = "serialize")]
    pub fn from_parts(
        parts: ProgramSvfgParts,
        irs: &FxHashMap<String, &'a FunctionIR>,
        config: &TaintConfig,
    ) -> Self {
        let ProgramSvfgParts {
            functions,
            topological_order,
            cross_edges,
        } = parts;

        // Rebuild function entries. The SVFG/bindings/def-sites come from the
        // store; the IR reference must point at the caller-supplied IRs (the
        // store's copies are structurally identical, but predicates like
        // `is_source` consult the live IR).
        //
        // Functions absent from `irs` fall back to their stored IR copy, leaked
        // to satisfy the `&'a` lifetime (program graphs are long-lived by
        // design; the leak is one copy per function per cache load, and the
        // self-contained-cache path has no live IR to hold anyway).
        let functions: Vec<FunctionEntry> = functions
            .into_iter()
            .map(|fp| {
                let name = fp.name.clone();
                let ir: &FunctionIR = match irs.get(&name) {
                    Some(&live) => live,
                    None => Box::leak(Box::new(fp.ir)),
                };
                let arg_slots: FxHashMap<NodeKey, (usize, usize)> = fp
                    .bindings
                    .iter()
                    .enumerate()
                    .flat_map(|(bi, b)| b.args.iter().map(move |(k, s)| (*k, (bi, *s))))
                    .collect();
                FunctionEntry {
                    name,
                    ir,
                    svfg: fp.svfg,
                    def_site: fp.def_site,
                    bindings: fp.bindings,
                    arg_slots,
                    summary: None,
                }
            })
            .collect();

        // Re-derive the name → index map (store order is preserved exactly).
        let func_index: FxHashMap<String, usize> = functions
            .iter()
            .enumerate()
            .map(|(i, f)| (f.name.clone(), i))
            .collect();

        let mut prog = Self {
            functions,
            func_index,
            topological_order,
            cross_edges: cross_edges
                .into_iter()
                .map(|(sk, edges)| ((sk.f, sk.k), edges))
                .collect(),
            suppressed: FxHashSet::default(),
        };

        // Recompute the config-dependent state under the NEW rule set.
        let default_facts = FactTable::from_config(config);
        prog.compute_summaries(config, &default_facts);
        prog
    }
}
