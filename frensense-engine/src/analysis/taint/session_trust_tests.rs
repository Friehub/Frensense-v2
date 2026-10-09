// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Tests for the session-trust sanitizer: values derived from a trusted
//! session store's accessor (`authenticatedUsers.get(token)`) are
//! server-issued, not attacker-controlled, so taint through the store
//! boundary is severed. Receiver-aware: `myMap.get(t)` stays tainted.

#[cfg(test)]
#[allow(clippy::module_inception)] // test file convention: module name repeats parent path segment
pub mod session_trust_tests {
    use crate::analysis::taint::engine::BackwardVerdict;
    use crate::analysis::taint::facts::seeded_tables;
    use crate::harness::lower_source;
    use crate::scan::{prepare, scan_prepared};

    /// The Juice Shop session pattern: token -> session store -> identity
    /// field -> finder sink. The identity field is server-issued; the flow
    /// must be severed at the store boundary.
    const SESSION_FLOW: &str = r#"
import { Request, Response } from 'express'
import * as security from './security'
declare const ordersCollection: any
export function orderHistory () {
  return async (req: Request, res: Response) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      const order = await ordersCollection.find({ email: email })
      res.status(200).json({ data: order })
    }
  }
}
"#;

    /// A plain Map.get with tainted args is NOT a session accessor.
    #[allow(dead_code)] // kept: documents the flow shape; used only in comments below
    const MAP_FLOW: &str = r#"
declare const myMap: any
export function handler (req: any) {
  const v = myMap.get(req.body.key)
  return { value: v }
}
"#;

    fn run(src: &str) -> Vec<crate::analysis::taint::engine::SinkFinding> {
        let files = vec![("test.ts".to_string(), src.to_string(), "ts".to_string())];
        // Session roots are pack vocabulary (the default pack's
        // per-language tables); the production-seeded table already carries them.
        let (config, facts) = seeded_tables(["ts"]);
        let prepared = prepare(&files).expect("prepare");
        scan_prepared(&prepared, &config, &facts).findings
    }

    #[test]
    fn session_derived_identity_is_not_a_flow() {
        let findings = run(SESSION_FLOW);
        let find_f = findings
            .iter()
            .find(|f| f.sink == "find" && f.verdict == BackwardVerdict::Vulnerable);
        assert!(
            find_f.is_none(),
            "session-derived identity must not alert: {:?}",
            find_f.map(|f| (&f.sink, &f.source_desc))
        );
    }

    #[test]
    fn plain_map_get_stays_a_flow() {
        // No sink in MAP_FLOW; the point is the engine's session predicate
        // doesn't fire on arbitrary receivers, assert via the fact table
        // directly for precision.
        let facts = seeded_tables(["ts"]).1;
        assert!(!facts.is_session_path("get", Some("myMap")));
        assert!(facts.is_session_path("get", Some("security.authenticatedUsers")));
        assert!(!facts.is_session_path("put", Some("security.authenticatedUsers")));
    }

    #[test]
    fn receiver_access_path_resolves_namespaced_stores() {
        let irs = lower_source("t.ts", SESSION_FLOW, "ts").unwrap();
        // The handler body lives in the IR that OWNS it - the returned
        // arrow (`<fn@N>`), not the `orderHistory` husk that only returns
        // it - so search every IR for the resolved path.
        let any_path = irs.values().any(|ir| {
            ir.var_metadata.keys().any(|v| {
                crate::analysis::taint::facts::FactTable::receiver_access_path(ir, *v)
                    .map(|p| p.contains("authenticatedUsers"))
                    .unwrap_or(false)
            })
        });
        assert!(
            any_path,
            "receiver_access_path must reach the store segment"
        );
    }
}
