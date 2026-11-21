// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package postgres

import (
	"github.com/Lutfifakee-Project/gseer/internal/fprule"
)

// fingerprint.go — v0.1.0 evidence enrichment at ingestion.
//
// When the operator-attached rule engine classifies the http/tls/ssh
// evidence a record already carries, the derived payload is merged
// into the STORED evidence copy under `fingerprint`:
//
//	"fingerprint": {
//	  "technologies": ["nginx", ...],        // plain product names,
//	                                         // confidence order — the
//	                                         // search_index array
//	  "derived": [ {"rule_id","family","product","version","confidence"} ]
//	}
//
// Honesty rules:
//   - the CALLER's evidence map is never mutated;
//   - PayloadHash (the L1/L2 dedup identity) is computed from the RAW
//     delivered record and is never affected;
//   - a source-provided `fingerprint` key always wins (the engine only
//     fills an absence);
//   - an unhealthy registry (compile problem) enriches nothing;
//   - no technology hit ever creates a service, port, or protocol —
//     technologies attach to the observation's own row.
func enrichEvidence(engine *fprule.Registry, evidence map[string]any) map[string]any {
	if engine == nil || !engine.Healthy() || len(evidence) == 0 {
		return evidence
	}
	if _, exists := evidence["fingerprint"]; exists {
		return evidence // source-provided fingerprints win
	}
	matches := engine.Apply(evidence)
	if len(matches) == 0 {
		return evidence
	}
	// Copy-on-write: the top-level map is a shallow copy; the engine
	// only adds one new key, so nested values can be shared.
	merged := make(map[string]any, len(evidence)+1)
	for k, v := range evidence {
		merged[k] = v
	}
	derived := make([]map[string]any, 0, len(matches))
	for _, m := range matches {
		d := map[string]any{
			"rule_id":    m.RuleID,
			"family":     m.Family,
			"product":    m.Product,
			"confidence": m.Confidence,
		}
		if m.Version != "" {
			d["version"] = m.Version
		}
		derived = append(derived, d)
	}
	merged["fingerprint"] = map[string]any{
		"technologies": fprule.Products(matches),
		"derived":      derived,
	}
	return merged
}
