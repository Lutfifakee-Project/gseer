// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package sqlite

// fingerprint.go — v0.1.0 evidence enrichment at ingestion (the same
// contract and honesty rules as the postgres package's copy):
//
// When the operator-attached rule engine classifies the http/tls/ssh
// evidence a record already carries, the derived payload is merged
// into the STORED evidence copy under `fingerprint`:
//
//	"fingerprint": {
//	  "technologies": ["nginx", ...],   // confidence order
//	  "derived": [ {"rule_id","family","product","version","confidence"} ]
//	}
//
// Honesty rules (identical to the PG store):
//   - the CALLER's evidence map is never mutated;
//   - PayloadHash (the L1/L2 dedup identity) is never affected;
//   - a source-provided `fingerprint` key always wins;
//   - an unhealthy registry enriches nothing;
//   - no technology hit ever creates a service, port, or protocol.

import (
	"github.com/Lutfifakee-Project/gseer/internal/fprule"
)

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
	merged := make(map[string]any, len(evidence)+1)
	for k, v := range evidence {
		merged[k] = v
	}
	technologies := make([]string, 0, len(matches))
	type derived struct {
		RuleID     string  `json:"rule_id"`
		Family     string  `json:"family"`
		Product    string  `json:"product"`
		Version    string  `json:"version,omitempty"`
		Confidence float64 `json:"confidence"`
	}
	derivedList := make([]derived, 0, len(matches))
	for _, m := range matches {
		technologies = append(technologies, m.Product)
		derivedList = append(derivedList, derived{
			RuleID:     m.RuleID,
			Family:     m.Family,
			Product:    m.Product,
			Version:    m.Version,
			Confidence: m.Confidence,
		})
	}
	merged["fingerprint"] = map[string]any{
		"technologies": technologies,
		"derived":      derivedList,
	}
	return merged
}
